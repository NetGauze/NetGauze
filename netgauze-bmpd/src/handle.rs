// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Utils to handle [crate::server::BmpServer] lifecycle
//! This module is heavily influenced by [axum-server](https://github.com/programatik29/axum-server/blob/84bc67b/src/handle.rs)

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Notify;

#[derive(Debug, Default)]
pub(crate) struct NotifyOnce {
    /// Track if the waiters has been notified already
    triggered: AtomicBool,
    notify: Notify,
}

/// Specialized version of [tokio::sync::Notify] that notify listeners only
/// once. Useful for shutdown signals, where we need to make sure that we don't
/// notify multiple times.
impl NotifyOnce {
    /// If not notified before, then call [tokio::sync::Notify::notify_waiters]
    pub(crate) fn notify_waiters(&self) {
        if !self.triggered.fetch_or(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    /// Return true if waiters has been notified already
    pub(crate) fn is_notified(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }

    /// If not notified before, then call [tokio::sync::Notify::notified]
    pub(crate) async fn notified(&self) {
        if !self.triggered.load(Ordering::SeqCst) {
            self.notify.notified().await;
        }
    }
}

/// Handle to be able to send signals or read atomic values from the BmpServer
/// after it's spawned into its own task.
#[derive(Clone, Debug, Default)]
pub struct BmpServerHandle {
    inner: Arc<BmpServerHandleInner>,
}

#[derive(Debug, Default)]
struct BmpServerHandleInner {
    connection_count: AtomicUsize,
    listening: NotifyOnce,
    shutdown: NotifyOnce,
    graceful_shutdown: NotifyOnce,
    graceful_shutdown_duration: Option<Duration>,
    connection_end: NotifyOnce,
}

impl BmpServerHandleInner {
    fn new(graceful_shutdown_duration: Option<Duration>) -> Self {
        Self {
            connection_count: AtomicUsize::default(),
            listening: NotifyOnce::default(),
            shutdown: NotifyOnce::default(),
            graceful_shutdown: NotifyOnce::default(),
            graceful_shutdown_duration,
            connection_end: NotifyOnce::default(),
        }
    }
}

impl BmpServerHandle {
    pub fn new(graceful_shutdown_duration: Option<Duration>) -> Self {
        let inner = BmpServerHandleInner::new(graceful_shutdown_duration);
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn connection_count(&self) -> usize {
        self.inner.connection_count.load(Ordering::SeqCst)
    }

    pub(crate) fn notify_listening(&self) {
        self.inner.listening.notify_waiters();
    }

    pub async fn listening(&self) {
        self.inner.listening.notified().await;
    }

    pub fn shutdown(&self) {
        println!("Shutdown signal is received");
        self.inner.shutdown.notify_waiters();
    }

    pub fn graceful_shutdown(&self) {
        self.inner.graceful_shutdown.notify_waiters();
    }

    pub(crate) async fn wait_shutdown(&self) {
        self.inner.shutdown.notified().await;
    }

    pub(crate) async fn wait_graceful_shutdown(&self) {
        self.inner.graceful_shutdown.notified().await;
    }

    pub(crate) fn watcher(&self) -> BmpServerHandleWatcher {
        BmpServerHandleWatcher::new(self.clone())
    }

    /// Wait for graceful shutdown duration, before forcing all connections to
    /// close Useful to make sure that server has cleanly closed all
    /// connections
    pub(crate) async fn wait_connections_end(&self) {
        if self.inner.connection_count.load(Ordering::SeqCst) == 0 {
            return;
        }
        match self.inner.graceful_shutdown_duration {
            Some(duration) => tokio::select! {
                biased;
                _ = tokio::time::sleep(duration) => self.shutdown(),
                _ = self.inner.connection_end.notified() => ()
            },
            None => self.inner.connection_end.notified().await,
        }
    }
}

pub(crate) struct BmpServerHandleWatcher {
    handle: BmpServerHandle,
}

impl BmpServerHandleWatcher {
    fn new(handle: BmpServerHandle) -> Self {
        handle.inner.connection_count.fetch_add(1, Ordering::SeqCst);
        Self { handle }
    }

    pub(crate) async fn wait_shutdown(&self) {
        self.handle.wait_shutdown().await;
    }
}

impl Drop for BmpServerHandleWatcher {
    fn drop(&mut self) {
        let count = self
            .handle
            .inner
            .connection_count
            .fetch_sub(1, Ordering::SeqCst)
            - 1;
        if count == 0 && self.handle.inner.graceful_shutdown.is_notified() {
            self.handle.inner.connection_end.notify_waiters();
        }
    }
}

#[cfg(test)]
mod test {
    use crate::handle::{BmpServerHandle, NotifyOnce};
    use std::time::Duration;

    #[tokio::test]
    async fn test_notify_once() {
        let notify_once = NotifyOnce::default();

        let notified = notify_once.notified();
        assert!(!notify_once.is_notified());

        notify_once.notify_waiters();
        assert!(notify_once.is_notified());
        assert!(tokio::time::timeout(Duration::from_millis(1), notified)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_shutdown() {
        let handle = BmpServerHandle::default();

        let shutdown_wait = handle.wait_shutdown();
        assert!(!handle.inner.shutdown.is_notified());

        handle.shutdown();
        assert!(handle.inner.shutdown.is_notified());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), shutdown_wait)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let handle = BmpServerHandle::default();

        let shutdown_wait = handle.wait_graceful_shutdown();
        assert!(!handle.inner.graceful_shutdown.is_notified());

        handle.graceful_shutdown();
        assert!(handle.inner.graceful_shutdown.is_notified());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), shutdown_wait)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_connection_count() {
        let handle = BmpServerHandle::default();
        let watcher_1 = handle.watcher();
        let watcher_2 = handle.watcher();

        assert_eq!(handle.connection_count(), 2);
        drop(watcher_1);
        assert_eq!(handle.connection_count(), 1);
        drop(watcher_2);
        assert_eq!(handle.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_wait_connections_end() {
        let handle = BmpServerHandle::new(Some(Duration::from_millis(1)));
        let _watcher_1 = handle.watcher();
        let _watcher_2 = handle.watcher();

        assert!(!handle.inner.connection_end.is_notified());
        assert_eq!(handle.connection_count(), 2);
        let wait_connection_end = handle.wait_connections_end();
        assert!(
            tokio::time::timeout(Duration::from_millis(2), wait_connection_end)
                .await
                .is_ok()
        );
        assert!(handle.inner.shutdown.is_notified());
    }
}
