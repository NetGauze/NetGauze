// Copyright (C) 2022-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

use crate::affinity::{AffinityStrategy, CoreId, NoAffinity, PinOutcome};
use crate::assignment::CoreAssignment;
use crate::unix_ms_now;
use crate::worker::{Worker, WorkerContext, WorkerIndex};
use arc_swap::{ArcSwap, ArcSwapOption};
use opentelemetry::metrics::Meter;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{io, thread};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

/// Everything about HOW to run a worker fleet, apart from the worker's
/// own `Config`: the growable half of [`CollectionSupervisor::start`]'s
/// signature.
#[non_exhaustive]
pub struct SupervisorOptions {
    /// One worker per entry; `worker_index` order.
    pub cores: CoreAssignment,
    /// Per-worker command-channel capacity (control-plane rate: small).
    pub mailbox: usize,
    pub affinity: Arc<dyn AffinityStrategy>,
    pub policy: RestartPolicy,
    /// Instance name to be used in logs and telemetry
    pub name: Box<str>,
}

impl SupervisorOptions {
    pub const DEFAULT_MAILBOX: usize = 64;

    pub fn new(cores: CoreAssignment, name: &str) -> Self {
        Self {
            cores,
            mailbox: Self::DEFAULT_MAILBOX,
            affinity: Arc::new(NoAffinity),
            policy: RestartPolicy::default(),
            name: Box::from(name),
        }
    }

    pub fn with_mailbox(mut self, mailbox: usize) -> Self {
        self.mailbox = mailbox;
        self
    }

    pub fn with_affinity(mut self, affinity: Arc<dyn AffinityStrategy>) -> Self {
        self.affinity = affinity;
        self
    }

    pub fn with_policy(mut self, policy: RestartPolicy) -> Self {
        self.policy = policy;
        self
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SlotExitInfo {
    pub kind: SlotExitKind,
    /// The error's `Display`, or the panic message; empty for `Clean`.
    pub message: String,
    /// Wall-clock stamp (Unix epoch ms) of when the supervisor processed
    /// the exit.
    pub at_unix_ms: u64,
    /// Restarts consumed in the slot's current window at stamp time.
    pub restarts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotExitKind {
    Clean,
    Error,
    Panic,
}

#[derive(Debug)]
enum ExitReason {
    /// `Worker::run` returned `Ok(())`;  command channel closed, or an
    /// explicit Shutdown was handled inside `run`. Not respawned.
    Clean,
    /// `Worker::run` returned `Err`. Respawn per `RestartPolicy`.
    Error(Box<dyn std::error::Error + Send + Sync>),
    /// The thread panicked: `std::thread::Result`'s own payload type.
    /// Respawn per `RestartPolicy`; `panic_message` best-efforts a string
    /// out of the common `&str`/`String` payload shapes for logging.
    Panic(Box<dyn std::any::Any + Send>),
}

/// Which worker exited and for what reason
struct WorkerExit {
    worker_index: WorkerIndex,
    reason: ExitReason,
}

/// The supervisor-private record of one spawned thread, one per
/// incarnation (a respawn replaces the whole record). Deliberately NOT
/// `Clone` and never exported: the `JoinHandle` must not be joinable out
/// from under the supervisor, and handing out `cmd_tx` directly would
/// open an unsupervised, stale-on-respawn path to the worker's mailbox.
struct WorkerThread<Cmd> {
    cmd_tx: mpsc::Sender<Cmd>,
}

/// Per-slot supervision bookkeeping, kept apart from `WorkerThread`
/// because it must survive respawns (a fresh `WorkerThread` replaces the
/// old one; the restart budget must not reset with it).
struct SlotState {
    restarts: usize,
    window_start: Instant,
    /// Restart budget exhausted: the slot is left dead ("give up loudly"),
    /// `route()` to it returns `WorkerGone`.
    failed: bool,
    /// Exited via `ExitReason::Clean`; deliberately not respawned.
    done: bool,
}

/// Respawn budget for crashed workers: up to `max_restarts` restarts
/// within any `window`, pacing each respawn by `backoff`; past the budget
/// the slot is given up loudly ([AdminHandle::failed_slots]).
///
/// `#[non_exhaustive]` + [`RestartPolicy::new`], so future knobs (e.g.,
/// respawn-on-clean for connection-oriented protocols, jittered backoff)
/// are additive rather than breaking.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestartPolicy {
    max_restarts: usize, // within `window`, before giving up loudly
    window: Duration,
    backoff: Duration,
    min_live_workers: usize,
}

impl RestartPolicy {
    pub const fn new(max_restarts: usize, window: Duration, backoff: Duration) -> Self {
        Self {
            max_restarts,
            window,
            backoff,
            min_live_workers: 0,
        }
    }

    pub const fn with_min_live_workers(mut self, min_live_workers: usize) -> Self {
        self.min_live_workers = min_live_workers;
        self
    }

    /// The budget must be REACHABLE: each respawn takes at least
    /// `backoff`, so a crash loop can only exhaust `max_restarts` inside
    /// `window` when `backoff * (max_restarts + 1) <= window`. Otherwise,
    /// the rolling window resets the count before it can ever exceed the
    /// budget and "give up loudly" is dead code which can cause an eternal
    /// crash loop that [AdminHandle::failed_slots] never reports.
    pub fn validate(&self) -> Result<(), RestartPolicyError> {
        if self.window.is_zero() {
            return Err(RestartPolicyError::ZeroWindow);
        }
        if self.backoff.is_zero() {
            return Err(RestartPolicyError::ZeroBackoff);
        }
        let budget_time = self
            .backoff
            .saturating_mul(u32::try_from(self.max_restarts).unwrap_or(u32::MAX));
        if budget_time > self.window {
            return Err(RestartPolicyError::UnreachableBudget {
                backoff: self.backoff,
                max_restarts: self.max_restarts,
                window: self.window,
            });
        }
        Ok(())
    }
}

impl Default for RestartPolicy {
    /// 3 restarts per 60s window, 100ms backoff.
    fn default() -> Self {
        Self::new(3, Duration::from_secs(60), Duration::from_millis(100))
    }
}

/// Why [`CollectionSupervisor::supervise`] returned. The embedder decides
/// what each means for the process; `BelowMinimumWorkers` is the signal
/// to tear the whole service down (call `shutdown()` for the survivors'
/// flush, then exit non-zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive] // future exit reasons must be additive, like RestartPolicy's knobs
#[must_use = "BelowMinimumWorkers means the service should shut itself down; ignoring it defeats the min-live check"]
pub enum SuperviseExit {
    /// The shutdown signal fired (or its sender dropped): normal
    /// teardown, proceed to `shutdown()`.
    ShutdownRequested,
    /// Live workers (neither failed nor cleanly done) dropped below
    /// `RestartPolicy::min_live_workers`.
    BelowMinimumWorkers { live: usize, minimum: usize },
}

/// Error in routing commands from the Supervisor to the worker threads
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("no worker at index {0}")]
    UnknownWorker(WorkerIndex),
    #[error(
        "worker {0}'s command channel is closed (thread exited: mid-respawn, done, or failed; check done_slots()/failed_slots())"
    )]
    WorkerGone(WorkerIndex),
    #[error("worker {0}'s command mailbox is full")]
    MailboxFull(WorkerIndex),
}

/// The concurrent-admin side of a supervisor: cloneable, usable WHILE
/// `supervise()` holds the supervisor mutably, where an admin surface
/// serves queries as supervision runs.
/// Per-slot senders live behind `ArcSwap` so a respawn refreshes them in place:
/// an admin holding this handle transparently reaches the NEW worker
/// after a restart, and gets `WorkerGone` only in the dead window.
pub struct AdminHandle<Cmd> {
    senders: Arc<[ArcSwap<mpsc::Sender<Cmd>>]>,
    failed: Arc<[AtomicBool]>,
    done: Arc<[AtomicBool]>,
    /// Per-slot record of the most recent exit (RCU: supervisor stores,
    /// admins load); `None` until a slot's first exit.
    last_exits: Arc<[ArcSwapOption<SlotExitInfo>]>,
    /// Name used for logging and OTEL metrics
    name: Box<str>,
}

/// Manually implemented since Cmd doesn't need to be clonable
impl<Cmd> Clone for AdminHandle<Cmd> {
    fn clone(&self) -> Self {
        Self {
            senders: Arc::clone(&self.senders),
            failed: Arc::clone(&self.failed),
            done: Arc::clone(&self.done),
            last_exits: Arc::clone(&self.last_exits),
            name: self.name.clone(),
        }
    }
}

impl<Cmd> AdminHandle<Cmd> {
    pub fn worker_count(&self) -> usize {
        self.senders.len()
    }

    /// The supervisor's instance name: the same value stamped on its log
    /// lines, so embedder-side admin surfaces can label their own output
    /// with the supervisor a reply came from.
    pub const fn name(&self) -> &str {
        &self.name
    }

    /// Worker whose restart budget is exhausted they are not going to be
    /// retried to start again.
    pub fn failed_slots(&self) -> Vec<WorkerIndex> {
        self.failed
            .iter()
            .enumerate()
            .filter(|(_, f)| f.load(Ordering::Relaxed))
            .map(|(i, _)| WorkerIndex::new(i))
            .collect()
    }

    /// Slots whose worker exited cleanly and is deliberately not
    /// respawned.
    pub fn done_slots(&self) -> Vec<WorkerIndex> {
        self.done
            .iter()
            .enumerate()
            .filter(|(_, f)| f.load(Ordering::Relaxed))
            .map(|(i, _)| WorkerIndex::new(i))
            .collect()
    }

    pub fn last_exit(&self, worker_index: WorkerIndex) -> Option<Arc<SlotExitInfo>> {
        self.last_exits.get(worker_index.get())?.load_full()
    }

    /// A blocking send a message for one worker. If the mailbox of the worker
    /// is full, this method will block (potentially for infinity), thus,
    /// it's recommended for callers to wrap the calls to this method with a
    /// timeout.
    pub async fn route(&self, worker_index: WorkerIndex, cmd: Cmd) -> Result<(), RouteError> {
        let slot = self
            .senders
            .get(worker_index.get())
            .ok_or(RouteError::UnknownWorker(worker_index))?;
        let sender = slot.load_full();
        sender
            .send(cmd)
            .await
            .map_err(|_| RouteError::WorkerGone(worker_index))
    }

    /// A non-blocking send for a message to a given worker.
    pub fn try_route(&self, worker_index: WorkerIndex, cmd: Cmd) -> Result<(), RouteError> {
        let slot = self
            .senders
            .get(worker_index.get())
            .ok_or(RouteError::UnknownWorker(worker_index))?;
        let sender = slot.load_full();
        sender.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => RouteError::MailboxFull(worker_index),
            mpsc::error::TrySendError::Closed(_) => RouteError::WorkerGone(worker_index),
        })
    }

    /// A util function to run one async operation per worker CONCURRENTLY,
    /// each bounded by `timeout`, collecting whatever the operation yields.
    ///
    /// The shared scaffolding behind [`Self::broadcast`] and [`Self::fan_out`]:
    /// N wedged workers cost ONE timeout, not a serial stack of them.
    async fn each_worker<F, Fut, T>(&self, timeout: Duration, f: F) -> Vec<(WorkerIndex, T)>
    where
        F: Fn(WorkerIndex) -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        let calls = (0..self.senders.len()).map(|i| {
            let worker_index = WorkerIndex::new(i);
            let call = f(worker_index); // built here, owned by the future below
            async move {
                match tokio::time::timeout(timeout, call).await {
                    Ok(Some(value)) => Some((worker_index, value)),
                    Ok(None) => None, // dead slot or no reply: skipped
                    Err(_) => {
                        warn!(
                            supervisor = %self.name,
                            worker_index = worker_index.get(),
                            "admin command timed out; worker wedged or overloaded -- skipping"
                        );
                        None
                    }
                }
            }
        });
        futures::future::join_all(calls)
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// A reliable concurrent broadcast function that collects the
    /// replies from each worker within `timeout`.
    ///
    /// `make_cmd` builds the command from a fresh reply channel,
    /// so each worker answers on its own oneshot.
    ///
    /// Dead or unreachable slots (respawning, failed, cleanly exited) are
    /// skipped silently.
    ///
    /// TIMEOUT IS NOT A NO-OP for mutating commands: a worker may accept
    /// and execute the command while its reply misses the deadline, in
    /// which case it is absent from the result. Treat the result as
    /// "confirmed", not "performed".
    pub async fn fan_out<R>(
        &self,
        timeout: Duration,
        make_cmd: impl Fn(oneshot::Sender<R>) -> Cmd,
    ) -> Vec<(WorkerIndex, R)> {
        self.each_worker(timeout, |worker_index| {
            let (tx, rx) = oneshot::channel();
            let cmd = make_cmd(tx);
            async move {
                // NOTE: route() AWAITS mailbox capacity (MailboxFull is a
                // try_route-only error), so a live-but-backlogged worker
                // is bounded by `timeout` rather than skipped fast.
                match self.route(worker_index, cmd).await {
                    Ok(()) => rx.await.ok(),
                    Err(_) => None, // dead slot: skipped
                }
            }
        })
        .await
    }

    /// Supervisor-side stamp (single writer); admins only load.
    fn record_exit(&self, idx: usize, kind: SlotExitKind, message: String, restarts: usize) {
        if let Some(cell) = self.last_exits.get(idx) {
            cell.store(Some(Arc::new(SlotExitInfo {
                kind,
                message,
                at_unix_ms: unix_ms_now(),
                restarts,
            })));
        }
    }
}

/// Why a [`RestartPolicy`] failed validation. Typed so an embedder can
/// distinguish which knob is wrong without string matching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RestartPolicyError {
    #[error("restart policy window must be > 0")]
    ZeroWindow,
    #[error("restart policy backoff must be > 0 (zero backoff allows an un-paced crash loop)")]
    ZeroBackoff,
    #[error(
        "restart budget is unreachable: backoff ({backoff:?}) x max_restarts ({max_restarts}) exceeds window ({window:?}); a crash loop would roll the window forever and never trip the budget"
    )]
    UnreachableBudget {
        backoff: Duration,
        max_restarts: usize,
        window: Duration,
    },
}

/// Why [`CollectionSupervisor::start`] refused to start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    #[error("CoreAssignment is empty: nothing to supervise")]
    EmptyCoreAssignment,
    #[error("mailbox capacity must be > 0 (tokio's bounded channel panics on 0)")]
    ZeroMailbox,
    #[error("min_live_workers ({minimum}) exceeds the worker count ({workers})")]
    MinLiveExceedsWorkers { minimum: usize, workers: usize },
    #[error("invalid restart policy: {0}")]
    Policy(#[from] RestartPolicyError),
    #[error("failed to spawn worker thread: {0}")]
    ThreadSpawn(#[source] io::Error),
}

pub struct CollectionSupervisor<W: Worker> {
    // Fixed-size, same reasoning as CoreAssignment: one slot per core,
    // never added to or removed from. `supervise()` replaces a slot in
    // place on respawn.
    workers: Box<[WorkerThread<W::Command>]>,

    slots: Box<[SlotState]>,

    /// Shared with every `AdminHandle`; respawn stores the fresh sender,
    /// budget exhaustion flips the failed flag.
    admin: AdminHandle<W::Command>,

    /// Per-slot metrics state, created once by `W::build_stats` at start and
    /// NEVER recreated on respawn.
    stats: Box<[Arc<W::Stats>]>,

    config: W::Config,

    cores: CoreAssignment,
    affinity: Arc<dyn AffinityStrategy>,
    /// per-worker command channel capacity
    mailbox: usize,
    policy: RestartPolicy,
    exit_rx: mpsc::Receiver<WorkerExit>,
    /// kept so it can be cloned into each spawn_pinned call
    exit_tx: mpsc::Sender<WorkerExit>,
    meter: Meter,
}

impl<W: Worker> CollectionSupervisor<W> {
    pub fn start(
        config: W::Config,
        options: SupervisorOptions,
        meter: Meter,
    ) -> Result<Self, StartError> {
        let SupervisorOptions {
            cores,
            mailbox,
            affinity,
            policy,
            name,
        } = options;
        if cores.is_empty() {
            return Err(StartError::EmptyCoreAssignment);
        }
        policy.validate()?;
        if mailbox == 0 {
            return Err(StartError::ZeroMailbox);
        }
        if policy.min_live_workers > cores.len() {
            return Err(StartError::MinLiveExceedsWorkers {
                minimum: policy.min_live_workers,
                workers: cores.len(),
            });
        }
        let stats: Box<[Arc<W::Stats>]> = (0..cores.len())
            .map(|i| W::build_stats(WorkerIndex::new(i), &config, &meter))
            .collect();
        // Channel capacity is the number of workers, since each worker expected to
        // send max one exit message.
        let (exit_tx, exit_rx) = mpsc::channel(cores.len());

        let workers: io::Result<Vec<WorkerThread<W::Command>>> = cores
            .iter()
            .map(|(worker_index, core_id)| {
                Self::spawn_pinned(
                    worker_index,
                    core_id,
                    meter.clone(),
                    config.clone(),
                    Arc::clone(&stats[worker_index.get()]),
                    mailbox,
                    Arc::clone(&affinity),
                    exit_tx.clone(),
                    name.clone(),
                )
            })
            .collect();
        let workers = workers.map_err(StartError::ThreadSpawn)?.into_boxed_slice();

        let senders: Arc<[ArcSwap<mpsc::Sender<W::Command>>]> = workers
            .iter()
            .map(|w| ArcSwap::from_pointee(w.cmd_tx.clone()))
            .collect();
        let failed: Arc<[AtomicBool]> = (0..cores.len()).map(|_| AtomicBool::new(false)).collect();
        let done: Arc<[AtomicBool]> = (0..cores.len()).map(|_| AtomicBool::new(false)).collect();
        let last_exits: Arc<[ArcSwapOption<SlotExitInfo>]> =
            (0..cores.len()).map(|_| ArcSwapOption::empty()).collect();
        let admin = AdminHandle {
            senders,
            failed,
            done,
            last_exits,
            name: name.clone(),
        };

        let now = Instant::now();
        let slots: Box<[SlotState]> = (0..cores.len())
            .map(|_| SlotState {
                restarts: 0,
                window_start: now,
                failed: false,
                done: false,
            })
            .collect();

        Ok(Self {
            workers,
            slots,
            admin,
            stats,
            config,
            cores,
            affinity,
            mailbox,
            policy,
            exit_rx,
            exit_tx,
            meter,
        })
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// A cloneable admin side that stays valid while `supervise()` holds
    /// this supervisor mutably
    pub fn admin_handle(&self) -> AdminHandle<W::Command> {
        self.admin.clone()
    }

    /// name to be used in logs and OTEL telemetry
    pub const fn name(&self) -> &str {
        self.admin.name()
    }

    /// Slots whose restart budget is exhausted
    pub fn failed_slots(&self) -> Vec<WorkerIndex> {
        self.admin.failed_slots()
    }

    /// See [AdminHandle::route]
    pub async fn route(
        &self,
        worker_index: WorkerIndex,
        cmd: W::Command,
    ) -> Result<(), RouteError> {
        self.admin.route(worker_index, cmd).await
    }

    /// The supervision loop.
    pub async fn supervise(&mut self, shutdown: &mut watch::Receiver<bool>) -> SuperviseExit {
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    // A closed shutdown channel means the signaller is
                    // gone; treat that as shutdown rather than supervising
                    // unstoppably.
                    if changed.is_err() || *shutdown.borrow() {
                        return SuperviseExit::ShutdownRequested;
                    }
                }
                exit = self.exit_rx.recv() => {
                    match exit {
                        None => return SuperviseExit::ShutdownRequested,
                        Some(exit) => {
                            if self.handle_exit(exit, shutdown).await {
                                return SuperviseExit::ShutdownRequested;
                            }
                            if let Some(below) = self.check_min_live() {
                                if *shutdown.borrow() {
                                    return SuperviseExit::ShutdownRequested
                                }
                                return below
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_min_live(&self) -> Option<SuperviseExit> {
        let minimum = self.policy.min_live_workers;
        if minimum == 0 {
            return None;
        }
        let live = self.slots.iter().filter(|s| !s.failed && !s.done).count();
        if live < minimum {
            error!(
                supervisor = self.name(),
                live,
                minimum,
                "live workers below the configured minimum; ending supervision so the embedder can fail the whole service"
            );
            return Some(SuperviseExit::BelowMinimumWorkers { live, minimum });
        }
        None
    }

    /// Graceful teardown
    ///
    /// This is the ONLY correct teardown: it first swaps every
    /// [`AdminHandle`] sender for a pre-closed one, which is what lets
    /// the workers' channels actually close while admin clones live on.
    /// Dropping the supervisor instead leaks the detached workers.
    pub async fn shutdown(self, deadline: Duration) {
        let Self {
            workers,
            slots,
            admin,
            exit_tx,
            mut exit_rx,
            ..
        } = self;
        // Log-only bookkeeping
        let expected = slots.iter().filter(|s| !s.failed && !s.done).count();

        // AdminHandle clones hold sender clones that would keep every
        // command channel open past the drop below.
        // Swap each slot to a pre-closed sender first,
        // so admins get WorkerGone from here on and the workers' channels actually
        // close.
        for slot in admin.senders.iter() {
            let (dead_tx, dead_rx) = mpsc::channel(1);
            drop(dead_rx);
            slot.store(Arc::new(dead_tx));
        }

        // Dropping the workers drops the last live cmd_tx per worker
        drop(workers);

        // Drop our own exit_tx so exit_rx terminates (None) once every
        // worker thread's clone is gone.
        drop(exit_tx);

        // Counted OUTSIDE the future: on the deadline branch the drain
        // future is dropped, and a count owned by it would be lost.
        let clean = std::sync::atomic::AtomicUsize::new(0);
        let drain = async {
            while let Some(exit) = exit_rx.recv().await {
                let idx = exit.worker_index.get();
                let restarts = slots.get(idx).map_or(0, |s| s.restarts);
                match exit.reason {
                    ExitReason::Clean => {
                        clean.fetch_add(1, Ordering::Relaxed);
                        admin.record_exit(idx, SlotExitKind::Clean, String::new(), restarts);
                        info!(
                            supervisor = admin.name(),
                            worker_index = exit.worker_index.get(),
                            "worker shut down cleanly"
                        );
                    }
                    ExitReason::Error(e) => {
                        warn!(
                            supervisor = admin.name(),
                            worker_index = exit.worker_index.get(),
                            error = %e,
                            "worker errored during shutdown"
                        );
                        admin.record_exit(idx, SlotExitKind::Error, e.to_string(), restarts);
                    }
                    ExitReason::Panic(p) => {
                        error!(
                            supervisor = admin.name(),
                            worker_index = exit.worker_index.get(),
                            panic = panic_message(p.as_ref()),
                            "worker panicked during shutdown"
                        );
                        admin.record_exit(
                            idx,
                            SlotExitKind::Panic,
                            panic_message(p.as_ref()).to_string(),
                            restarts,
                        );
                    }
                }
            }
        };

        match tokio::time::timeout(deadline, drain).await {
            Ok(()) => {
                info!(
                    supervisor = admin.name(),
                    clean = clean.load(Ordering::Relaxed),
                    expected,
                    "supervisor shutdown complete"
                );
            }
            Err(_) => {
                warn!(
                    supervisor = admin.name(),
                    clean = clean.load(Ordering::Relaxed),
                    expected,
                    "supervisor shutdown deadline expired; abandoning remaining workers"
                );
            }
        }
    }

    /// Returns `true` when the shutdown signal was observed during the
    /// respawn backoff (the caller must then end supervision).
    async fn handle_exit(
        &mut self,
        exit: WorkerExit,
        shutdown: &mut watch::Receiver<bool>,
    ) -> bool {
        let worker_index = exit.worker_index;
        let idx = worker_index.get();
        let restarts_now = self.slots.get(idx).map_or(0, |s| s.restarts);
        match exit.reason {
            ExitReason::Clean => {
                info!(
                    supervisor = self.name(),
                    worker_index = idx,
                    "worker exited cleanly; not respawning"
                );
                self.admin
                    .record_exit(idx, SlotExitKind::Clean, String::new(), restarts_now);
                if let Some(slot) = self.slots.get_mut(idx) {
                    slot.done = true;
                    self.admin.done[idx].store(true, Ordering::Relaxed);
                }
                false
            }
            ExitReason::Error(e) => {
                warn!(supervisor = self.name(), worker_index = idx, error = %e, "worker failed");
                self.admin
                    .record_exit(idx, SlotExitKind::Error, e.to_string(), restarts_now);
                self.respawn(worker_index, shutdown).await
            }
            ExitReason::Panic(p) => {
                error!(
                    supervisor = self.name(),
                    worker_index = idx,
                    panic = panic_message(p.as_ref()),
                    "worker panicked"
                );
                self.admin.record_exit(
                    idx,
                    SlotExitKind::Panic,
                    panic_message(p.as_ref()).to_string(),
                    restarts_now,
                );
                self.respawn(worker_index, shutdown).await
            }
        }
    }

    async fn respawn(
        &mut self,
        worker_index: WorkerIndex,
        shutdown: &mut watch::Receiver<bool>,
    ) -> bool {
        let idx = worker_index.get();
        let supervisor = self.name().to_string().into_boxed_str();
        let (Some(slot), Some(core_id)) =
            (self.slots.get_mut(idx), self.cores.core_id(worker_index))
        else {
            return false;
        };
        if slot.failed {
            return false;
        }
        if slot.window_start.elapsed() > self.policy.window {
            slot.restarts = 0;
            slot.window_start = Instant::now();
        }
        slot.restarts += 1;
        if slot.restarts > self.policy.max_restarts {
            slot.failed = true;
            self.admin.failed[idx].store(true, Ordering::Relaxed);
            error!(
                supervisor,
                worker_index = idx,
                restarts = slot.restarts,
                window_secs = self.policy.window.as_secs(),
                "restart budget exhausted; giving up on this slot"
            );
            return false;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!(
                        supervisor,
                        worker_index = idx,
                        "shutdown during respawn backoff; not respawning"
                    );
                    return true;
                }
                // A change that is NOT shutdown (send(false)): proceed to
                // the respawn without the rest of the backoff -- harmless,
                // and simpler than re-arming the sleep.
            }
            _ = tokio::time::sleep(self.policy.backoff) => {}
        }
        let spawn_pinned_result = Self::spawn_pinned(
            worker_index,
            core_id,
            self.meter.clone(),
            self.config.clone(),
            Arc::clone(&self.stats[idx]),
            self.mailbox,
            Arc::clone(&self.affinity),
            self.exit_tx.clone(),
            supervisor.clone(),
        );
        match spawn_pinned_result {
            Ok(worker) => {
                info!(
                    supervisor,
                    worker_index = idx,
                    restart = slot.restarts,
                    "worker respawned"
                );
                // Refresh the admin side FIRST: from here on, admin sends
                // reach the new incarnation.
                self.admin.senders[idx].store(Arc::new(worker.cmd_tx.clone()));
                self.workers[idx] = worker;
            }
            Err(e) => {
                slot.failed = true;
                self.admin.failed[idx].store(true, Ordering::Relaxed);
                self.admin.record_exit(
                    idx,
                    SlotExitKind::Error,
                    format!("thread spawn failed on respawn: {e}"),
                    slot.restarts,
                );
                error!(
                    supervisor = self.name(),
                    worker_index = worker_index.get(),
                    error = %e,
                    "thread spawn failed on respawn; giving up on this slot"
                );
            }
        }
        false
    }
    #[allow(clippy::too_many_arguments)]
    fn spawn_pinned(
        worker_index: WorkerIndex,
        core_id: CoreId, // candidate/target; not yet a confirmed outcome
        meter: Meter,
        config: W::Config,
        stats: Arc<W::Stats>, // per-slot, from build_stats; SAME Arc on every respawn
        mailbox: usize,
        affinity: Arc<dyn AffinityStrategy>,
        exit_tx: mpsc::Sender<WorkerExit>,
        name: Box<str>,
    ) -> io::Result<WorkerThread<W::Command>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(mailbox);

        let join = thread::Builder::new()
            .name(format!("{}-{worker_index}", W::NAME)) // worker_index: stable regardless of pin outcome
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let core_id = match affinity.apply(core_id) {
                        PinOutcome::Pinned(actual) => Some(actual),
                        PinOutcome::Unpinned => None,
                        PinOutcome::Failed => {
                            warn!(
                                supervisor = name,
                                worker_index = worker_index.get(),
                                requested_core = core_id.get(),
                                "CPU pin failed; worker runs unpinned"
                            );
                            None
                        }
                    };

                    let ctx = WorkerContext::new(worker_index, core_id, meter);

                    match Builder::new_current_thread().enable_all().build() {
                        Ok(rt) => match rt.block_on(async move {
                            W::build(&ctx, config, stats)?.run(cmd_rx).await
                        }) {
                            Ok(()) => ExitReason::Clean,
                            Err(e) => ExitReason::Error(Box::new(e)),
                        },
                        Err(e) => ExitReason::Error(Box::new(e)),
                    }
                }));
                let reason = result.unwrap_or_else(ExitReason::Panic);
                let _ = exit_tx.blocking_send(WorkerExit {
                    worker_index,
                    reason,
                });
            })?;
        // detached the JoinHandle deliberately since every exit, including
        // panics, is caught in the code above and the exit channel communicates the
        // exit reason.
        drop(join);

        Ok(WorkerThread { cmd_tx })
    }
}

/// Best-effort extraction of a printable message from a panic payload --
/// the two shapes `panic!` actually produces. Anything else is opaque.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affinity::NoAffinity;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A worker whose behavior is steered by shared state in its Config:
    /// counts builds, optionally panics exactly once (whichever incarnation
    /// claims the flag), then runs until its command channel closes.
    struct TestWorker {
        cfg: TestConfig,
    }
    #[derive(Clone)]
    struct TestConfig {
        builds: Arc<AtomicUsize>,
        panic_once: Arc<AtomicBool>,
        /// One incarnation returns Ok immediately: the clean-exit path.
        exit_clean_once: Arc<AtomicBool>,
        /// Never read the command channel: mailbox fills, worker wedges.
        stall: bool,
        /// What build() observed as ctx.core_id(): -2 = build never ran,
        /// -1 = ran unpinned (None), >= 0 = the pinned core.
        saw_core_id: Arc<std::sync::atomic::AtomicI64>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("test worker error")]
    struct TestError;

    impl Worker for TestWorker {
        type Command = ();
        type Config = TestConfig;
        type Stats = ();
        type Error = TestError;
        const NAME: &'static str = "test";

        fn build_stats(
            _worker_index: WorkerIndex,
            _config: &TestConfig,
            _meter: &Meter,
        ) -> Arc<()> {
            Arc::new(())
        }

        fn build(
            ctx: &WorkerContext,
            config: TestConfig,
            _stats: Arc<()>,
        ) -> Result<Self, TestError> {
            config.builds.fetch_add(1, Ordering::SeqCst);
            config.saw_core_id.store(
                ctx.core_id().map_or(-1, |c| c.get() as i64),
                Ordering::SeqCst,
            );
            Ok(Self { cfg: config })
        }

        async fn run(self, mut cmd_rx: mpsc::Receiver<()>) -> Result<(), TestError> {
            // Exactly one incarnation across all slots claims the panic.
            if self.cfg.panic_once.swap(false, Ordering::SeqCst) {
                panic!("deliberate test panic");
            }
            if self.cfg.exit_clean_once.swap(false, Ordering::SeqCst) {
                return Ok(()); // clean exit while supervised
            }
            if self.cfg.stall {
                std::future::pending::<()>().await; // wedged worker
            }
            while cmd_rx.recv().await.is_some() {}
            Ok(())
        }
    }

    fn default_test_config() -> TestConfig {
        TestConfig {
            builds: Arc::new(AtomicUsize::new(0)),
            panic_once: Arc::new(AtomicBool::new(false)),
            exit_clean_once: Arc::new(AtomicBool::new(false)),
            stall: false,
            saw_core_id: Arc::new(std::sync::atomic::AtomicI64::new(-2)),
        }
    }

    fn test_supervisor_with(
        cfg: TestConfig,
        workers: usize,
        mailbox: usize,
        max_restarts: usize,
    ) -> (CollectionSupervisor<TestWorker>, TestConfig) {
        let sup = CollectionSupervisor::<TestWorker>::start(
            cfg.clone(),
            SupervisorOptions::new(
                CoreAssignment::explicit(vec![0usize; workers]),
                "test-supervisor",
            )
            .with_mailbox(mailbox)
            .with_affinity(Arc::new(NoAffinity))
            .with_policy(RestartPolicy::new(
                max_restarts,
                Duration::from_secs(60),
                Duration::from_millis(10),
            )),
            opentelemetry::global::meter("test"),
        )
        .expect("supervisor start");
        (sup, cfg)
    }

    fn test_supervisor(
        panic_once: bool,
        workers: usize,
        max_restarts: usize,
    ) -> (CollectionSupervisor<TestWorker>, TestConfig) {
        let cfg = TestConfig {
            panic_once: Arc::new(AtomicBool::new(panic_once)),
            ..default_test_config()
        };
        test_supervisor_with(cfg, workers, 4, max_restarts)
    }
    async fn wait_for(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn panic_is_detected_and_respawned_once() {
        let (mut sup, cfg) = test_supervisor(true, 2, 3);
        let admin = sup.admin_handle();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let supervise = async {
            let _ = sup.supervise(&mut shutdown_rx).await;
            sup
        };
        let checks = async {
            // 2 initial builds + exactly 1 respawn after the panic.
            let builds = Arc::clone(&cfg.builds);
            assert!(
                wait_for(Duration::from_secs(5), || builds.load(Ordering::SeqCst)
                    == 3)
                .await,
                "expected exactly one respawn (3 builds), got {}",
                builds.load(Ordering::SeqCst)
            );
            // Give the respawn a beat to prove it does NOT keep respawning
            // (the panic flag was consumed; no further exits should occur).
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(cfg.builds.load(Ordering::SeqCst), 3);
            // Triage record: exactly one slot's last exit is the panic,
            // with the payload message preserved for readiness surfaces.
            let panics: Vec<_> = (0..2)
                .filter_map(|i| admin.last_exit(WorkerIndex::new(i)))
                .filter(|e| e.kind == SlotExitKind::Panic)
                .collect();
            assert_eq!(panics.len(), 1, "exactly one slot panicked");
            assert_eq!(panics[0].message, "deliberate test panic");
            assert!(panics[0].at_unix_ms > 0);
            shutdown_tx.send(true).expect("signal shutdown");
        };
        let (sup, ()) = tokio::join!(supervise, checks);
        assert!(sup.failed_slots().is_empty(), "no slot should be failed");
        // The log trail is part of the contract: the panic is reported
        // (with its message) and the respawn is announced.
        assert!(logs_contain("worker panicked"));
        assert!(logs_contain("deliberate test panic"));
        assert!(logs_contain("worker respawned"));
        sup.shutdown(Duration::from_secs(5)).await;
    }

    #[test]
    fn start_rejects_min_live_above_worker_count() {
        let cfg = default_test_config();
        let result = CollectionSupervisor::<TestWorker>::start(
            cfg,
            SupervisorOptions::new(CoreAssignment::explicit(vec![0usize; 2]), "test-supervisor")
                .with_mailbox(4)
                .with_affinity(Arc::new(NoAffinity))
                .with_policy(RestartPolicy::default().with_min_live_workers(3)),
            opentelemetry::global::meter("test"),
        );
        match result {
            Ok(_) => panic!("min_live_workers above worker count must be rejected"),
            Err(err) => assert!(matches!(
                err,
                StartError::MinLiveExceedsWorkers {
                    minimum: 3,
                    workers: 2
                }
            )),
        }
    }

    #[test]
    fn restart_policy_zero_backoff_rejected() {
        // Zero backoff would permit an un-paced crash loop that the
        // reachability check cannot see (budget_time == 0 passes).
        assert!(
            RestartPolicy::new(3, Duration::from_secs(60), Duration::ZERO)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn start_rejects_zero_mailbox() {
        // tokio's bounded channel panics on capacity 0; start() must turn
        // that config value into InvalidInput, not a panic.
        let cfg = default_test_config();
        let result = CollectionSupervisor::<TestWorker>::start(
            cfg,
            SupervisorOptions::new(CoreAssignment::explicit(vec![0usize]), "test-supervisor")
                .with_mailbox(0)
                .with_affinity(Arc::new(NoAffinity))
                .with_policy(RestartPolicy::default()),
            opentelemetry::global::meter("test"),
        );
        match result {
            Ok(_) => panic!("zero mailbox must be rejected"),
            Err(err) => assert!(matches!(err, StartError::ZeroMailbox)),
        }
    }

    #[test]
    fn start_rejects_unreachable_restart_budget() {
        let cfg = default_test_config();
        let result = CollectionSupervisor::<TestWorker>::start(
            cfg,
            SupervisorOptions::new(CoreAssignment::explicit(vec![0usize]), "test-supervisor")
                .with_mailbox(4)
                .with_affinity(Arc::new(NoAffinity))
                .with_policy(RestartPolicy::new(
                    3,
                    Duration::from_millis(10),
                    Duration::from_secs(60),
                )),
            opentelemetry::global::meter("test"),
        );
        match result {
            Ok(_) => panic!("unreachable budget must be rejected"),
            Err(err) => assert!(matches!(
                err,
                StartError::Policy(RestartPolicyError::UnreachableBudget { .. })
            )),
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn clean_exit_marks_slot_done_for_admins() {
        let cfg = TestConfig {
            exit_clean_once: Arc::new(AtomicBool::new(true)),
            ..default_test_config()
        };
        let (mut sup, cfg) = test_supervisor_with(cfg, 2, 4, 3);
        let admin = sup.admin_handle();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let supervise = tokio::spawn(async move {
            let _ = sup.supervise(&mut shutdown_rx).await;
            sup
        });

        // One incarnation exits cleanly; the slot must become visible as
        // done to admin-plane readiness, must NOT be respawned (builds
        // stays at the initial 2), and must NOT count as failed.
        assert!(
            wait_for(Duration::from_secs(5), || admin.done_slots().len() == 1).await,
            "clean exit never became visible via done_slots()"
        );
        assert!(admin.failed_slots().is_empty());
        // Both INITIAL builds must have happened: worker 1 builds on its
        // own OS thread, unsynchronized with worker 0's done flag, so
        // asserting == 2 immediately is a race (seen flaking as == 1)...
        let builds = Arc::clone(&cfg.builds);
        assert!(
            wait_for(Duration::from_secs(5), || builds.load(Ordering::SeqCst)
                == 2)
            .await,
            "both workers must build once"
        );
        // ...and a respawn of the done slot would push it to 3: hold a
        // beat to prove it stays at 2.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cfg.builds.load(Ordering::SeqCst), 2, "done slot respawned");

        let _ = shutdown_tx.send(true);
        let sup = supervise.await.expect("supervise task");
        sup.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn try_route_reports_full_mailbox_and_shutdown_abandons_wedged_worker() {
        // A wedged worker (never reads its mailbox): try_route must report
        // MailboxFull instead of hanging, and shutdown(deadline) must
        // return;  worker threads are detached, so the runtime must then
        // drop without waiting on the stuck thread (the regression this
        // test pins: spawn_blocking-based panic watchers hung runtime
        // drop; watchers are gone entirely now, panics are caught
        // in-thread).
        let cfg = TestConfig {
            stall: true,
            ..default_test_config()
        };
        let (mut sup, _cfg) = test_supervisor_with(cfg, 1, 1, 3);
        let admin = sup.admin_handle();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let supervise = tokio::spawn(async move {
            let _ = sup.supervise(&mut shutdown_rx).await;
            sup
        });

        // Capacity 1: the first command parks in the mailbox forever, the
        // second must fail fast.
        admin
            .try_route(WorkerIndex::new(0), ())
            .expect("first command fits the mailbox");
        assert!(matches!(
            admin.try_route(WorkerIndex::new(0), ()),
            Err(RouteError::MailboxFull(_))
        ));
        assert!(matches!(
            admin.try_route(WorkerIndex::new(9), ()),
            Err(RouteError::UnknownWorker(_))
        ));

        let _ = shutdown_tx.send(true);
        let sup = supervise.await.expect("supervise task");
        // Must return at the deadline despite the wedged worker; the test
        // process exiting afterward proves runtime drop doesn't wait on
        // the detached watcher.
        let start = Instant::now();
        sup.shutdown(Duration::from_millis(300)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown did not respect its deadline"
        );
    }
}
