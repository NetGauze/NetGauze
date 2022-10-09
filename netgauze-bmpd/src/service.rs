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

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::Future;

use tower_service::Service;

use tokio::sync::mpsc;

#[derive(Debug)]
pub struct MpscSenderService<T> {
    sender: mpsc::Sender<T>,
}

impl<T> MpscSenderService<T>
where
    T: Send,
{
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }
}

#[derive(Debug)]
pub enum MpscSenderServiceError {
    SendError,
}

impl std::fmt::Display for MpscSenderServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for MpscSenderServiceError {}

impl<T> Service<T> for MpscSenderService<T>
where
    T: Send + 'static,
{
    type Response = ();
    type Error = MpscSenderServiceError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: T) -> Self::Future {
        let sender = self.sender.clone();
        Box::pin(async move {
            match sender.send(req).await {
                Ok(_) => Ok(()),
                Err(_) => Err(MpscSenderServiceError::SendError),
            }
        })
    }
}
