// Copyright (C) 2025-present The NetGauze Authors.
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

//! YANG library cache subsystem.
//!
//! This module groups the cache components used by the YANG-Push pipeline:
//! storage for persisted YANG libraries, fetchers for retrieving missing
//! libraries from devices, and an actor-based interface for concurrent access.
//! For details and examples, see the documentation in each submodule.

pub mod actor;
pub mod fetcher;
pub mod storage;
