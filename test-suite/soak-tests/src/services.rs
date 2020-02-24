// Copyright 2020 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use exonum::runtime::SUPERVISOR_INSTANCE_ID;
use exonum::{
    helpers::Height,
    merkledb::access::AccessExt,
    runtime::{ExecutionContext, ExecutionError, InstanceId},
};
use exonum_derive::*;
use exonum_rust_runtime::{AfterCommitContext, DefaultInstance, Service};

#[exonum_interface(auto_ids)]
pub trait MainServiceInterface<Ctx> {
    type Output;

    fn timestamp(&self, context: Ctx, height: Height) -> Self::Output;
}

#[derive(Debug, Clone, Copy, ServiceDispatcher, ServiceFactory)]
#[service_dispatcher(implements("MainServiceInterface"))]
#[service_factory(artifact_name = "main", artifact_version = "1.0.0")]
pub struct MainService;

impl MainServiceInterface<ExecutionContext<'_>> for MainService {
    type Output = Result<(), ExecutionError>;

    fn timestamp(&self, _context: ExecutionContext<'_>, _height: Height) -> Self::Output {
        Ok(())
    }
}

impl Service for MainService {
    fn after_transactions(&self, context: ExecutionContext<'_>) -> Result<(), ExecutionError> {
        let height = context.data().for_core().next_height();
        let height_str = height.0.to_string();

        let mut map = context
            .service_data()
            .get_proof_map::<_, u64, String>("some");
        map.put(&0, height_str.clone());
        map.put(&(height.0 / 2), height_str.clone());
        map.put(&height.0, height_str.clone());
        map.put(&(height.0 + 1), height_str);

        Ok(())
    }

    fn after_commit(&self, context: AfterCommitContext<'_>) {
        if let Some(broadcaster) = context.broadcaster() {
            if let Err(e) = broadcaster.timestamp((), context.height()) {
                log::error!(
                    "[{}] Failed to broadcast transaction at height {}: {}",
                    context.service_key(),
                    context.height(),
                    e
                );
            }
        }
    }
}

impl DefaultInstance for MainService {
    const INSTANCE_ID: InstanceId = 100;
    const INSTANCE_NAME: &'static str = "main";
}

#[derive(Debug, Clone, Copy, ServiceDispatcher, ServiceFactory)]
#[service_factory(artifact_name = "supervisor", artifact_version = "1.0.0")]
pub struct TogglingSupervisor;

impl Service for TogglingSupervisor {
    fn after_transactions(&self, mut context: ExecutionContext<'_>) -> Result<(), ExecutionError> {
        let height = context.data().for_core().next_height();
        let mut extensions = context.supervisor_extensions();

        match height.0 % 5 {
            1 => extensions.initiate_stopping_service(MainService::INSTANCE_ID),
            4 => extensions.initiate_resuming_service(MainService::INSTANCE_ID, ()),
            _ => Ok(()),
        }
    }
}

impl DefaultInstance for TogglingSupervisor {
    const INSTANCE_ID: InstanceId = SUPERVISOR_INSTANCE_ID;
    const INSTANCE_NAME: &'static str = "supervisor";
}