// Copyright 2019 The Exonum Team
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

pub use self::{error::Error, schema::Schema};

use exonum_merkledb::{Fork, Snapshot};
use futures::{future, Future};

use std::{
    collections::{BTreeMap, HashMap},
    panic,
};

use crate::{
    api::ApiBuilder,
    blockchain::{FatalError, IndexCoordinates, IndexOwner},
    crypto::{Hash, PublicKey, SecretKey},
    helpers::ValidateInput,
    merkledb::BinaryValue,
    messages::{AnyTx, Verified},
    node::ApiSender,
};

use super::{
    api::ApiContext, error::ExecutionError, ApiChange, ArtifactId, ArtifactProtobufSpec,
    ArtifactSpec, Caller, ExecutionContext, InstanceId, InstanceSpec, Runtime,
};

mod error;
mod schema;
#[cfg(test)]
mod tests;

/// Max instance identifier for builtin service.
///
/// By analogy with the privileged ports of the network, we use a range 0..1023 of instance
/// identifiers for built-in services which can be created only during the blockchain genesis
/// block creation.
// FIXME: remove
pub const MAX_BUILTIN_INSTANCE_ID: InstanceId = 1024;

#[derive(Debug)]
struct ServiceInfo {
    runtime_id: u32,
    name: String,
}

#[derive(Debug, Default)]
pub struct Dispatcher {
    runtimes: BTreeMap<u32, Box<dyn Runtime>>,
    service_infos: BTreeMap<InstanceId, ServiceInfo>,
    api_changes: BTreeMap<u32, Vec<ApiChange>>,
}

impl Dispatcher {
    /// Create a new dispatcher with the specified runtimes.
    pub(crate) fn with_runtimes(
        runtimes: impl IntoIterator<Item = (u32, Box<dyn Runtime>)>,
    ) -> Self {
        Self {
            runtimes: runtimes.into_iter().collect(),
            service_infos: BTreeMap::new(),
            api_changes: BTreeMap::new(),
        }
    }

    /// Restore the dispatcher from the state which was saved in the specified snapshot.
    pub(crate) fn restore_state(&mut self, snapshot: &dyn Snapshot) -> Result<(), ExecutionError> {
        let schema = Schema::new(snapshot);
        // Restore information about the deployed services.
        for ArtifactSpec { artifact, payload } in schema.artifacts().values() {
            self.deploy_artifact(artifact, payload).wait()?;
        }
        // Restart active service instances.
        for instance in schema.service_instances().values() {
            self.add_service(&instance)?;
        }
        Ok(())
    }

    /// Add a built-in service with the predefined identifier.
    ///
    /// This method must be followed by the `after_commit()` call in order to persist information
    /// about deployed artifacts / services. Multiple `add_builtin_service()` calls can be covered
    /// by a single `after_commit()`.
    ///
    /// # Panics
    ///
    /// * If instance spec contains invalid service name or artifact id.
    /// * If instance id is greater than [`MAX_BUILTIN_INSTANCE_ID`]
    ///
    /// [`MAX_BUILTIN_INSTANCE_ID`]: constant.MAX_BUILTIN_INSTANCE_ID.html
    pub(crate) fn add_builtin_service(
        &mut self,
        fork: &Fork,
        spec: InstanceSpec,
        artifact_spec: impl BinaryValue,
        constructor: Vec<u8>,
    ) -> Result<(), ExecutionError> {
        assert!(
            spec.id < MAX_BUILTIN_INSTANCE_ID,
            "Instance identifier for builtin service should be lesser than {}",
            MAX_BUILTIN_INSTANCE_ID
        );

        // Register service artifact in the runtime.
        // TODO Write test for such situations [ECR-3222]
        if !self.is_artifact_deployed(&spec.artifact) {
            self.deploy_and_register_artifact(fork, spec.artifact.clone(), artifact_spec)?;
        }

        // Start the built-in service instance.
        self.start_adding_service(fork, spec, constructor)?;
        Ok(())
    }

    pub(crate) fn state_hash(
        &self,
        access: &dyn Snapshot,
    ) -> impl IntoIterator<Item = (IndexCoordinates, Hash)> {
        let mut aggregator = HashMap::new();
        // Inserts state hashes for the runtimes.
        for (runtime_id, runtime) in &self.runtimes {
            let state = runtime.state_hashes(access);
            aggregator.extend(
                // Runtime state hash.
                IndexCoordinates::locate(IndexOwner::Runtime(*runtime_id), state.runtime),
            );
            for (instance_id, instance_hashes) in state.instances {
                aggregator.extend(
                    // Instance state hashes.
                    IndexCoordinates::locate(IndexOwner::Service(instance_id), instance_hashes),
                );
            }
        }
        aggregator
    }

    // FIXME: remove in favor of "on node start" hook
    pub(crate) fn api_endpoints(
        &self,
        context: &ApiContext,
    ) -> impl IntoIterator<Item = (String, ApiBuilder)> {
        self.runtimes
            .values()
            .map(|runtime| {
                runtime
                    .api_endpoints(context)
                    .into_iter()
                    .map(|(service_name, builder)| (service_name, ApiBuilder::from(builder)))
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    /// Initiate artifact deploy procedure in the corresponding runtime.
    ///
    /// # Panics
    ///
    /// * If artifact identifier is invalid.
    pub(crate) fn deploy_artifact(
        &mut self,
        artifact: ArtifactId,
        payload: Vec<u8>,
    ) -> Box<dyn Future<Item = (), Error = ExecutionError>> {
        debug_assert!(artifact.validate().is_ok());

        if let Some(runtime) = self.runtimes.get_mut(&artifact.runtime_id) {
            runtime.deploy_artifact(artifact, payload)
        } else {
            Box::new(future::err(Error::IncorrectRuntime.into()))
        }
    }

    /// Registers artifact to be deployed in the dispatcher's information schema.
    /// The artifact is not guaranteed to be deployed until the block built on top of the
    /// provided `Fork` is committed.
    pub(crate) fn start_artifact_registration(
        fork: &Fork,
        artifact: ArtifactId,
        spec: Vec<u8>,
    ) -> Result<(), ExecutionError> {
        debug_assert!(artifact.validate().is_ok(), "{:?}", artifact.validate());
        Schema::new(fork).add_pending_artifact(artifact, spec)?;
        Ok(())
    }

    fn register_artifact(&mut self, artifact: ArtifactId, spec: Vec<u8>) {
        if !self.is_artifact_deployed(&artifact) {
            self.deploy_artifact(artifact, spec)
                .wait()
                .unwrap_or_else(|e| {
                    // In this case artifact deployment error is fatal because there are
                    // confirmation that this node can deploy this artifact.
                    panic!(FatalError::new(format!(
                        "Unable to deploy registered artifact. {}",
                        e
                    )))
                });
        }
    }

    pub(crate) fn deploy_and_register_artifact(
        &mut self,
        fork: &Fork,
        artifact: ArtifactId,
        spec: impl BinaryValue,
    ) -> Result<(), ExecutionError> {
        let spec = spec.into_bytes();
        self.deploy_artifact(artifact.clone(), spec.clone())
            .wait()?;
        Self::start_artifact_registration(fork, artifact.clone(), spec.clone())?;
        self.register_artifact(artifact, spec);
        Ok(())
    }

    /// Starts adding a new service instance to the blockchain. The service is not active
    /// (i.e., does not process transactions or the `before_commit` hook)
    /// until the block built on top of the provided `fork` is committed.
    pub(crate) fn start_adding_service(
        &self,
        fork: &Fork,
        spec: InstanceSpec,
        constructor: impl BinaryValue,
    ) -> Result<(), ExecutionError> {
        debug_assert!(spec.validate().is_ok(), "{:?}", spec.validate());

        // Check that service doesn't use existing identifiers.
        if self.service_infos.contains_key(&spec.id) {
            return Err(Error::ServiceIdExists.into());
        }
        // Try to add the service instance.
        let runtime = self
            .runtimes
            .get(&spec.artifact.runtime_id)
            .ok_or(Error::IncorrectRuntime)?;
        runtime.start_adding_service(fork, &spec, constructor.into_bytes())?;

        // Add service instance to the dispatcher schema.
        Schema::new(fork)
            .add_pending_service(spec)
            .map_err(From::from)
    }

    // TODO documentation [ECR-3275]
    pub(crate) fn execute(
        &self,
        fork: &mut Fork,
        tx_id: Hash,
        tx: &Verified<AnyTx>,
    ) -> Result<(), ExecutionError> {
        let caller = Caller::Transaction {
            author: tx.author(),
            hash: tx_id,
        };
        let call_info = &tx.as_ref().call_info;
        let runtime = self
            .runtime_for_service(call_info.instance_id)
            .ok_or(Error::IncorrectRuntime)?;
        let context = ExecutionContext::new(self, fork, caller);
        runtime.execute(context, call_info, &tx.as_ref().arguments)
    }

    /// Looks up the runtime for the specified service instance. Returns a reference to
    /// the runtime, or an error if the service with the sepcified instance ID does not exist.
    pub(crate) fn runtime_for_service(&self, instance_id: InstanceId) -> Option<&dyn Runtime> {
        let ServiceInfo { runtime_id, .. } = self.service_infos.get(&instance_id)?;
        let runtime = self.runtimes[&runtime_id].as_ref();
        Some(runtime)
    }

    #[cfg(test)]
    pub(crate) fn call(
        &self,
        fork: &mut Fork,
        caller: Caller,
        call_info: &super::CallInfo,
        arguments: &[u8],
    ) -> Result<(), ExecutionError> {
        let runtime = self
            .runtime_for_service(call_info.instance_id)
            .ok_or(Error::IncorrectRuntime)?;
        let context = ExecutionContext::new(self, fork, caller);
        runtime.execute(context, call_info, arguments)
    }

    pub(crate) fn before_commit(&self, fork: &mut Fork) {
        for (&service_id, info) in &self.service_infos {
            let context = ExecutionContext::new(self, fork, Caller::BeforeCommit);
            if self.runtimes[&info.runtime_id]
                .before_commit(context, service_id)
                .is_ok()
            {
                fork.flush();
            } else {
                fork.rollback();
            }
        }
    }

    pub(crate) fn after_commit(
        &mut self,
        fork: &Fork,
        service_keypair: &(PublicKey, SecretKey),
        tx_sender: &ApiSender,
    ) {
        // Run `after_commit` for runtimes.
        let mut mailbox = Mailbox::default();
        for runtime in self.runtimes.values_mut() {
            runtime.after_commit(&mut mailbox, fork.as_ref(), &service_keypair, &tx_sender);
        }
        for action in mailbox.actions {
            action.execute(self);
        }

        // **NB.** Changes to the `fork` below MUST be the same for all nodes.
        let mut schema = Schema::new(fork);

        // Deploy pending artifacts.
        let mut artifacts = schema.pending_artifacts();
        for ArtifactSpec {
            artifact,
            payload: spec,
        } in artifacts.values()
        {
            self.register_artifact(artifact.clone(), spec.clone());
            schema.add_artifact(artifact, spec);
        }
        artifacts.clear();

        // Start pending services.
        let mut services = schema.pending_service_instances();
        for spec in services.values() {
            self.add_service(&spec).expect("Cannot add service");
            schema.add_service(spec);
        }
        services.clear();
    }

    /// Return additional information about the artifact if it is deployed.
    pub(crate) fn artifact_protobuf_spec(&self, id: &ArtifactId) -> Option<ArtifactProtobufSpec> {
        self.runtimes
            .get(&id.runtime_id)?
            .artifact_protobuf_spec(id)
    }

    /// Return true if the artifact with the given identifier is deployed.
    pub(crate) fn is_artifact_deployed(&self, id: &ArtifactId) -> bool {
        if let Some(runtime) = self.runtimes.get(&id.runtime_id) {
            runtime.is_artifact_deployed(id)
        } else {
            false
        }
    }

    /// Returns the name corresponding to the specified `instance_id`.
    pub(crate) fn service_name(&self, instance_id: InstanceId) -> Option<&str> {
        self.service_infos
            .get(&instance_id)
            .map(|info| info.name.as_str())
    }

    /// Notify the runtime about API changes and return true if there are such changes.
    pub(crate) fn notify_api_changes(&mut self, context: &ApiContext) -> bool {
        let api_changes = {
            let mut api_changes = BTreeMap::default();
            std::mem::swap(&mut api_changes, &mut self.api_changes);
            api_changes
        };

        let has_changes = !api_changes.is_empty();
        for (runtime_id, changes) in api_changes {
            self.runtimes[&runtime_id].notify_api_changes(context, &changes)
        }
        has_changes
    }

    /// Notify the runtimes that it has to shutdown.
    pub(crate) fn shutdown(&self) {
        for runtime in self.runtimes.values() {
            runtime.shutdown();
        }
    }

    /// Register the service instance in the runtime lookup table.
    fn register_running_service(&mut self, instance: &InstanceSpec) {
        info!("Running service instance {:?}", instance);
        self.service_infos.insert(
            instance.id,
            ServiceInfo {
                runtime_id: instance.artifact.runtime_id,
                name: instance.name.to_owned(),
            },
        );
        // Add service instance to the list of modified APIs.
        let runtime_changes = self
            .api_changes
            .entry(instance.artifact.runtime_id)
            .or_default();
        runtime_changes.push(ApiChange::InstanceAdded(instance.id));
    }

    /// Restart a new previously added service instance.
    fn add_service(&mut self, instance: &InstanceSpec) -> Result<(), ExecutionError> {
        let runtime = self
            .runtimes
            .get_mut(&instance.artifact.runtime_id)
            .ok_or(Error::IncorrectRuntime)?;
        runtime.add_service(instance)?;
        self.register_running_service(&instance);
        Ok(())
    }

    /// Assigns an instance identifier to the new service instance.
    pub(crate) fn assign_instance_id(&self, fork: &Fork) -> InstanceId {
        Schema::new(fork).assign_instance_id()
    }
}

/// Mailbox accumulating `Action`s to be performed by the dispatcher.
#[derive(Debug, Default)]
pub struct Mailbox {
    actions: Vec<Action>,
}

impl Mailbox {
    /// Appends a new action to be performed by the dispatcher.
    pub fn push(&mut self, action: Action) {
        self.actions.push(action);
    }
}

#[derive(Debug)]
pub enum Action {
    StartDeploy { artifact: ArtifactId, spec: Vec<u8> },
}

impl Action {
    fn execute(self, dispatcher: &mut Dispatcher) {
        match self {
            Action::StartDeploy { artifact, spec } => {
                dispatcher
                    .deploy_artifact(artifact.clone(), spec)
                    .wait()
                    .unwrap_or_else(|e| {
                        error!("Deploying artifact {:?} failed: {}", artifact, e);
                    });
            }
        }
    }
}
