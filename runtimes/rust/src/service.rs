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

use exonum::{
    blockchain::{config::InstanceInitParams, ApiSender, SendError},
    crypto::{Hash, KeyPair, PublicKey},
    helpers::{Height, ValidatorId},
    merkledb::{access::Prefixed, BinaryValue, ObjectHash, Snapshot},
    runtime::{
        ArtifactId, BlockchainData, DispatcherAction, ExecutionContext, ExecutionError,
        InstanceDescriptor, InstanceId, Mailbox, MethodId,
    },
};
use futures::{Future, IntoFuture};

use std::{
    borrow::Cow,
    fmt::{self, Debug},
};

use super::{api::ServiceApiBuilder, ArtifactProtobufSpec, GenericCall, MethodDescriptor};

/// Describes how the service instance should dispatch specific method calls
/// with consideration of the interface where the method belongs.
///
/// Usually, `ServiceDispatcher` can be derived using the
/// [`ServiceDispatcher`](index.html#examples) macro.
pub trait ServiceDispatcher: Send {
    /// Dispatches the interface method call within the specified context.
    fn call(
        &self,
        context: ExecutionContext<'_>,
        method: MethodId,
        payload: &[u8],
    ) -> Result<(), ExecutionError>;
}

/// Describes an Exonum service instance.
///
/// That is, `Service` determines how a service instance responds to certain requests and events
/// from the runtime.
pub trait Service: ServiceDispatcher + Debug + 'static {
    /// Initializes a new service instance with the given parameters. This method is called once
    /// after creating a new service instance.
    ///
    /// The default implementation does nothing and returns `Ok(())`.
    ///
    /// The parameters passed to the method are not saved by the framework
    /// automatically, hence the user must do it manually, if needed.
    fn initialize(
        &self,
        _context: ExecutionContext<'_>,
        _params: Vec<u8>,
    ) -> Result<(), ExecutionError> {
        Ok(())
    }

    /// Resumes a previously stopped service instance with given parameters. This method
    /// is called once after restarting a service instance.
    ///
    /// The default implementation does nothing and returns `Ok(())`.
    ///
    /// The parameters passed to the method are not saved by the framework
    /// automatically, hence the user must do it manually, if needed.
    ///
    /// **Warning:** please note that you should not change the service data layout,
    /// as this may violate the migration process.
    fn resume(
        &self,
        _context: ExecutionContext<'_>,
        _params: Vec<u8>,
    ) -> Result<(), ExecutionError> {
        Ok(())
    }

    /// Performs storage operations on behalf of the service before processing any transaction
    /// in the block.
    ///
    /// The default implementation does nothing and returns `Ok(())`.
    ///
    /// Any changes of the storage state will affect `state_hash`, which means this method must
    /// act similarly on different nodes. In other words, the service should only use data available
    /// in the provided `ExecutionContext`.
    ///
    /// Services should not rely on a particular ordering of `Service::before_transactions`
    /// invocations among services.
    fn before_transactions(&self, _context: ExecutionContext<'_>) -> Result<(), ExecutionError> {
        Ok(())
    }

    /// Performs storage operations on behalf of the service after processing all transactions
    /// in the block.
    ///
    /// The default implementation does nothing and returns `Ok(())`.
    ///
    /// Any changes of the storage state will affect `state_hash`, which means this method must
    /// act similarly on different nodes. In other words, the service should only use data available
    /// in the provided `ExecutionContext`.
    ///
    /// Note that if service was added in the genesis block, it will be activated immediately and
    /// thus `after_transactions` will be invoked for such a service after the genesis block creation.
    /// If you aren't interested in the processing of for the genesis block, you can use
    /// [`ExecutionContext::in_genesis_block`] method and exit early if `true` is returned.
    ///
    /// Invocation of the `height()` method of the core blockchain schema will **panic**
    /// if invoked within `after_transactions` of the genesis block. If you are going
    /// to process the genesis block and need to know current height, use the `next_height()` method
    /// to infer the current blockchain height.
    ///
    /// Services should not rely on a particular ordering of `Service::after_transactions`
    /// invocations among services.
    ///
    /// [`ExecutionContext::in_genesis_block`]: struct.ExecutionContext.html#method.in_genesis_block
    fn after_transactions(&self, _context: ExecutionContext<'_>) -> Result<(), ExecutionError> {
        Ok(())
    }

    /// Handles block commit event.
    ///
    /// This handler is a callback which is invoked by the blockchain
    /// after each block commit. For example, a service can broadcast one or more transactions
    /// if a specific condition has occurred.
    ///
    /// The default implementation does nothing.
    ///
    /// Try not to perform long operations in this handler since it is executed
    /// on the consensus thread.
    fn after_commit(&self, _context: AfterCommitContext<'_>) {}

    /// Attaches the request handlers of the service API to the Exonum API schema.
    ///
    /// The default implementation does nothing (i.e., does not provide any API for the service).
    ///
    /// The request handlers are mounted on the `/api/services/{instance_name}` path at the
    /// listen address of every full node in the blockchain network.
    fn wire_api(&self, _builder: &mut ServiceApiBuilder) {}

    // TODO: add other hooks such as "on node startup", etc. [ECR-3222]
}

/// Describes a service instance factory for the specific Rust artifact.
///
/// Usually, `ServiceFactory` can be derived using the
/// [`ServiceFactory`](index.html#examples) macro.
pub trait ServiceFactory: Send + Debug + 'static {
    /// Returns the unique artifact identifier corresponding to the factory.
    fn artifact_id(&self) -> ArtifactId;
    /// Returns the Protobuf specification used by the instances of this service.
    fn artifact_protobuf_spec(&self) -> ArtifactProtobufSpec;
    /// Creates a new service instance.
    fn create_instance(&self) -> Box<dyn Service>;
}

impl<T> From<T> for Box<dyn ServiceFactory>
where
    T: ServiceFactory,
{
    fn from(factory: T) -> Self {
        Box::new(factory) as Self
    }
}

/// Provides default instance configuration parameters for `ServiceFactory`.
pub trait DefaultInstance: ServiceFactory {
    /// Default id for a service.
    const INSTANCE_ID: InstanceId;
    /// Default name for a service.
    const INSTANCE_NAME: &'static str;

    /// Creates default instance configuration parameters for the service.
    fn default_instance(&self) -> InstanceInitParams {
        self.artifact_id()
            .into_default_instance(Self::INSTANCE_ID, Self::INSTANCE_NAME)
    }
}

/// Provide context for the `after_commit` handler.
pub struct AfterCommitContext<'a> {
    /// Reference to the dispatcher mailbox.
    mailbox: &'a mut Mailbox,
    /// Read-only snapshot of the current blockchain state.
    snapshot: &'a dyn Snapshot,
    /// Transaction broadcaster.
    broadcaster: Broadcaster<'a>,
    /// ID of the node as a validator.
    validator_id: Option<ValidatorId>,
}

impl<'a> AfterCommitContext<'a> {
    /// Creates a new `AfterCommit` context.
    pub(crate) fn new(
        mailbox: &'a mut Mailbox,
        instance: InstanceDescriptor,
        snapshot: &'a dyn Snapshot,
        service_keypair: &'a KeyPair,
        tx_sender: &'a ApiSender,
        validator_id: Option<ValidatorId>,
    ) -> Self {
        Self {
            mailbox,
            snapshot,
            validator_id,
            broadcaster: Broadcaster::new(instance, service_keypair, tx_sender),
        }
    }

    /// Returns blockchain data for the snapshot associated with this context.
    pub fn data(&self) -> BlockchainData<&'a dyn Snapshot> {
        BlockchainData::new(self.snapshot, &self.broadcaster.instance().name)
    }

    /// Returns snapshot of the data for the executing service.
    pub fn service_data(&self) -> Prefixed<&'a dyn Snapshot> {
        self.data().for_executing_service()
    }

    /// Returns a current blockchain height. This height is "height of the latest committed block".
    pub fn height(&self) -> Height {
        // TODO Perhaps we should optimize this method [ECR-3222]
        self.data().for_core().height()
    }

    /// Returns the service key of this node.
    pub fn service_key(&self) -> PublicKey {
        self.broadcaster.service_keypair.public_key()
    }

    /// Returns the ID of this node as a validator. If the node is not a validator, returns `None`.
    pub fn validator_id(&self) -> Option<ValidatorId> {
        self.validator_id
    }

    /// Returns a transaction broadcaster if the current node is a validator. If the node
    /// is not a validator, returns `None`.
    pub fn broadcaster(&self) -> Option<Broadcaster<'a>> {
        self.validator_id?;
        Some(self.broadcaster.clone())
    }

    /// Returns a transaction broadcaster regardless of the node status (validator or auditor).
    pub fn generic_broadcaster(&self) -> Broadcaster<'a> {
        self.broadcaster.clone()
    }

    /// Provides a privileged interface to the supervisor service.
    ///
    /// `None` will be returned if the caller is not a supervisor.
    #[doc(hidden)]
    pub fn supervisor_extensions(&mut self) -> Option<SupervisorExtensions<'_>> {
        if !is_supervisor(self.broadcaster.instance().id) {
            return None;
        }
        Some(SupervisorExtensions {
            mailbox: &mut *self.mailbox,
        })
    }
}

/// Transaction broadcaster.
///
/// Transaction broadcast allows a service to create transactions in the `after_commit`
/// handler or the HTTP API handlers and broadcast them to the connected Exonum nodes.
/// The transactions are addressed to the executing service instance and are signed
/// by the service keypair of the node.
///
/// Broadcasting functionality is primarily useful for services that receive information
/// from outside the blockchain and need to translate it to transactions. As an example,
/// a time oracle service may broadcast local node time and build the blockchain-wide time
/// by processing corresponding transactions.
#[derive(Debug, Clone)]
pub struct Broadcaster<'a> {
    instance: InstanceDescriptor,
    service_keypair: Cow<'a, KeyPair>,
    tx_sender: Cow<'a, ApiSender>,
}

impl<'a> Broadcaster<'a> {
    /// Creates a new broadcaster.
    pub(super) fn new(
        instance: InstanceDescriptor,
        service_keypair: &'a KeyPair,
        tx_sender: &'a ApiSender,
    ) -> Self {
        Self {
            instance,
            service_keypair: Cow::Borrowed(service_keypair),
            tx_sender: Cow::Borrowed(tx_sender),
        }
    }

    pub(super) fn keypair(&self) -> &KeyPair {
        self.service_keypair.as_ref()
    }

    pub(super) fn instance(&self) -> &InstanceDescriptor {
        &self.instance
    }

    /// Converts the broadcaster into the owned representation, which can be used to broadcast
    /// transactions asynchronously.
    pub fn into_owned(self) -> Broadcaster<'static> {
        Broadcaster {
            instance: self.instance,
            service_keypair: Cow::Owned(self.service_keypair.into_owned()),
            tx_sender: Cow::Owned(self.tx_sender.into_owned()),
        }
    }
}

/// Signs and broadcasts a transaction to the other nodes in the network.
///
/// The transaction is signed by the service keypair of the node. The same input transaction
/// will lead to the identical transaction being broadcast. If this is undesired, add a nonce
/// field to the input transaction (e.g., a `u64`) and change it between the calls.
///
/// # Return value
///
/// Returns the hash of the created transaction, or an error if the transaction cannot be
/// broadcast. An error means that the node is being shut down.
impl GenericCall<()> for Broadcaster<'_> {
    type Output = Result<Hash, SendError>;

    fn generic_call(&self, _ctx: (), method: MethodDescriptor<'_>, args: Vec<u8>) -> Self::Output {
        let msg = self
            .service_keypair
            .generic_call(self.instance().id, method, args);
        let tx_hash = msg.object_hash();
        self.tx_sender
            .broadcast_transaction(msg)
            .wait()
            .map(|()| tx_hash)
    }
}

/// Extended blockchain interface for the service instance authorized as a supervisor.
#[derive(Debug)]
pub struct SupervisorExtensions<'a> {
    mailbox: &'a mut Mailbox,
}

impl SupervisorExtensions<'_> {
    /// Starts the deployment of an artifact. The provided callback is executed after
    /// the deployment is completed.
    pub fn start_deploy<F>(
        &mut self,
        artifact: ArtifactId,
        spec: impl BinaryValue,
        then: impl FnOnce(Result<(), ExecutionError>) -> F + 'static + Send,
    ) where
        F: IntoFuture<Item = (), Error = ExecutionError>,
        F::Future: 'static + Send,
    {
        let action = DispatcherAction::StartDeploy {
            artifact,
            spec: spec.into_bytes(),
            then: Box::new(|res| Box::new(then(res).into_future())),
        };
        self.mailbox.push(action);
    }
}

impl Debug for AfterCommitContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AfterCommitContext")
            .field("instance", &self.broadcaster.instance)
            .finish()
    }
}

fn is_supervisor(instance_id: InstanceId) -> bool {
    instance_id == exonum::runtime::SUPERVISOR_INSTANCE_ID
}
