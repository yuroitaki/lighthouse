/// The Lighthouse logic for searching for single blocks or a chain of blocks given an unknown
/// block hash seen on the network.
///
/// There are two main cases where this logic gets invoked:
/// 1. We receive a block but we don't know its parent. This invokes a `parent_lookup` search via
///    the `add_unknown_block` function. A `parent_lookup` search recursively tries to download a
///    chain of blocks until we reach a block on our canonical chain, or we reach a max search
///    depth. After downloading all the blocks we then try to process the chain.
///
/// 2. We receive an attestation or object that references a block hash that we don't know about.
///    This invokes a `single_block_lookup`. Here we request the block by the hash. If we receive
///    the block but don't know its parent. This search transitions into a `parent_lookup` search. 
///
/// In both cases, peers that fail to respond correctly to our queries get penalized. If multiple
/// peers are supposed to house the requested blocks, they are added to the pool of potential peers
/// to download the block from and are all penalized if we are unable to achieve the desired block.

use crate::sync::network_context::SyncNetworkContext;
use crate::beacon_processor::{ProcessId, WorkEvent};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::rpc::{BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUCache;
use slog::{crit, debug, error, info, trace, warn, Logger};
use smallvec::SmallVec;
use ssz_types::VariableList;
use std::boxed::Box;
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use crate::sync::RequestId;
use super::manager::SLOT_IMPORT_TOLERANCE;

use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};


//TODO: Add Metrics

/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
struct ParentRequests<T: EthSpec> {
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,
    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,
    /// The peers that have indicated they have access to this chain of blocks. If the chain fails
    /// to download, all peers here get penalized.
    related_peers: HashSet<PeerId>,
    /// The request ID of this lookup is in progress.
    state: ParentRequestState,
}

/// The state of a parent request.
enum ParentRequestState {
    /// The request is idle.
    Idle,
    /// We are actively requesting a block.
    Requesting(RequestId),
    /// A block is being processed.
    Processing(ProcessId),
}

/// Object representing a single block lookup request.
struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
    /// The number of failed attempts at getting this block.
    pub failures: usize,
    /// Peers that should also have this block. These peers get penalized if the single block
    /// lookup request fails.
    pub related_peers: HashSet<PeerId>,
}

impl SingleBlockRequest {
    pub fn new(hash: Hash256) -> Self {
        Self {
            hash,
            block_returned: false,
        }
    }
}

/// Main object handling block lookup logic.
pub struct BlockLookup<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequests<T::EthSpec>; 3]>,
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUCache<Hash256>,
    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: FnvHashMap<RequestId, SingleBlockRequest>,
    /// A record of blocks being processed from a single block lookup, along with the related peers
    /// for this block hash.
    single_blocks_being_processed: FnvHashMap<ProcessId, SingleBlockRequest>,
    /// An id to keep track of in-flight blocks being processed by the beacon processor.
    process_id: ProcessId, 
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<WorkEvent<T>>,
    /// Logger for block lookup logic.
    log: Logger,
}


impl<T: BeaconChainTypes> BlockLookup<T> {

    pub fn new(chain: Arc<BeaconChain<T>>, beacon_processor_send: mpsc::Sender<WorkEvent<T>>, log: Logger) -> Self {
        BlockLookup {
        chain,
        parent_queue: SmallVec::new(),
        failed_chains: LRUCache::new(500),
        single_block_lookups: FnvHashMap::default(),
        process_id: 0,
        beacon_processor_send,
        log
        }
    }

    /// The response to a `BlocksByRoot` request.
    /// The current implementation takes one block at a time. As blocks are streamed, any
    /// subsequent blocks will simply be ignored.
    /// There are two reasons we could have received a BlocksByRoot response
    /// - We requested a single hash and have received a response for the single_block_lookup
    /// - We are looking up parent blocks in parent lookup search
    pub fn on_blocks_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        block: Option<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        match block {
            Some(block) => {
                // data was returned, not just a stream termination
                // check if this is a single block lookup - i.e we were searching for a specific hash
                let mut single_block_hash = None;
                if let Some(block_request) = self.single_block_lookups.get_mut(&request_id) {
                    // update the state of the lookup indicating a block was received from the peer
                    block_request.block_returned = true;
                    single_block_hash = Some(block_request.hash);
                }
                if let Some(block_hash) = single_block_hash {
                    self.single_block_lookup_response(peer_id, block, block_hash, seen_timestamp, network_context);
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| matches!(request.state,ParentRequestState::Requesting(request_id)))
                {
                    // we remove from the queue and process it. It will get re-added if required
                    Some(pos) => self.parent_queue.remove(pos),
                    None => {
                        // No pending request, invalid request_id or coding error
                        warn!(self.log, "BlocksByRoot response unknown"; "request_id" => request_id);
                        return;
                    }
                };

                // check if the parent of this block isn't in our failed cache. If it is, this
                // chain should be dropped and the peer downscored.
                if self.failed_chains.contains(&block.message().parent_root()) {
                    debug!(
                        self.log,
                        "Parent chain ignored due to past failure";
                        "block" => ?block.message().parent_root(),
                        "slot" => block.slot()
                    );
                    if !parent_request.downloaded_blocks.is_empty() {
                        // Add the root block to failed chains
                        self.failed_chains
                            .insert(parent_request.downloaded_blocks[0].canonical_root());
                    } else {
                        crit!(self.log, "Parent chain has no blocks");
                    }
                   network_context 
                        .report_peer(peer_id, PeerAction::MidToleranceError);
                    return;
                }
                // add the block to response
                parent_request.downloaded_blocks.push(block);
                // queue for processing
                self.process_parent_request(parent_request, network_context).await;
            }
            None => {
                // this is a stream termination

                // stream termination for a single block lookup, remove the key
                if let Some(single_block_request) = self.single_block_lookups.remove(&request_id) {
                    // The peer didn't respond with a block that it referenced.
                    // This can be allowed as some clients may implement pruning. We mildly
                    // tolerate this behaviour.
                    if !single_block_request.block_returned {
                        warn!(self.log, "Peer didn't respond with a block it referenced"; "referenced_block_hash" => %single_block_request.hash, "peer_id" =>  %peer_id);
                       network_context 
                            .report_peer(peer_id, PeerAction::MidToleranceError);
                    }
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request and remove it
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| matches!(request.state, ParentRequestState::Requesting(request_id)))
                {
                    Some(pos) => self.parent_queue.remove(pos),
                    None => {
                        // No pending request, the parent request has been processed and this is
                        // the resulting stream termination.
                        return;
                    }
                };
                // An empty response has been returned to a parent request
                // if an empty response is given, the peer didn't have the requested block, try again
                parent_request.failed_attempts += 1;
                parent_request.last_submitted_peer = peer_id;
                self.request_parent(parent_request, network_context);
            }
        }
    }

    /// A peer sent an object (block or attestation) that referenced a parent and the processing of this chain failed.
    pub fn parent_lookup_failed(&mut self, chain_head: Hash256, peer_id: PeerId, network_context: &mut SyncNetworkContext<T:: EthSpec>) {
                self.failed_chains.insert(chain_head);
                network_context.report_peer(peer_id, PeerAction::MidToleranceError);
    }

    pub fn on_peer_disconnection(&mut self, peer_id: &PeerId) {
        //TODO: Handle peer disconnection

    }

    /// Handles RPC errors related to requests that were emitted from the sync manager.
    pub fn on_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId, network_context: &mut SyncNetworkContext<T::EthSpec>) {
        trace!(self.log, "Sync manager received a failed RPC");

        // TODO: Handle single block lookup failure attempts

        // remove any single block lookups
        if self.single_block_lookups.remove(&request_id).is_some() {
            // this was a single block request lookup, look no further
            return;
        }

        // increment the failure of a parent lookup if the request matches a parent search
        if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| matches!(request.state, ParentRequestState::Requesting(request_id)))
        {
            let mut parent_request = self.parent_queue.remove(pos);
            parent_request.failed_attempts += 1;
            parent_request.last_submitted_peer = peer_id;
            self.request_parent(parent_request, network_context);
            return;
        }

        // Otherwise this error matches no known request.
        trace!(self.log, "Response/Error for non registered request"; "request_id" => request_id)
    }

    /// A request to search for a block hash has been received. This function begins a BlocksByRoot
    /// request and starts a single block lookup. This can later turn into a chain of parent
    /// requests.
    pub fn search_for_block(&mut self, peer_id: PeerId, block_hash: Hash256, network_context: &mut SyncNetworkContext<T::EthSpec>) {
        // If we are not synced, ignore this block
        if !network_context.network_globals.sync_state.read().is_synced() {
            return;
        }

        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values()
            .any(|single_block_request| single_block_request.hash == block_hash)
        {
            return;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => %peer_id,
            "block" => %block_hash
        );

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![block_hash]),
        };

        if let Ok(request_id) = network_context.blocks_by_root_request(peer_id, request) {
            self.single_block_lookups
                .insert(request_id, SingleBlockRequest::new(block_hash));
        }
    }

    /// Processes the response obtained from a single block lookup search. If the block is
    /// processed or errors, the search ends. If the blocks parent is unknown, a block parent
    /// lookup search is started.
    fn single_block_lookup_response(
        &mut self,
        peer_id: PeerId,
        block: SignedBeaconBlock<T::EthSpec>,
        expected_block_hash: Hash256,
        seen_timestamp: Duration,
        network_context: &mut SyncNetworkContext<T::EthSpec>
    ) {
        // verify the hash is correct and try and process the block
        if expected_block_hash != block.canonical_root() {
            // The peer that sent this, sent us the wrong block.
            // We do not tolerate this behaviour. The peer is instantly disconnected and banned.
            warn!(self.log, "Peer sent incorrect block for single block lookup"; "peer_id" => %peer_id);
            network_context.goodbye_peer(peer_id, GoodbyeReason::Fault);
            return;
        }

        // Send the block to get processed
        let process_id = self.process_block(block, false);
        self.processing_single_blocks.insert(process_id, related_peers); 

    }

    /// The beacon processor has indicated 
    pub fn on_single_block_lookup_result(process_id: ProcessId, result: Result<Hash256, BlockError<T::EthSpec>>) {

            // Find the corresponding processing block.
            if let Some(related_peers) = self.processing_blocks.remove(process_id) {

                match result {
                    Ok(block_root) => info!(self.log, "Processed block"; "block" => %block_root),
                    Err(BlockError::ParentUnknown { .. }) => {
                        // We don't know of the blocks parent, begin a parent lookup search
                        self.add_unknown_block(related_peers, block, network_context);
                    }
                    Err(BlockError::BlockIsAlreadyKnown) => {
                        trace!(self.log, "Single block lookup already known");
                    }
                    Err(BlockError::BeaconChainError(e)) => {
                        warn!(self.log, "Unexpected block processing error"; "error" => ?e);
                    }
                    outcome => {
                        warn!(self.log, "Single block lookup failed"; "outcome" => ?outcome);
                        // This could be a range of errors. But we couldn't process the block.
                        // For now we consider this a mid tolerance error.
                        for peer_id in related_peers.iter() {
                            network_context
                                .report_peer(peer_id, PeerAction::MidToleranceError);
                        }
                    }
                }

            } else {
                error!(self.log, "Single block lookup process id not found", "process_id" => process_id);
            }

        }

    /*

        let block_result = match clone()).await {
            Some(block_result) => block_result,
            None => return,
        };

        // we have the correct block, try and process it
        match block_result {
            Ok(block_root) => {
                // Block has been processed, so write the block time to the cache.
                self.chain.block_times_cache.write().set_time_observed(
                    block_root,
                    block.slot(),
                    seen_timestamp,
                    None,
                    None,
                );
                info!(self.log, "Processed block"; "block" => %block_root);

                match self.chain.fork_choice() {
                    Ok(()) => trace!(
                        self.log,
                        "Fork choice success";
                        "location" => "single block"
                    ),
                    Err(e) => error!(
                        self.log,
                        "Fork choice failed";
                        "error" => ?e,
                        "location" => "single block"
                    ),
                }
            }
    }
    */

    /// A block has been sent to us that has an unknown parent. This begins a parent lookup search
    /// to find the parent or chain of parents that match our current chain.
    pub fn add_unknown_block(&mut self, peer_id: PeerId, block: SignedBeaconBlock<T::EthSpec>, network_context: &mut SyncNetworkContext<T::EthSpec>) {
        // If we are not synced or outside the SLOT_IMPORT_TOLERANCE of the block, ignore it
        if !network_context.network_globals.sync_state.read().is_synced() {
            let head_slot = self
                .chain
                .head_info()
                .map(|info| info.slot)
                .unwrap_or_else(|_| Slot::from(0u64));
            let unknown_block_slot = block.slot();

            // if the block is far in the future, ignore it. If its within the slot tolerance of
            // our current head, regardless of the syncing state, fetch it.
            if (head_slot >= unknown_block_slot
                && head_slot.sub(unknown_block_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
                || (head_slot < unknown_block_slot
                    && unknown_block_slot.sub(head_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
            {
                return;
            }
        }

        let block_root = block.canonical_root();
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block.message().parent_root())
            || self.failed_chains.contains(&block_root)
        {
            debug!(self.log, "Block is from a past failed chain. Dropping"; "block_root" => ?block_root, "block_slot" => block.slot());
            return;
        }

        // Make sure this block is not already being searched for
        // NOTE: Potentially store a hashset of blocks for O(1) lookups
        for parent_req in self.parent_queue.iter() {
            if parent_req
                .downloaded_blocks
                .iter()
                .any(|d_block| d_block == &block)
            {
                // we are already searching for this block, ignore it
                return;
            }
        }

        debug!(self.log, "Unknown block received. Starting a parent lookup"; "block_slot" => block.slot(), "block_hash" => %block.canonical_root());

        let parent_request = ParentRequests {
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            last_submitted_peer: peer_id,
            pending: None,
        };

        self.request_parent(parent_request, network_context)
    }


    /* Processing State Functions */
    // These functions are called in the main poll function to transition the state of the sync
    // manager

    /// A new block has been received for a parent lookup query, process it.
    async fn process_parent_request(&mut self, mut parent_request: ParentRequests<T::EthSpec> , network_context: &mut SyncNetworkContext<T::EthSpec>) {
        // verify the last added block is the parent of the last requested block

        if parent_request.downloaded_blocks.len() < 2 {
            crit!(
                self.log,
                "There must be at least two blocks in a parent request lookup at all times"
            );
            panic!("There must be at least two blocks in parent request lookup at all times");
            // fail loudly
        }
        let previous_index = parent_request.downloaded_blocks.len() - 2;
        let expected_hash = parent_request.downloaded_blocks[previous_index].parent_root();

        // Note: the length must be greater than 2 so this cannot panic.
        let block_hash = parent_request
            .downloaded_blocks
            .last()
            .expect("Complete batch cannot be empty")
            .canonical_root();
        if block_hash != expected_hash {
            // The sent block is not the correct block, remove the head block and downvote
            // the peer
            let _ = parent_request.downloaded_blocks.pop();
            let peer = parent_request.last_submitted_peer;

            warn!(self.log, "Peer sent invalid parent.";
                "peer_id" => %peer,
                "received_block" => %block_hash,
                "expected_parent" => %expected_hash,
            );

            // We try again, but downvote the peer.
            self.request_parent(parent_request, network_context);
            // We do not tolerate these kinds of errors. We will accept a few but these are signs
            // of a faulty peer.
           network_context 
                .report_peer(peer, PeerAction::LowToleranceError);
        } else {
            // The last block in the queue is the only one that has not attempted to be processed yet.
            //
            // The logic here attempts to process the last block. If it can be processed, the rest
            // of the blocks must have known parents. If any of them cannot be processed, we
            // consider the entire chain corrupt and drop it, notifying the user.
            //
            // If the last block in the queue cannot be processed, we also drop the entire queue.
            // If the last block in the queue has an unknown parent, we continue the parent
            // lookup-search.

            let chain_block_hash = parent_request.downloaded_blocks[0].canonical_root();

            let newest_block = parent_request
                .downloaded_blocks
                .pop()
                .expect("There is always at least one block in the queue");

            let block_result = match self.process_block_async(newest_block.clone()).await {
                Some(block_result) => block_result,
                None => return,
            };

            match block_result {
                Err(BlockError::ParentUnknown { .. }) => {
                    // need to keep looking for parents
                    // add the block back to the queue and continue the search
                    parent_request.downloaded_blocks.push(newest_block);
                    self.request_parent(parent_request, network_context);
                }
                Ok(_) | Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                    let process_id = ProcessId::ParentLookup(
                        parent_request.last_submitted_peer,
                        chain_block_hash,
                    );
                    let blocks = parent_request.downloaded_blocks;

                    match self
                        .beacon_processor_send
                        .try_send(WorkEvent::chain_segment(process_id, blocks))
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!(
                                self.log,
                                "Failed to send chain segment to processor";
                                "error" => ?e
                            );
                        }
                    }
                }
                Err(outcome) => {
                    // all else we consider the chain a failure and downvote the peer that sent
                    // us the last block
                    warn!(
                        self.log, "Invalid parent chain";
                        "score_adjustment" => %PeerAction::MidToleranceError,
                        "outcome" => ?outcome,
                        "last_peer" => %parent_request.last_submitted_peer,
                    );

                    // Add this chain to cache of failed chains
                    self.failed_chains.insert(chain_block_hash);

                    // This currently can be a host of errors. We permit this due to the partial
                    // ambiguity.
                    network_context.report_peer(
                        parent_request.last_submitted_peer,
                        PeerAction::MidToleranceError,
                    );
                }
            }
        }
    }

    /// Progresses a parent request query.
    ///
    /// This checks to ensure there a peers to progress the query, checks for failures and
    /// initiates requests.
    fn request_parent(&mut self, mut parent_request: ParentRequests<T::EthSpec>, network_context: &mut SyncNetworkContext<T::EthSpec>) {
        // check to make sure this request hasn't failed
        if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE
            || parent_request.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE
        {
            let error = if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE {
                // This is a peer-specific error and the chain could be continued with another
                // peer. We don't consider this chain a failure and prevent retries with another
                // peer.
                "too many failed attempts"
            } else if !parent_request.downloaded_blocks.is_empty() {
                self.failed_chains
                    .insert(parent_request.downloaded_blocks[0].canonical_root());
                "reached maximum lookup-depth"
            } else {
                crit!(self.log, "Parent lookup has no blocks");
                "no blocks"
            };

            debug!(self.log, "Parent import failed";
            "block" => ?parent_request.downloaded_blocks[0].canonical_root(),
            "ancestors_found" => parent_request.downloaded_blocks.len(),
            "reason" => error
            );
            // Downscore the peer.
            network_context.report_peer(
                parent_request.last_submitted_peer,
                PeerAction::LowToleranceError,
            );
            return; // drop the request
        }

        let parent_hash = if let Some(block) = parent_request.downloaded_blocks.last() {
            block.parent_root()
        } else {
            crit!(self.log, "Parent queue is empty. This should never happen");
            return;
        };

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![parent_hash]),
        };

        // We continue to search for the chain of blocks from the same peer. Other peers are not
        // guaranteed to have this chain of blocks.
        let peer_id = parent_request.last_submitted_peer;

        if let Ok(request_id) = network_context.blocks_by_root_request(peer_id, request) {
            // if the request was successful add the queue back into self
            parent_request.state = ParentRequestState::Requesting(request_id);
            self.parent_queue.push(parent_request);
        }
    }

    /// Send the block to get processed.
    fn process_block(
        &mut self,
        block: SignedBeaconBlock<T::EthSpec>,
        parent_lookup: bool,
    ) -> Result<(),()> {
        let event = WorkEvent::rpc_beacon_block(Box::new(block), parent_lookup, self.process_id);
        self.process_id += 1;
        self.beacon_processor_send.try_send(event) 
    }
}

