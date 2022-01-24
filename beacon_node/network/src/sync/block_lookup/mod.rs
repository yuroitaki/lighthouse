use super::manager::SLOT_IMPORT_TOLERANCE;
use crate::beacon_processor::WorkEvent;
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
use crate::sync::RequestId;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::rpc::{BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUCache;
use rand::seq::IteratorRandom;
use slog::{crit, debug, error, info, trace, warn, Logger};
use smallvec::SmallVec;
use ssz_types::VariableList;
use std::boxed::Box;
use std::collections::HashSet;
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};

/// The ProcessId used to keep track of blocks being processed by the beacon processor.
type ProcessId = usize;

//TODO: Add Metrics

/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
struct ParentRequest<T: EthSpec> {
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,
    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,
    /// The peers that have indicated they have access to this chain of blocks. If the chain fails
    /// to download, all peers here get penalized.
    related_peers: HashSet<PeerId>,
    /// The peer that last submitted data. This is used to potentially penalize the individual peer
    /// for malicious behaviour.
    last_submitted_peer: PeerId,
    /// Blocks are currently being requested for this lookup.
    requesting: Option<RequestId>,
}

/// Object representing a single block lookup request.
struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
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
            failures: 0,
            related_peers: HashSet::new(),
        }
    }
}

/// Main object handling block lookup logic.
pub struct BlockLookup<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequest<T::EthSpec>; 3]>,
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUCache<Hash256>,
    /// A collection of block hashes being searched for. Once we receive a block we move the
    /// SingleBlockRequest into processing but leave the entry to wait for the RPC stream
    /// termination.
    single_block_lookups: FnvHashMap<RequestId, Option<SingleBlockRequest>>,
    /// A record of blocks being processed from a single block lookup, along with the related peers
    /// for this block hash.
    single_blocks_being_processed:
        FnvHashMap<ProcessId, (SingleBlockRequest, SignedBeaconBlock<T::EthSpec>)>,
    /// A record of blocks being processed for a parent lookup request.
    parent_lookup_blocks_being_processed: FnvHashMap<ProcessId, ParentRequest<T::EthSpec>>,
    /// An id to keep track of in-flight blocks being processed by the beacon processor.
    process_id: ProcessId,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<WorkEvent<T>>,
    /// Logger for block lookup logic.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookup<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        beacon_processor_send: mpsc::Sender<WorkEvent<T>>,
        log: Logger,
    ) -> Self {
        BlockLookup {
            chain,
            parent_queue: SmallVec::new(),
            failed_chains: LRUCache::new(500),
            single_block_lookups: FnvHashMap::default(),
            single_blocks_being_processed: FnvHashMap::default(),
            parent_lookup_blocks_being_processed: FnvHashMap::default(),
            process_id: 0,
            beacon_processor_send,
            log,
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
                // NOTE: We don't remove the lookup from the mapping, because we still wait for the
                // stream termination or an error.
                // TODO: Metrics: Update single block lookup size
                if let Some(Some(block_request)) =
                    self.single_block_lookups.get_mut(&request_id).take()
                {
                    // verify the hash is correct and try and process the block
                    if block_request.hash != block.canonical_root() {
                        // The peer that sent this, sent us the wrong block.
                        // We do not tolerate this behaviour. The peer is instantly disconnected and banned.
                        warn!(self.log, "Peer sent incorrect block for single block lookup"; "peer_id" => %peer_id);
                        network_context.goodbye_peer(peer_id, GoodbyeReason::Fault);

                        //TODO: Re-request the block remove the bad peer.
                        return;
                    }

                    // Send the block to get processed
                    if self
                        .process_block(block.clone(), false, seen_timestamp)
                        .is_err()
                    {
                        error!(self.log, "Couldn't send block to processor"; "message" => "Dropping single block lookup");
                    } else {
                        self.single_blocks_being_processed
                            .insert(self.process_id, (*block_request, block));
                    }
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| request.requesting == Some(request_id))
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
                // chain should be dropped and the peer penalized.
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
                    network_context.report_peer(
                        peer_id,
                        PeerAction::MidToleranceError,
                        "parent part of a failed chain",
                    );
                    return;
                }
                // add the block to response
                parent_request.downloaded_blocks.push(block);
                // queue for processing
                self.process_parent_request(parent_request, seen_timestamp, network_context);
            }
            None => {
                // this is a stream termination

                // stream termination for a single block lookup, remove the key
                if let Some(Some(single_block_request)) =
                    self.single_block_lookups.remove(&request_id)
                {
                    // The peer didn't respond with a block that it referenced.
                    // This can be allowed as some clients may implement pruning. We mildly
                    // tolerate this behaviour.
                    warn!(self.log, "Peer didn't respond with a block it referenced"; "referenced_block_hash" => %single_block_request.hash, "peer_id" =>  %peer_id);
                    network_context.report_peer(
                        peer_id,
                        PeerAction::MidToleranceError,
                        "Peer sent empty response to block lookup",
                    );
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request and remove it
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| request.requesting == Some(request_id))
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
    pub fn parent_lookup_failed(
        &mut self,
        chain_head: Hash256,
        related_peers: HashSet<PeerId>,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        self.failed_chains.insert(chain_head);
        for peer_id in related_peers {
            network_context.report_peer(
                peer_id,
                PeerAction::MidToleranceError,
                "parent_lookup_failed",
            );
        }
    }

    pub fn on_peer_disconnection(&mut self, peer_id: &PeerId) {
        //TODO: Handle peer disconnection
    }

    /// Handles RPC errors related to requests that were emitted from the sync manager.
    pub fn on_rpc_error(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
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
            .position(|request| request.requesting == Some(request_id))
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
    pub fn search_for_block(
        &mut self,
        peer_id: PeerId,
        block_hash: Hash256,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        // If we are not synced, ignore this block
        if !network_context
            .network_globals
            .sync_state
            .read()
            .is_synced()
        {
            return;
        }

        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values()
            .any(|single_block_request| single_block_request.map(|r| r.hash) == Some(block_hash))
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
                .insert(request_id, Some(SingleBlockRequest::new(block_hash)));
        }
    }

    /// The beacon processor has indicated
    pub fn on_single_block_lookup_result(
        &mut self,
        process_id: ProcessId,
        result: Result<Hash256, BlockError<T::EthSpec>>,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        // Find the corresponding processing block.
        if let Some((single_block_lookup_request, block)) =
            self.single_blocks_being_processed.remove(&process_id)
        {
            match result {
                Ok(block_root) => info!(self.log, "Processed block"; "block" => %block_root),
                Err(BlockError::ParentUnknown { .. }) => {
                    // We don't know of the blocks parent, begin a parent lookup search
                    self.add_unknown_block(
                        // The for last submitted peer, we just use the first peer in related
                        // peers.
                        *single_block_lookup_request
                            .related_peers
                            .iter()
                            .next()
                            .expect("related peers must have at least one entry"),
                        single_block_lookup_request.related_peers,
                        block,
                        network_context,
                    );
                }
                Err(BlockError::BlockIsAlreadyKnown) => {
                    trace!(self.log, "Single block lookup already known");
                }
                Err(BlockError::BeaconChainError(e)) => {
                    warn!(self.log, "Unexpected block processing error"; "error" => ?e);
                }
                outcome => {
                    warn!(self.log, "Single block lookup failed"; "outcome" => ?outcome);
                    // TODO: Potentially try again.
                    // This could be a range of errors. But we couldn't process the block.
                    // For now we consider this a mid tolerance error.
                    for peer_id in single_block_lookup_request.related_peers.iter() {
                        network_context.report_peer(
                            *peer_id,
                            PeerAction::MidToleranceError,
                            "failed to process single block lookup",
                        );
                    }
                }
            }
        } else {
            error!(self.log, "Single block lookup process id not found"; "process_id" => process_id);
        }
    }

    /// A block has been sent to us that has an unknown parent. This begins a parent lookup search
    /// to find the parent or chain of parents that match our current chain.
    pub fn add_unknown_block(
        &mut self,
        last_submitted_peer: PeerId,
        related_peers: HashSet<PeerId>,
        block: SignedBeaconBlock<T::EthSpec>,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        // If we are not synced or outside the SLOT_IMPORT_TOLERANCE of the block, ignore it
        if !network_context
            .network_globals
            .sync_state
            .read()
            .is_synced()
        {
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

        let parent_request = ParentRequest {
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            related_peers: related_peers,
            last_submitted_peer,
            requesting: None,
        };

        self.request_parent(parent_request, network_context)
    }

    /* Processing State Functions */
    // These functions are called in the main poll function to transition the state of the sync
    // manager

    /// A new block has been received for a parent lookup query, process it.
    fn process_parent_request(
        &mut self,
        mut parent_request: ParentRequest<T::EthSpec>,
        seen_timestamp: Duration,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
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
            network_context.report_peer(
                peer,
                PeerAction::LowToleranceError,
                "parent request sent invalid block hash",
            );
        } else {
            // The last block in the queue is the only one that has not attempted to be processed yet.
            //
            // We try and process this block here.

            let newest_block = parent_request
                .downloaded_blocks
                .iter()
                .last()
                .expect("There is always at least one block in the queue");

            // Attempt to process the block.
            if self
                .process_block(newest_block.clone(), true, seen_timestamp)
                .is_err()
            {
                error!(self.log, "Could not send parent request to block processor"; "message" => "dropping parent request");
                return;
            } else {
                self.parent_lookup_blocks_being_processed
                    .insert(self.process_id, parent_request);
            }
        }
    }

    /// A block has been processed for a parent lookup request. This functions handles the
    /// post-processing of the block.
    pub fn on_parent_block_lookup_result(
        &mut self,
        process_id: ProcessId,
        result: Result<Hash256, BlockError<T::EthSpec>>,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        // Obtain the parent_request related to the processing request.
        if let Some(parent_request) = self
            .parent_lookup_blocks_being_processed
            .remove(&process_id)
        {
            // The logic here attempts to process the last block. If it can be processed, the rest
            // of the blocks must have known parents. If any of them cannot be processed, we
            // consider the entire chain corrupt and drop it, notifying the user.
            //
            // If the last block in the queue cannot be processed, we also drop the entire queue.
            // If the last block in the queue has an unknown parent, we continue the parent
            // lookup-search.

            match result {
                Err(BlockError::ParentUnknown { .. }) => {
                    // We need to keep looking for parents
                    self.request_parent(parent_request, network_context);
                }
                Ok(_) | Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                    // The block was processed correctly, pop it from the request.
                    parent_request.downloaded_blocks.pop();

                    let chain_block_hash = parent_request.downloaded_blocks[0].canonical_root();

                    let process_id = crate::beacon_processor::ProcessId::ParentLookup(
                        parent_request.related_peers,
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
                    // TODO: Handle re-lookups and related peers.
                    warn!(
                        self.log, "Invalid parent chain";
                        "score_adjustment" => %PeerAction::MidToleranceError,
                        "outcome" => ?outcome,
                        "last_peer" => %parent_request.last_submitted_peer,
                    );

                    let chain_block_hash = parent_request.downloaded_blocks[0].canonical_root();
                    // Add this chain to cache of failed chains
                    self.failed_chains.insert(chain_block_hash);

                    // This currently can be a host of errors. We permit this due to the partial
                    // ambiguity.
                    // TODO: Handle re-lookups
                    network_context.report_peer(
                        parent_request.last_submitted_peer,
                        PeerAction::MidToleranceError,
                        "parent chain block failed",
                    );
                }
            }
        }
    }

    /// Progresses a parent request query.
    ///
    /// This checks to ensure there a peers to progress the query, checks for failures and
    /// initiates requests.
    fn request_parent(
        &mut self,
        mut parent_request: ParentRequest<T::EthSpec>,
        network_context: &mut SyncNetworkContext<T::EthSpec>,
    ) {
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
            // Penalize all the related peers
            for peer_id in parent_request.related_peers.iter() {
                network_context.report_peer(
                    *peer_id,
                    PeerAction::LowToleranceError,
                    "parent chain failed",
                );
            }
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

        // We continue to search for the chain of blocks from any relevant peer. Other peers are not
        // guaranteed to have this chain of blocks.
        let peer_id = match parent_request
            .related_peers
            .iter()
            .choose(&mut rand::thread_rng())
        {
            Some(peer_id) => peer_id,
            None => {
                crit!(self.log, "Parent request has no peers to choose from");
                return;
            }
        };

        if let Ok(request_id) = network_context.blocks_by_root_request(*peer_id, request) {
            // if the request was successful add the queue back into self
            parent_request.requesting = Some(request_id);
            self.parent_queue.push(parent_request);
        }
    }

    /// Send the block to get processed.
    fn process_block(
        &mut self,
        block: SignedBeaconBlock<T::EthSpec>,
        parent_lookup: bool,
        seen_timestamp: Duration,
    ) -> Result<(), ()> {
        let event = WorkEvent::rpc_beacon_block(
            Box::new(block),
            parent_lookup,
            self.process_id,
            seen_timestamp,
        );
        self.process_id += 1;
        self.beacon_processor_send.try_send(event).map_err(|_| ())
    }
}
