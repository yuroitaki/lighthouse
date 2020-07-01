use crate::{
    attestation_verification::VerifiedAggregatedAttestation, beacon_chain::HeadInfo,
    builder::BeaconChainBuilder, eth1_chain::CachingEth1Backend, events::NullEventHandler,
    migrate::NullMigrator, BeaconChain,
};
use genesis::interop_genesis_state;
use itertools::Itertools;
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use sloggers::{null::NullLoggerBuilder, Build};
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::per_slot_processing;
use std::borrow::Cow;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use store::{config::StoreConfig, HotColdDB, MemoryStore};
use tempfile::{tempdir, TempDir};
use types::test_utils::generate_deterministic_keypairs;
use types::*;

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// This parameter is required by a builder but not used because we use the `TestingSlotClock`.
pub const HARNESS_SLOT_TIME: Duration = Duration::from_secs(1);
pub const INITIAL_VALIDATOR_COUNT: usize = 64;

lazy_static! {
    pub static ref KEYPAIRS: Vec<Keypair> =
        generate_deterministic_keypairs(INITIAL_VALIDATOR_COUNT);
}

/// Get the secret key for a validator.
fn sk(validator_index: usize) -> &'static SecretKey {
    &KEYPAIRS[validator_index].sk
}

type E = MinimalEthSpec;
pub type Witness = crate::builder::Witness<
    // BlockingMigrator<E, MemoryStore<E>, MemoryStore<E>>,
    NullMigrator,
    TestingSlotClock,
    CachingEth1Backend<E>,
    E,
    NullEventHandler<E>,
    MemoryStore<E>,
    MemoryStore<E>,
>;

/// What should happen with block production at a single slot on a single chain?
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum BlockEvent {
    ProduceBlock,
    SkipSlot,
    NewSkipFork,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AttestationEvent {
    // NOTE: tweak type width if running with larger validator counts
    committee_bitfield: u8,
}

impl AttestationEvent {
    fn new(committee_bitfield: u8) -> Self {
        Self { committee_bitfield }
    }

    fn is_attester(&self, committee_position: usize) -> bool {
        self.committee_bitfield
            .checked_shr(committee_position.try_into().unwrap())
            .unwrap()
            & 1
            == 1
    }
}

/// An event occuring on a single chain.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ChainEvent {
    block_event: BlockEvent,
    attestation_event: AttestationEvent,
}

impl ChainEvent {
    fn full_participation() -> Self {
        Self {
            block_event: BlockEvent::ProduceBlock,
            attestation_event: AttestationEvent::new(0xff),
        }
    }

    fn skip_slot() -> Self {
        Self {
            block_event: BlockEvent::SkipSlot,
            attestation_event: AttestationEvent::new(0xff),
        }
    }
}

/// All the events occuring during a single slot, for each chain.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlotEvent {
    chain_events: Vec<ChainEvent>,
}

impl PartialEq for SlotEvent {
    fn eq(&self, other: &Self) -> bool {
        self.chain_events.iter().eq(other.chain_events.iter())
    }
}

/// All the events occuring during an execution.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Execution {
    /// Events for each slot, beginning with events for slot 0.
    ///
    /// Given `n` events, the simulation will run through until the slot
    /// clock reaches slot `n`, with the last event (and highest potential head)
    /// occuring at slot `n - 1`.
    slot_events: Vec<SlotEvent>,
}

impl PartialEq for Execution {
    fn eq(&self, other: &Self) -> bool {
        self.slot_events.iter().eq(other.slot_events.iter())
    }
}

impl Execution {
    pub fn is_well_formed(&self) -> bool {
        if self.slot_events.is_empty() {
            return false;
        }

        let mut max_num_forks = 1;
        for slot_event in &self.slot_events {
            if slot_event.chain_events.is_empty() || slot_event.chain_events.len() > max_num_forks {
                return false;
            }
            max_num_forks += slot_event
                .chain_events
                .iter()
                .filter(|ev| ev.block_event == BlockEvent::NewSkipFork)
                .count();
        }
        true
    }
}

pub struct Harness {
    /// Beacon chain under test.
    pub chain: BeaconChain<Witness>,
    /// Hash of the block at the head of each chain.
    pub forks: Vec<Hash256>,
    /// Last observed finalized checkpoint.
    pub last_finalized_checkpoint: Option<Checkpoint>,
    pub data_dir: TempDir,
}

impl Harness {
    pub fn new() -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let mut spec = E::default_spec();

        spec.target_aggregators_per_committee = 1 << 32;

        let log = NullLoggerBuilder.build().expect("logger should build");
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone(), log.clone()).unwrap();
        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log)
            .custom_spec(spec.clone())
            .store(Arc::new(store))
            .store_migrator(NullMigrator)
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(
                interop_genesis_state::<E>(&KEYPAIRS, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .build()
            .expect("should build");

        let forks = vec![chain.head_info().unwrap().block_root];

        Self {
            chain,
            forks,
            last_finalized_checkpoint: None,
            data_dir,
        }
    }

    // Fuzz target, don't crash!
    pub fn apply_execution(&mut self, exec: Execution) {
        if !exec.is_well_formed() {
            return;
        }

        for slot_event in exec.slot_events {
            let slot = self.chain.slot_clock.now().unwrap();
            self.apply_slot_event(slot, slot_event);

            self.chain.fork_choice().unwrap();

            self.check_slot_invariants();

            self.chain.slot_clock.advance_slot();
        }

        self.check_invariants();
    }

    fn apply_slot_event(&mut self, slot: Slot, slot_event: SlotEvent) {
        for (chain_id, chain_event) in slot_event.chain_events.into_iter().enumerate() {
            self.apply_chain_event(slot, chain_id, chain_event);
        }
    }

    fn apply_chain_event(&mut self, slot: Slot, chain_id: usize, chain_event: ChainEvent) {
        if let Some((block_root, state)) =
            self.apply_block_event(slot, chain_id, chain_event.block_event)
        {
            self.apply_attestation_event(slot, block_root, state, chain_event.attestation_event);
        }
    }

    // Return (new_head_block_root, new_head_state)
    fn apply_block_event(
        &mut self,
        slot: Slot,
        chain_id: usize,
        block_event: BlockEvent,
    ) -> Option<(Hash256, BeaconState<E>)> {
        use BlockEvent::*;

        let parent_block_root = self.forks[chain_id];
        // TODO: handle pruning
        let parent_block = self.chain.get_block(&parent_block_root).unwrap().unwrap();
        let mut parent_state = self
            .chain
            .get_state(&parent_block.state_root(), Some(parent_block.slot()))
            .unwrap()
            .unwrap();

        // Advance state to proposal epoch so we can get the proposer index.
        while parent_state.current_epoch() < slot.epoch(E::slots_per_epoch()) {
            per_slot_processing(&mut parent_state, None, self.spec()).unwrap();
        }

        // Apply the block event.
        match block_event {
            SkipSlot => Some((parent_block_root, parent_state)),
            ProduceBlock | NewSkipFork => {
                let proposer_idx = parent_state
                    .get_beacon_proposer_index(slot, self.spec())
                    .unwrap();
                let randao_reveal = self.randao_reveal(proposer_idx, slot, &parent_state);

                let (block, state) = self
                    .chain
                    .produce_block_on_state(parent_state, slot, randao_reveal)
                    .ok()?;
                let signed_block = block.sign(
                    sk(proposer_idx),
                    &state.fork,
                    state.genesis_validators_root,
                    self.spec(),
                );

                let block_root = self.chain.process_block(signed_block).ok()?;
                self.forks[chain_id] = block_root;

                // TODO: allow attestations to skipped slot
                if block_event == NewSkipFork {
                    self.forks.push(parent_block_root);
                }

                Some((block_root, state))
            }
        }
    }

    /// Generate attestations and supply them to fork choice and the op-pool.
    ///
    /// Return `None` if the attestations were impossible to create/apply.
    fn apply_attestation_event(
        &mut self,
        slot: Slot,
        head_block_root: Hash256,
        state: BeaconState<E>,
        attestation_event: AttestationEvent,
    ) -> Option<()> {
        for committee in state.get_beacon_committees_at_slot(slot).unwrap() {
            let mut attestation = self
                .chain
                .produce_unaggregated_attestation_for_block(
                    slot,
                    committee.index,
                    head_block_root,
                    Cow::Borrowed(&state),
                )
                .unwrap();

            for (i, &validator_index) in committee
                .committee
                .iter()
                .enumerate()
                .filter(|(i, _)| attestation_event.is_attester(*i))
            {
                attestation
                    .sign(
                        sk(validator_index),
                        i,
                        &state.fork,
                        state.genesis_validators_root,
                        self.spec(),
                    )
                    .unwrap();
            }

            let aggregator_index = committee
                .committee
                .iter()
                .enumerate()
                .filter(|(i, _)| attestation_event.is_attester(*i))
                .find(|(_, validator_index)| {
                    let selection_proof = SelectionProof::new::<E>(
                        slot,
                        sk(**validator_index),
                        &state.fork,
                        state.genesis_validators_root,
                        self.spec(),
                    );

                    selection_proof
                        .is_aggregator(committee.committee.len(), self.spec())
                        .unwrap_or(false)
                })
                .map(|(_, validator_index)| *validator_index)?;

            let signed_aggregate = SignedAggregateAndProof::from_aggregate(
                aggregator_index as u64,
                attestation,
                None,
                sk(aggregator_index),
                &state.fork,
                state.genesis_validators_root,
                self.spec(),
            );

            // Verifying the attestation may not succeed, particularly with forking, so we just
            // ignore failures and keep running.
            let verified_attestation =
                VerifiedAggregatedAttestation::verify(signed_aggregate, &self.chain).ok()?;

            self.chain
                .apply_attestation_to_fork_choice(&verified_attestation)
                .ok()?;
            self.chain
                .add_to_block_inclusion_pool(verified_attestation)
                .ok()?;
        }
        Some(())
    }

    /// Check invariants at each slot of the
    fn check_slot_invariants(&mut self) {
        self.check_finalization_linearity();
    }

    /// Check that the chain's finalized checkpoint is descended from the last finalized checkpoint.
    fn check_finalization_linearity(&mut self) {
        let new_checkpoint = self.head_info().finalized_checkpoint;
        self.last_finalized_checkpoint
            .replace(new_checkpoint)
            .map(|old_checkpoint| {
                assert!(new_checkpoint.epoch >= old_checkpoint.epoch);
                // TODO: map zero to genesis block root
                if !old_checkpoint.root.is_zero() && !new_checkpoint.root.is_zero() {
                    assert_eq!(
                        self.get_ancestor(
                            new_checkpoint.root,
                            old_checkpoint.epoch.start_slot(E::slots_per_epoch())
                        ),
                        Some(old_checkpoint.root)
                    );
                }
            });
    }

    /// Check invariants at the end of an execution.
    fn check_invariants(&self) {
        self.check_integrity_of_all_forks();
    }

    fn check_integrity_of_all_forks(&self) {
        for &head_block_root in &self.forks {
            if !self.chain.knows_head(&head_block_root.into()) {
                assert_eq!(self.chain.get_block(&head_block_root).unwrap(), None);
                continue;
            }

            self.check_block_root_iterators(head_block_root);
        }
    }

    /// Check the forwards and backwards block iterators from `head_block_root`.
    ///
    /// Return the vector of all block roots from genesis, in ascending order.
    fn check_block_root_iterators(&self, head_block_root: Hash256) -> Vec<(Hash256, Slot)> {
        // Block roots from the reverse iterator, but in ascending order.
        let mut rev_block_roots = self
            .chain
            .rev_iter_block_roots_from(head_block_root)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        rev_block_roots.reverse();

        // Ends at the head of the fork.
        let (last_root, last_slot) = rev_block_roots.last().unwrap().clone();
        assert_eq!(last_root, head_block_root);
        // Length equal to the number of slots plus 1.
        assert_eq!(rev_block_roots.len(), last_slot.as_usize() + 1);
        // Reaches genesis.
        assert_eq!(rev_block_roots.first().unwrap().1, 0);

        // Is equal to the forwards iterator.
        let head_block = self.chain.get_block(&head_block_root).unwrap().unwrap();
        assert_eq!(head_block.slot(), last_slot);
        let head_state = self
            .chain
            .get_state(&head_block.state_root(), Some(head_block.slot()))
            .unwrap()
            .unwrap();
        let forward_block_roots = HotColdDB::forwards_block_roots_iterator(
            self.chain.store.clone(),
            Slot::new(0),
            head_state,
            head_block_root,
            self.spec(),
        )
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();

        assert_eq!(rev_block_roots, forward_block_roots);

        forward_block_roots
    }

    fn randao_reveal(&self, validator_idx: usize, slot: Slot, state: &BeaconState<E>) -> Signature {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain = self.spec().get_domain(
            epoch,
            Domain::Randao,
            &state.fork,
            state.genesis_validators_root,
        );
        let message = epoch.signing_root(domain);
        Signature::new(message.as_bytes(), sk(validator_idx))
    }

    fn head_info(&self) -> HeadInfo {
        self.chain.head_info().unwrap()
    }

    fn spec(&self) -> &ChainSpec {
        &self.chain.spec
    }

    fn get_ancestor(&self, block_root: Hash256, ancestor_slot: Slot) -> Option<Hash256> {
        self.chain
            .fork_choice
            .read()
            .get_ancestor(block_root, ancestor_slot)
            .unwrap()
    }
}

/// Manually-written test case generators which generate starting material for the fuzzer.
impl Execution {
    pub fn linear_chain(num_slots: usize) -> Self {
        Self::long_skip(num_slots, 0, 0, 0xff)
    }

    pub fn long_skip(
        initial_length: usize,
        skip_length: usize,
        post_skip_length: usize,
        skip_attester_bitfield: u8,
    ) -> Self {
        let mut slot_events = vec![];

        // Skip slot 0
        slot_events.push(SlotEvent {
            chain_events: vec![ChainEvent::skip_slot()],
        });
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::full_participation()]
            };
            initial_length.saturating_sub(1)
        ]);
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent {
                    block_event: BlockEvent::SkipSlot,
                    attestation_event: AttestationEvent::new(skip_attester_bitfield),
                }]
            };
            skip_length
        ]);
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::full_participation()],
            };
            post_skip_length
        ]);
        Execution { slot_events }
    }

    /// Form two chains, which initially each share 50% of attestations, before all attestations
    /// switch to the main chain.
    pub fn transient_fork(
        initial_length: usize,
        fork_length: usize,
        post_fork_length: usize,
    ) -> Self {
        let mut slot_events = vec![];
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::full_participation()]
            };
            initial_length.checked_sub(1).unwrap()
        ]);
        slot_events.push(SlotEvent {
            chain_events: vec![ChainEvent {
                block_event: BlockEvent::NewSkipFork,
                attestation_event: AttestationEvent::new(0xff),
            }],
        });
        slot_events.extend(vec![
            SlotEvent {
                // Majority fork on chain 0 without the skip, half the attestations each.
                chain_events: vec![
                    ChainEvent {
                        block_event: BlockEvent::ProduceBlock,
                        attestation_event: AttestationEvent::new(0b01),
                    },
                    ChainEvent {
                        block_event: BlockEvent::ProduceBlock,
                        attestation_event: AttestationEvent::new(0b10),
                    },
                ],
            };
            fork_length
        ]);
        slot_events.extend(vec![
            SlotEvent {
                // Majority fork gets all the attestations.
                chain_events: vec![
                    ChainEvent {
                        block_event: BlockEvent::ProduceBlock,
                        attestation_event: AttestationEvent::new(0xff),
                    },
                    ChainEvent {
                        block_event: BlockEvent::ProduceBlock,
                        attestation_event: AttestationEvent::new(0b00),
                    },
                ],
            };
            post_fork_length
        ]);
        Execution { slot_events }
    }

    // TODO: implement post-hydra finalization
    pub fn hydra(fork_points: Vec<usize>) -> Self {
        // let total_forks = fork_points.len() + 1;
        let slot_events = std::iter::once(0)
            .chain(fork_points.into_iter())
            .tuple_windows()
            .enumerate()
            .flat_map(|(i, (n1, n2))| {
                let segment_length = n2.checked_sub(n1).unwrap();
                let num_forks = i + 1;
                // TODO: full participation is probably ill-advised
                vec![
                    SlotEvent {
                        chain_events: vec![ChainEvent::full_participation(); num_forks],
                    };
                    segment_length
                ]
            })
            .collect();
        Execution { slot_events }
    }
}

#[cfg(test)]
mod manual_execution {
    use super::*;
    use bincode::serialize_into;
    use std::fs::{create_dir_all, File};
    use std::path::Path;

    const OUTPUT_DIR: &str = "fuzz/manual_corpus";

    fn write_to_file(filename: &str, exec: &Execution) {
        create_dir_all(OUTPUT_DIR).unwrap();
        let mut f = File::create(Path::new(OUTPUT_DIR).join(filename)).unwrap();
        serialize_into(&mut f, exec).unwrap();
    }

    fn exec_test(name: &str, exec: Execution) -> Harness {
        let mut harness = Harness::new();
        write_to_file(name, &exec);
        assert!(exec.is_well_formed());
        harness.apply_execution(exec);
        harness
    }

    #[test]
    fn linear_chain_1() {
        let harness = exec_test(
            "linear_chain_1.bin",
            Execution::linear_chain(1 * E::slots_per_epoch() as usize),
        );
        let head_info = harness.chain.head_info().unwrap();
        assert_eq!(head_info.slot, Slot::new(E::slots_per_epoch() - 1));
    }

    #[test]
    fn linear_chain_4() {
        exec_test(
            "linear_chain_4.bin",
            Execution::linear_chain(4 * E::slots_per_epoch() as usize),
        );
    }

    #[test]
    fn linear_chain_5() {
        exec_test(
            "linear_chain_5.bin",
            Execution::linear_chain(5 * E::slots_per_epoch() as usize),
        );
    }

    #[test]
    fn long_skip_0_2_3_0xff() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "long_skip_0_2_3_0xff.bin",
            Execution::long_skip(0, 2 * slots_per_epoch, 3 * slots_per_epoch, 0xff),
        );
    }

    #[test]
    fn long_skip_0_2_3_0x00() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "long_skip_0_2_3_0x00.bin",
            Execution::long_skip(0, 2 * slots_per_epoch, 3 * slots_per_epoch, 0x00),
        );
    }

    #[test]
    fn long_skip_2_1_2() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "long_skip_2_1_2.bin",
            Execution::long_skip(
                2 * slots_per_epoch,
                1 * slots_per_epoch,
                2 * slots_per_epoch,
                0xff,
            ),
        );
    }

    #[test]
    fn long_skip_2_1_3() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "long_skip_2_1_3.bin",
            Execution::long_skip(
                2 * slots_per_epoch,
                1 * slots_per_epoch,
                3 * slots_per_epoch,
                0xff,
            ),
        );
    }

    #[test]
    fn transient_fork_1_2_3() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        let harness = exec_test(
            "transient_fork_1_2_3.bin",
            Execution::transient_fork(
                1 * slots_per_epoch - 1,
                2 * slots_per_epoch,
                3 * slots_per_epoch + 2,
            ),
        );
        let head_info = harness.chain.head_info().unwrap();
        assert_eq!(head_info.slot, Slot::from(6 * slots_per_epoch));
        assert_eq!(head_info.finalized_checkpoint.epoch, 4);
    }

    // As above but forking *after* the first block of the epoch.
    #[test]
    fn transient_fork_first_slot_1_2_3() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        let harness = exec_test(
            "transient_fork_first_slot_1_2_3.bin",
            Execution::transient_fork(
                1 * slots_per_epoch + 1,
                2 * slots_per_epoch,
                3 * slots_per_epoch,
            ),
        );
        let head_info = harness.chain.head_info().unwrap();
        assert_eq!(head_info.slot, Slot::from(6 * slots_per_epoch));
        assert_eq!(head_info.finalized_checkpoint.epoch, 4);
    }

    // Transient fork with no resolution
    #[test]
    fn transient_fork_1_5_0() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        let harness = exec_test(
            "transient_fork_1_5_0.bin",
            Execution::transient_fork(1 * slots_per_epoch, 5 * slots_per_epoch + 1, 0),
        );
        let head_info = harness.chain.head_info().unwrap();
        assert_eq!(head_info.slot, Slot::from(6 * slots_per_epoch));
        assert_eq!(head_info.finalized_checkpoint.epoch, 0);
    }

    // TODO: finish the hydra
    #[test]
    #[should_panic]
    fn hydra_five_forks() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "hydra_five_forks.bin",
            Execution::hydra(vec![
                slots_per_epoch,
                slots_per_epoch,
                2 * slots_per_epoch,
                5 * slots_per_epoch / 2,
                3 * slots_per_epoch,
            ]),
        );
    }
}
