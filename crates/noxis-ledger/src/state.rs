//! In-memory representation and read-only views of the public ledger state.

use std::collections::{HashMap, HashSet};

use noxis_crypto::StateAnchor;
use noxis_merkle::{InclusionProof, MerkleRoot, MerkleTree};
use noxis_types::{
    Amount, AssetDefinition, AssetId, Commitment, GenesisId, Nullifier, StateId, TransactionId,
};
use sha2::{Digest, Sha256};

use crate::LedgerError;

#[derive(Clone, Debug)]
pub struct LedgerState {
    pub(crate) assets: HashMap<AssetId, AssetDefinition>,
    pub(crate) commitments: HashSet<Commitment>,
    pub(crate) commitment_tree: MerkleTree,
    pub(crate) spent_nullifiers: HashSet<Nullifier>,
    pub(crate) issued_supply: HashMap<AssetId, Amount>,
    pub(crate) accepted_transactions: HashSet<TransactionId>,
}

/// A complete, canonical, read-only representation of one ledger state.
///
/// Collections that are sets or maps are strictly sorted. Commitment order is
/// deliberately retained because it defines the Merkle tree and membership
/// proof positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub(crate) tree_depth: u8,
    pub(crate) assets: Vec<AssetDefinition>,
    pub(crate) commitments: Vec<Commitment>,
    pub(crate) spent_nullifiers: Vec<Nullifier>,
    pub(crate) issued_supply: Vec<(AssetId, Amount)>,
    pub(crate) accepted_transactions: Vec<TransactionId>,
}

impl LedgerSnapshot {
    pub const fn tree_depth(&self) -> u8 {
        self.tree_depth
    }
    pub fn assets(&self) -> &[AssetDefinition] {
        &self.assets
    }
    /// Commitments in their original append/Merkle order.
    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }
    pub fn spent_nullifiers(&self) -> &[Nullifier] {
        &self.spent_nullifiers
    }
    pub fn issued_supply(&self) -> &[(AssetId, Amount)] {
        &self.issued_supply
    }
    pub fn accepted_transactions(&self) -> &[TransactionId] {
        &self.accepted_transactions
    }
}

impl LedgerState {
    /// Creates an empty ledger with a fixed commitment-tree depth.
    pub fn new(tree_depth: u8) -> Result<Self, LedgerError> {
        Ok(Self {
            assets: HashMap::new(),
            commitments: HashSet::new(),
            commitment_tree: MerkleTree::new(tree_depth).map_err(LedgerError::Merkle)?,
            spent_nullifiers: HashSet::new(),
            issued_supply: HashMap::new(),
            accepted_transactions: HashSet::new(),
        })
    }

    pub fn issued_supply(&self, asset_id: AssetId) -> Option<Amount> {
        self.issued_supply.get(&asset_id).copied()
    }
    pub fn contains_commitment(&self, commitment: Commitment) -> bool {
        self.commitments.contains(&commitment)
    }
    pub fn is_spent(&self, nullifier: Nullifier) -> bool {
        self.spent_nullifiers.contains(&nullifier)
    }
    /// Current cryptographic commitment to the ordered note set.
    pub fn merkle_root(&self) -> MerkleRoot {
        self.commitment_tree.root()
    }
    pub fn commitment_count(&self) -> usize {
        self.commitment_tree.len()
    }

    /// Exports a complete canonical state snapshot without exposing mutation.
    pub fn snapshot(&self) -> LedgerSnapshot {
        let mut assets: Vec<_> = self.assets.values().cloned().collect();
        assets.sort_unstable_by_key(|asset| asset.id);
        let commitments = self.commitment_tree.commitments().to_vec();
        let mut spent_nullifiers: Vec<_> = self.spent_nullifiers.iter().copied().collect();
        spent_nullifiers.sort_unstable();
        let mut issued_supply: Vec<_> = self
            .issued_supply
            .iter()
            .map(|(asset_id, amount)| (*asset_id, *amount))
            .collect();
        issued_supply.sort_unstable_by_key(|(asset_id, _)| *asset_id);
        let mut accepted_transactions: Vec<_> =
            self.accepted_transactions.iter().copied().collect();
        accepted_transactions.sort_unstable();
        LedgerSnapshot::from_canonical_parts(
            self.commitment_tree.depth(),
            assets,
            commitments,
            spent_nullifiers,
            issued_supply,
            accepted_transactions,
        )
        .expect("live ledger state always satisfies snapshot invariants")
    }

    /// Deterministic commitment to every public component managed by this ledger.
    pub fn state_id(&self, genesis_id: GenesisId) -> StateId {
        let mut hash = Sha256::new();
        hash.update(b"NOXIS/STATE/V2\0");
        hash.update(genesis_id.0);
        let root = self.merkle_root();
        hash.update([root.depth()]);
        hash.update(root.as_bytes());

        let mut assets: Vec<_> = self.assets.values().collect();
        assets.sort_unstable_by_key(|asset| asset.id);
        write_count(&mut hash, assets.len());
        for asset in assets {
            hash.update(asset.id.0);
            hash.update([match asset.kind {
                noxis_types::AssetKind::NativeBacked => 1,
                noxis_types::AssetKind::Synthetic => 2,
            }]);
            write_bytes(&mut hash, asset.ticker.as_bytes());
        }

        let mut supplies: Vec<_> = self.issued_supply.iter().collect();
        supplies.sort_unstable_by_key(|(asset_id, _)| **asset_id);
        write_count(&mut hash, supplies.len());
        for (asset_id, amount) in supplies {
            hash.update(asset_id.0);
            hash.update(amount.units().to_be_bytes());
        }

        let mut nullifiers: Vec<_> = self.spent_nullifiers.iter().collect();
        nullifiers.sort_unstable();
        write_count(&mut hash, nullifiers.len());
        for nullifier in nullifiers {
            hash.update(nullifier.0);
        }

        let mut transactions: Vec<_> = self.accepted_transactions.iter().collect();
        transactions.sort_unstable();
        write_count(&mut hash, transactions.len());
        for transaction in transactions {
            hash.update(transaction.0);
        }
        StateId::new(hash.finalize().into())
    }

    pub fn prove_commitment(&self, leaf_index: u32) -> Result<InclusionProof, LedgerError> {
        self.commitment_tree
            .prove(leaf_index)
            .map_err(LedgerError::Merkle)
    }

    pub(crate) fn state_anchor(&self) -> StateAnchor {
        let root = self.merkle_root();
        StateAnchor {
            root: root.as_bytes(),
            tree_depth: root.depth(),
        }
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new(32).expect("the documented default tree depth is valid")
    }
}

fn write_count(hash: &mut Sha256, count: usize) {
    let count = u32::try_from(count).expect("ledger state count is bounded by memory");
    hash.update(count.to_be_bytes());
}
fn write_bytes(hash: &mut Sha256, bytes: &[u8]) {
    write_count(hash, bytes.len());
    hash.update(bytes);
}
