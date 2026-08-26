//! Deterministic state-transition engine for the Noxis research ledger.
//!
//! The engine validates public invariants and delegates privacy/conservation proofs
//! to an injected verifier. It contains no network, database or custody code.

use std::collections::{HashMap, HashSet};
use std::fmt;

use noxis_crypto::{
    CryptoSuite, Proof, ProofVerifier, StateAnchor, TransferStatement, VerificationError,
};
use noxis_merkle::{InclusionProof, MerkleError, MerkleRoot, MerkleTree};
use noxis_types::{
    Amount, AssetDefinition, AssetId, Commitment, GenesisId, MintPolicyId, Nullifier,
    ProofVerifierId, StateId, TransactionId, TransactionIntentId, ValidationContextId,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub id: TransactionId,
    pub suite: CryptoSuite,
    pub operation: Operation,
}

/// Immutable deployment and intent bindings supplied when a transition is
/// evaluated. These fields are carried into every transfer-proof and
/// mint-authorization statement so an otherwise valid proof cannot be
/// interpreted under another ledger's genesis, rule set, intent, or state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionValidationContext {
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub transaction_intent_id: TransactionIntentId,
    pub state_id: StateId,
}

impl TransactionValidationContext {
    pub const fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        transaction_intent_id: TransactionIntentId,
        state_id: StateId,
    ) -> Self {
        Self {
            genesis_id,
            validation_context_id,
            transaction_intent_id,
            state_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    Transfer(Transfer),
    Mint(Mint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub asset_id: AssetId,
    pub input_nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<Commitment>,
    pub proof: Proof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mint {
    pub asset_id: AssetId,
    pub amount: Amount,
    pub output_commitments: Vec<Commitment>,
    /// Opaque policy-specific authorization payload; it is never interpreted by the ledger.
    pub authorization: Vec<u8>,
}

/// The complete public issuance request a [`MintPolicy`] must authorize.
///
/// The policy receives this statement separately from the opaque authorization
/// envelope so a future signature, bridge attestation, or collateral proof can
/// bind all consensus-relevant issuance details without parsing transaction
/// wire bytes. `issued_supply_before` and `state_anchor` prevent an approval
/// from silently being interpreted against another point in the same ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintStatement {
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub transaction_intent_id: TransactionIntentId,
    pub state_id: StateId,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub output_commitments: Vec<Commitment>,
    pub state_anchor: StateAnchor,
    pub issued_supply_before: Option<Amount>,
}

pub trait MintPolicy: Send + Sync {
    /// Stable public identity of this policy's non-secret configuration and rules.
    fn mint_policy_id(&self) -> MintPolicyId;

    /// Determines whether this complete issuance statement is authorized.
    ///
    /// The `authorization` bytes are opaque to the ledger and must be
    /// interpreted only by the concrete policy. The policy must bind its
    /// decision to every relevant field in `statement`; accepting a signature
    /// or external attestation that omits these fields is unsafe.
    fn authorize(
        &self,
        statement: &MintStatement,
        authorization: &[u8],
    ) -> Result<(), MintAuthorizationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenyAllMints;

impl MintPolicy for DenyAllMints {
    fn mint_policy_id(&self) -> MintPolicyId {
        MintPolicyId::new([0; 32])
    }

    fn authorize(
        &self,
        _statement: &MintStatement,
        _authorization: &[u8],
    ) -> Result<(), MintAuthorizationError> {
        Err(MintAuthorizationError::Denied)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MintAuthorizationError {
    Denied,
}

impl fmt::Display for MintAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mint authorization was denied")
    }
}

impl std::error::Error for MintAuthorizationError {}

#[derive(Clone, Debug)]
pub struct LedgerState {
    assets: HashMap<AssetId, AssetDefinition>,
    commitments: HashSet<Commitment>,
    commitment_tree: MerkleTree,
    spent_nullifiers: HashSet<Nullifier>,
    issued_supply: HashMap<AssetId, Amount>,
    accepted_transactions: HashSet<TransactionId>,
}

/// A complete, canonical, read-only representation of one ledger state.
///
/// Collections that are sets or maps are strictly sorted. Commitment order is
/// deliberately retained because it defines the Merkle tree and membership
/// proof positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    tree_depth: u8,
    assets: Vec<AssetDefinition>,
    commitments: Vec<Commitment>,
    spent_nullifiers: Vec<Nullifier>,
    issued_supply: Vec<(AssetId, Amount)>,
    accepted_transactions: Vec<TransactionId>,
}

impl LedgerSnapshot {
    /// Validates and constructs canonical snapshot parts from a decoder.
    pub fn from_canonical_parts(
        tree_depth: u8,
        assets: Vec<AssetDefinition>,
        commitments: Vec<Commitment>,
        spent_nullifiers: Vec<Nullifier>,
        issued_supply: Vec<(AssetId, Amount)>,
        accepted_transactions: Vec<TransactionId>,
    ) -> Result<Self, LedgerSnapshotError> {
        let mut canonical_assets = Vec::with_capacity(assets.len());
        let mut prior_asset_id = None;
        for (index, asset) in assets.into_iter().enumerate() {
            if prior_asset_id.is_some_and(|previous| previous >= asset.id) {
                return Err(LedgerSnapshotError::AssetsNotStrictlySorted { index });
            }
            let canonical = AssetDefinition::new(asset.id, asset.ticker, asset.kind)
                .map_err(|source| LedgerSnapshotError::InvalidAsset { index, source })?;
            prior_asset_id = Some(canonical.id);
            canonical_assets.push(canonical);
        }

        let mut tree = MerkleTree::new(tree_depth).map_err(LedgerSnapshotError::Merkle)?;
        let mut commitment_set = HashSet::with_capacity(commitments.len());
        for commitment in &commitments {
            if !commitment_set.insert(*commitment) {
                return Err(LedgerSnapshotError::DuplicateCommitment(*commitment));
            }
            tree.append(*commitment)
                .map_err(LedgerSnapshotError::Merkle)?;
        }

        ensure_strictly_sorted(&spent_nullifiers)
            .then_some(())
            .ok_or(LedgerSnapshotError::NullifiersNotStrictlySorted)?;
        ensure_strictly_sorted(&accepted_transactions)
            .then_some(())
            .ok_or(LedgerSnapshotError::TransactionsNotStrictlySorted)?;

        let asset_ids: HashSet<_> = canonical_assets.iter().map(|asset| asset.id).collect();
        let mut prior_supply_asset = None;
        for (index, (asset_id, _)) in issued_supply.iter().enumerate() {
            if prior_supply_asset.is_some_and(|previous| previous >= *asset_id) {
                return Err(LedgerSnapshotError::SupplyNotStrictlySorted { index });
            }
            if !asset_ids.contains(asset_id) {
                return Err(LedgerSnapshotError::SupplyForUnknownAsset(*asset_id));
            }
            prior_supply_asset = Some(*asset_id);
        }

        Ok(Self {
            tree_depth,
            assets: canonical_assets,
            commitments,
            spent_nullifiers,
            issued_supply,
            accepted_transactions,
        })
    }

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

    pub fn register_asset(&mut self, asset: AssetDefinition) -> Result<(), LedgerError> {
        if self.assets.contains_key(&asset.id) {
            return Err(LedgerError::AssetAlreadyRegistered(asset.id));
        }
        self.assets.insert(asset.id, asset);
        Ok(())
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

    /// Reconstructs a ledger only from a validated canonical snapshot.
    pub fn from_snapshot(snapshot: LedgerSnapshot) -> Result<Self, LedgerSnapshotError> {
        let snapshot = LedgerSnapshot::from_canonical_parts(
            snapshot.tree_depth,
            snapshot.assets,
            snapshot.commitments,
            snapshot.spent_nullifiers,
            snapshot.issued_supply,
            snapshot.accepted_transactions,
        )?;
        let mut state = Self::new(snapshot.tree_depth).map_err(LedgerSnapshotError::Ledger)?;
        for asset in snapshot.assets {
            state
                .register_asset(asset)
                .map_err(LedgerSnapshotError::Ledger)?;
        }
        for commitment in snapshot.commitments {
            state
                .commitment_tree
                .append(commitment)
                .map_err(LedgerSnapshotError::Merkle)?;
            state.commitments.insert(commitment);
        }
        state.spent_nullifiers.extend(snapshot.spent_nullifiers);
        state.issued_supply.extend(snapshot.issued_supply);
        state
            .accepted_transactions
            .extend(snapshot.accepted_transactions);
        Ok(state)
    }

    /// Returns a deterministic, domain-separated commitment to all public
    /// state managed by this ledger implementation.
    ///
    /// The caller-provided genesis identity is committed first, so equivalent
    /// mutable states from different deployments cannot share a state ID.
    ///
    /// This remains a local durable-state identity, not network consensus
    /// finality or an external-asset proof.
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

    /// Returns a public membership proof for an occupied commitment position.
    pub fn prove_commitment(&self, leaf_index: u32) -> Result<InclusionProof, LedgerError> {
        self.commitment_tree
            .prove(leaf_index)
            .map_err(LedgerError::Merkle)
    }

    /// Applies a transition only after every validation has passed.
    pub fn apply(
        &mut self,
        transaction: &Transaction,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
        validation_context: TransactionValidationContext,
    ) -> Result<(), LedgerError> {
        let computed_state_id = self.state_id(validation_context.genesis_id);
        if computed_state_id != validation_context.state_id {
            return Err(LedgerError::ValidationStateIdMismatch {
                expected: computed_state_id,
                supplied: validation_context.state_id,
            });
        }
        self.ensure_new_transaction(transaction.id)?;
        let next_minted_supply = match &transaction.operation {
            Operation::Transfer(transfer) => {
                self.validate_transfer(transaction.suite, transfer, verifier, validation_context)?;
                None
            }
            Operation::Mint(mint) => {
                Some(self.validate_mint(mint, mint_policy, validation_context)?)
            }
        };

        match &transaction.operation {
            Operation::Transfer(transfer) => {
                self.append_commitments(&transfer.output_commitments)?;
                self.spent_nullifiers
                    .extend(transfer.input_nullifiers.iter().copied());
            }
            Operation::Mint(mint) => {
                self.append_commitments(&mint.output_commitments)?;
                if let Some(total) = next_minted_supply {
                    self.issued_supply.insert(mint.asset_id, total);
                }
            }
        }
        self.accepted_transactions.insert(transaction.id);
        Ok(())
    }

    fn validate_transfer(
        &self,
        suite: CryptoSuite,
        transfer: &Transfer,
        verifier: &dyn ProofVerifier,
        validation_context: TransactionValidationContext,
    ) -> Result<(), LedgerError> {
        self.ensure_registered_asset(transfer.asset_id)?;
        ensure_non_empty(&transfer.input_nullifiers, "input nullifiers")?;
        self.ensure_unique_nullifiers(&transfer.input_nullifiers)?;
        self.ensure_new_commitments(&transfer.output_commitments)?;

        let statement = TransferStatement {
            genesis_id: validation_context.genesis_id,
            validation_context_id: validation_context.validation_context_id,
            transaction_intent_id: validation_context.transaction_intent_id,
            state_id: validation_context.state_id,
            asset_id: transfer.asset_id,
            input_nullifiers: transfer.input_nullifiers.clone(),
            output_commitments: transfer.output_commitments.clone(),
            state_anchor: self.state_anchor(),
        };
        if transfer.proof.suite_version != suite.version {
            return Err(LedgerError::Proof(VerificationError::UnsupportedSuite));
        }
        verifier
            .verify_transfer(&statement, &transfer.proof)
            .map_err(LedgerError::Proof)
    }

    fn validate_mint(
        &self,
        mint: &Mint,
        mint_policy: &dyn MintPolicy,
        validation_context: TransactionValidationContext,
    ) -> Result<Amount, LedgerError> {
        self.ensure_registered_asset(mint.asset_id)?;
        self.ensure_new_commitments(&mint.output_commitments)?;
        let issued_supply_before = self.issued_supply.get(&mint.asset_id).copied();
        let statement = MintStatement {
            genesis_id: validation_context.genesis_id,
            validation_context_id: validation_context.validation_context_id,
            transaction_intent_id: validation_context.transaction_intent_id,
            state_id: validation_context.state_id,
            asset_id: mint.asset_id,
            amount: mint.amount,
            output_commitments: mint.output_commitments.clone(),
            state_anchor: self.state_anchor(),
            issued_supply_before,
        };
        mint_policy
            .authorize(&statement, &mint.authorization)
            .map_err(LedgerError::MintAuthorization)?;
        issued_supply_before
            .map_or(Some(mint.amount), |current| {
                current.checked_add(mint.amount)
            })
            .ok_or(LedgerError::SupplyOverflow(mint.asset_id))
    }

    fn ensure_new_transaction(&self, id: TransactionId) -> Result<(), LedgerError> {
        if self.accepted_transactions.contains(&id) {
            Err(LedgerError::DuplicateTransaction(id))
        } else {
            Ok(())
        }
    }

    fn ensure_registered_asset(&self, asset_id: AssetId) -> Result<(), LedgerError> {
        if self.assets.contains_key(&asset_id) {
            Ok(())
        } else {
            Err(LedgerError::UnknownAsset(asset_id))
        }
    }

    fn ensure_unique_nullifiers(&self, nullifiers: &[Nullifier]) -> Result<(), LedgerError> {
        let mut seen = HashSet::new();
        for nullifier in nullifiers {
            if !seen.insert(*nullifier) || self.spent_nullifiers.contains(nullifier) {
                return Err(LedgerError::NullifierAlreadySpent(*nullifier));
            }
        }
        Ok(())
    }

    fn ensure_new_commitments(&self, commitments: &[Commitment]) -> Result<(), LedgerError> {
        ensure_non_empty(commitments, "output commitments")?;
        let mut seen = HashSet::new();
        for commitment in commitments {
            if !seen.insert(*commitment) || self.commitments.contains(commitment) {
                return Err(LedgerError::CommitmentAlreadyExists(*commitment));
            }
        }
        let resulting_count = self
            .commitment_tree
            .len()
            .checked_add(commitments.len())
            .ok_or(LedgerError::Merkle(MerkleError::IndexOverflow))?;
        if resulting_count > self.commitment_tree.capacity() {
            return Err(LedgerError::Merkle(MerkleError::TreeFull {
                capacity: self.commitment_tree.capacity(),
            }));
        }
        Ok(())
    }

    fn append_commitments(&mut self, commitments: &[Commitment]) -> Result<(), LedgerError> {
        for commitment in commitments {
            self.commitment_tree
                .append(*commitment)
                .map_err(LedgerError::Merkle)?;
        }
        self.commitments.extend(commitments.iter().copied());
        Ok(())
    }

    fn state_anchor(&self) -> StateAnchor {
        let root = self.merkle_root();
        StateAnchor {
            root: root.as_bytes(),
            tree_depth: root.depth(),
        }
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

fn ensure_strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

impl Default for LedgerState {
    fn default() -> Self {
        // This is a local-development default. A real network fixes this in its
        // genesis configuration and never changes it per node.
        Self::new(32).expect("the documented default tree depth is valid")
    }
}

fn ensure_non_empty<T>(items: &[T], label: &'static str) -> Result<(), LedgerError> {
    if items.is_empty() {
        Err(LedgerError::EmptyField(label))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    AssetAlreadyRegistered(AssetId),
    UnknownAsset(AssetId),
    DuplicateTransaction(TransactionId),
    NullifierAlreadySpent(Nullifier),
    CommitmentAlreadyExists(Commitment),
    EmptyField(&'static str),
    SupplyOverflow(AssetId),
    ValidationStateIdMismatch {
        expected: StateId,
        supplied: StateId,
    },
    Merkle(MerkleError),
    MintAuthorization(MintAuthorizationError),
    Proof(VerificationError),
}

/// A reason a purported complete ledger snapshot is not canonical or safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerSnapshotError {
    Merkle(MerkleError),
    Ledger(LedgerError),
    AssetsNotStrictlySorted {
        index: usize,
    },
    InvalidAsset {
        index: usize,
        source: noxis_types::AssetError,
    },
    DuplicateCommitment(Commitment),
    NullifiersNotStrictlySorted,
    SupplyNotStrictlySorted {
        index: usize,
    },
    SupplyForUnknownAsset(AssetId),
    TransactionsNotStrictlySorted,
}

impl fmt::Display for LedgerSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Merkle(error) => write!(formatter, "invalid snapshot Merkle tree: {error}"),
            Self::Ledger(error) => write!(formatter, "invalid snapshot ledger state: {error}"),
            Self::AssetsNotStrictlySorted { index } => {
                write!(
                    formatter,
                    "snapshot assets are not strictly sorted at index {index}"
                )
            }
            Self::InvalidAsset { index, source } => {
                write!(formatter, "snapshot asset {index} is invalid: {source}")
            }
            Self::DuplicateCommitment(commitment) => {
                write!(formatter, "snapshot repeats commitment {commitment}")
            }
            Self::NullifiersNotStrictlySorted => {
                formatter.write_str("snapshot nullifiers are not strictly sorted")
            }
            Self::SupplyNotStrictlySorted { index } => {
                write!(
                    formatter,
                    "snapshot supply is not strictly sorted at index {index}"
                )
            }
            Self::SupplyForUnknownAsset(asset_id) => {
                write!(formatter, "snapshot supply names unknown asset {asset_id}")
            }
            Self::TransactionsNotStrictlySorted => {
                formatter.write_str("snapshot transaction IDs are not strictly sorted")
            }
        }
    }
}

impl std::error::Error for LedgerSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Merkle(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::InvalidAsset { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssetAlreadyRegistered(asset) => {
                write!(formatter, "asset {asset} is already registered")
            }
            Self::UnknownAsset(asset) => write!(formatter, "asset {asset} is not registered"),
            Self::DuplicateTransaction(transaction) => {
                write!(formatter, "transaction {transaction} was already accepted")
            }
            Self::NullifierAlreadySpent(nullifier) => {
                write!(formatter, "nullifier {nullifier} was already spent")
            }
            Self::CommitmentAlreadyExists(commitment) => {
                write!(formatter, "commitment {commitment} already exists")
            }
            Self::EmptyField(label) => write!(formatter, "{label} cannot be empty"),
            Self::SupplyOverflow(asset) => {
                write!(formatter, "issued supply overflow for asset {asset}")
            }
            Self::ValidationStateIdMismatch { .. } => formatter.write_str(
                "transaction validation context does not identify the current ledger state",
            ),
            Self::Merkle(error) => error.fmt(formatter),
            Self::MintAuthorization(error) => error.fmt(formatter),
            Self::Proof(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LedgerError {}

#[cfg(test)]
mod tests {
    use noxis_types::AssetKind;

    use super::*;

    const ASSET: AssetId = AssetId::new([1; 32]);

    struct TestVerifier;
    impl ProofVerifier for TestVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    struct ContextCheckingVerifier;

    impl ProofVerifier for ContextCheckingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            assert_eq!(statement.genesis_id, GenesisId::new([40; 32]));
            assert_eq!(
                statement.validation_context_id,
                ValidationContextId::new([41; 32])
            );
            assert_eq!(
                statement.transaction_intent_id,
                TransactionIntentId::new([42; 32])
            );
            assert_eq!(
                statement.state_id,
                state().state_id(GenesisId::new([40; 32]))
            );
            Ok(())
        }
    }

    struct TestMintPolicy;
    impl MintPolicy for TestMintPolicy {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([3; 32])
        }

        fn authorize(
            &self,
            _statement: &MintStatement,
            authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            if authorization == b"test-authorized" {
                Ok(())
            } else {
                Err(MintAuthorizationError::Denied)
            }
        }
    }

    struct ContextCheckingMintPolicy;

    impl MintPolicy for ContextCheckingMintPolicy {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([3; 32])
        }

        fn authorize(
            &self,
            statement: &MintStatement,
            authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            assert_eq!(statement.genesis_id, GenesisId::new([40; 32]));
            assert_eq!(
                statement.validation_context_id,
                ValidationContextId::new([41; 32])
            );
            assert_eq!(
                statement.transaction_intent_id,
                TransactionIntentId::new([42; 32])
            );
            assert_eq!(
                statement.state_id,
                state().state_id(GenesisId::new([40; 32]))
            );
            assert_eq!(statement.asset_id, ASSET);
            assert_eq!(statement.amount, Amount::new(100).unwrap());
            assert_eq!(statement.output_commitments, vec![Commitment::new([4; 32])]);
            assert_eq!(statement.issued_supply_before, None);
            assert_eq!(statement.state_anchor.tree_depth, 32);
            assert_eq!(authorization, b"test-authorized");
            Ok(())
        }
    }

    fn state() -> LedgerState {
        let mut state = LedgerState::default();
        state
            .register_asset(
                AssetDefinition::new(ASSET, "USDX", noxis_types::AssetKind::Synthetic).unwrap(),
            )
            .unwrap();
        state
    }

    fn transfer(id: u8, nullifier: u8, commitment: u8) -> Transaction {
        Transaction {
            id: TransactionId::new([id; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: ASSET,
                input_nullifiers: vec![Nullifier::new([nullifier; 32])],
                output_commitments: vec![Commitment::new([commitment; 32])],
                proof: Proof {
                    suite_version: 1,
                    bytes: vec![1],
                },
            }),
        }
    }

    fn test_context(state: &LedgerState) -> TransactionValidationContext {
        let genesis_id = GenesisId::new([40; 32]);
        TransactionValidationContext::new(
            genesis_id,
            ValidationContextId::new([41; 32]),
            TransactionIntentId::new([42; 32]),
            state.state_id(genesis_id),
        )
    }

    fn apply_with_test_context<V: ProofVerifier, P: MintPolicy>(
        state: &mut LedgerState,
        transaction: &Transaction,
        verifier: &V,
        mint_policy: &P,
    ) -> Result<(), LedgerError> {
        let context = test_context(state);
        state.apply(transaction, verifier, mint_policy, context)
    }

    #[test]
    fn a_nullifier_can_only_be_spent_once() {
        let mut state = state();
        apply_with_test_context(&mut state, &transfer(1, 9, 5), &TestVerifier, &DenyAllMints)
            .unwrap();
        let error =
            apply_with_test_context(&mut state, &transfer(2, 9, 6), &TestVerifier, &DenyAllMints)
                .unwrap_err();
        assert_eq!(
            error,
            LedgerError::NullifierAlreadySpent(Nullifier::new([9; 32]))
        );
    }

    #[test]
    fn a_commitment_cannot_be_reintroduced() {
        let mut state = state();
        apply_with_test_context(&mut state, &transfer(1, 8, 5), &TestVerifier, &DenyAllMints)
            .unwrap();
        let error =
            apply_with_test_context(&mut state, &transfer(2, 7, 5), &TestVerifier, &DenyAllMints)
                .unwrap_err();
        assert_eq!(
            error,
            LedgerError::CommitmentAlreadyExists(Commitment::new([5; 32]))
        );
    }

    #[test]
    fn transfer_proof_statement_carries_deployment_and_intent_bindings() {
        let mut state = state();
        apply_with_test_context(
            &mut state,
            &transfer(1, 8, 5),
            &ContextCheckingVerifier,
            &DenyAllMints,
        )
        .unwrap();
    }

    #[test]
    fn rejects_a_validation_context_for_a_different_pre_transition_state() {
        let mut state = state();
        let wrong_context = TransactionValidationContext::new(
            GenesisId::new([40; 32]),
            ValidationContextId::new([41; 32]),
            TransactionIntentId::new([42; 32]),
            StateId::new([99; 32]),
        );
        assert!(matches!(
            state.apply(
                &transfer(1, 8, 5),
                &TestVerifier,
                &DenyAllMints,
                wrong_context,
            ),
            Err(LedgerError::ValidationStateIdMismatch { .. })
        ));
    }

    #[test]
    fn minting_is_rejected_without_explicit_authorization() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([3; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([3; 32])],
                authorization: vec![],
            }),
        };
        assert_eq!(
            apply_with_test_context(&mut state, &mint, &TestVerifier, &DenyAllMints),
            Err(LedgerError::MintAuthorization(
                MintAuthorizationError::Denied
            ))
        );
        assert_eq!(state.issued_supply(ASSET), None);
    }

    #[test]
    fn authorized_mint_updates_supply_once() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([4; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([4; 32])],
                authorization: b"test-authorized".to_vec(),
            }),
        };
        apply_with_test_context(&mut state, &mint, &TestVerifier, &TestMintPolicy).unwrap();
        assert_eq!(state.issued_supply(ASSET).unwrap().units(), 100);
        assert!(state.contains_commitment(Commitment::new([4; 32])));
    }

    #[test]
    fn mint_policy_receives_a_complete_deployment_bound_issuance_statement() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([4; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([4; 32])],
                authorization: b"test-authorized".to_vec(),
            }),
        };
        apply_with_test_context(&mut state, &mint, &TestVerifier, &ContextCheckingMintPolicy)
            .unwrap();
    }

    #[test]
    fn equivalent_state_has_same_identity_and_transition_changes_it() {
        let genesis_id = GenesisId::new([42; 32]);
        let initial = state();
        let initial_id = initial.state_id(genesis_id);
        assert_eq!(initial_id, state().state_id(genesis_id));
        assert_ne!(initial_id, state().state_id(GenesisId::new([43; 32])));

        let mut changed = state();
        apply_with_test_context(
            &mut changed,
            &transfer(5, 6, 7),
            &TestVerifier,
            &DenyAllMints,
        )
        .unwrap();
        assert_ne!(initial_id, changed.state_id(genesis_id));
        assert_eq!(changed.state_id(genesis_id), changed.state_id(genesis_id));
    }

    #[test]
    fn canonical_snapshot_restores_every_observable_state_component() {
        let genesis_id = GenesisId::new([55; 32]);
        let mut original = state();
        apply_with_test_context(
            &mut original,
            &transfer(1, 9, 5),
            &TestVerifier,
            &DenyAllMints,
        )
        .unwrap();
        let snapshot = original.snapshot();
        let restored = LedgerState::from_snapshot(snapshot).unwrap();

        assert_eq!(restored.merkle_root(), original.merkle_root());
        assert_eq!(restored.state_id(genesis_id), original.state_id(genesis_id));
        assert!(restored.is_spent(Nullifier::new([9; 32])));
        assert!(restored.contains_commitment(Commitment::new([5; 32])));
        let proof = restored.prove_commitment(0).unwrap();
        assert!(
            MerkleTree::verify(restored.merkle_root(), Commitment::new([5; 32]), &proof).unwrap()
        );
    }

    #[test]
    fn snapshot_parts_reject_noncanonical_collections_before_restoring() {
        let first =
            AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap();
        let second =
            AssetDefinition::new(AssetId::new([1; 32]), "EURX", AssetKind::Synthetic).unwrap();
        assert!(matches!(
            LedgerSnapshot::from_canonical_parts(
                4,
                vec![first, second],
                vec![],
                vec![],
                vec![],
                vec![]
            ),
            Err(LedgerSnapshotError::AssetsNotStrictlySorted { index: 1 })
        ));

        let asset = AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic).unwrap();
        assert!(matches!(
            LedgerSnapshot::from_canonical_parts(
                4,
                vec![asset],
                vec![Commitment::new([4; 32]), Commitment::new([4; 32])],
                vec![],
                vec![],
                vec![],
            ),
            Err(LedgerSnapshotError::DuplicateCommitment(_))
        ));
    }
}
