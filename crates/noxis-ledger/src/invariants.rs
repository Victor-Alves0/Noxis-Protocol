//! Canonicalization and transition preconditions for the public ledger.

use std::collections::HashSet;

use noxis_crypto::{CryptoSuite, ProofVerifier, TransferStatement, VerificationError};
use noxis_merkle::{MerkleError, MerkleTree};
use noxis_types::{Amount, AssetDefinition, AssetId, Commitment, Nullifier, TransactionId};

use crate::{
    LedgerError, LedgerSnapshot, LedgerSnapshotError, LedgerState, Mint, MintPolicy, MintStatement,
    Operation, Transaction, TransactionValidationContext, Transfer,
};

pub(crate) enum ValidatedTransition<'a> {
    Transfer(&'a Transfer),
    Mint {
        mint: &'a Mint,
        resulting_supply: Amount,
    },
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
        if !ensure_strictly_sorted(&spent_nullifiers) {
            return Err(LedgerSnapshotError::NullifiersNotStrictlySorted);
        }
        if !ensure_strictly_sorted(&accepted_transactions) {
            return Err(LedgerSnapshotError::TransactionsNotStrictlySorted);
        }
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
}

impl LedgerState {
    pub(crate) fn prepare_transition<'a>(
        &self,
        transaction: &'a Transaction,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
        validation_context: TransactionValidationContext,
    ) -> Result<ValidatedTransition<'a>, LedgerError> {
        let computed_state_id = self.state_id(validation_context.genesis_id);
        if computed_state_id != validation_context.state_id {
            return Err(LedgerError::ValidationStateIdMismatch {
                expected: computed_state_id,
                supplied: validation_context.state_id,
            });
        }
        self.ensure_new_transaction(transaction.id)?;
        match &transaction.operation {
            Operation::Transfer(transfer) => {
                self.validate_transfer(transaction.suite, transfer, verifier, validation_context)?;
                Ok(ValidatedTransition::Transfer(transfer))
            }
            Operation::Mint(mint) => Ok(ValidatedTransition::Mint {
                mint,
                resulting_supply: self.validate_mint(mint, mint_policy, validation_context)?,
            }),
        }
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
        (!self.accepted_transactions.contains(&id))
            .then_some(())
            .ok_or(LedgerError::DuplicateTransaction(id))
    }
    fn ensure_registered_asset(&self, asset_id: AssetId) -> Result<(), LedgerError> {
        self.assets
            .contains_key(&asset_id)
            .then_some(())
            .ok_or(LedgerError::UnknownAsset(asset_id))
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
}

fn ensure_strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}
fn ensure_non_empty<T>(items: &[T], label: &'static str) -> Result<(), LedgerError> {
    items
        .is_empty()
        .then_some(())
        .map_or(Ok(()), |_| Err(LedgerError::EmptyField(label)))
}
