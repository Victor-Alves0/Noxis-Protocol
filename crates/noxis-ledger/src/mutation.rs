//! The only ledger operations that alter public state after validation.

use noxis_crypto::ProofVerifier;
use noxis_types::{AssetDefinition, Commitment};

use crate::invariants::ValidatedTransition;
use crate::{
    LedgerError, LedgerSnapshot, LedgerSnapshotError, LedgerState, MintPolicy, Transaction,
    TransactionValidationContext,
};

impl LedgerState {
    pub fn register_asset(&mut self, asset: AssetDefinition) -> Result<(), LedgerError> {
        if self.assets.contains_key(&asset.id) {
            return Err(LedgerError::AssetAlreadyRegistered(asset.id));
        }
        self.assets.insert(asset.id, asset);
        Ok(())
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

    /// Validates a transaction completely, then commits the already-validated plan.
    pub fn apply(
        &mut self,
        transaction: &Transaction,
        verifier: &dyn ProofVerifier,
        mint_policy: &dyn MintPolicy,
        validation_context: TransactionValidationContext,
    ) -> Result<(), LedgerError> {
        let transition =
            self.prepare_transition(transaction, verifier, mint_policy, validation_context)?;
        self.commit_transition(transaction.id, transition)
    }

    fn commit_transition(
        &mut self,
        transaction_id: noxis_types::TransactionId,
        transition: ValidatedTransition<'_>,
    ) -> Result<(), LedgerError> {
        match transition {
            ValidatedTransition::Transfer(transfer) => {
                self.append_commitments(&transfer.output_commitments)?;
                self.spent_nullifiers
                    .extend(transfer.input_nullifiers.iter().copied());
            }
            ValidatedTransition::Mint {
                mint,
                resulting_supply,
            } => {
                self.append_commitments(&mint.output_commitments)?;
                self.issued_supply.insert(mint.asset_id, resulting_supply);
            }
        }
        self.accepted_transactions.insert(transaction_id);
        Ok(())
    }

    fn append_commitments(&mut self, commitments: &[Commitment]) -> Result<(), LedgerError> {
        // Validation already checks capacity. Building the next tree separately
        // makes the all-or-nothing boundary explicit even if a future Merkle
        // implementation adds another fallible condition.
        let mut next_tree = self.commitment_tree.clone();
        for commitment in commitments {
            next_tree.append(*commitment).map_err(LedgerError::Merkle)?;
        }
        self.commitment_tree = next_tree;
        self.commitments.extend(commitments.iter().copied());
        Ok(())
    }
}
