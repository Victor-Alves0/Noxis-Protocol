//! Explicit offline migration from the post-state-only private store to v2.
//!
//! The source is opened through its v1 recovery path under the v1 writer lock.
//! The destination is a different, fresh v2 location. No historic receipt is
//! fabricated because v1 did not persist the information needed to do so.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use noxis_types::StateId;

use crate::{
    PrivateStateStoreError, PrivateStateStoreV1, PrivateSubmissionStoreError,
    PrivateSubmissionStoreV2,
};

/// Evidence returned after an offline copy has independently reopened the v2
/// target. It contains no transaction, proof or receipt identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSubmissionMigrationReceiptV1 {
    source_state_id: StateId,
    target_state_id: StateId,
}

impl PrivateSubmissionMigrationReceiptV1 {
    pub const fn source_state_id(self) -> StateId {
        self.source_state_id
    }
    pub const fn target_state_id(self) -> StateId {
        self.target_state_id
    }
}

/// Recovers a v1 source, creates a distinct v2 target with that state as its
/// authenticated base, then reopens the target before reporting success.
///
/// The target contains zero v2 receipt frames: v1 has no authoritative source
/// from which historic receipt facts or envelope IDs could be reconstructed.
/// The original v1 directory is never deleted, renamed or modified beyond the
/// v1 recovery behavior already selected by its own store.
pub fn migrate_private_state_store_v1_to_submission_store_v2(
    source_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> Result<PrivateSubmissionMigrationReceiptV1, PrivateSubmissionMigrationError> {
    let source_path = source_path.as_ref().to_path_buf();
    let target_path = target_path.as_ref().to_path_buf();
    if source_path == target_path {
        return Err(PrivateSubmissionMigrationError::SamePath(source_path));
    }
    let source =
        PrivateStateStoreV1::open(&source_path).map_err(PrivateSubmissionMigrationError::Source)?;
    let source_state = source.state().clone();
    let source_state_id = source_state.anchor().state_id();
    drop(source);

    let target =
        PrivateSubmissionStoreV2::initialize_with_authenticated_base(&target_path, source_state)
            .map_err(PrivateSubmissionMigrationError::Target)?;
    drop(target);

    let mut reopened = PrivateSubmissionStoreV2::open(&target_path)
        .map_err(PrivateSubmissionMigrationError::Target)?;
    let target_state_id = reopened.state().anchor().state_id();
    if target_state_id != source_state_id {
        return Err(PrivateSubmissionMigrationError::StateMismatch {
            source: source_state_id,
            target: target_state_id,
        });
    }
    if !reopened
        .submissions()
        .map_err(PrivateSubmissionMigrationError::Target)?
        .is_empty()
    {
        return Err(PrivateSubmissionMigrationError::UnexpectedTargetHistory);
    }
    Ok(PrivateSubmissionMigrationReceiptV1 {
        source_state_id,
        target_state_id,
    })
}

/// Migration failure leaves the source untouched by the migration operation;
/// any partial target remains for investigation and must not be reused.
#[derive(Debug)]
pub enum PrivateSubmissionMigrationError {
    SamePath(PathBuf),
    Source(PrivateStateStoreError),
    Target(PrivateSubmissionStoreError),
    StateMismatch { source: StateId, target: StateId },
    UnexpectedTargetHistory,
}

impl fmt::Display for PrivateSubmissionMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "private submission-store migration error: {self:?}"
        )
    }
}
impl std::error::Error for PrivateSubmissionMigrationError {}
