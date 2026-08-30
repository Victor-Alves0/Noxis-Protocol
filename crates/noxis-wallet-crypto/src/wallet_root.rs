//! Local-only wallet-root capability for deterministic recipient derivation.
//!
//! This type owns the 64-byte root only in process memory. It deliberately
//! exposes neither serialization nor byte extraction: a future dedicated
//! keystore must own every persistence and recovery boundary.

use rand_core::{OsRng, RngCore as _};
use zeroize::Zeroize;

use crate::{CandidatePrivateRecipientError, CandidatePrivateRecipientKeysetV1};

/// Secret root from which one local wallet session can derive multiple
/// recipient keysets. It has no persistence, backup or export API.
pub struct CandidateWalletRootV1([u8; 64]);

impl CandidateWalletRootV1 {
    /// Creates a fresh root with the operating-system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derives one recipient keyset for a particular public key epoch and
    /// wallet-local address index. The resulting recipient material is
    /// domain-separated from every other index and epoch.
    pub fn derive_recipient_keyset(
        &self,
        key_epoch: u64,
        address_index: u32,
    ) -> Result<CandidatePrivateRecipientKeysetV1, CandidatePrivateRecipientError> {
        CandidatePrivateRecipientKeysetV1::from_wallet_root(self, key_epoch, address_index)
    }

    pub(crate) const fn bytes(&self) -> &[u8; 64] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_bytes_for_test(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl Drop for CandidateWalletRootV1 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_root_reproduces_one_address_and_separates_address_indexes() {
        let root = CandidateWalletRootV1::from_bytes_for_test([0xA5; 64]);
        let first = root.derive_recipient_keyset(4, 0).unwrap();
        let repeated = root.derive_recipient_keyset(4, 0).unwrap();
        let next = root.derive_recipient_keyset(4, 1).unwrap();

        assert_eq!(
            first.recipient_commitment(),
            repeated.recipient_commitment()
        );
        assert_eq!(
            first.public_descriptor().payment_address().address_id(),
            repeated.public_descriptor().payment_address().address_id()
        );
        assert_ne!(first.recipient_commitment(), next.recipient_commitment());
        assert_ne!(
            first.public_descriptor().payment_address().address_id(),
            next.public_descriptor().payment_address().address_id()
        );
    }
}
