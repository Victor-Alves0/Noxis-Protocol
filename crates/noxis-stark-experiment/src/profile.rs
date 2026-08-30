//! Versioned, code-level parameters for the executable STARK research setup.
//!
//! These descriptors make the P3 FRI/PCS choices reviewable in one place. They
//! are not Noxis protocol parameters, a selected verifier profile, or a wire
//! format. In particular, they do not stabilize Plonky3 proof serialization.

/// Code-level version of the executable research verifier descriptor.
pub const RESEARCH_STARK_VERIFIER_PROFILE_VERSION: u16 = 1;

/// Explicit parameters used to construct an executable hiding-FRI verifier.
///
/// The descriptor is intentionally limited to parameters represented by the
/// current Plonky3 construction. Field choice, extension degree, hash/PCS
/// types and dependency versions remain fixed by the crate source and lockfile
/// and must become explicit in a future protocol-level profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResearchStarkVerifierProfileV1 {
    name: &'static str,
    version: u16,
    fri_log_blowup: usize,
    fri_log_final_poly_len: usize,
    fri_max_log_arity: usize,
    fri_num_queries: usize,
    fri_commit_proof_of_work_bits: usize,
    fri_query_proof_of_work_bits: usize,
    num_random_codewords: usize,
}

impl ResearchStarkVerifierProfileV1 {
    /// Standard profile used by the P24 permutation, address, note and intent
    /// research relations.
    pub const STANDARD_P24: Self = Self {
        name: "noxis-research-stark-p24-standard-v1",
        version: RESEARCH_STARK_VERIFIER_PROFILE_VERSION,
        fri_log_blowup: 3,
        fri_log_final_poly_len: 0,
        fri_max_log_arity: 1,
        fri_num_queries: 32,
        fri_commit_proof_of_work_bits: 0,
        fri_query_proof_of_work_bits: 0,
        num_random_codewords: 4,
    };

    /// Higher-blowup profile required by the degree-ten full-depth membership
    /// and NXSM research AIRs.
    pub const HIGH_DEGREE_P24: Self = Self {
        name: "noxis-research-stark-p24-high-degree-v1",
        version: RESEARCH_STARK_VERIFIER_PROFILE_VERSION,
        fri_log_blowup: 4,
        fri_log_final_poly_len: 0,
        fri_max_log_arity: 1,
        fri_num_queries: 32,
        fri_commit_proof_of_work_bits: 0,
        fri_query_proof_of_work_bits: 0,
        num_random_codewords: 4,
    };

    /// Human-readable identifier for this code-level descriptor.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Version of this code-level descriptor.
    pub const fn version(self) -> u16 {
        self.version
    }

    /// FRI blowup exponent.
    pub const fn fri_log_blowup(self) -> usize {
        self.fri_log_blowup
    }

    /// FRI final-polynomial length exponent.
    pub const fn fri_log_final_poly_len(self) -> usize {
        self.fri_log_final_poly_len
    }

    /// Maximum FRI folding-arity exponent.
    pub const fn fri_max_log_arity(self) -> usize {
        self.fri_max_log_arity
    }

    /// Number of FRI queries.
    pub const fn fri_num_queries(self) -> usize {
        self.fri_num_queries
    }

    /// Proof-of-work bits required while committing.
    pub const fn fri_commit_proof_of_work_bits(self) -> usize {
        self.fri_commit_proof_of_work_bits
    }

    /// Proof-of-work bits required while querying.
    pub const fn fri_query_proof_of_work_bits(self) -> usize {
        self.fri_query_proof_of_work_bits
    }

    /// Random codewords added by the hiding PCS.
    pub const fn num_random_codewords(self) -> usize {
        self.num_random_codewords
    }
}

#[cfg(test)]
mod tests {
    use super::{RESEARCH_STARK_VERIFIER_PROFILE_VERSION, ResearchStarkVerifierProfileV1};

    #[test]
    fn research_profiles_are_explicit_and_distinct() {
        let standard = ResearchStarkVerifierProfileV1::STANDARD_P24;
        let high_degree = ResearchStarkVerifierProfileV1::HIGH_DEGREE_P24;

        assert_eq!(standard.version(), RESEARCH_STARK_VERIFIER_PROFILE_VERSION);
        assert_eq!(
            high_degree.version(),
            RESEARCH_STARK_VERIFIER_PROFILE_VERSION
        );
        assert_ne!(standard.name(), high_degree.name());
        assert_eq!(standard.fri_log_blowup(), 3);
        assert_eq!(high_degree.fri_log_blowup(), 4);
        assert_eq!(standard.fri_num_queries(), 32);
        assert_eq!(high_degree.fri_num_queries(), 32);
    }
}
