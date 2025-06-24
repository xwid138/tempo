//! Cryptographic providers for signing and verification

use malachitebft_core_types::{
    SignedExtension, SignedProposal, SignedProposalPart, SignedVote, SigningProvider, SigningScheme,
};
pub use malachitebft_signing_ed25519::{PrivateKey, PublicKey, Signature};

use crate::context::{BaseProposal, BaseProposalPart, BaseVote, MalachiteContext};
use malachitebft_core_types::{Height as MalachiteHeight, NilOrVal, VoteType};

/// Ed25519 signing provider for Malachite consensus
#[derive(Debug, Clone)]
pub struct Ed25519Provider {
    private_key: PrivateKey,
}

impl PartialEq for Ed25519Provider {
    fn eq(&self, other: &Self) -> bool {
        // Compare public keys instead of private keys
        self.public_key() == other.public_key()
    }
}

impl Eq for Ed25519Provider {}

impl Ed25519Provider {
    /// Create a new provider with a private key
    pub fn new(private_key: PrivateKey) -> Self {
        Self { private_key }
    }

    /// Create a new provider with a default/test key
    pub fn new_test() -> Self {
        let private_key = PrivateKey::generate(rand::thread_rng());
        Self::new(private_key)
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    /// Get the private key reference
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Sign raw bytes
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.private_key.sign(data)
    }

    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

impl Default for Ed25519Provider {
    fn default() -> Self {
        Self::new_test()
    }
}

impl SigningScheme for Ed25519Provider {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type DecodingError = std::io::Error;

    fn decode_signature(bytes: &[u8]) -> Result<Self::Signature, Self::DecodingError> {
        if bytes.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature length",
            ));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);
        Ok(Signature::from_bytes(sig_bytes))
    }

    fn encode_signature(signature: &Self::Signature) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }
}

// Implement the to_sign_bytes trait for our types
pub trait ToSignBytes {
    fn to_sign_bytes(&self) -> Vec<u8>;
}

impl ToSignBytes for BaseVote {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        // In production, this should match the consensus protocol's canonical format
        let mut bytes = Vec::new();

        // Add vote type (1 byte)
        bytes.push(match self.vote_type.0 {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        });

        // Add height (8 bytes)
        bytes.extend_from_slice(&self.height.as_u64().to_le_bytes());

        // Add round (4 bytes)
        bytes.extend_from_slice(&self.round.0.as_u32().unwrap_or(0).to_le_bytes());

        // Add value_id (32 bytes or 0 for nil)
        match &self.value_id {
            NilOrVal::Val(id) => bytes.extend_from_slice(&id.0),
            NilOrVal::Nil => bytes.extend_from_slice(&[0u8; 32]),
        }

        // Add voter address (20 bytes)
        bytes.extend_from_slice(self.voter.0.as_bytes());

        bytes
    }
}

impl ToSignBytes for BaseProposal {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        let mut bytes = Vec::new();

        // Add height (8 bytes)
        bytes.extend_from_slice(&self.height.as_u64().to_le_bytes());

        // Add round (4 bytes)
        bytes.extend_from_slice(&self.round.0.as_u32().unwrap_or(0).to_le_bytes());

        // Add value data
        bytes.extend_from_slice(&self.value.data);

        // Add proposer address (20 bytes)
        bytes.extend_from_slice(self.proposer.0.as_bytes());

        // Add pol_round (4 bytes)
        bytes.extend_from_slice(&self.pol_round.0.as_u32().unwrap_or(0).to_le_bytes());

        bytes
    }
}

impl ToSignBytes for BaseProposalPart {
    fn to_sign_bytes(&self) -> Vec<u8> {
        // Create a canonical byte representation for signing
        let mut bytes = Vec::new();

        // Add height (8 bytes)
        bytes.extend_from_slice(&self.height.as_u64().to_le_bytes());

        // Add round (4 bytes)
        bytes.extend_from_slice(&self.round.0.as_u32().unwrap_or(0).to_le_bytes());

        // Add value data
        bytes.extend_from_slice(&self.value.data);

        // Add proposer address (20 bytes)
        bytes.extend_from_slice(self.proposer.0.as_bytes());

        bytes
    }
}

impl SigningProvider<MalachiteContext> for Ed25519Provider {
    fn sign_vote(&self, vote: BaseVote) -> SignedVote<MalachiteContext> {
        let signature = self.sign(&vote.to_sign_bytes());
        SignedVote::new(vote, signature)
    }

    fn verify_signed_vote(
        &self,
        vote: &BaseVote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key.verify(&vote.to_sign_bytes(), signature).is_ok()
    }

    fn sign_proposal(&self, proposal: BaseProposal) -> SignedProposal<MalachiteContext> {
        let signature = self.sign(&proposal.to_sign_bytes());
        SignedProposal::new(proposal, signature)
    }

    fn verify_signed_proposal(
        &self,
        proposal: &BaseProposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key
            .verify(&proposal.to_sign_bytes(), signature)
            .is_ok()
    }

    fn sign_proposal_part(
        &self,
        proposal_part: BaseProposalPart,
    ) -> SignedProposalPart<MalachiteContext> {
        let signature = self.sign(&proposal_part.to_sign_bytes());
        SignedProposalPart::new(proposal_part, signature)
    }

    fn verify_signed_proposal_part(
        &self,
        proposal_part: &BaseProposalPart,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key
            .verify(&proposal_part.to_sign_bytes(), signature)
            .is_ok()
    }

    fn sign_vote_extension(
        &self,
        extension: crate::context::BaseExtension,
    ) -> SignedExtension<MalachiteContext> {
        let signature = self.sign(&extension.data);
        malachitebft_core_types::SignedMessage::new(extension, signature)
    }

    fn verify_signed_vote_extension(
        &self,
        extension: &crate::context::BaseExtension,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        public_key.verify(&extension.data, signature).is_ok()
    }
}
