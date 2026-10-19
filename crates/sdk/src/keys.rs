//! Whose key is whose.
//!
//! A wallet cannot do key agreement — it signs and nothing else — so each
//! device makes its own X25519 keypair and has the wallet *certify* it. The
//! certificate is the sign-in challenge, kept: the encryption key is read back
//! out of the bytes that were signed rather than carried in a field beside
//! them, so there is one source of truth and no way for the two to disagree.
//!
//! **The relay's copy is not evidence.** It verifies certificates before
//! storing them, but a bot that took its word for one would be sealing every
//! reply to whatever key the relay chose to hand over — which is precisely the
//! thing end-to-end encryption is for. So this checks the signature itself, and
//! checks that the address it derives from the signing key is the address it
//! asked about. Both, or neither is worth anything: a valid signature by the
//! wrong key is exactly what a relay in the middle would produce.

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::address;
use crate::identity::signed_message_digest;

/// The line in a signed statement that carries the key.
const KEY_PREFIX: &str = "Device public key: ";

/// A wallet's signed statement that it owns an encryption key.
#[derive(Debug, Clone, Deserialize)]
pub struct Certificate {
    pub address: String,
    /// The exact bytes the wallet signed.
    pub statement: String,
    /// The Ed25519 key that signed, hex.
    pub public_key: String,
    pub signature: String,
}

impl Certificate {
    /// The X25519 key to seal to, if this certificate proves `expected` owns it.
    ///
    /// `None` for anything that does not: an unparseable key, a signature that
    /// does not cover the statement, or a signature by somebody else. One
    /// answer for all three because they are one fact — this is not a key you
    /// may use — and a bot has nothing different to do about any of them.
    pub fn key_for(&self, expected: &str) -> Option<[u8; 32]> {
        let public: [u8; 32] = HEXLOWER
            .decode(self.public_key.trim().to_ascii_lowercase().as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        let signature: [u8; 64] = HEXLOWER
            .decode(self.signature.trim().to_ascii_lowercase().as_bytes())
            .ok()?
            .try_into()
            .ok()?;

        // Whose signature it is, before whether it is valid: a perfectly good
        // signature by a key the relay minted proves only that the relay can
        // sign.
        if !address::same(&address::from_public_key(&public), expected) {
            return None;
        }

        VerifyingKey::from_bytes(&public)
            .ok()?
            .verify(
                &signed_message_digest(self.statement.as_bytes()),
                &Signature::from_bytes(&signature),
            )
            .ok()?;

        // Only now is the statement worth reading.
        encryption_key_in(&self.statement)
    }
}

/// The key a signed statement carries, if it carries one.
fn encryption_key_in(statement: &str) -> Option<[u8; 32]> {
    let line = statement
        .lines()
        .find_map(|line| line.trim().strip_prefix(KEY_PREFIX))?;
    HEXLOWER
        .decode(line.trim().to_ascii_lowercase().as_bytes())
        .ok()?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// A certificate as a wallet would produce one: sign a statement that names
    /// a device key.
    fn certificate(signer: &Identity, device: [u8; 32], claimed: &str) -> Certificate {
        let statement = format!("Sign in to Knock\n{KEY_PREFIX}{}", HEXLOWER.encode(&device));
        Certificate {
            address: claimed.to_string(),
            signature: signer.sign_hex(&statement),
            public_key: signer.public_key_hex(),
            statement,
        }
    }

    fn public_of(identity: &Identity) -> [u8; 32] {
        HEXLOWER
            .decode(identity.public_key_hex().as_bytes())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn a_certificate_yields_the_key_it_was_signed_over() {
        let wallet = Identity::new([9u8; 32]);
        let mine = address::from_public_key(&public_of(&wallet));
        let device = [3u8; 32];
        assert_eq!(
            certificate(&wallet, device, &mine).key_for(&mine),
            Some(device)
        );
    }

    #[test]
    fn a_certificate_signed_by_somebody_else_is_worth_nothing() {
        // What a relay in the middle would produce: a real signature, its own
        // key, and the address it was asked about written on the front.
        let wallet = Identity::new([9u8; 32]);
        let impostor = Identity::new([66u8; 32]);
        let mine = address::from_public_key(&public_of(&wallet));

        let forged = certificate(&impostor, [3u8; 32], &mine);
        assert_eq!(
            forged.key_for(&mine),
            None,
            "the signature is valid, and it is not theirs"
        );
    }

    #[test]
    fn a_statement_that_was_edited_after_signing_is_worth_nothing() {
        let wallet = Identity::new([9u8; 32]);
        let mine = address::from_public_key(&public_of(&wallet));
        let mut tampered = certificate(&wallet, [3u8; 32], &mine);
        tampered.statement = tampered.statement.replace("03", "04");
        assert_eq!(tampered.key_for(&mine), None);
    }

    #[test]
    fn a_statement_naming_no_key_yields_none() {
        let wallet = Identity::new([9u8; 32]);
        let mine = address::from_public_key(&public_of(&wallet));
        let mut bare = certificate(&wallet, [3u8; 32], &mine);
        bare.statement = "Sign in to Knock".to_string();
        bare.signature = wallet.sign_hex(&bare.statement);
        assert_eq!(bare.key_for(&mine), None);
    }
}
