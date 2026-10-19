//! Who a bot is.
//!
//! An Ed25519 key, and that is the whole of it. The relay derives the address
//! from the key that signed, so a bot never states who it is — it proves it,
//! the same way a phone does, and gets told the answer back.
//!
//! What it signs is not the challenge but a digest of it. A Nimiq wallet wraps
//! a message in a length-prefixed envelope before signing, an EIP-191-style
//! guard so a signing request can never be dressed up as a transaction:
//!
//! ```text
//! digest = SHA256( 0x16 ‖ "Nimiq Signed Message:\n" ‖ ascii(byte_len) ‖ message )
//! ```
//!
//! Mirrors `signature.rs` in the relay, which is the code that will be checking
//! this, and `prepare_message_for_signature` in core-rs-albatross before that.
//! Get it wrong and the relay answers "signature does not match", which is at
//! least a sentence — unlike the message layer, this fails loudly.

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

/// `0x16` is the byte length of the ASCII portion that follows it.
const PREFIX: &[u8] = b"\x16Nimiq Signed Message:\n";

/// The 32 bytes a wallet actually signs for `message`.
pub fn signed_message_digest(message: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(PREFIX.len() + 8 + message.len());
    buffer.extend_from_slice(PREFIX);
    buffer.extend_from_slice(message.len().to_string().as_bytes());
    buffer.extend_from_slice(message);
    Sha256::digest(&buffer).into()
}

/// A bot's key.
///
/// Held as bytes rather than read from a wallet: there is no wallet here and no
/// human to approve anything, which is the one real difference between a bot
/// and a person on this network.
#[derive(Clone)]
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    /// From 32 raw bytes.
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&secret),
        }
    }

    /// From 32 bytes of hex, with or without an `0x`, as an environment
    /// variable would carry it.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let clean = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = HEXLOWER
            .decode(clean.to_ascii_lowercase().as_bytes())
            .map_err(|_| KeyError::NotHex)?;
        let secret: [u8; 32] = bytes.try_into().map_err(|_| KeyError::WrongLength)?;
        Ok(Self::new(secret))
    }

    /// The public half, hex, as `/v1/auth/verify` wants it.
    pub fn public_key_hex(&self) -> String {
        HEXLOWER.encode(self.key.verifying_key().as_bytes())
    }

    /// The address this key belongs to, derived here.
    ///
    /// Never asked of anybody. The relay reports an address at sign-in and it
    /// is welcome to, but a value that can be computed from something already
    /// held should not be taken on trust from a party with its own interests —
    /// and this one is the bot's whole public identity, the string it hands out
    /// for people to knock on.
    pub fn address(&self) -> String {
        crate::address::from_public_key(self.key.verifying_key().as_bytes())
    }

    /// Sign a challenge the way a wallet would, hex.
    pub fn sign_hex(&self, message: &str) -> String {
        let digest = signed_message_digest(message.as_bytes());
        HEXLOWER.encode(&self.key.sign(&digest).to_bytes())
    }
}

impl std::fmt::Debug for Identity {
    /// The public half only.
    ///
    /// Written by hand because the derived one would print the secret, and a
    /// stray `{:?}` in a log line is exactly how a key gets out. This one signs
    /// for an address that can be sent money.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

/// Why a key could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("a key must be hex")]
    NotHex,
    #[error("a key must be 32 bytes")]
    WrongLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector in the relay's `signature.rs`, which came from a real Nimiq
    /// Pay wallet on iOS. Same bytes on both sides or a bot cannot sign in.
    #[test]
    fn the_digest_is_what_a_wallet_signs() {
        // "hello" is 5 bytes, so the envelope carries the ASCII "5".
        let digest = signed_message_digest(b"hello");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x16Nimiq Signed Message:\n5hello");
        assert_eq!(digest.to_vec(), Sha256::digest(&expected).to_vec());
    }

    #[test]
    fn a_key_reads_the_same_from_bytes_and_from_hex() {
        let raw = [7u8; 32];
        let from_bytes = Identity::new(raw);
        let from_hex = Identity::from_hex(&"07".repeat(32)).unwrap();
        assert_eq!(from_bytes.public_key_hex(), from_hex.public_key_hex());
        // And an `0x` in front changes nothing, since an environment variable
        // is as likely to carry one as not.
        let prefixed = Identity::from_hex(&format!("0x{}", "07".repeat(32))).unwrap();
        assert_eq!(from_bytes.public_key_hex(), prefixed.public_key_hex());
    }

    #[test]
    fn a_key_that_is_not_one_is_refused_rather_than_padded() {
        assert_eq!(
            Identity::from_hex("not hex at all!!").unwrap_err(),
            KeyError::NotHex
        );
        assert_eq!(Identity::from_hex("07").unwrap_err(), KeyError::WrongLength);
    }

    #[test]
    fn a_signature_covers_the_digest_and_not_the_message() {
        // The distinction the envelope exists for. Signing the raw bytes would
        // verify against nothing the relay computes.
        let identity = Identity::new([3u8; 32]);
        let signed = identity.sign_hex("hello");
        let key = identity.key.verifying_key();
        let signature =
            ed25519_dalek::Signature::from_slice(&HEXLOWER.decode(signed.as_bytes()).unwrap())
                .unwrap();

        use ed25519_dalek::Verifier;
        assert!(
            key.verify(&signed_message_digest(b"hello"), &signature)
                .is_ok()
        );
        assert!(key.verify(b"hello", &signature).is_err());
    }
}
