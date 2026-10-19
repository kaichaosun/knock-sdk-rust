//! Message encryption, as the app does it.
//!
//! This is the one part of speaking Knock with no Rust to borrow from. The
//! relay carries ciphertext and never opens it, so it has no key agreement, no
//! cipher and no opinion about the frame — all of that lives in the client, in
//! TypeScript, and a bot is the other end of exactly that conversation.
//!
//! Two implementations of one format in two languages is where formats quietly
//! diverge, and this one diverges *silently*: a bot that derives the key a
//! little differently does not crash, it simply never reads anything. So the
//! agreement is pinned by vectors generated from the app's own code — see
//! `tests/crypto_vectors.rs` and `tools/crypto-vectors.ts`. Change anything
//! here and those fail; change the app's format and regenerating them fails.
//!
//! ```text
//! key = HKDF-SHA256( X25519(mine, theirs),
//!                    salt = ∅,
//!                    info = "knock/v1/message" ‖ first ‖ second )
//! ```
//!
//! where `first` and `second` are the two public keys sorted bytewise, so both
//! ends feed the hash identical input while holding the keys in opposite roles.
//! Bodies are sealed with XChaCha20-Poly1305 and framed `version ‖ nonce ‖
//! ciphertext`, base64.
//!
//! What this deliberately does not provide, exactly as the app does not:
//! forward secrecy. One key covers a whole conversation.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::{BASE64, HEXLOWER};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Bumped if the wire format ever changes; readers reject anything else.
pub const VERSION: u8 = 1;

const NONCE_BYTES: usize = 24;
/// What Poly1305 adds. A body shorter than the frame plus this cannot be one.
const TAG_BYTES: usize = 16;
const INFO: &[u8] = b"knock/v1/message";

/// The public half of an X25519 secret.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*secret)).as_bytes()
}

/// The key both sides of a conversation derive independently.
///
/// The sort is the whole trick: each party holds the two keys in opposite
/// roles, and ordering them by their bytes is what makes "mine and theirs" and
/// "theirs and mine" the same two bytes strings.
pub fn conversation_key(mine: &[u8; 32], theirs: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*mine);
    let shared = secret.diffie_hellman(&PublicKey::from(*theirs));
    let ours = public_key(mine);

    let (first, second) = if ours.as_slice() <= theirs.as_slice() {
        (ours, *theirs)
    } else {
        (*theirs, ours)
    };

    let mut info = Vec::with_capacity(INFO.len() + 64);
    info.extend_from_slice(INFO);
    info.extend_from_slice(&first);
    info.extend_from_slice(&second);

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF length");
    key
}

/// Bind a ciphertext to its sender and recipient, so one cannot be lifted into
/// a different conversation — or a different direction of the same one — and
/// still authenticate.
fn associated_data(from: &str, to: &str) -> Vec<u8> {
    let compact = |address: &str| address.split_whitespace().collect::<String>();
    format!("{}>{}", compact(from), compact(to)).into_bytes()
}

/// Seal `plaintext` into `version ‖ nonce ‖ ciphertext`, base64.
pub fn seal(
    plaintext: &str,
    key: &[u8; 32],
    from: &str,
    to: &str,
    nonce: &[u8; NONCE_BYTES],
) -> String {
    let cipher = XChaCha20Poly1305::new(key.into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &associated_data(from, to),
            },
        )
        .expect("sealing cannot fail for a key and nonce of the right size");

    let mut framed = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
    framed.push(VERSION);
    framed.extend_from_slice(nonce);
    framed.extend_from_slice(&sealed);
    BASE64.encode(&framed)
}

/// Open a sealed body.
///
/// `None` for anything that is not a valid message from `from` to `to` under
/// `key` — a wrong key, tampering, the other direction of the conversation, or
/// a body that was never encrypted at all. One answer for all of them on
/// purpose: to a reader they are the same fact, and telling them apart would
/// say more about the key than the caller needs to know.
pub fn open(body: &str, key: &[u8; 32], from: &str, to: &str) -> Option<String> {
    let raw = BASE64.decode(body.as_bytes()).ok()?;
    if raw.len() < 1 + NONCE_BYTES + TAG_BYTES || raw[0] != VERSION {
        return None;
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    let opened = cipher
        .decrypt(
            XNonce::from_slice(&raw[1..1 + NONCE_BYTES]),
            Payload {
                msg: &raw[1 + NONCE_BYTES..],
                aad: &associated_data(from, to),
            },
        )
        .ok()?;
    String::from_utf8(opened).ok()
}

/// Whether a body looks like something [`open`] should be handed.
pub fn looks_encrypted(body: &str) -> bool {
    match BASE64.decode(body.as_bytes()) {
        Ok(raw) => raw.len() >= 1 + NONCE_BYTES + TAG_BYTES && raw[0] == VERSION,
        Err(_) => false,
    }
}

/// A fresh nonce, which must never repeat under one key.
///
/// From the operating system rather than a counter: a bot that restarts and
/// starts counting again would reuse nonces under a key it kept, and XChaCha's
/// 24 bytes are wide enough that random ones will not collide.
pub fn nonce() -> [u8; 24] {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("the OS must be able to produce randomness");
    bytes
}

/// Read a 32-byte key from hex, or `None` if that is not what it is.
pub fn key_from_hex(hex: &str) -> Option<[u8; 32]> {
    HEXLOWER
        .decode(hex.trim().to_ascii_lowercase().as_bytes())
        .ok()?
        .try_into()
        .ok()
}
