//! Proof that this crate and the app mean the same thing by an encrypted body.
//!
//! The vectors in `vectors/crypto.json` are produced by the app's own
//! `src/lib/crypto.ts` — see `tools/crypto-vectors.ts` — so what is asserted
//! here is not "the Rust is self-consistent" but "the Rust reads what a phone
//! wrote". That distinction is the whole point: two implementations of one
//! format diverge silently, and a bot that derives the key a little differently
//! does not fail, it just never reads anything again.
//!
//! Regenerate after any change to the app's format, with
//! [knock-chat](https://github.com/kaichaosun/knock-chat) checked out beside
//! this repository:
//!
//!     cd ../knock-chat && node_modules/.bin/jiti ../knock-sdk-rust/tools/crypto-vectors.ts \
//!         ../knock-sdk-rust/crates/sdk/tests/vectors/crypto.json

use data_encoding::HEXLOWER;
use knock_sdk::crypto::{conversation_key, looks_encrypted, open, public_key, seal};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    agreement: Vec<Agreement>,
    messages: Vec<Message>,
    rejects: Vec<Reject>,
}

#[derive(Deserialize)]
struct Agreement {
    name: String,
    a_secret: String,
    a_public: String,
    b_secret: String,
    b_public: String,
    key: String,
}

#[derive(Deserialize)]
struct Message {
    name: String,
    from: String,
    to: String,
    key: String,
    plaintext: String,
    body: String,
}

#[derive(Deserialize)]
struct Reject {
    name: String,
    from: String,
    to: String,
    key: String,
    body: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors/crypto.json")).expect("the vectors should parse")
}

fn key_of(hex: &str) -> [u8; 32] {
    HEXLOWER
        .decode(hex.as_bytes())
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

#[test]
fn the_public_key_of_a_secret_is_the_one_the_app_derived() {
    for pair in vectors().agreement {
        assert_eq!(
            HEXLOWER.encode(&public_key(&key_of(&pair.a_secret))),
            pair.a_public,
            "{}: a's public key",
            pair.name
        );
        assert_eq!(
            HEXLOWER.encode(&public_key(&key_of(&pair.b_secret))),
            pair.b_public,
            "{}: b's public key",
            pair.name
        );
    }
}

#[test]
fn both_ends_derive_the_key_the_app_derived() {
    // Each pair is checked from both sides, which is what proves the sort in
    // the HKDF info rather than merely exercising it. The vectors carry a pair
    // that sorts each way for the same reason.
    for pair in vectors().agreement {
        let (a_secret, a_public) = (key_of(&pair.a_secret), key_of(&pair.a_public));
        let (b_secret, b_public) = (key_of(&pair.b_secret), key_of(&pair.b_public));

        assert_eq!(
            HEXLOWER.encode(&conversation_key(&a_secret, &b_public)),
            pair.key,
            "{}: from a's side",
            pair.name
        );
        assert_eq!(
            HEXLOWER.encode(&conversation_key(&b_secret, &a_public)),
            pair.key,
            "{}: from b's side",
            pair.name
        );
    }
}

#[test]
fn what_the_app_sealed_opens_here() {
    for message in vectors().messages {
        assert_eq!(
            open(
                &message.body,
                &key_of(&message.key),
                &message.from,
                &message.to
            )
            .as_deref(),
            Some(message.plaintext.as_str()),
            "{}",
            message.name
        );
        assert!(looks_encrypted(&message.body), "{}", message.name);
    }
}

#[test]
fn what_the_app_refuses_is_refused_here() {
    for reject in vectors().rejects {
        assert_eq!(
            open(&reject.body, &key_of(&reject.key), &reject.from, &reject.to),
            None,
            "{} should not have opened",
            reject.name
        );
    }
}

#[test]
fn what_is_sealed_here_opens_here() {
    // The direction the vectors cannot pin, since the app picks a random nonce
    // and its ciphertext is therefore not reproducible. What makes this more
    // than self-consistency is the test above: the same `open` reads the app's
    // bodies, so a `seal` it can read is one the app could have written.
    let message = &vectors().messages[0];
    let key = key_of(&message.key);
    let nonce = [7u8; 24];

    let body = seal(
        "hello from a bot 🤖",
        &key,
        &message.from,
        &message.to,
        &nonce,
    );
    assert!(looks_encrypted(&body));
    assert_eq!(
        open(&body, &key, &message.from, &message.to).as_deref(),
        Some("hello from a bot 🤖")
    );
    // And is bound to its direction, like everything the app seals.
    assert_eq!(open(&body, &key, &message.to, &message.from), None);
}
