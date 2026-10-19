//! Signing in against a relay that is actually running.
//!
//! Ignored by default: it needs a relay listening. Everything it proves is a
//! thing no unit test can — that the digest is the one the relay recomputes,
//! that the hex is the hex it expects, and that it will certify an encryption
//! key handed over this way.
//!
//!     KNOCK_RELAY=http://127.0.0.1:3199 \
//!     cargo test --test sign_in -- --ignored --nocapture

use knock_sdk::identity::Identity;
use knock_sdk::session::{Client, Error};

fn relay() -> Client {
    Client::new(std::env::var("KNOCK_RELAY").unwrap_or_else(|_| "http://127.0.0.1:3199".into()))
}

#[tokio::test]
#[ignore]
async fn a_bot_signs_in_like_anybody_else() {
    let identity = Identity::new([9u8; 32]);
    let session = relay()
        .sign_in(&identity, &[4u8; 32])
        .await
        .expect("sign in");

    assert!(
        session.address.starts_with("NQ"),
        "address: {}",
        session.address
    );
    assert!(!session.token.is_empty());
    println!(
        "signed in as {} until {}",
        session.address, session.expires_at
    );
}

#[tokio::test]
#[ignore]
async fn the_address_comes_from_the_key_that_signed() {
    // Two keys, two addresses, and neither bot ever said which it was. This is
    // what makes a bot no different from a person here: identity is proved,
    // never claimed.
    let one = relay()
        .sign_in(&Identity::new([9u8; 32]), &[4u8; 32])
        .await
        .unwrap();
    let two = relay()
        .sign_in(&Identity::new([8u8; 32]), &[4u8; 32])
        .await
        .unwrap();
    assert_ne!(one.address, two.address);

    // And the same key twice is the same address, so a bot keeps its identity
    // across restarts as long as it keeps its key.
    let again = relay()
        .sign_in(&Identity::new([9u8; 32]), &[5u8; 32])
        .await
        .unwrap();
    assert_eq!(one.address, again.address);
    assert_ne!(one.token, again.token, "each sign-in is its own session");
}

#[tokio::test]
#[ignore]
async fn a_relay_that_is_not_there_says_so() {
    let nowhere = Client::new("http://127.0.0.1:1");
    let failure = nowhere
        .sign_in(&Identity::new([9u8; 32]), &[4u8; 32])
        .await
        .unwrap_err();
    assert!(matches!(failure, Error::Unreachable(_)), "{failure:?}");
}
