//! Speaking Knock.
//!
//! A bot is an address that can sign a challenge, which is all the relay has
//! ever asked of anybody — so nothing here needs the relay's cooperation or a
//! notion of "bot" on its side. What it does need is to be a real endpoint: the
//! relay carries ciphertext and never opens it, so a bot decrypts for itself.
//! That is [`crypto`], and it is the part with no Rust to borrow from.

pub mod address;
pub mod bot;
pub mod crypto;
pub mod identity;
pub mod keys;
pub mod session;
pub mod store;
