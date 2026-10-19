//! Turning a public key into the address people read.
//!
//! Needed for one thing, and it is the thing that makes end-to-end encryption
//! mean anything here: checking that a key certificate was signed by the
//! address it claims. Without it the relay could hand a bot a certificate
//! signed by a key it holds itself, and the bot would seal every reply where
//! the relay could read it. See [`crate::keys`].
//!
//! Mirrors `address.rs` in the relay, which mirrors `nimiq_keys::Address`.
//! Blake2b-256 of the public key, first twenty bytes, then base32 in Nimiq's
//! alphabet with an IBAN check.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use std::fmt::Write as _;
use std::sync::LazyLock;

const ADDRESS_LEN: usize = 20;
const CCODE: &str = "NQ";
/// No I, O, W or Z — the letters people mistype.
const NIMIQ_ALPHABET: &str = "0123456789ABCDEFGHJKLMNPQRSTUVXY";

static ENCODING: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    data_encoding::Specification {
        symbols: NIMIQ_ALPHABET.into(),
        ..Default::default()
    }
    .encoding()
    .expect("the Nimiq alphabet is a valid base32 specification")
});

/// The address an Ed25519 public key belongs to, in the spaced form the relay
/// and the app both use.
pub fn from_public_key(public_key: &[u8; 32]) -> String {
    let hash = Blake2b::<U32>::digest(public_key);
    let base32 = ENCODING.encode(&hash[..ADDRESS_LEN]);
    let checksum = 98 - iban_checksum(&format!("{CCODE}00{base32}"));
    let mut friendly = format!("{CCODE}{checksum:02}{base32}");
    for i in (1..9).rev() {
        friendly.insert(4 * i, ' ');
    }
    friendly
}

/// Whether two addresses are the same one, however they were written.
///
/// Spacing is presentation — the relay hands them over spaced, a query string
/// carries them either way — so comparing the strings as they arrive would make
/// a true answer depend on typography.
pub fn same(a: &str, b: &str) -> bool {
    let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    compact(a).eq_ignore_ascii_case(&compact(b))
}

/// The IBAN mod-97 check, folded digit by digit because the whole number fits
/// in no integer type.
fn iban_checksum(iban: &str) -> u32 {
    let mut digits = String::with_capacity(iban.len() * 2);
    let mut push = |part: &str| {
        for c in part.chars() {
            match c {
                '0'..='9' => digits.push(c),
                'a'..='z' => write!(digits, "{}", c as u32 - 'a' as u32 + 10).unwrap(),
                'A'..='Z' => write!(digits, "{}", c as u32 - 'A' as u32 + 10).unwrap(),
                _ => {}
            }
        }
    };
    push(&iban[4..]);
    push(&iban[..4]);

    digits
        .bytes()
        .fold(0u32, |sum, digit| (sum * 10 + u32::from(digit - b'0')) % 97)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn a_key_gives_the_address_the_relay_gives() {
        // From a live sign-in against the relay with this key — so this is not
        // this module agreeing with itself.
        let identity = Identity::new([9u8; 32]);
        let public: [u8; 32] = data_encoding::HEXLOWER
            .decode(identity.public_key_hex().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            from_public_key(&public),
            "NQ23 1KSQ XYG1 JJ90 EMHF G1EF 6TBB N882 K3KC"
        );
    }

    #[test]
    fn a_key_derives_its_address_without_asking_anybody() {
        // The same answer `sign_in` checks the relay's against, from the key
        // alone and with nothing on the network.
        assert_eq!(
            Identity::new([9u8; 32]).address(),
            "NQ23 1KSQ XYG1 JJ90 EMHF G1EF 6TBB N882 K3KC"
        );
    }

    #[test]
    fn spacing_is_not_part_of_who_somebody_is() {
        assert!(same(
            "NQ23 1KSQ XYG1 JJ90 EMHF G1EF 6TBB N882 K3KC",
            "NQ231KSQXYG1JJ90EMHFG1EF6TBBN882K3KC"
        ));
        assert!(!same(
            "NQ23 1KSQ XYG1 JJ90 EMHF G1EF 6TBB N882 K3KC",
            "NQ23 1KSQ XYG1 JJ90 EMHF G1EF 6TBB N882 K3KD"
        ));
    }
}
