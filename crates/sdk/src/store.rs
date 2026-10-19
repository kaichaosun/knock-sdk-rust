//! What a bot has to remember.
//!
//! Three things, and no more: the key its conversations are encrypted against,
//! where it had read up to, and the keys of everyone it talks to. Everything
//! else a bot knows it can ask the relay for again.
//!
//! A trait rather than a table, because the right answer differs per bot. One
//! answering a handful of people is well served by a file; one in every room on
//! the relay wants Postgres. The SDK has no business choosing, and this is small
//! enough that neither choice is much work.
//!
//! The device secret is the one that must not be lost. A bot that comes back
//! with a new one is still the same address, still signs in, still reads its
//! queue — and cannot open a single message in it, because everyone is sealing
//! to the key it published before.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

/// Where a bot keeps what it must not forget.
pub trait Store: Send + Sync {
    /// This bot's X25519 secret, minted on first run and never again.
    fn device_secret(&self) -> [u8; 32];

    /// How far through its queue it has read, or `None` on a first run.
    fn cursor(&self) -> Option<String>;

    /// Remember a new one. Called after messages have been handled, never
    /// before: a cursor saved early is a message nobody answered.
    fn set_cursor(&self, cursor: &str);

    /// The encryption key published for `address`, if it has been fetched.
    fn key_for(&self, address: &str) -> Option<[u8; 32]>;

    /// Remember one, so the next message from the same person costs no lookup.
    fn remember_key(&self, address: &str, key: [u8; 32]);
}

/// A store that forgets everything when the process ends.
///
/// Right for tests and for a bot that has nothing to say twice. Wrong for
/// anything else, and loudly so: a restart mints a new device secret, and every
/// conversation opened before it goes dark.
pub struct Ephemeral {
    secret: [u8; 32],
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    cursor: Option<String>,
    keys: HashMap<String, [u8; 32]>,
}

impl Ephemeral {
    /// With a device secret of your own, so a test can be repeatable.
    pub fn with_secret(secret: [u8; 32]) -> Self {
        Self {
            secret,
            state: Mutex::new(State::default()),
        }
    }
}

impl Store for Ephemeral {
    fn device_secret(&self) -> [u8; 32] {
        self.secret
    }

    fn cursor(&self) -> Option<String> {
        self.locked().cursor.clone()
    }

    fn set_cursor(&self, cursor: &str) {
        self.locked().cursor = Some(cursor.to_string());
    }

    fn key_for(&self, address: &str) -> Option<[u8; 32]> {
        self.locked().keys.get(address).copied()
    }

    fn remember_key(&self, address: &str, key: [u8; 32]) {
        self.locked().keys.insert(address.to_string(), key);
    }
}

impl Ephemeral {
    /// Reading through a poisoned lock: another thread's panic says nothing
    /// about a cursor and a map, and should not take the bot down with it.
    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A bot's memory, in a file.
///
/// Enough for a bot with one process and a disk. A busy one wants Postgres and
/// can have it — [`Store`] is five methods and this is the whole of what
/// implementing one takes.
///
/// Written whole on every change rather than appended to. What is in here is a
/// device secret, a cursor and a handful of keys; rewriting all of it costs
/// nothing at that size, and a crash mid-write cannot leave a half-record that
/// parses.
///
/// Lived in the echo bot until a second bot wanted it. Two copies of a file
/// format is how two bots come to disagree about one.
pub struct Files {
    path: PathBuf,
    state: Mutex<Remembered>,
}

#[derive(Default, Serialize, Deserialize)]
struct Remembered {
    /// Hex, so the file can be read by a person.
    device_secret: String,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    keys: HashMap<String, String>,
}

impl Files {
    /// Open `path`, minting a device secret if this is a first run.
    ///
    /// The secret is made here rather than asked for, because unlike the
    /// identity key it means nothing to anybody: it is not who the bot is, it
    /// is what its conversations are locked with. What matters is that it
    /// survives, which is this file's whole job — start again with a new one
    /// and every conversation already open goes dark.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let state = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut secret = [0u8; 32];
                getrandom::fill(&mut secret).expect("the OS must produce randomness");
                Remembered {
                    device_secret: HEXLOWER.encode(&secret),
                    ..Default::default()
                }
            }
            Err(e) => return Err(e),
        };

        let store = Self {
            path,
            state: Mutex::new(state),
        };
        store.write()?;
        Ok(store)
    }

    fn write(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Written beside and renamed over: a rename is atomic, so a reader — or
        // the next start after a crash — sees the old file or the new one and
        // never a partial one.
        let scratch = self.path.with_extension("writing");
        std::fs::write(&scratch, serde_json::to_string_pretty(&*self.locked())?)?;
        std::fs::rename(&scratch, &self.path)
    }

    /// Saving is best effort: a bot that stopped answering because a disk was
    /// full would be a worse bot than one that repeats itself after a restart.
    fn save(&self) {
        if let Err(e) = self.write() {
            eprintln!("could not save {}: {e}", self.path.display());
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Remembered> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Store for Files {
    fn device_secret(&self) -> [u8; 32] {
        HEXLOWER
            .decode(self.locked().device_secret.as_bytes())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("the file holds 32 bytes of hex, or it was not written by this")
    }

    fn cursor(&self) -> Option<String> {
        self.locked().cursor.clone()
    }

    fn set_cursor(&self, cursor: &str) {
        self.locked().cursor = Some(cursor.to_string());
        self.save();
    }

    fn key_for(&self, address: &str) -> Option<[u8; 32]> {
        let hex = self.locked().keys.get(address)?.clone();
        HEXLOWER.decode(hex.as_bytes()).ok()?.try_into().ok()
    }

    fn remember_key(&self, address: &str, key: [u8; 32]) {
        self.locked()
            .keys
            .insert(address.to_string(), HEXLOWER.encode(&key));
        self.save();
    }
}

/// Where a bot keeps its file when nobody says otherwise.
pub fn default_path() -> &'static Path {
    Path::new("echo.json")
}
