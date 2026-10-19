//! A bot that says back what it was told.
//!
//! The smallest bot that is nonetheless a real one — it signs in, is reachable,
//! remembers what it read, and survives a restart. Which makes it two things at
//! once: the example of what writing a bot involves, and a live check of the
//! whole chain. Message it and you have exercised sign-in, both directions of
//! the encryption, polling, acks and replies against a running relay. That is
//! worth far more than reasoning about which layer broke.
//!
//! Configuration is three variables, and only the first is required:
//!
//! ```text
//! KNOCK_BOT_KEY    32 bytes of hex — the bot's identity. `openssl rand -hex 32`
//! KNOCK_RELAY      where the relay is. Default https://knockchat.org/api
//! KNOCK_BOT_STORE  where to keep the device key and cursor. Default echo.json
//! KNOCK_BOT_NAME   what to call itself. Left alone if unset
//! KNOCK_BOT_AVATAR a path to an image to wear. Left alone if unset
//! ```

use knock_sdk::store::{Files, Store};

use knock_sdk::bot::{Bot, Handler, Heard, Presence, Saying};
use knock_sdk::identity::Identity;
use knock_sdk::session::{Client, PUBLIC_RELAY};

/// Everything this bot knows how to do.
///
/// One method, and no idea that cursors, nonces or certificates exist. That is
/// the whole point of the split: a bot with something to say writes this and
/// nothing else.
struct Echo;

impl Handler for Echo {
    // Nothing to stream: an echo is as long as what it echoes and arrives
    // whole. See `Saying` for what a handler that writes as it goes does.
    async fn reply(&self, message: &Heard, _: &Saying) -> Option<String> {
        // Words only. Everything else the app sends — a payment, a shared
        // contact, a reaction — arrives framed, and handing a frame back would
        // have the app draw that card a second time, from this bot: a payment
        // nobody made, a contact nobody shared.
        if message.invited.is_some() {
            return Some("I've joined that room.".into());
        }
        let Some(said) = message.text() else {
            return Some("I can only echo text.".into());
        };
        // Verbatim. An echo that adds a word of its own is not an echo, and
        // what this bot is for is showing that what went in came back
        // unchanged — through two encryptions, a relay, and a poll.
        Some(said.to_string())
    }
}

#[tokio::main]
async fn main() {
    // Printed here rather than returned. `main`'s error is shown with `Debug`,
    // which puts a usage message on one line with its newlines spelled out —
    // and unlike the relay, where one error type could be taught to print
    // itself, these come from four places and share only `dyn Error`.
    if let Err(trouble) = dispatch().await {
        eprintln!("{trouble}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        None => run().await,
        // Clearing is a one-off act rather than a description of how the bot
        // should run, so it does not belong in the configuration a deployment
        // carries: a `KNOCK_BOT_NAME=` that meant "take the name away" would
        // have to keep meaning it on every start forever after.
        Some("clear-name") => clear(Clearing::Name).await,
        Some("clear-avatar") => clear(Clearing::Avatar).await,
        Some("-h" | "--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("no such command: {other}\n\n{USAGE}").into()),
    }
}

const USAGE: &str = "\
knock-echo                 run the bot
knock-echo clear-name      go back to having no name
knock-echo clear-avatar    stop wearing a picture

  KNOCK_BOT_KEY     required — 32 bytes of hex
  KNOCK_RELAY       default https://knockchat.org/api
  KNOCK_BOT_STORE   default echo.json
  KNOCK_BOT_NAME    what to call itself. Unset leaves it alone
  KNOCK_BOT_AVATAR  a path to an image to wear. Unset leaves it alone";

/// What the two one-off commands take away.
enum Clearing {
    Name,
    Avatar,
}

/// Sign in, take one thing off, and stop.
///
/// Signs in through the same store the bot uses, and that is not incidental:
/// signing in publishes a device key, so doing it with a fresh one would
/// re-register a key nobody is sealing to and take every open conversation
/// dark. A command that only meant to remove a name would have removed rather
/// more than that.
async fn clear(what: Clearing) -> Result<(), Box<dyn std::error::Error>> {
    let (identity, relay, at) = configured()?;
    let client = Client::new(relay);
    let session = client
        .sign_in(&identity, &Files::open(at)?.device_secret())
        .await?;

    match what {
        Clearing::Name => {
            client.clear_name(&session.token).await?;
            println!("{} has no name now", session.address);
        }
        Clearing::Avatar => {
            client.clear_avatar(&session.token).await?;
            println!("{} wears its identicon now", session.address);
        }
    }
    Ok(())
}

/// Run until something stops it.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (identity, relay, at) = configured()?;

    // Absent leaves whatever the relay already holds, which is what makes these
    // safe to omit: a start without them is not a start that strips the bot.
    let name = std::env::var("KNOCK_BOT_NAME")
        .ok()
        .filter(|name| !name.trim().is_empty());
    // Read here rather than in the SDK, which has no business touching a disk.
    // Read *now* rather than when it is wanted, so a path that is wrong is
    // wrong before the bot is signed in and half configured.
    let avatar = match std::env::var("KNOCK_BOT_AVATAR") {
        Ok(path) => Some(std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?),
        Err(_) => None,
    };

    // Said before signing in, and derived rather than reported: if the relay is
    // unreachable this is still the address to knock on, and it is the one
    // thing somebody needs in order to talk to this bot at all.
    println!("echo is {}", identity.address());
    println!("relay   {relay}");
    println!("store   {at}");
    if let Some(name) = &name {
        println!("name    {name}");
    }
    if let Some(image) = &avatar {
        println!("avatar  {} bytes", image.len());
    }

    let mut bot = Bot::start(
        Client::new(relay),
        identity,
        Files::open(at)?,
        Echo,
        // A name is not proof of anything — it sits next to an address, which
        // is — so the relay refuses one carrying invisible or text-reordering
        // characters, and caps it at 32. Whatever it makes of this comes back
        // in its own words rather than being swallowed here.
        Presence {
            name,
            price_luna: FREE,
            avatar,
        },
    )
    .await?;
    println!("listening");
    bot.run().await?;
    Ok(())
}

/// The three things every command needs.
fn configured() -> Result<(Identity, String, String), Box<dyn std::error::Error>> {
    // Asked for rather than invented. This key is the bot's identity — the
    // address people knock on — so a bot that generated one when it could not
    // find one would come back as a stranger after every restart, and nobody's
    // saved conversation would lead anywhere.
    let key = std::env::var("KNOCK_BOT_KEY")
        .map_err(|_| "set KNOCK_BOT_KEY to 32 bytes of hex — `openssl rand -hex 32` makes one")?;
    Ok((
        Identity::from_hex(&key)?,
        std::env::var("KNOCK_RELAY").unwrap_or_else(|_| PUBLIC_RELAY.into()),
        std::env::var("KNOCK_BOT_STORE").unwrap_or_else(|_| "echo.json".to_string()),
    ))
}

/// What this bot charges strangers to reach it.
///
/// Nothing. Postage exists to make sending to thousands of people expensive,
/// and an echo bot has nothing to protect — a service nobody can afford to try
/// is not a service. A bot that does want paying sets this instead, and the
/// knock becomes the invoice.
const FREE: u64 = 0;
