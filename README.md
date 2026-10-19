# knock-sdk-rust

Build on [Knock](https://knockchat.org) from Rust. A bot is not a special kind
of account: it is an address that can sign a challenge, which is all the relay
has ever asked of anybody. Nothing here needs the relay's cooperation, and the
relay has no notion of a bot — this speaks the same protocol a phone does.

```
crates/
  sdk/      knock-sdk — sign in, poll, decrypt, reply
  echo/     a bot that says back what it was told
```

Not writing Rust? [PROTOCOL.md](PROTOCOL.md) is the HTTP API and the
encryption, and `crates/sdk/tests/vectors/crypto.json` is what to test an
implementation against.

## Writing a bot

```toml
[dependencies]
knock-sdk = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

A bot is one method. Cursors, nonces, key certificates, retries and sessions
running out are the SDK's business:

```rust
use knock_sdk::bot::{Bot, Handler, Heard, Presence, Saying};
use knock_sdk::identity::Identity;
use knock_sdk::session::{Client, PUBLIC_RELAY};
use knock_sdk::store::Files;

struct Shout;

impl Handler for Shout {
    async fn reply(&self, message: &Heard, _: &Saying) -> Option<String> {
        Some(message.text()?.to_uppercase())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_hex(&std::env::var("KNOCK_BOT_KEY")?)?;
    println!("knock on {}", identity.address());

    let mut bot = Bot::start(
        Client::new(PUBLIC_RELAY),
        identity,
        Files::open("shout.json")?,
        Shout,
        Presence { name: Some("Shout".into()), ..Default::default() },
    )
    .await?;
    bot.run().await?;
    Ok(())
}
```

`reply` returning `None` says nothing, which is a real answer — most of a room
is not addressed to the bot. `Heard::text()` is `None` for anything the app
frames (a payment, a contact, a reaction), and a bot should never hand one of
those back: the app would draw it again, from the bot.

A handler that writes slowly — a language model, say — can send as it goes
through `Saying`, and the app joins the pieces into one message. See
`crates/sdk/src/bot.rs`.

## Running echo

The smallest bot that is nonetheless a real one: message it and you have
exercised sign-in, both directions of the encryption, polling, acks and
replies against a live relay.

```sh
[ -f echo.key ] || openssl rand -hex 32 > echo.key   # once — this is its address

KNOCK_BOT_KEY=$(cat echo.key) \
KNOCK_BOT_NAME=Echo \
cargo run -p knock-echo
```

It prints its address first. Knock on it from the app.

| | |
| --- | --- |
| `KNOCK_BOT_KEY` | required — 32 bytes of hex. The bot's identity, so the address people knock on |
| `KNOCK_RELAY` | default `https://knockchat.org/api` |
| `KNOCK_BOT_STORE` | default `echo.json` — the device key and the cursor |
| `KNOCK_BOT_NAME` | what it calls itself. Unset leaves whatever the relay already holds |
| `KNOCK_BOT_AVATAR` | a path to an image to wear. Unset leaves whatever it already wears |

Name and picture are read on every start and written **only where the relay
disagrees**, so a restart that changes nothing sends nothing. Unsetting them
leaves them alone; taking them off is a one-off command:

```sh
knock-echo clear-name      # back to being shown as an address
knock-echo clear-avatar    # back to the identicon
```

A name sits beside an address, which is the thing that proves anything, so the
relay caps it at 32 characters and refuses invisible or text-reordering
characters.

### Staying up

The loop survives being wrong. A timeout, a relay restarting, a network that
goes away for a minute — each failure waits longer than the last, up to a
minute. A session that runs out is not a failure at all: the bot signs in again
and re-states its name and price, because a relay that forgot the session may
have forgotten the rest.

What it still returns for is a refusal about the *request* rather than the
moment, and a relay that is unreachable at startup. Both want a supervisor —
`restart: unless-stopped` or its equivalent.

## Keys to keep

**The identity key** decides the address. Hex, and only hex. If the bot will
ever charge strangers to knock, postage accumulates at its address — so make the
key somewhere you can also spend from, rather than with `openssl`.

**The store** (`echo.json`, or whatever `KNOCK_BOT_STORE` says) holds the device
key, and that decides whether anything can be *read*. Start again without it
and the bot is the same address, signs in, sees its queue — and cannot open a
message in it, because everyone is still sealing to the key it published
before.

`Files` is the store that ships. `Store` is a trait of five methods, so a bot
that wants Postgres or a secret manager instead writes its own.

## Tests

```sh
cargo test
```

runs everything that needs no network, including the crypto vectors. The tests
in `tests/sign_in.rs` and `tests/conversation.rs` talk to a real relay and are
ignored by default; `conversation` wants one started empty, since a knock
between two addresses can only happen once.

### Crypto vectors

The relay never opens a message, so the encryption has no server-side
counterpart to check against — only the app's TypeScript. Two implementations
of one format diverge silently: a bot that derives the key slightly differently
does not crash, it simply never reads anything again.

So the agreement is pinned by vectors generated from the app's own code. After
any change to the format, with
[knock-chat](https://github.com/kaichaosun/knock-chat) checked out beside this
repository:

```sh
cd ../knock-chat
node_modules/.bin/jiti ../knock-sdk-rust/tools/crypto-vectors.ts \
    ../knock-sdk-rust/crates/sdk/tests/vectors/crypto.json
cd ../knock-sdk-rust && cargo test
```

The generator refuses to write vectors that do not round-trip, and the tests
refuse to pass on vectors they cannot read.

## License

MIT
