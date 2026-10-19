//! Signing in.
//!
//! Three steps, and none of them the relay's idea of a bot — this is what a
//! phone does:
//!
//! 1. ask for a challenge, handing over this device's X25519 public key
//! 2. sign the challenge's message with the identity key
//! 3. swap the signature for a session token
//!
//! The encryption key rides along in step 1 on purpose. The relay certifies it
//! with the same signature that proves the address, so registering a device and
//! proving who owns it are one act rather than two — see the app's `lib/keys`
//! and the relay's `keys.rs`. It follows that a bot cannot sign in without
//! deciding on an encryption key first, which is the right way round: one that
//! signed in and then thought about decryption would be unreachable.

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::identity::Identity;

/// The relay the Knock app talks to, and where a bot goes unless told otherwise.
pub const PUBLIC_RELAY: &str = "https://knockchat.org/api";

/// A relay, and who we are to it.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

/// What a signed-in bot holds.
#[derive(Debug, Clone)]
pub struct Session {
    /// The relay's word for who signed, derived from the key rather than
    /// claimed by it.
    pub address: String,
    /// Carried as `Authorization: Bearer` on everything afterwards.
    pub token: String,
    /// When the relay will stop honouring it.
    pub expires_at: String,
}

#[derive(Serialize)]
struct ChallengeRequest<'a> {
    encryption_key: &'a str,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    nonce: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    nonce: &'a str,
    public_key: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct VerifyResponse {
    token: String,
    address: String,
    expires_at: String,
}

/// One envelope, as the relay hands it over. The body is still sealed.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    /// Stable for all time, and what to deduplicate on.
    pub id: String,
    pub from: String,
    pub to: String,
    /// Which room this came from, or absent for a direct message.
    #[serde(default)]
    pub group_id: Option<String>,
    /// Ciphertext. See [`crate::crypto::open`].
    pub body: String,
    pub created_at: String,
}

/// A queue, as far as it has been read.
#[derive(Debug, Clone, Deserialize)]
pub struct Fetched {
    pub messages: Vec<Envelope>,
    /// Hand this back next time, unchanged. Only the relay can tell whether it
    /// still means anything.
    pub next: String,
}

/// Somebody asking to be let in.
#[derive(Debug, Clone, Deserialize)]
pub struct Knock {
    pub id: String,
    pub from: String,
    /// Sealed exactly like a message; the relay cannot read this either.
    pub body: String,
}

/// The relay's answer to a send.
///
/// Only its name for the message is wanted: a message sent in pieces needs it,
/// because every piece after the first says which message it belongs to.
#[derive(Deserialize)]
struct Sent {
    id: String,
}

#[derive(Deserialize)]
struct KnockList {
    knocks: Vec<Knock>,
}

/// What an address publishes about itself.
#[derive(Debug, Clone, Deserialize)]
pub struct Published {
    pub policy: Policy,
    /// What it calls itself, if it has said.
    #[serde(default)]
    pub name: Option<String>,
    /// The fingerprint of the picture it wears, hex, if it wears one.
    #[serde(default)]
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// What a stranger must attach to reach it, in luna.
    pub amount_luna: u64,
}

/// The body every refusal from the relay carries.
#[derive(Deserialize)]
struct ApiError {
    error: String,
}

impl Client {
    /// `base` is the relay's root, with no trailing slash — `/v1/…` is appended.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Sign in, and come back knowing who we are.
    ///
    /// `device_secret` is this bot's X25519 secret — the one whose public half
    /// the relay is about to certify, and the one every message to this bot
    /// will be encrypted against. Keep it: sign in again with a different one
    /// and every conversation already open goes dark, because the other side
    /// is still sealing to the key it was given.
    pub async fn sign_in(
        &self,
        identity: &Identity,
        device_secret: &[u8; 32],
    ) -> Result<Session, Error> {
        let encryption_key = HEXLOWER.encode(&crypto::public_key(device_secret));

        let challenge: ChallengeResponse = self
            .post(
                "/v1/auth/challenge",
                &ChallengeRequest {
                    encryption_key: &encryption_key,
                },
            )
            .await?;

        let verified: VerifyResponse = self
            .post(
                "/v1/auth/verify",
                &VerifyRequest {
                    nonce: &challenge.nonce,
                    public_key: &identity.public_key_hex(),
                    // The message is signed exactly as handed over. Anything
                    // else — trimmed, re-encoded, rebuilt from its parts — is a
                    // signature over a different string, and the relay will say
                    // so rather than guess at what was meant.
                    signature: &identity.sign_hex(&challenge.message),
                },
            )
            .await?;

        // The relay says who signed; this checks. Both are derived from the
        // same public key by the same rule, so disagreeing means something is
        // wrong that no later request would make obvious — a relay on another
        // network, a key read from the wrong place, or one that is not telling
        // the truth. Whichever it is, a bot should not adopt a name it cannot
        // work out for itself.
        let mine = identity.address();
        if !crate::address::same(&mine, &verified.address) {
            return Err(Error::WrongAddress {
                derived: mine,
                relay: verified.address,
            });
        }

        Ok(Session {
            address: verified.address,
            token: verified.token,
            expires_at: verified.expires_at,
        })
    }

    /// What this bot asks of strangers, in luna.
    ///
    /// Zero is what most bots want: a service nobody can reach is not a
    /// service, and postage exists to make bulk messaging expensive rather than
    /// to charge for being spoken to. A bot that does want paying sets this and
    /// the knock becomes the invoice.
    pub async fn set_policy(&self, token: &str, amount_luna: u64) -> Result<(), Error> {
        #[derive(Serialize)]
        struct PolicyRequest {
            amount_luna: u64,
        }
        self.send(
            reqwest::Method::PUT,
            "/v1/policy",
            token,
            Some(&PolicyRequest { amount_luna }),
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    /// Ask to be let in.
    ///
    /// What the app does on somebody's behalf, and what a test has to do by
    /// hand to give a bot anybody to talk to. Postage rides along where the
    /// recipient asks for any; a bot that asks for none needs none.
    pub async fn knock(&self, token: &str, from: &str, to: &str, body: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct KnockRequest<'a> {
            from: &'a str,
            to: &'a str,
            body: &'a str,
        }
        self.send(
            reqwest::Method::POST,
            "/v1/knocks",
            token,
            Some(&KnockRequest { from, to, body }),
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    /// What this bot calls itself.
    ///
    /// Unverified by anybody, and shown next to an address that is — which is
    /// why the relay refuses names carrying invisible or text-reordering
    /// characters, and caps them at 32. A name that could hide characters or
    /// reorder the text around it would defeat the one check a reader has.
    ///
    /// Blank clears it. Whatever the relay makes of the name comes back in its
    /// own words, so a bot named badly says so at startup rather than running
    /// anonymously.
    pub async fn set_name(&self, token: &str, name: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct ProfileRequest<'a> {
            name: &'a str,
        }
        self.send(
            reqwest::Method::PUT,
            "/v1/profile",
            token,
            Some(&ProfileRequest { name }),
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    /// The picture this bot wears.
    ///
    /// Raw bytes of a JPEG, PNG, WebP or GIF — whatever a phone's picker
    /// produces — capped by the relay at a megabyte. It decodes and re-encodes
    /// rather than serving what it was sent, so nothing about the file survives
    /// but the picture in it.
    pub async fn set_avatar(&self, token: &str, image: Vec<u8>) -> Result<(), Error> {
        let response = self
            .http
            .put(format!("{}/v1/profile/avatar", self.base))
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(image)
            .send()
            .await
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        Self::read("/v1/profile/avatar", response)
            .await
            .map(|_: serde_json::Value| ())
    }

    /// Stop wearing a picture, falling back to the identicon the address
    /// always had.
    ///
    /// Forgets the pointer, not the image: somebody else may be wearing the
    /// same one, and the relay sweeps unreferenced pictures itself.
    pub async fn clear_avatar(&self, token: &str) -> Result<(), Error> {
        self.send::<(), serde_json::Value>(
            reqwest::Method::DELETE,
            "/v1/profile/avatar",
            token,
            None,
        )
        .await
        .map(|_| ())
    }

    /// Go back to having no name, so an address is shown as an address.
    ///
    /// Blank is how the relay spells this, but `set_name(token, "")` at a call
    /// site reads like a mistake rather than an intention.
    pub async fn clear_name(&self, token: &str) -> Result<(), Error> {
        self.set_name(token, "").await
    }

    /// What the relay currently publishes about an address.
    ///
    /// Asked of ourselves at startup, so that [`crate::bot::Presence`] can put
    /// right only what is actually wrong. One request tells all three.
    pub async fn published(&self, token: &str, address: &str) -> Result<Published, Error> {
        self.get(&format!("/v1/reachability/{}", urlencode(address)), token)
            .await
    }

    /// Who is waiting to be let in.
    pub async fn knocks(&self, token: &str) -> Result<Vec<Knock>, Error> {
        let list: KnockList = self.get("/v1/knocks", token).await?;
        Ok(list.knocks)
    }

    /// Let one in. This is what opens the channel a reply travels down.
    pub async fn accept_knock(&self, token: &str, id: &str) -> Result<(), Error> {
        self.send::<(), serde_json::Value>(
            reqwest::Method::POST,
            &format!("/v1/knocks/{id}/accept"),
            token,
            None,
        )
        .await
        .map(|_| ())
    }

    /// Whatever has arrived since `cursor`.
    pub async fn fetch(
        &self,
        token: &str,
        me: &str,
        cursor: Option<&str>,
    ) -> Result<Fetched, Error> {
        let mut path = format!("/v1/messages?to={}", urlencode(me));
        if let Some(cursor) = cursor {
            path.push_str(&format!("&cursor={}", urlencode(cursor)));
        }
        self.get(&path, token).await
    }

    /// Tell the relay what has been read, which is what lets it forget.
    ///
    /// Separate from fetching on purpose: a message is delivered when it has
    /// been *handled*, not when it arrived, and acking on arrival would drop
    /// anything a crash interrupted.
    pub async fn ack(&self, token: &str, me: &str, cursor: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct Ack<'a> {
            to: &'a str,
            cursor: &'a str,
        }
        self.send(
            reqwest::Method::POST,
            "/v1/messages/ack",
            token,
            Some(&Ack { to: me, cursor }),
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    /// Send a sealed body. The channel has to be open, which is what accepting
    /// a knock is for.
    ///
    /// Answers with the relay's name for it, which is what a message sent in
    /// pieces needs: every piece after the first says which message it belongs
    /// to, and that is the id the first was given. See `Part` in the app.
    pub async fn say(
        &self,
        token: &str,
        from: &str,
        to: &str,
        body: &str,
    ) -> Result<String, Error> {
        #[derive(Serialize)]
        struct SendRequest<'a> {
            from: &'a str,
            to: &'a str,
            body: &'a str,
        }
        self.send(
            reqwest::Method::POST,
            "/v1/messages",
            token,
            Some(&SendRequest { from, to, body }),
        )
        .await
        .map(|sent: Sent| sent.id)
    }

    /// Say something in a room.
    ///
    /// Not sealed, and not a mistake: a room message is written once and fanned
    /// out to every member, so there is no single recipient to seal it to. The
    /// app says as much to anybody joining — "Group messages aren't encrypted."
    /// A bot in a room is reading and writing in the open, and so is the relay.
    pub async fn say_in_group(&self, token: &str, room: &str, body: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct SayRequest<'a> {
            body: &'a str,
        }
        self.send(
            reqwest::Method::POST,
            &format!("/v1/groups/{}/messages", urlencode(room)),
            token,
            Some(&SayRequest { body }),
        )
        .await
        .map(|sent: Sent| sent.id)
    }

    /// Open a room.
    ///
    /// Free to join and open to anybody, which is the only shape a bot has any
    /// business creating: one that charged would be collecting money, and one
    /// that needed approving would need somebody watching it.
    pub async fn create_group(&self, token: &str, name: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct CreateGroup<'a> {
            name: &'a str,
            join_price_luna: u64,
            requires_approval: bool,
        }
        #[derive(Deserialize)]
        struct Made {
            id: String,
        }
        let made: Made = self
            .send(
                reqwest::Method::POST,
                "/v1/groups",
                token,
                Some(&CreateGroup {
                    name,
                    join_price_luna: 0,
                    requires_approval: false,
                }),
            )
            .await?;
        Ok(made.id)
    }

    /// Ask to be let into a room.
    ///
    /// Only rooms that cost nothing: postage would mean spending, and a bot
    /// that could pay its own way into rooms is a bot that can be made to spend
    /// by whoever tells it which rooms to join. What the relay says — full,
    /// paid, waiting on the owner — comes back in its own words.
    pub async fn join_group(&self, token: &str, room: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct JoinGroup {
            postage: Option<()>,
        }
        self.send(
            reqwest::Method::POST,
            &format!("/v1/groups/{}/join", urlencode(room)),
            token,
            Some(&JoinGroup { postage: None }),
        )
        .await
        .map(|_: serde_json::Value| ())
    }

    /// The certificate `address` published, unverified.
    ///
    /// Unverified because verifying it is not this layer's business and must
    /// not be skippable by accident — see [`crate::keys::Certificate::key_for`],
    /// which is the only way to get a key out of one.
    pub async fn certificate(
        &self,
        token: &str,
        address: &str,
    ) -> Result<crate::keys::Certificate, Error> {
        self.get(&format!("/v1/keys/{}", urlencode(address)), token)
            .await
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str, token: &str) -> Result<T, Error> {
        self.send::<(), T>(reqwest::Method::GET, path, token, None)
            .await
    }

    async fn send<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&B>,
    ) -> Result<T, Error> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        Self::read(path, response).await
    }

    async fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        Self::read(path, response).await
    }

    /// What the relay said, or why it would not say it.
    async fn read<T: for<'de> Deserialize<'de>>(
        at: &str,
        response: reqwest::Response,
    ) -> Result<T, Error> {
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Unreachable(e.to_string()))?;

        if !status.is_success() {
            // The relay's own words where it gave any. Its refusals are written
            // to be read — "signature does not match", "no open channel with
            // that address" — and summarising them into a status code would
            // throw away the only part that says what to do about it.
            let said = serde_json::from_str::<ApiError>(&text)
                .map(|body| body.error)
                .unwrap_or_else(|_| format!("relay answered {}", status.as_u16()));
            return Err(Error::Refused {
                status: status.as_u16(),
                said,
                at: at.to_string(),
            });
        }

        // Several of these are 204s, which carry nothing, and serde will not
        // make a `Value` out of an empty string. The callers that ignore the
        // answer are exactly the ones that get no body.
        serde_json::from_str(if text.is_empty() { "null" } else { &text })
            .map_err(|e| Error::Unexpected(format!("{at}: {e}")))
    }
}

/// Enough of one to carry an address, which has spaces in it, through a query
/// string. Nothing else here needs escaping.
fn urlencode(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            other => other
                .to_string()
                .bytes()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
}

impl Error {
    /// Whether asking again later might get a different answer.
    ///
    /// A timeout, a rate limit, or the relay falling over: none of them are
    /// about what was asked, so a bot that stopped for one would be a bot that
    /// stops for a blip. Everything else means what it says.
    pub fn worth_retrying(&self) -> bool {
        match self {
            Error::Unreachable(_) => true,
            Error::Refused { status, .. } => *status == 408 || *status == 429 || *status >= 500,
            Error::Unexpected(_) | Error::WrongAddress { .. } => false,
        }
    }

    /// Whether the session has run out and signing in again would help.
    pub fn session_expired(&self) -> bool {
        matches!(self, Error::Refused { status: 401, .. })
    }
}

/// Why a call to the relay did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The relay could not be reached at all.
    #[error("could not reach the relay: {0}")]
    Unreachable(String),
    /// The relay answered, and said no.
    ///
    /// The status is kept as well as the words, because what a caller should do
    /// about a refusal depends on which it is: 408 and 5xx are the relay having
    /// a moment and are worth trying again, 401 means the session has run out,
    /// and the rest are about the request and will say the same thing however
    /// many times they are asked.
    ///
    /// And the path, because "the relay answered 408" is a sentence nobody can
    /// act on. A timeout on `/v1/messages` and one on `/v1/knocks` are
    /// different problems, and the first thing anybody asks is which.
    #[error("{said} ({status} from {at})")]
    Refused {
        status: u16,
        said: String,
        at: String,
    },
    /// The relay answered with something this does not understand — a version
    /// that has moved on, or something else entirely at that address.
    #[error("the relay said something unexpected: {0}")]
    Unexpected(String),
    /// The relay named an address this key does not derive to.
    #[error("this key is {derived}, and the relay called it {relay}")]
    WrongAddress { derived: String, relay: String },
}
