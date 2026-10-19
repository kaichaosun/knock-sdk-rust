//! The loop.
//!
//! Let people in, read what they said, answer, remember how far you got. A bot
//! is that, repeated, and the point of this module is that a bot author writes
//! none of it — they write [`Handler`], which is one method and knows nothing
//! about cursors or nonces.
//!
//! The order within a turn is deliberate. Knocks are answered first, because
//! somebody who cannot get in has nothing to say and no reply can reach them.
//! The cursor is saved last, after every message in the batch has been handled,
//! so a crash costs a repeat rather than a silence — a message answered twice
//! is a bot that looks confused, and one answered never is a bot that looks
//! broken. Those are not the same cost.

use std::future::Future;
use std::time::Duration;

use crate::crypto;
use crate::identity::Identity;
use crate::session::{Client, Envelope, Error, Session};
use crate::store::Store;

/// What a bot does with what it was told.
pub trait Handler: Send + Sync {
    /// Answer `said`, or don't.
    ///
    /// `None` says nothing, which is a real answer: not every message wants a
    /// reply, most of a room is not addressed to the bot, and a bot that
    /// answers its own kind is a loop with two participants.
    ///
    /// Async because anything past echo does I/O — asks a model, reads a
    /// database, calls somebody's API — and a handler that had to block would
    /// stall the loop that feeds it.
    ///
    /// `saying` is for a handler that would rather not wait until it has
    /// finished. Anything put there is sent while the rest is still being
    /// written, and what comes back at the end is the remainder — so a handler
    /// that ignores it works exactly as it always did, and one that uses it
    /// returns `None`.
    fn reply(
        &self,
        message: &Heard,
        saying: &Saying,
    ) -> impl Future<Output = Option<String>> + Send;
}

/// Where a handler puts an answer it is still writing.
///
/// Each piece becomes a message of its own, joined back into one by the app —
/// see `Part` in its `lib/payload`. So this is not a different kind of message,
/// it is the same long answer arriving sooner.
///
/// The channel holds one. A model writes faster than a relay accepts, and a
/// queue would let it run ahead and then send a burst; waiting here is what
/// paces the two to each other.
///
/// A handler that says anything this way leaves the message open, and the SDK
/// closes it with an empty piece once the handler returns.
pub struct Saying {
    pieces: tokio::sync::mpsc::Sender<String>,
}

impl Saying {
    /// Send what has been written since the last time.
    ///
    /// Quiet about a bot that has stopped listening: the answer is on its way
    /// out either way, and a handler mid-sentence has nothing useful to do
    /// about it.
    pub async fn piece(&self, said: impl Into<String>) {
        let _ = self.pieces.send(said.into()).await;
    }

    /// Say that an answer is coming, before there is any of it.
    ///
    /// Opens the message with nothing in it, which the app draws as the three
    /// dots and no bubble. Worth a message of its own because the alternative
    /// is silence: a model on somebody's own machine can think for half a
    /// minute, and a bot that has said nothing is indistinguishable from a bot
    /// that is not running.
    ///
    /// Only the first thing said counts as one: an opener after an answer has
    /// started would be a blank message in the middle of it, and is dropped.
    pub async fn working(&self, parse: Option<&str>) {
        let opener = match parse {
            Some("markdown") => markdown(""),
            _ => String::new(),
        };
        self.piece(opener).await;
    }
}

/// Whether a piece is one of those openers: a message with no words in it.
///
/// Held back like any other it would arrive after the thing it was meant to
/// come before, so this is what tells the two apart.
fn opens_only(said: &str) -> bool {
    words_in(said)
        .unwrap_or_else(|| said.to_string())
        .is_empty()
}

/// What the app puts in front of anything that is not words.
///
/// A unit separator, a version, a newline, then JSON. Plain text is sent as
/// itself and carries no frame at all, so the presence of this prefix is the
/// whole test — the same one the app applies when it decodes.
const FRAME: &str = "\u{1f}knock1\n";

/// A message, opened.
#[derive(Debug, Clone)]
pub struct Heard {
    /// Who said it.
    pub from: String,
    /// Which room, or `None` for a direct message.
    pub group_id: Option<String>,
    /// What they said, decrypted.
    pub said: String,
    /// The relay's name for it, stable for all time.
    pub id: String,
    /// A room this message pointed the bot at, which it has already joined.
    ///
    /// Set only for direct messages: an invite shared into a room is one member
    /// telling another about somewhere else, not somebody bringing the bot
    /// along.
    pub invited: Option<Invited>,
}

/// A room somebody has pointed the bot at.
#[derive(Debug, Clone)]
pub struct Invited {
    pub room: String,
    /// What the sender's app called it — a label they were shown, not checked
    /// against the room itself.
    pub name: Option<String>,
}

/// The words inside a framed text payload, if that is what this is.
///
/// The app sends plain writing unframed and frames it only to say something
/// about how it should be read — see `Parse` in the app's `lib/payload`. What
/// it says is the sender's business and not a bot's, so only the words come
/// back out.
fn words_in(said: &str) -> Option<String> {
    let json = said.strip_prefix(FRAME)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    if value.get("kind")?.as_str()? != "text" {
        return None;
    }
    Some(value.get("text")?.as_str()?.to_string())
}

/// The most the relay will take in one message body.
///
/// Its own `MAX_BODY_LEN`. Named here rather than asked for, because a bot that
/// discovered it by being refused has already lost the message.
const MOST_BODY: usize = 4096;

/// What a direct message may hold once it is sealed.
///
/// The limit is on what the relay receives, and for a direct message that is
/// base64 of a version byte, a nonce, the ciphertext and its tag — so the words
/// have to fit in three quarters of it, less the framing. A room's messages are
/// not sealed and get the whole of it.
const MOST_SEALED: usize = MOST_BODY / 4 * 3 - 41;

/// A reply, cut into what the relay will take.
struct Split {
    /// Whether the words are to be read as markdown.
    markdown: bool,
    /// In order. One piece is the overwhelmingly common case.
    pieces: Vec<String>,
}

/// A stand-in for the head id while pieces are being measured.
///
/// The first piece has no head — it is the one being named — but every other
/// one does, and a uuid is a fixed thirty-six characters. Reserving room for it
/// on every piece costs the first a few dozen bytes it could have used, and
/// saves a piece being measured without a field it will be sent with.
const HEAD_SHAPE: &str = "00000000-0000-0000-0000-000000000000";

/// Cut `reply` into pieces the relay will take, in order.
///
/// The relay caps a message body and refuses anything over it outright, so a
/// long answer sent whole is a long answer nobody gets. The app puts the pieces
/// back together before drawing them — see `joined` in its `lib/messages` — so
/// what arrives is one bubble with one id, and a piece is not required to make
/// sense on its own. That is what lets this break wherever it likes: a fenced
/// block cut in half is whole again by the time anything reads it.
///
/// It still prefers a line ending, because a piece *is* shown on its own for as
/// long as the next one is in flight.
fn split(reply: String, budget: usize) -> Split {
    let (markdown, words) = match words_in(&reply) {
        Some(words) => (true, words),
        None => (false, reply),
    };

    let whole = Split {
        markdown,
        pieces: vec![words],
    };
    // Nearly always. An answer that fits travels exactly as it did before any
    // of this existed — unframed, when it has nothing to declare.
    if pieced(&whole, 0, None).len() <= budget {
        return whole;
    }
    let words = whole.pieces.into_iter().next().expect("the whole of it");

    let mut pieces = Vec::new();
    let mut rest = words.as_str();
    while !rest.is_empty() {
        if one_piece(rest, markdown, budget) {
            pieces.push(rest.to_string());
            break;
        }
        // Down from the budget rather than up from nothing: escaping decides
        // how much of a piece survives into JSON, and the only honest way to
        // ask is to build the thing and measure it.
        let mut at = edge(rest, budget);
        while at > 0 && !one_piece(&rest[..at], markdown, budget) {
            at = edge(rest, at * 3 / 4);
        }
        if at == 0 {
            at = rest.chars().next().map(char::len_utf8).unwrap_or(1);
        }
        // Back to the last line ending, unless that throws away most of the
        // piece — a wall of text with no newline in it still has to move.
        let at = rest[..at]
            .rfind('\n')
            .map(|found| found + 1)
            .filter(|found| found * 2 > at)
            .unwrap_or(at);
        pieces.push(rest[..at].to_string());
        rest = &rest[at..];
    }
    Split { markdown, pieces }
}

/// One answer on its way out, however many messages that takes.
///
/// Held across the whole of a reply rather than built per message, because the
/// numbering is what ties the pieces together: the first is named by the relay,
/// every one after it says that name, and only the very last says it is the
/// last. A handler that answers in one go and one that writes as it thinks both
/// come through here, and the difference is only how many times `say` is
/// called.
struct Outgoing {
    /// The room this is being said in, or `None` for a direct message.
    room: Option<String>,
    /// Who it is for, when it is direct.
    to: String,
    /// What to seal with, when it is direct.
    key: Option<[u8; 32]>,
    /// The relay's name for the first message, once there is one.
    head: Option<String>,
    /// How many have gone.
    at: usize,
}

impl Outgoing {
    /// Say `reply`, in as many messages as it needs.
    ///
    /// `last` marks the end of the whole answer, not of this call — a handler
    /// still writing passes false, and the app keeps the message open.
    async fn say<S: Store, H: Handler>(
        &mut self,
        bot: &Bot<S, H>,
        reply: String,
        last: bool,
    ) -> Result<(), Error> {
        let budget = if self.room.is_some() {
            MOST_BODY
        } else {
            MOST_SEALED
        };
        let answer = split(reply, budget);
        let pieces = answer.pieces.len();
        for at in 0..pieces {
            let end = last && at + 1 == pieces;
            let body = body_of(
                &answer.pieces[at],
                answer.markdown,
                self.head.as_deref(),
                self.at,
                end,
            );
            let id = match &self.room {
                Some(room) => {
                    bot.client
                        .say_in_group(&bot.session.token, room, &body)
                        .await?
                }
                None => {
                    let key = self.key.expect("a direct message was opened with a key");
                    let sealed = crypto::seal(
                        &body,
                        &key,
                        &bot.session.address,
                        &self.to,
                        &crypto::nonce(),
                    );
                    bot.client
                        .say(&bot.session.token, &bot.session.address, &self.to, &sealed)
                        .await?
                }
            };
            self.head.get_or_insert(id);
            self.at += 1;
        }
        Ok(())
    }
}

/// The body one message of an answer travels as.
///
/// The first and only message of an answer carries no marker at all, and no
/// frame either unless its words need one — which is every message anybody
/// types, and most of what a bot says.
fn body_of(words: &str, markdown: bool, head: Option<&str>, at: usize, end: bool) -> String {
    if at == 0 && end {
        return if markdown {
            frame_of(words, true, None)
        } else {
            words.to_string()
        };
    }
    frame_of(words, markdown, Some((head, at, end)))
}

/// The body one piece travels as.
fn pieced(split: &Split, at: usize, head: Option<&str>) -> String {
    // Alone and with nothing to declare is a message like any other, and goes
    // as itself. Only something to say about the words puts a frame on the wire.
    if split.pieces.len() == 1 && !split.markdown {
        return split.pieces[0].clone();
    }
    let part = (split.pieces.len() > 1).then(|| (head, at, at + 1 == split.pieces.len()));
    frame_of(&split.pieces[at], split.markdown, part)
}

/// Words, framed the way the app reads them.
fn frame_of(words: &str, markdown: bool, part: Option<(Option<&str>, usize, bool)>) -> String {
    let mut body = serde_json::Map::new();
    body.insert("kind".into(), "text".into());
    if markdown {
        body.insert("parse".into(), "markdown".into());
    }
    if let Some((head, at, end)) = part {
        let mut marker = serde_json::Map::new();
        if let Some(head) = head {
            marker.insert("head".into(), head.into());
        }
        marker.insert("at".into(), at.into());
        if end {
            marker.insert("end".into(), true.into());
        }
        body.insert("part".into(), serde_json::Value::Object(marker));
    }
    body.insert("text".into(), words.into());
    format!("{FRAME}{}", serde_json::Value::Object(body))
}

/// Whether `words` fit one piece.
///
/// Measured with the most framing a piece can be given — a head, a high index,
/// an end flag — so one that fits here fits wherever in the answer it lands.
fn one_piece(words: &str, markdown: bool, budget: usize) -> bool {
    frame_of(words, markdown, Some((Some(HEAD_SHAPE), usize::MAX, true))).len() <= budget
}

/// The largest index at or below `at` that does not split a character.
fn edge(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// Words to be read as markdown, framed the way the app expects.
///
/// A dimension of a text message rather than a kind of its own: what travels is
/// still the words, and anything that only wants those — a chat row, a quote, a
/// notification — reads them without knowing this was here.
///
/// Not every reply wants it. A bot's own sentence is a sentence; this is for
/// one that is genuinely written in markdown, which for now means what a
/// language model hands back.
pub fn markdown(said: &str) -> String {
    let framed = serde_json::json!({ "kind": "text", "parse": "markdown", "text": said });
    format!("{FRAME}{framed}")
}

/// The room an invite names, if this is one.
///
/// Two shapes, because people send both. The app shares a room as a frame with
/// the id and a name in it; somebody who copied the link out and pasted it
/// sends text with a uuid somewhere inside. The id is the part that survives
/// being wrapped by another app, trailed by punctuation, or rearranged — the
/// same reasoning as `groupIdFrom` in the app.
fn invite_in(said: &str) -> Option<Invited> {
    if let Some(json) = said.strip_prefix(FRAME) {
        let value: serde_json::Value = serde_json::from_str(json).ok()?;
        if value.get("kind")?.as_str()? != "invite" {
            return None;
        }
        return Some(Invited {
            room: value.get("group")?.as_str()?.to_string(),
            name: value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string),
        });
    }
    uuid_in(said).map(|room| Invited { room, name: None })
}

/// The first uuid in `text`, lowercased.
///
/// Hand-written rather than a regex crate: one shape, 8-4-4-4-12, and the
/// alternative is a dependency and a compiled pattern for a scan that fits on a
/// screen.
fn uuid_in(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    const SHAPE: [usize; 5] = [8, 4, 4, 4, 12];

    'start: for from in 0..chars.len() {
        let mut at = from;
        let mut found = String::with_capacity(36);
        for (part, len) in SHAPE.iter().enumerate() {
            if part > 0 {
                if chars.get(at) != Some(&'-') {
                    continue 'start;
                }
                found.push('-');
                at += 1;
            }
            for _ in 0..*len {
                match chars.get(at) {
                    Some(c) if c.is_ascii_hexdigit() => {
                        found.push(c.to_ascii_lowercase());
                        at += 1;
                    }
                    _ => continue 'start,
                }
            }
        }
        return Some(found);
    }
    None
}

impl Heard {
    /// What was said, if it was words.
    ///
    /// `None` for a payment, a shared contact, a reaction, a gift, an invite —
    /// everything the app frames. A bot that only deals in prose should answer
    /// those by saying it cannot rather than by guessing, and one that echoes
    /// must not hand a frame back: the app would draw the card again, from the
    /// bot, which is a payment nobody made.
    ///
    /// Recognising the frame is not parsing it. What is inside stays unread
    /// until something needs it.
    pub fn text(&self) -> Option<&str> {
        (!self.said.starts_with(FRAME)).then_some(self.said.as_str())
    }

    /// Whether this was one of the app's cards rather than words.
    pub fn is_framed(&self) -> bool {
        self.said.starts_with(FRAME)
    }
}

/// How long to wait between empty turns.
///
/// Polling, because the relay pushes only to browsers. Slow enough not to be
/// rude to a relay carrying real traffic, quick enough that a reply feels like
/// one — a person waits a second or two for a bot without minding.
pub const IDLE: Duration = Duration::from_secs(2);

/// The longest a failing loop waits before asking again.
///
/// A relay that has been down for a minute may be down for an hour, and there
/// is nothing to be gained by asking every two seconds throughout. Short enough
/// that a bot is answering again within a minute of the relay coming back.
pub const PATIENCE: Duration = Duration::from_secs(60);

/// What a bot publishes about itself.
///
/// Both of these live on the relay rather than in this process, which is why
/// they are re-stated on every start: a bot renamed by hand, or one meant to be
/// free that finds itself charging, has no way to notice otherwise. Two
/// requests at startup is a cheap way to make the running configuration the one
/// in front of you.
#[derive(Debug, Clone, Default)]
pub struct Presence {
    /// What to call itself, or `None` to leave whatever is already set.
    ///
    /// `None` leaves it alone rather than clearing it: a bot with no opinion
    /// about its name should not silently take one away. Clearing is a
    /// deliberate act and has its own call — see [`Client::clear_name`].
    pub name: Option<String>,
    /// What to ask of strangers, in luna.
    ///
    /// Zero by default, and that is usually right: postage exists to make
    /// sending to thousands of people expensive, and a service nobody can
    /// afford to try is not a service. A bot that does want paying sets this,
    /// and the knock becomes the invoice.
    pub price_luna: u64,
    /// The picture to wear, as the bytes of an image file, or `None` to leave
    /// whatever is already worn.
    ///
    /// Bytes rather than a path, because the SDK has no business reading files —
    /// a bot may keep its picture in a config map, an object store or its own
    /// binary, and only it knows which.
    pub avatar: Option<Vec<u8>>,
}

/// How many luna are a NIM.
///
/// Five decimal places, and the app's `LUNA_PER_NIM` says the same. Postage is
/// set here in luna because that is what the relay stores; people think in NIM,
/// which is what [`luna`] is for.
pub const LUNA_PER_NIM: u64 = 100_000;

/// The luna in an amount of NIM written the way a person writes it.
///
/// Parsed digit by digit rather than through a float. This is money, and the
/// obvious `nim.parse::<f64>()? * 100_000.0` is exact for the amounts anybody
/// will type and quietly wrong for the ones they won't — a rounding mode is not
/// something a price should have.
///
/// More than five decimal places is refused rather than truncated. Somebody who
/// wrote `0.000001` meant something, and silently charging them nothing for it
/// is worse than saying it cannot be done.
pub fn luna(nim: &str) -> Result<u64, String> {
    let nim = nim.trim();
    let (whole, fraction) = match nim.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (nim, ""),
    };
    let bad = || format!("`{nim}` is not an amount of NIM");

    if whole.is_empty() && fraction.is_empty() {
        return Err(bad());
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    if fraction.len() > 5 {
        return Err(format!(
            "`{nim}` is finer than a luna — five decimal places is all there is"
        ));
    }

    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    // Padded, not parsed as written: `.5` is half a NIM, not five luna.
    let fraction: u64 = format!("{fraction:0<5}").parse().map_err(|_| bad())?;

    whole
        .checked_mul(LUNA_PER_NIM)
        .and_then(|luna| luna.checked_add(fraction))
        .ok_or_else(|| format!("`{nim}` is more NIM than there will ever be"))
}

/// A price, as the person who set it wrote it.
///
/// The startup line is where an operator checks that a change took effect, and
/// `asking 1000000 luna` is not a number anybody set — they set ten.
fn priced(price_luna: u64) -> String {
    if price_luna == 0 {
        return "nothing".into();
    }
    let (whole, fraction) = (price_luna / LUNA_PER_NIM, price_luna % LUNA_PER_NIM);
    if fraction == 0 {
        format!("{whole} NIM")
    } else {
        format!("{whole}.{fraction:05} NIM")
    }
}

/// A signed-in bot, ready to run.
pub struct Bot<S: Store, H: Handler> {
    client: Client,
    /// Kept, because a session runs out and the only way to get another is to
    /// sign the challenge again.
    identity: Identity,
    /// Kept for the same reason as the identity: a relay that lost its state
    /// has forgotten all of this, and signing in again is exactly when it needs
    /// saying a second time.
    presence: Presence,
    session: Session,
    store: S,
    handler: H,
}

impl<S: Store, H: Handler> Bot<S, H> {
    /// Sign in and make this address reachable.
    ///
    /// [`Presence`] is re-stated on every start, for the reason given there.
    pub async fn start(
        client: Client,
        identity: Identity,
        store: S,
        handler: H,
        presence: Presence,
    ) -> Result<Self, Error> {
        let session = client.sign_in(&identity, &store.device_secret()).await?;
        publish(&client, &session.token, &session.address, &presence).await?;

        Ok(Self {
            client,
            identity,
            presence,
            session,
            store,
            handler,
        })
    }

    /// Ask to be let into a room, so its messages start arriving.
    ///
    /// A bot cannot follow an invite link — there is no browser to open one in
    /// — so somebody has to tell it which room, by id.
    ///
    /// A one-off act, and not something to repeat at startup. Membership lives
    /// on the relay, so a bot that has joined is still in the room after a
    /// restart; and an owner can remove it, which a bot that rejoined on every
    /// start would silently undo. A bot that cannot be removed from a room is
    /// worse than one that is occasionally missing from it.
    ///
    /// Already being a member is still not an error — running the command twice
    /// is an ordinary thing to do.
    pub async fn join(&self, room: &str) -> Result<(), Error> {
        match self.client.join_group(&self.session.token, room).await {
            Ok(()) => {
                println!("joined {room}");
                Ok(())
            }
            Err(Error::Refused { status: 409, .. }) => {
                println!("already in {room}");
                Ok(())
            }
            Err(trouble) => Err(trouble),
        }
    }

    /// Who this bot is, as the relay derived it.
    pub fn address(&self) -> &str {
        &self.session.address
    }

    /// One turn: let people in, answer what has arrived, remember where we got
    /// to. Returns how many messages were handled.
    pub async fn turn(&mut self) -> Result<usize, Error> {
        self.answer_knocks().await?;

        let fetched = self
            .client
            .fetch(
                &self.session.token,
                &self.session.address,
                self.store.cursor().as_deref(),
            )
            .await?;

        let mut handled = 0;
        for envelope in &fetched.messages {
            match self.handle(envelope).await {
                Ok(true) => handled += 1,
                Ok(false) => {}
                // Nothing reached the relay, so nothing was said and nothing
                // was lost. Leave the cursor where it is and let the loop try
                // the whole turn again.
                Err(gone @ Error::Unreachable(_)) => return Err(gone),
                // The relay answered, and answering is the part that failed —
                // the reply may well have landed. Carrying on is the important
                // half: a message that stops the cursor is a message answered
                // again on the next turn, and again after that. That is how a
                // timeout on a reply became somebody's inbox full of the same
                // word. One lost answer beats an endless one.
                Err(trouble) => eprintln!("could not answer {}: {trouble}", envelope.from),
            }
        }

        // Only now. Everything above has either been answered or deliberately
        // passed over, and a cursor moved before that is a message lost.
        self.store.set_cursor(&fetched.next);
        self.client
            .ack(&self.session.token, &self.session.address, &fetched.next)
            .await?;
        Ok(handled)
    }

    /// Run until something goes wrong that is worth stopping for.
    /// Run, and keep running.
    ///
    /// A bot is a thing you leave alone for weeks, so the loop's job is not to
    /// be correct once but to survive being wrong: a relay restarting, a
    /// timeout, a network that goes away for a minute. Those are not reasons to
    /// stop, and the first version of this stopped for all of them — one 408
    /// and the bot was gone, with the next message nobody answered arriving
    /// hours later.
    ///
    /// What it will not do is spin. Each failure waits longer than the last, up
    /// to [`PATIENCE`], so a relay that is down is asked occasionally rather
    /// than hammered while it tries to come back.
    ///
    /// It still returns for the things retrying cannot fix — a refusal about
    /// the request rather than the moment. Those want somebody to look.
    pub async fn run(&mut self) -> Result<(), Error> {
        let mut waiting = IDLE;
        loop {
            match self.turn().await {
                Ok(0) => {
                    waiting = IDLE;
                    tokio::time::sleep(IDLE).await;
                }
                Ok(_) => waiting = IDLE,
                Err(trouble) if trouble.worth_retrying() => {
                    eprintln!("{trouble} — trying again in {}s", waiting.as_secs());
                    tokio::time::sleep(waiting).await;
                    waiting = (waiting * 2).min(PATIENCE);
                }
                Err(trouble) if trouble.session_expired() => {
                    // Not a failure so much as time passing. The relay hands
                    // out sessions that end, and a bot outlives several of
                    // them; signing in again is what a phone does too, without
                    // telling anybody.
                    eprintln!("{trouble} — signing in again");
                    self.session = self
                        .client
                        .sign_in(&self.identity, &self.store.device_secret())
                        .await?;
                    // And say again what this bot is, because a relay that
                    // forgot the session may have forgotten the rest: coming
                    // back nameless is survivable, coming back charging for
                    // what was free is not.
                    publish(
                        &self.client,
                        &self.session.token,
                        &self.session.address,
                        &self.presence,
                    )
                    .await?;
                    waiting = IDLE;
                }
                Err(trouble) => return Err(trouble),
            }
        }
    }

    /// Let everybody in.
    ///
    /// Every knock, without reading it. A bot has no door policy to apply — it
    /// exists to be talked to — and the postage it asks for has already been
    /// paid by the time one of these is waiting.
    ///
    /// Said out loud, because being let in is the one thing here that happens
    /// *to* a bot rather than being asked of it, and an operator looking at a
    /// quiet bot needs to tell "nobody knocked" from "nobody was let in".
    /// Printed rather than raised as an event: it is one line, and a bot
    /// wanting structured logs would want them for a great deal more than
    /// this.
    async fn answer_knocks(&self) -> Result<(), Error> {
        for knock in self.client.knocks(&self.session.token).await? {
            self.client
                .accept_knock(&self.session.token, &knock.id)
                .await?;
            println!("let in {} (knock {})", knock.from, knock.id);
        }
        Ok(())
    }

    /// Open one message and answer it. `false` for one that was not for us to
    /// answer — our own words coming back, or a body we cannot read.
    async fn handle(&self, envelope: &Envelope) -> Result<bool, Error> {
        // A room fans a message out to every member, this bot included. Without
        // this a bot in a room answers itself, and then answers the answer.
        if envelope.from == self.session.address {
            return Ok(false);
        }

        // A room's messages are not sealed — one body is written and fanned out
        // to every member, so there is nobody in particular to seal it to. A
        // direct message is, and the key that opened it is the key to answer
        // with.
        let (said, key) = match envelope.group_id {
            Some(_) => (envelope.body.clone(), None),
            None => match self.open(envelope).await? {
                Some((said, key)) => (said, Some(key)),
                None => return Ok(false),
            },
        };

        // Somebody pointing the bot at a room. Joined before the handler sees
        // it, because joining is mechanical and what to *say* about it is not:
        // a bot cannot follow a link, so being sent one is the only way in
        // besides being handed an id on the command line.
        let invited = match &envelope.group_id {
            None => invite_in(&said),
            Some(_) => None,
        };
        if let Some(invite) = &invited {
            self.join(&invite.room).await?;
        }

        let heard = Heard {
            from: envelope.from.clone(),
            group_id: envelope.group_id.clone(),
            // A frame that is only saying how to read its words is unwrapped
            // here, so everything downstream sees the words. Two bots talking
            // would otherwise each decide the other had sent them a card.
            said: words_in(&said).unwrap_or(said),
            id: envelope.id.clone(),
            invited,
        };
        // Answered where it was said. A room message answered privately is a
        // bot talking behind the room's back, and one nobody else can follow.
        let mut out = Outgoing {
            room: envelope.group_id.clone(),
            to: envelope.from.clone(),
            key,
            head: None,
            at: 0,
        };

        // Every piece goes the moment it arrives. Holding one back was the
        // obvious way to know which was the last — the last is the one nothing
        // follows — but it meant a paragraph reached the reader only once the
        // next was written, and an answer of a single paragraph was not sent
        // until the whole thing was finished. Closing the message with an empty
        // piece costs one message and buys back all of that.
        let (sender, mut arriving) = tokio::sync::mpsc::channel::<String>(1);
        let saying = Saying { pieces: sender };

        let remainder = {
            let answering = self.handler.reply(&heard, &saying);
            tokio::pin!(answering);
            loop {
                tokio::select! {
                    // Sent from inside the arm, so the handler is not running
                    // while a message is in flight. That is the backpressure:
                    // a model cannot outrun the relay.
                    said = arriving.recv() => {
                        if let Some(said) = said {
                            // An opener says an answer is coming and has nothing
                            // in it. One after the answer has started would be a
                            // blank message in the middle of it.
                            if !opens_only(&said) || out.at == 0 {
                                out.say(self, said, false).await?;
                            }
                        }
                    }
                    answer = &mut answering => break answer,
                }
            }
        };
        // Nothing else can arrive once the handler has returned, but whatever
        // it managed to queue before then still has to go.
        drop(saying);
        while let Some(said) = arriving.recv().await {
            out.say(self, said, false).await?;
        }

        match remainder {
            // What it said at the end is the end.
            Some(last) => out.say(self, last, true).await?,
            // It said everything as it went, so the message is open and the app
            // is still waiting on the flag that closes it. Nothing said at all
            // is a real answer, and leaves nothing to close.
            None if out.at > 0 => out.say(self, String::new(), true).await?,
            None => {}
        }
        Ok(true)
    }

    /// The key for talking to `address`, fetched once and then remembered.
    /// Open a message, and hand back the key that opened it.
    ///
    /// The store first, because most messages come from somebody already spoken
    /// to. But a remembered key stops being the right one without anything
    /// saying so: the relay keeps a single device key per address, so signing
    /// in from another browser — a phone, a laptop, `localhost` after
    /// `192.168` — publishes a new one over the top of the old. The first sign
    /// is a message that will not open.
    ///
    /// So a failure to open is not final until the key has been asked for
    /// again. Getting this wrong is quiet and total: the bot reads nothing
    /// further from that person, and every reply it seals is unreadable to
    /// them, with no error on either side to say why.
    async fn open(&self, envelope: &Envelope) -> Result<Option<(String, [u8; 32])>, Error> {
        if let Some(theirs) = self.store.key_for(&envelope.from) {
            let key = crypto::conversation_key(&self.store.device_secret(), &theirs);
            if let Some(said) = crypto::open(&envelope.body, &key, &envelope.from, &envelope.to) {
                return Ok(Some((said, key)));
            }
        }

        let Some(theirs) = self.fetch_key(&envelope.from).await? else {
            return Ok(None);
        };
        let key = crypto::conversation_key(&self.store.device_secret(), &theirs);
        match crypto::open(&envelope.body, &key, &envelope.from, &envelope.to) {
            Some(said) => Ok(Some((said, key))),
            // Sealed to a key nobody here has ever held — a device secret this
            // bot lost, or something that was never a message. Nothing to be
            // done, and nothing to be gained by stopping.
            None => Ok(None),
        }
    }

    /// Ask the relay for `address`'s device key, verify it, and remember it.
    async fn fetch_key(&self, address: &str) -> Result<Option<[u8; 32]>, Error> {
        // Verified here, not taken on the relay's word. A bot that trusted the
        // certificate it was handed would seal every reply to whatever key the
        // relay chose — see `keys`.
        let certificate = self
            .client
            .certificate(&self.session.token, address)
            .await?;
        let Some(theirs) = certificate.key_for(address) else {
            return Ok(None);
        };

        // Worth saying out loud. From here it looks like nothing; to whoever
        // signed in somewhere new it is the moment the bot started answering
        // again, and to anybody reading a log it is the difference between a
        // key that rotated and a bot that broke.
        if self
            .store
            .key_for(address)
            .is_some_and(|held| held != theirs)
        {
            println!("{address} has a new device key");
        }
        self.store.remember_key(address, theirs);
        Ok(Some(theirs))
    }
}

/// Say what a bot is, where the relay does not already agree.
///
/// One request to ask, and a write only where it differs. Stating each of them
/// unconditionally would mean shipping the avatar — a megabyte — on every start
/// and every renewal to discover it had not changed.
async fn publish(
    client: &Client,
    token: &str,
    address: &str,
    presence: &Presence,
) -> Result<(), Error> {
    let published = client.published(token, address).await?;

    // Each of these says so when it acts, and stays quiet when it does not —
    // which is the difference between a start that changed something and one
    // that merely agreed with what was already there.
    if published.policy.amount_luna != presence.price_luna {
        client.set_policy(token, presence.price_luna).await?;
        println!("asking {} of strangers", priced(presence.price_luna));
    }
    if let Some(name) = &presence.name
        && published.name.as_deref() != Some(name.as_str())
    {
        client.set_name(token, name).await?;
        println!("named {name}");
    }
    if let Some(image) = &presence.avatar
        && published.avatar.as_deref() != Some(fingerprint(image).as_str())
    {
        client.set_avatar(token, image.clone()).await?;
        println!("wearing a new picture ({} bytes)", image.len());
    }
    Ok(())
}

/// What the relay will call a picture once it has it.
///
/// `blake2b-256(RENDER_VERSION ‖ source)`, mirroring `picture.rs` in the relay
/// so that a bot can tell whether the picture it holds is the one already
/// published without uploading it to find out.
///
/// A drift in the version string costs an upload that was not needed, and
/// nothing else — the relay recognises the bytes it already has and skips the
/// work. That is the right way round for a constant kept in two repositories.
fn fingerprint(source: &[u8]) -> String {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"knock-image-v1");
    hasher.update(source);
    data_encoding::HEXLOWER.encode(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heard(said: &str) -> Heard {
        Heard {
            from: "NQ00".into(),
            group_id: None,
            said: said.to_string(),
            id: "one".into(),
            invited: None,
        }
    }

    const ROOM: &str = "e151867b-e9bf-494c-92f2-6b8aa4ad4625";

    #[test]
    fn a_shared_room_is_recognised() {
        let shared =
            format!("{FRAME}{{\"kind\":\"invite\",\"group\":\"{ROOM}\",\"name\":\"Builders\"}}");
        let invite = invite_in(&shared).expect("an invite");
        assert_eq!(invite.room, ROOM);
        assert_eq!(invite.name.as_deref(), Some("Builders"));
    }

    #[test]
    fn a_pasted_link_is_recognised_too() {
        // What survives being wrapped by another app, trailed by punctuation,
        // or rearranged on the way.
        for text in [
            format!("https://knockchat.org/?group={ROOM}"),
            format!("join us: https://knockchat.org/?group={ROOM}."),
            format!("<https://nimpay.app/miniapps/open/knockchat.org%2F%3Fgroup%3D{ROOM}>"),
            ROOM.to_uppercase(),
        ] {
            assert_eq!(invite_in(&text).expect(&text).room, ROOM, "{text}");
        }
    }

    #[test]
    fn ordinary_words_are_not_invitations() {
        assert!(invite_in("hello").is_none());
        assert!(
            invite_in("e151867b-e9bf-494c-92f2").is_none(),
            "half a uuid is not one"
        );
        // A frame that is something else entirely.
        assert!(invite_in(&format!("{FRAME}{{\"kind\":\"payment\",\"luna\":1}}")).is_none());
    }

    /// What the app does on the other side: the pieces, in order, joined.
    fn rejoined(answer: &Split) -> String {
        (0..answer.pieces.len())
            .map(|at| {
                let head = (at > 0).then_some(HEAD_SHAPE);
                words_in(&pieced(answer, at, head)).unwrap_or_else(|| pieced(answer, at, head))
            })
            .collect()
    }

    #[test]
    fn an_empty_last_piece_closes_a_message_that_was_said_as_it_went() {
        // What the SDK sends once a streaming handler returns. It adds no words
        // — the app puts the pieces end to end — and carries the flag that
        // stops the answer reading as still arriving.
        let closing = split(String::new(), MOST_BODY);
        let body = body_of(
            &closing.pieces[0],
            closing.markdown,
            Some("9f3c1a2b"),
            3,
            true,
        );
        assert!(body.contains("\"end\":true"), "{body}");
        assert!(body.contains("9f3c1a2b"), "{body}");
        assert_eq!(words_in(&body).as_deref(), Some(""));
    }

    #[test]
    fn a_price_is_shown_the_way_it_was_set() {
        assert_eq!(priced(0), "nothing");
        assert_eq!(priced(1_000_000), "10 NIM");
        assert_eq!(priced(50_000), "0.50000 NIM");
        assert_eq!(priced(1), "0.00001 NIM");
    }

    #[test]
    fn nim_is_read_as_the_luna_it_is_worth() {
        assert_eq!(luna("10"), Ok(1_000_000));
        assert_eq!(luna("0"), Ok(0));
        assert_eq!(luna(" 2 "), Ok(200_000));
        // The fraction is padded, not parsed as written: half a NIM is fifty
        // thousand luna, and reading `.5` as five would undercharge by 10,000x.
        assert_eq!(luna("0.5"), Ok(50_000));
        assert_eq!(luna(".5"), Ok(50_000));
        assert_eq!(luna("1.00001"), Ok(100_001));
    }

    #[test]
    fn an_amount_that_is_not_one_is_refused_rather_than_guessed() {
        for said in ["", ".", "ten", "1.2.3", "-1", "1e5", "10 NIM"] {
            assert!(luna(said).is_err(), "read an amount out of {said:?}");
        }
        // Finer than a luna. Truncating would charge a price nobody named.
        assert!(luna("0.000001").is_err());
        assert!(luna("99999999999999999999").is_err());
    }

    #[test]
    fn an_opener_is_a_message_with_no_words_in_it() {
        assert!(opens_only(""));
        assert!(opens_only(&markdown("")));
        // Anything actually said is not one, however short.
        assert!(!opens_only("."));
        assert!(!opens_only(&markdown("hi")));
    }

    #[test]
    fn an_opener_says_more_is_coming_and_declares_how_to_read_it() {
        // The head is what the app reads the whole answer's mode from, so an
        // opener that said nothing about it would leave the pieces after it
        // drawn as plain text.
        let answer = split(markdown(""), MOST_BODY);
        let body = body_of(&answer.pieces[0], answer.markdown, None, 0, false);
        assert!(body.contains("\"parse\":\"markdown\""), "{body}");
        assert!(body.contains("\"at\":0"), "{body}");
        assert!(!body.contains("end"), "{body}");
    }

    #[test]
    fn a_reply_that_fits_travels_as_one_message_and_as_itself() {
        let answer = split("short enough".into(), MOST_BODY);
        assert_eq!(answer.pieces.len(), 1);
        // Nothing to declare, so no frame: the wire is what it always was.
        assert_eq!(pieced(&answer, 0, None), "short enough");
    }

    #[test]
    fn a_markdown_reply_that_fits_is_one_message_with_no_marker() {
        let answer = split(markdown("**hi**"), MOST_BODY);
        assert_eq!(answer.pieces.len(), 1);
        let body = pieced(&answer, 0, None);
        assert_eq!(words_in(&body).as_deref(), Some("**hi**"));
        assert!(!body.contains("part"), "{body}");
    }

    #[test]
    fn a_long_reply_becomes_pieces_that_each_fit() {
        let said = "a line of an answer\n".repeat(600);
        let answer = split(markdown(&said), MOST_SEALED);
        assert!(answer.pieces.len() > 1);
        for at in 0..answer.pieces.len() {
            let body = pieced(&answer, at, (at > 0).then_some(HEAD_SHAPE));
            assert!(
                body.len() <= MOST_SEALED,
                "piece {at} is {} bytes",
                body.len()
            );
        }
        assert_eq!(rejoined(&answer), said);
    }

    #[test]
    fn every_piece_but_the_first_names_the_first_and_only_the_last_ends() {
        let answer = split(markdown(&"words ".repeat(3000)), MOST_SEALED);
        let last = answer.pieces.len() - 1;
        assert!(last > 0, "this answer has to need more than one message");

        assert!(!pieced(&answer, 0, None).contains("head"));
        for at in 1..=last {
            let body = pieced(&answer, at, Some("9f3c1a2b"));
            assert!(body.contains("9f3c1a2b"), "piece {at} names nothing");
        }
        assert!(!pieced(&answer, 0, None).contains("end"));
        assert!(pieced(&answer, last, Some("9f3c1a2b")).contains("\"end\":true"));
    }

    #[test]
    fn a_break_never_splits_a_character() {
        // Every character multi-byte, so a naive cut would panic or corrupt.
        let said = "🛰".repeat(4000);
        let answer = split(markdown(&said), MOST_SEALED);
        assert!(answer.pieces.len() > 1);
        assert_eq!(rejoined(&answer), said);
    }

    #[test]
    fn a_break_prefers_the_end_of_a_line() {
        let answer = split(markdown(&"a readable line\n".repeat(400)), MOST_SEALED);
        assert!(answer.pieces.len() > 1);
        for piece in &answer.pieces[..answer.pieces.len() - 1] {
            assert!(
                piece.ends_with('\n'),
                "cut mid-line: {:?}",
                &piece[piece.len() - 20..]
            );
        }
    }

    #[test]
    fn a_framed_text_payload_is_read_as_the_words_in_it() {
        let said = markdown("# Title\n- **one**");
        assert!(said.starts_with(FRAME));
        assert_eq!(words_in(&said).as_deref(), Some("# Title\n- **one**"));
    }

    #[test]
    fn nothing_else_is_read_as_words() {
        // A card is not a sentence, and plain writing was never framed.
        assert!(words_in("just talking").is_none());
        assert!(words_in(&format!("{FRAME}{{\"kind\":\"payment\",\"luna\":1}}")).is_none());
        assert!(words_in(&format!("{FRAME}not json")).is_none());
    }

    #[test]
    fn words_are_words() {
        // Plain text is sent as itself — the app frames only what is not text —
        // so anything without the prefix is what somebody typed.
        assert_eq!(heard("hello").text(), Some("hello"));
        assert_eq!(heard("").text(), Some(""));
        assert!(!heard("hello").is_framed());
    }

    #[test]
    fn a_card_is_not_words() {
        // Exactly what the app puts on the wire for a payment. Handing this
        // back would have it drawn again, from the bot, as a payment nobody
        // made.
        let payment = "\u{1f}knock1\n{\"kind\":\"payment\",\"luna\":500000}";
        assert_eq!(heard(payment).text(), None);
        assert!(heard(payment).is_framed());
    }

    #[test]
    fn something_merely_odd_is_still_words() {
        // A message that happens to contain JSON, or a lone separator, is not
        // framed: the prefix is the whole test, at the start and nowhere else.
        assert!(heard("{\"kind\":\"payment\"}").text().is_some());
        assert!(heard("look: \u{1f}knock1\nnot a frame").text().is_some());
    }
}
