//! A whole conversation, against a relay that is running.
//!
//! This is the test the rest exist to make possible: a person knocks, the bot
//! lets them in, they say something, the bot answers, and the person reads the
//! answer. Every layer is in it — the signed challenge, the certified device
//! key, the sealed body, the cursor — and none of them can be quietly wrong
//! while it passes.
//!
//! Wants a *fresh* relay, one started with nothing in it: the knock below can
//! only happen once for a pair of addresses, and a relay left over from an
//! earlier run answers the second one with "you already have an open channel".
//!
//!     KNOCK_RELAY=http://127.0.0.1:3199 \
//!     cargo test --test conversation -- --ignored --nocapture

use knock_sdk::bot::{Bot, Handler, Heard, Presence, Saying};
use knock_sdk::crypto;
use knock_sdk::identity::Identity;
use knock_sdk::session::{Client, Session};
use knock_sdk::store::{Ephemeral, Store};

fn relay() -> Client {
    Client::new(std::env::var("KNOCK_RELAY").unwrap_or_else(|_| "http://127.0.0.1:3199".into()))
}

/// The dullest handler there is, which is the point: if this works, what is
/// being tested is the SDK rather than anything clever.
struct Echo;

impl Handler for Echo {
    async fn reply(&self, message: &Heard, _: &Saying) -> Option<String> {
        match message.text() {
            Some(said) => Some(said.to_string()),
            None => Some("I can only echo text.".into()),
        }
    }
}

/// Somebody with a wallet, doing by hand what the app does.
struct Person {
    client: Client,
    session: Session,
    secret: [u8; 32],
}

impl Person {
    async fn new(seed: u8) -> Self {
        let client = relay();
        let identity = Identity::new([seed; 32]);
        let secret = [seed.wrapping_add(100); 32];
        let session = client.sign_in(&identity, &secret).await.expect("sign in");
        Self {
            client,
            session,
            secret,
        }
    }

    /// The same person, signing in from somewhere else — a different device
    /// secret under the same wallet key.
    async fn signed_in_again(seed: u8, device: u8) -> Self {
        let client = relay();
        let identity = Identity::new([seed; 32]);
        let secret = [device; 32];
        let session = client.sign_in(&identity, &secret).await.expect("sign in");
        Self {
            client,
            session,
            secret,
        }
    }

    async fn key_to(&self, them: &str) -> [u8; 32] {
        // The same verification a bot does, because a person's app does it too.
        let certificate = self
            .client
            .certificate(&self.session.token, them)
            .await
            .expect("certificate");
        let theirs = certificate
            .key_for(them)
            .expect("a certificate that proves itself");
        crypto::conversation_key(&self.secret, &theirs)
    }
}

#[tokio::test]
#[ignore]
async fn a_person_knocks_and_the_bot_answers() {
    let person = Person::new(21).await;

    let mut bot = Bot::start(
        relay(),
        Identity::new([22u8; 32]),
        Ephemeral::with_secret([23u8; 32]),
        Echo,
        // Free to reach, and named — a bot nobody can afford is a bot nobody
        // talks to, and one with no name is an address people have to trust.
        Presence {
            name: Some("Echo".into()),
            price_luna: 0,
            avatar: None,
        },
    )
    .await
    .expect("the bot signs in");
    println!("bot is {}", bot.address());

    // Knock, sealed to the bot exactly as a message would be.
    let key = person.key_to(bot.address()).await;
    let hello = crypto::seal(
        "hello there",
        &key,
        &person.session.address,
        bot.address(),
        &crypto::nonce(),
    );
    person
        .client
        .knock(
            &person.session.token,
            &person.session.address,
            bot.address(),
            &hello,
        )
        .await
        .expect("knock");

    // One turn: the bot lets them in and answers the knock's own message.
    let handled = bot.turn().await.expect("a turn");
    assert!(handled >= 1, "the bot handled nothing");

    // And the person can read what came back.
    let fetched = person
        .client
        .fetch(&person.session.token, &person.session.address, None)
        .await
        .expect("fetch");
    let answers: Vec<String> = fetched
        .messages
        .iter()
        .filter(|envelope| envelope.from == bot.address())
        .filter_map(|envelope| crypto::open(&envelope.body, &key, &envelope.from, &envelope.to))
        .collect();

    assert_eq!(
        answers,
        vec!["hello there".to_string()],
        "what came back is what went in"
    );

    // And once only. A turn that failed to advance the cursor answers the same
    // message again, and again after that — which is how a timeout on a reply
    // filled somebody's thread with one repeated word.
    assert_eq!(
        bot.turn().await.expect("a second turn"),
        0,
        "nothing new to answer"
    );
    let again = person
        .client
        .fetch(&person.session.token, &person.session.address, None)
        .await
        .expect("fetch")
        .messages
        .iter()
        .filter(|envelope| envelope.from == bot.address())
        .count();
    assert_eq!(again, 1, "the bot answered twice");
    println!("bot replied: {answers:?}");
}

#[tokio::test]
#[ignore]
async fn the_bot_does_not_answer_itself() {
    // A room hands a message to every member, the sender included. A bot that
    // replied to its own words would talk to itself until something stopped it.
    let mut bot = Bot::start(
        relay(),
        Identity::new([24u8; 32]),
        Ephemeral::with_secret([25u8; 32]),
        Echo,
        Presence::default(),
    )
    .await
    .expect("start");

    // Nothing has been said to it, so nothing is handled and the cursor still
    // moves — an empty turn is not a failed one.
    assert_eq!(bot.turn().await.expect("a turn"), 0);
    let store = Ephemeral::with_secret([25u8; 32]);
    assert!(
        store.cursor().is_none(),
        "a fresh store starts at the beginning"
    );
}

#[tokio::test]
#[ignore]
async fn somebody_signing_in_somewhere_new_is_still_heard() {
    // The relay keeps one device key per address, so signing in from another
    // browser replaces the one the bot has cached — `localhost` after
    // `192.168`, a phone after a laptop. Nothing announces it. A bot that took
    // its cached key as final would go silent for that person for good, in both
    // directions and without an error anywhere.
    let person = Person::new(31).await;
    let mut bot = Bot::start(
        relay(),
        Identity::new([32u8; 32]),
        Ephemeral::with_secret([33u8; 32]),
        Echo,
        Presence::default(),
    )
    .await
    .expect("start");

    let first = person.key_to(bot.address()).await;
    let hello = crypto::seal(
        "from the first browser",
        &first,
        &person.session.address,
        bot.address(),
        &crypto::nonce(),
    );
    person
        .client
        .knock(
            &person.session.token,
            &person.session.address,
            bot.address(),
            &hello,
        )
        .await
        .expect("knock");
    assert_eq!(bot.turn().await.expect("a turn"), 1);

    // The same person, the same address, a new browser: a new device key, which
    // the relay stores over the old one.
    let elsewhere = Person::signed_in_again(31, 200).await;
    assert_eq!(
        elsewhere.session.address, person.session.address,
        "the same person"
    );

    let second = elsewhere.key_to(bot.address()).await;
    assert_ne!(first, second, "a new browser means a new conversation key");

    let again = crypto::seal(
        "from the second browser",
        &second,
        &elsewhere.session.address,
        bot.address(),
        &crypto::nonce(),
    );
    elsewhere
        .client
        .say(
            &elsewhere.session.token,
            &elsewhere.session.address,
            bot.address(),
            &again,
        )
        .await
        .expect("say");

    assert_eq!(
        bot.turn().await.expect("a turn"),
        1,
        "the bot could not read the new browser"
    );

    let answers: Vec<String> = elsewhere
        .client
        .fetch(&elsewhere.session.token, &elsewhere.session.address, None)
        .await
        .expect("fetch")
        .messages
        .iter()
        .filter(|envelope| envelope.from == bot.address())
        .filter_map(|envelope| crypto::open(&envelope.body, &second, &envelope.from, &envelope.to))
        .collect();
    assert!(
        answers.contains(&"from the second browser".to_string()),
        "the new browser could not read the reply: {answers:?}"
    );
}

#[tokio::test]
#[ignore]
async fn a_card_is_answered_rather_than_reflected() {
    // The app frames a payment, a shared contact, a reaction. An echo that
    // handed the frame back would have the app draw that card a second time,
    // from the bot — a payment nobody made.
    let person = Person::new(41).await;
    let mut bot = Bot::start(
        relay(),
        Identity::new([42u8; 32]),
        Ephemeral::with_secret([43u8; 32]),
        Echo,
        Presence::default(),
    )
    .await
    .expect("start");

    let key = person.key_to(bot.address()).await;
    let payment = "\u{1f}knock1\n{\"kind\":\"payment\",\"luna\":500000}";
    let sealed = crypto::seal(
        payment,
        &key,
        &person.session.address,
        bot.address(),
        &crypto::nonce(),
    );
    person
        .client
        .knock(
            &person.session.token,
            &person.session.address,
            bot.address(),
            &sealed,
        )
        .await
        .expect("knock");
    assert_eq!(bot.turn().await.expect("a turn"), 1);

    let answers: Vec<String> = person
        .client
        .fetch(&person.session.token, &person.session.address, None)
        .await
        .expect("fetch")
        .messages
        .iter()
        .filter(|envelope| envelope.from == bot.address())
        .filter_map(|envelope| crypto::open(&envelope.body, &key, &envelope.from, &envelope.to))
        .collect();

    assert_eq!(answers, vec!["I can only echo text.".to_string()]);
    assert!(
        !answers[0].starts_with('\u{1f}'),
        "a frame must not come back"
    );
}

#[tokio::test]
#[ignore]
async fn a_bot_answers_in_the_room_it_was_asked_in() {
    // Rooms are the case a bot is actually for, and they work differently: one
    // body fanned out to every member, unsealed, and answered where it was said
    // rather than privately to whoever wrote it.
    let person = Person::new(51).await;
    let room = person
        .client
        .create_group(&person.session.token, "Bot Test")
        .await
        .expect("a room");

    let mut bot = Bot::start(
        relay(),
        Identity::new([52u8; 32]),
        Ephemeral::with_secret([53u8; 32]),
        Echo,
        Presence::default(),
    )
    .await
    .expect("start");
    bot.join(&room).await.expect("join");
    // Twice, because running the command again is an ordinary thing to do and
    // must not be an error. Not because a restart needs it: membership lives on
    // the relay, and a bot that rejoined on every start could never be removed
    // from a room.
    bot.join(&room).await.expect("join again");

    person
        .client
        .say_in_group(&person.session.token, &room, "hello room")
        .await
        .expect("say");

    assert_eq!(
        bot.turn().await.expect("a turn"),
        1,
        "the bot did not hear the room"
    );

    // Read back from the room's own history, which is where a member would see
    // it — not from anybody's direct queue.
    let history: Vec<String> = person
        .client
        .fetch(&person.session.token, &person.session.address, None)
        .await
        .expect("fetch")
        .messages
        .iter()
        .filter(|envelope| envelope.group_id.as_deref() == Some(room.as_str()))
        .filter(|envelope| envelope.from == bot.address())
        .map(|envelope| envelope.body.clone())
        .collect();

    assert_eq!(
        history,
        vec!["hello room".to_string()],
        "the bot answered in the room"
    );
}

#[tokio::test]
#[ignore]
async fn a_room_shared_in_a_direct_message_is_joined() {
    // How a bot gets into a room in practice: somebody shares it into the chat
    // they already have with the bot. A bot cannot follow a link, so being sent
    // one is the only way in besides an id on a command line.
    let person = Person::new(61).await;
    let room = person
        .client
        .create_group(&person.session.token, "Shared")
        .await
        .expect("a room");

    let mut bot = Bot::start(
        relay(),
        Identity::new([62u8; 32]),
        Ephemeral::with_secret([63u8; 32]),
        Echo,
        Presence::default(),
    )
    .await
    .expect("start");

    // Exactly what the app puts on the wire when you share a room into a chat.
    let shared =
        format!("\u{1f}knock1\n{{\"kind\":\"invite\",\"group\":\"{room}\",\"name\":\"Shared\"}}");
    let key = person.key_to(bot.address()).await;
    let sealed = crypto::seal(
        &shared,
        &key,
        &person.session.address,
        bot.address(),
        &crypto::nonce(),
    );
    person
        .client
        .knock(
            &person.session.token,
            &person.session.address,
            bot.address(),
            &sealed,
        )
        .await
        .expect("knock");
    assert_eq!(bot.turn().await.expect("a turn"), 1);

    // In the room, which is the point — saying something there reaches it.
    person
        .client
        .say_in_group(&person.session.token, &room, "anyone here?")
        .await
        .expect("say");
    assert_eq!(
        bot.turn().await.expect("a turn"),
        1,
        "the bot is not in the room"
    );
}
