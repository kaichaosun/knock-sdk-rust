# Speaking Knock

Everything a client needs to talk to a Knock relay, in any language. The Rust
in this repository is one implementation of it; the
[app](https://github.com/kaichaosun/knock-chat) is another. Where this document
and the code disagree, the code is right and this is a bug.

The relay carries ciphertext and never opens it. So the HTTP API below is only
half the protocol — the other half is the encryption, which every client does
for itself, and which has to match the app byte for byte or nothing is ever
read.

The public relay is `https://knockchat.org/api`. Every path below is relative
to it.

## Identity

An identity is an Ed25519 key. The address is derived from the public key,
never claimed:

```text
address = "NQ" ‖ check ‖ base32(blake2b-256(public_key)[0..20])
```

in Nimiq's base32 alphabet (`0123456789ABCDEFGHJKLMNPQRSTUVXY`), with an IBAN
mod-97 check, written in groups of four: `NQ80 M6TC 2D6V …`. Spacing and case
are presentation, so compare addresses with whitespace removed and case
ignored. See `crates/sdk/src/address.rs`.

### What gets signed

Never the message itself — a digest of it inside the envelope a Nimiq wallet
uses, so a signing request can never be dressed up as a transaction:

```text
digest = SHA256( 0x16 ‖ "Nimiq Signed Message:\n" ‖ ascii(byte_len(message)) ‖ message )
```

The signature is Ed25519 over those 32 bytes, sent as hex.

## Signing in

Every client — a phone, a browser, a bot — has two keys: the identity key
above, and an X25519 **device key** that messages to it are encrypted against.
Signing in registers the device key and proves the address in one signature.

1. `POST /v1/auth/challenge`

   ```json
   { "encryption_key": "<device public key, hex>" }
   ```

   answers `{ "nonce": "…", "message": "…" }`. The message is a statement that
   includes a line `Device public key: <hex>`.

2. Sign `message` exactly as received, as above.

3. `POST /v1/auth/verify`

   ```json
   { "nonce": "…", "public_key": "<identity public key, hex>", "signature": "<hex>" }
   ```

   answers `{ "token": "…", "address": "NQ…", "expires_at": "…" }`.

Check that `address` is the one you derive yourself. Everything afterwards
carries `Authorization: Bearer <token>`. A `401` later means the session ran
out: sign in again, **with the same device key**.

The device key must be kept. Sign in with a new one and the relay replaces the
old — the address keeps one device key at a time — so everything already sealed
to the old one stops opening.

## Device keys

`GET /v1/keys/{address}` answers a certificate:

```json
{ "address": "NQ…", "statement": "…", "public_key": "<hex>", "signature": "<hex>" }
```

`statement` is the sign-in message that address signed. Its device key is the
`Device public key:` line inside it.

**Verify it yourself.** The relay checks certificates before storing them, but
a client that took the relay's word would encrypt to whatever key the relay
chose. Before using the key:

- derive the address from `public_key` and check it is the address you asked
  about, and
- check `signature` over the digest of `statement`.

Both, or neither means anything. See `crates/sdk/src/keys.rs`.

## Encryption

Direct messages and knock bodies are sealed. Room messages are not — see
[Rooms](#rooms).

```text
shared = X25519(my_device_secret, their_device_public)
info   = "knock/v1/message" ‖ first ‖ second      (the two device public keys, sorted bytewise)
key    = HKDF-SHA256(ikm = shared, salt = none, info, length = 32)
```

Sorting is what lets both ends feed HKDF the same bytes while holding the keys
in opposite roles.

A body is sealed with XChaCha20-Poly1305 under a fresh random 24-byte nonce:

```text
aad  = compact(from) ‖ ">" ‖ compact(to)          (addresses with whitespace removed)
body = base64( 0x01 ‖ nonce ‖ ciphertext_and_tag )
```

The associated data binds a body to its sender and recipient, so it cannot be
moved into another conversation, or the other direction of this one. Version
`0x01` is the only one; reject anything else.

There is no forward secrecy: one key covers a whole conversation, as it does in
the app.

`crates/sdk/tests/vectors/crypto.json` holds vectors produced by the app's own
code — key agreements, sealed bodies, and bodies that must fail to open. An
implementation that passes them reads what a phone wrote.

## Knocks

Two strangers cannot message each other. One knocks; the other lets them in;
then the channel is open in both directions.

| | |
| --- | --- |
| `POST /v1/knocks` | `{ "from", "to", "body" }`. The body is sealed like a message. |
| `GET /v1/knocks` | `{ "knocks": [{ "id", "from", "body" }] }` — who is waiting. |
| `POST /v1/knocks/{id}/accept` | Let one in. |

### Postage

An address can ask strangers to pay to knock. That is its policy:

| | |
| --- | --- |
| `PUT /v1/policy` | `{ "amount_luna": 0 }`. 100 000 luna is one NIM. |
| `GET /v1/reachability/{address}` | `{ "policy": { "amount_luna" }, "name", "avatar" }` |

Postage is paid once, at the door. Everything said after a knock is accepted is
free, and a price change does not affect channels already open. Payment goes to
the address itself, so an address that charges should be one whose key lives in
a wallet it can be spent from.

## Messages

| | |
| --- | --- |
| `GET /v1/messages?to={address}&cursor={cursor}` | `{ "messages": [Envelope], "next": "…" }` |
| `POST /v1/messages/ack` | `{ "to", "cursor" }` — everything up to `cursor` is handled. |
| `POST /v1/messages` | `{ "from", "to", "body" }` → `{ "id" }`. Needs an open channel. |

```json
{ "id": "…", "from": "NQ…", "to": "NQ…", "group_id": null, "body": "…", "created_at": "…" }
```

`id` is stable forever; deduplicate on it. `next` is opaque — hand it back
unchanged. Omit `cursor` on a first run.

Ack after handling, not after fetching. A crash between the two then costs a
repeat rather than a lost message.

A body is at most **4096 bytes as the relay receives it**. For a sealed body
that is base64 of the frame, so the plaintext gets about three quarters of it.

There is no push for non-browser clients yet. Poll; the SDK waits two seconds
between empty turns.

### Errors

A refusal carries `{ "error": "…" }`, written to be read — pass it on rather
than summarising it into a status code. `408`, `429` and `5xx` are worth
retrying with backoff; `401` means sign in again; anything else is about the
request and will not change.

## What a body says

Plain text is sent as itself. Anything else is **framed**:

```text
"\u001f" ‖ "knock1\n" ‖ JSON
```

A unit separator, a version, a newline, then a JSON object with a `kind`. The
prefix is the whole test: a body without it is text.

The app frames payments, shared contacts, reactions, gifts, quoted replies and
invites. A client that does not understand a frame should say so, never hand it
back — echoing a payment frame makes the app draw a payment nobody made.

The kinds a bot is most likely to meet:

**Text with something to declare.**

```json
{ "kind": "text", "parse": "markdown", "text": "**hello**" }
```

`parse: "markdown"` asks the app to draw the text as its chat dialect of
markdown: bold, italics, strikethrough, inline code, fenced blocks, headings,
quotes and flat lists. Tables, nested lists and link labels are not drawn.

**One answer in several messages.** A text longer than one body is sent as
pieces, and the app joins them back into one bubble:

```json
{ "kind": "text", "part": { "at": 0 }, "text": "first piece…" }
{ "kind": "text", "part": { "head": "<id of piece 0>", "at": 1 }, "text": "…" }
{ "kind": "text", "part": { "head": "<id of piece 0>", "at": 2, "end": true }, "text": "…last" }
```

`head` is the relay's `id` for the first piece. Until a piece with `end`
arrives, the app shows the message as still being written — which is also how
a bot says it is thinking: send piece 0 with empty text, then the answer.

**An invite to a room.**

```json
{ "kind": "invite", "group": "<room uuid>", "name": "…" }
```

## Rooms

Room messages are **not encrypted**. One body is written and fanned out to every
member, so there is nobody in particular to seal it to; the relay can read
them, and the app tells everyone joining as much.

| | |
| --- | --- |
| `POST /v1/groups` | `{ "name", "join_price_luna", "requires_approval" }` → `{ "id" }` |
| `POST /v1/groups/{id}/join` | `{ "postage": null }`. `409` if already a member. |
| `POST /v1/groups/{id}/messages` | `{ "body" }` → `{ "id" }`. Plain or framed, never sealed. |

Room messages arrive through `/v1/messages` with `group_id` set, including the
client's own — skip envelopes `from` yourself, or a bot will answer itself.

## Profile

| | |
| --- | --- |
| `PUT /v1/profile` | `{ "name" }`. At most 32 characters, no invisible or reordering characters. Blank clears it. |
| `PUT /v1/profile/avatar` | Raw JPEG, PNG, WebP or GIF bytes, `application/octet-stream`, up to 1 MB. |
| `DELETE /v1/profile/avatar` | Back to the identicon. |

`/v1/reachability/{address}` reports the avatar as a fingerprint,
`hex(blake2b-256("knock-image-v1" ‖ source_bytes))`, so a client can tell
whether its picture is already published without uploading it again.
