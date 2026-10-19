import { writeFileSync } from "node:fs"
import {
  conversationKey,
  decryptBody,
  encryptBody,
  fromHex,
  publicKeyFrom,
  toHex,
} from "../../knock-chat/src/lib/crypto"

const secret = (byte: number) => new Uint8Array(32).fill(byte)

const alice = { secret: secret(0x11), public: publicKeyFrom(secret(0x11)) }
const bob = { secret: secret(0x22), public: publicKeyFrom(secret(0x22)) }
// A second pair whose sort order is the other way round, so the ordering rule
// in the HKDF info is exercised in both directions.
const carol = { secret: secret(0xee), public: publicKeyFrom(secret(0xee)) }

const ALICE_ADDRESS = "NQ65 6MV2 TPDD 4H1J KDAU 7HBF 9Y51 7MEQ 0MS9"
const BOB_ADDRESS = "NQ52 B1N0 YTG5 P1R7 NSC7 R25H ER9G EYPD FFCX"

const pairs = [
  { name: "alice-bob", a: alice, b: bob },
  { name: "alice-carol", a: alice, b: carol },
]

const agreement = pairs.map(({ name, a, b }) => {
  const fromA = conversationKey(a.secret, b.public)
  const fromB = conversationKey(b.secret, a.public)
  if (toHex(fromA) !== toHex(fromB)) throw new Error(`${name}: both ends must agree`)
  return {
    name,
    a_secret: toHex(a.secret),
    a_public: toHex(a.public),
    b_secret: toHex(b.secret),
    b_public: toHex(b.public),
    key: toHex(fromA),
  }
})

const key = conversationKey(alice.secret, bob.public)
const plaintexts = [
  { name: "ascii", text: "hello" },
  { name: "empty", text: "" },
  { name: "emoji", text: "Yay! a beautiful snowflake 👇" },
  { name: "multiline", text: "one\ntwo\n\nthree" },
  { name: "long", text: "x".repeat(3000) },
  { name: "json-payload", text: JSON.stringify({ kind: "text", text: "hi" }) },
]

const messages = plaintexts.map(({ name, text }) => {
  const body = encryptBody(text, key, ALICE_ADDRESS, BOB_ADDRESS)
  if (decryptBody(body, key, ALICE_ADDRESS, BOB_ADDRESS) !== text) {
    throw new Error(`${name}: does not round trip`)
  }
  return { name, from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), plaintext: text, body }
})

// Every one of these must come back as "not for me" rather than as plaintext.
const sound = messages[0].body
const raw = Buffer.from(sound, "base64")
const flip = (at: number) => {
  const copy = Buffer.from(raw)
  copy[at] ^= 0x01
  return copy.toString("base64")
}
const rejects = [
  { name: "swapped-direction", from: BOB_ADDRESS, to: ALICE_ADDRESS, key: toHex(key), body: sound },
  { name: "wrong-key", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(conversationKey(alice.secret, carol.public)), body: sound },
  { name: "wrong-version", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), body: flip(0) },
  { name: "tampered-nonce", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), body: flip(3) },
  { name: "tampered-ciphertext", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), body: flip(raw.length - 1) },
  { name: "not-base64", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), body: "not a message" },
  { name: "too-short", from: ALICE_ADDRESS, to: BOB_ADDRESS, key: toHex(key), body: Buffer.from([1, 2, 3]).toString("base64") },
]
for (const reject of rejects) {
  if (decryptBody(reject.body, fromHex(reject.key), reject.from, reject.to) !== null) {
    throw new Error(`${reject.name}: should not have opened`)
  }
}

writeFileSync(
  process.argv[2],
  JSON.stringify({ version: 1, info: "knock/v1/message", agreement, messages, rejects }, null, 2) + "\n",
)
console.log(`agreement ${agreement.length}, messages ${messages.length}, rejects ${rejects.length}`)
