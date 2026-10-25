// Known-answer vector generator for fa_network fanet1 interop tests.
// Uses the REAL dap/1 reference crypto (mcp-bridge/src/crypto.ts) for
// verification; vectors are built with fixed nonces so Go can compare
// ciphertext byte-for-byte. Run from the mcp-bridge package after npm ci:
//   node fanet-vectors.mjs > /tmp/fanet-vectors.json
import { open, b64e, utf8 } from './src/crypto.ts';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { writeFileSync } from 'node:fs';

const kp = (seed) => {
  const priv = new Uint8Array(32).fill(seed);
  return { priv, pub: x25519.getPublicKey(priv) };
};
const hex = (b) => Buffer.from(b).toString('hex');
const channel = kp(7);
const agent = kp(11);   // DAP agent sender
const app = kp(19);     // fa app sender
const channelId = 'ab'.repeat(32); // realistic 64-hex fa channel id

function vector(sender, frameId, plaintext, nonceSeed) {
  // Exactly seal(): HKDF-SHA256(ecdh, salt=utf8(frameId), info=dap1/v1),
  // AAD dap1|<frameId>|<channel>, base64(nonce(12)||ct||tag).
  const key = hkdf(sha256, x25519.getSharedSecret(sender.priv, channel.pub), utf8(frameId), utf8('dap1/v1'), 32);
  const nonce = new Uint8Array(12).fill(nonceSeed);
  const aad = utf8(`dap1|${frameId}|${channelId}`);
  const ct = chacha20poly1305(key, nonce, aad).encrypt(utf8(plaintext));
  const ciphertext = b64e(new Uint8Array([...nonce, ...ct]));
  // REAL reference open() must accept our construction (receiver side):
  const pt = open(ciphertext, frameId, channelId, channel.priv, sender.pub);
  if (pt !== plaintext) throw new Error(`reference open rejected vector: ${pt}`);
  return {
    frameId, channelId, plaintext,
    ciphertext,
    senderPriv: hex(sender.priv),
    senderPub: b64e(sender.pub),
    channelPriv: b64e(channel.priv),
    channelPub: b64e(channel.pub),
  };
}

const vectors = [
  vector(agent, '0f5b7c34-1111-4aaa-8aaa-aaaaaaaaaaa1', '{"t":"msg","body":"dap agent to app known answer"}', 3),
  vector(app, '0f5b7c34-2222-4aaa-8aaa-aaaaaaaaaaa2', '{"t":"msg","body":"app to dap agent known answer"}', 5),
];
const out = JSON.stringify(vectors, null, 2);
writeFileSync('/tmp/fanet-vectors.json', out + '\n');
console.log('vectors written; both accepted by the REAL reference open()');
