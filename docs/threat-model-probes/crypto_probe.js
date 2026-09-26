// Probes for docs/THREAT_MODEL.md findings T-05 and T-09.
//
// Loads the REAL functions out of chat/templates/chatbox.html (regex + brace
// matching, never retyped) and runs two probes against them:
//   A. chain_index tampering by the server -> permanent silent message loss (T-09)
//   B. forward secrecy vs. (retained wrapped seed + recipient RSA private key) (T-05)
//
// Run:  node docs/threat-model-probes/crypto_probe.js      (Node 20+, no dependencies)
// Probe A documented T-09 at 123be67 (a lied-about chain_index destroyed the
// message for good); since the #94 fix it shows the message surviving the lie.
// Probe B still documents T-05 until #99 lands.
const fs = require('fs');
const path = require('path');
const src = fs.readFileSync(path.join(__dirname, '..', '..', 'chat', 'templates', 'chatbox.html'), 'utf8');

function grabFunction(name) {
  const re = new RegExp(`(async\\s+)?function\\s+${name}\\s*\\(`);
  const m = re.exec(src);
  if (!m) throw new Error('function not found: ' + name);
  let i = src.indexOf('{', m.index + m[0].length + src.slice(m.index + m[0].length).indexOf(')'));
  let depth = 0, j = i;
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (depth === 0) break; }
  }
  return src.slice(m.index, j + 1);
}
function grabConst(name) {
  const re = new RegExp(`const\\s+${name}\\s*=[^;]*;`);
  const m = re.exec(src);
  if (!m) throw new Error('const not found: ' + name);
  return m[0];
}

const fnNames = ['ab2b64', 'b642ab', 'importHmacKey', 'importAesKey', 'ratchetStep', 'advanceChainTo',
  'padPlaintext', 'unpadPlaintext', 'encryptWithAES', 'decryptWithAES', 'deriveReceivedKeys'];
const constNames = ['recvChainEpochName', 'recvChainKeyName', 'msgKeyName', 'skippedKeyName', 'MAX_SKIP', 'AES_PAD_BUCKET'];
const code = constNames.map(grabConst).join('\n') + '\n' + fnNames.map(grabFunction).join('\n');

async function makeReceiver(myPriv, chainKeysFromServer) {
  const idb = new Map(), ls = new Map();
  const localStorage = { getItem: k => ls.has(k) ? ls.get(k) : null, setItem: (k, v) => ls.set(k, String(v)), removeItem: k => ls.delete(k) };
  const idbGet = async k => idb.has(k) ? idb.get(k) : null;
  const idbSet = async (k, v) => { idb.set(k, v); };
  const idbDelete = async k => { idb.delete(k); };
  const chatId = '1234';
  const myEncKeys = { privateKey: myPriv };
  const fetchChainKeysOnce = async () => chainKeysFromServer;
  const factory = new Function('crypto', 'localStorage', 'idbGet', 'idbSet', 'idbDelete', 'chatId', 'myEncKeys',
    'fetchChainKeysOnce', code + '\nreturn {deriveReceivedKeys, decryptWithAES, encryptWithAES, ratchetStep, importHmacKey, importAesKey, b642ab, ab2b64};');
  const api = factory(globalThis.crypto, localStorage, idbGet, idbSet, idbDelete, chatId, myEncKeys, fetchChainKeysOnce);
  api.idb = idb; return api;
}

(async () => {
  const subtle = crypto.subtle;
  // Receiver's RSA burner key. extractable:true ONLY so the probe can play the
  // "attacker who obtains the key" role; the client itself generates it non-extractable.
  const rsa = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);

  // ── Sender side: exactly what chatbox.html's send path does (seed -> ratchet -> AES) ──
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const wrappedSeed = Buffer.from(await subtle.encrypt({ name: 'RSA-OAEP' }, rsa.publicKey, seed)).toString('base64');
  const S = await makeReceiver(rsa.privateKey, new Map()); // reuse helpers for the sender too
  let chain = await S.importHmacKey(seed.buffer);
  const sent = [];
  for (let idx = 0; idx < 4; idx++) {
    const step = await S.ratchetStep(chain);
    const enc = await S.encryptWithAES(await S.importAesKey(step.messageKeyBytes, ['encrypt']), `secret message #${idx}`);
    sent.push({ id: `m${idx}`, sender_id: 7, sender_chain_epoch: 0, chain_index: idx, encrypted_text: enc.ciphertext, aes_nonce: enc.nonce, aes_tag: enc.tag });
    chain = step.nextChainKey;
  }
  const serverChainKeys = new Map([[7, { sender_id: 7, epoch: 0, encrypted_seed: wrappedSeed }]]);

  // ── Probe A: control (honest server) ──
  const tryDecrypt = async (R, msg) => {
    // Mirrors renderMsg: derive, decrypt, and only then commit (#94).
    try { const { messageKey, commit } = await R.deriveReceivedKeys(msg); const pt = await R.decryptWithAES(messageKey, { ciphertext: msg.encrypted_text, nonce: msg.aes_nonce, tag: msg.aes_tag }); await commit(); return pt; }
    catch (e) { return `FAILED (${e.constructor.name}: ${e.message || 'decrypt error'})`; }
  };
  console.log('== Probe A: server tampers with chain_index (not covered by the hash chain) ==');
  const R0 = await makeReceiver(rsa.privateKey, serverChainKeys);
  console.log('control  m0..m3 honest      :', await tryDecrypt(R0, sent[0]), '|', await tryDecrypt(R0, sent[1]));

  const R1 = await makeReceiver(rsa.privateKey, serverChainKeys);
  const lie = { ...sent[0], chain_index: 50 };                 // server rewrites one field in the JSON it serves
  console.log('m0 served with chain_index=50 :', await tryDecrypt(R1, lie));
  console.log('skipkey_* after the lie       :', [...R1.idb.keys()].filter(k => k.startsWith('skipkey_')).length, '(fixed in #94: a failed decrypt commits nothing)');
  console.log('m0 re-served HONESTLY later   :', await tryDecrypt(R1, sent[0]), '  <- before #94 this was permanently lost');
  console.log('m1 honest, arrives afterwards :', await tryDecrypt(R1, sent[1]));

  // ── Probe B: forward secrecy vs. wrapped seed retained on the server + recipient RSA key ──
  console.log('\n== Probe B: receiver has ratcheted past m0..m3; attacker later gets RSA key + DB dump ==');
  const R2 = await makeReceiver(rsa.privateKey, serverChainKeys);
  for (const m of sent) await tryDecrypt(R2, m);              // victim reads everything, ratchet advances, old chain keys discarded
  const st = R2.idb.get('chain_recv_key_1234_7');
  console.log('victim chain position now     :', st.index, '(keys for indices <', st.index, 'are gone from the live ratchet)');
  // Attacker: no access to the live ratchet state at all — only the server's stored wrapped seed, the ciphertext, and the RSA private key.
  const seedBuf = await subtle.decrypt({ name: 'RSA-OAEP' }, rsa.privateKey, Buffer.from(wrappedSeed, 'base64'));
  const A = await makeReceiver(rsa.privateKey, new Map());
  let ck = await A.importHmacKey(seedBuf);
  for (const m of sent) {
    const step = await A.ratchetStep(ck);
    const pt = await A.decryptWithAES(await A.importAesKey(step.messageKeyBytes, ['decrypt']), { ciphertext: m.encrypted_text, nonce: m.aes_nonce, tag: m.aes_tag });
    console.log(`attacker decrypts index ${m.chain_index}       :`, pt);
    ck = step.nextChainKey;
  }
})().catch(e => { console.error('PROBE ERROR', e); process.exit(1); });
