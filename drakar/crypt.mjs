// SL_KOD=xxx node crypt.mjs lock     data.mjs + maps/ -> data.enc   (data.enc committas)
// SL_KOD=xxx node crypt.mjs unlock   data.enc -> data.mjs + maps/   (båda gitignorerade)
import { webcrypto as crypto } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';

const [mode] = process.argv.slice(2);
const pw = process.env.SL_KOD;
if (!pw || !['lock', 'unlock'].includes(mode)) {
  console.error('Användning: SL_KOD=xxx node crypt.mjs lock|unlock');
  process.exit(1);
}

async function key(salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

if (mode === 'lock') {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(salt), Buffer.from(JSON.stringify(
    { data: readFileSync('data.mjs', 'utf8'), maps: Object.fromEntries(readdirSync('maps').map((n) => [n, readFileSync('maps/' + n).toString('base64')])) })));
  writeFileSync('data.enc', Buffer.concat([salt, iv, Buffer.from(ct)]).toString('base64') + '\n');
  console.log('data.mjs + maps/ -> data.enc');
} else {
  const raw = Buffer.from(readFileSync('data.enc', 'utf8'), 'base64');
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(16, 28) }, await key(raw.subarray(0, 16)), raw.subarray(28));
    const { data, maps } = JSON.parse(Buffer.from(pt).toString('utf8'));
    writeFileSync('data.mjs', data);
    mkdirSync('maps', { recursive: true });
    for (const [n, b] of Object.entries(maps)) writeFileSync('maps/' + n, Buffer.from(b, 'base64'));
    console.log('data.enc -> data.mjs + maps/');
  } catch {
    console.error('Fel SL_KOD.');
    process.exit(1);
  }
}
