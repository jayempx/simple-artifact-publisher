import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const root = await mkdtemp(join(tmpdir(), 'artifact-api-'));
const token = randomBytes(32).toString('base64url');
const hash = createHash('sha256').update(token).digest('hex');
const crc = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc[n] = c; }
const crc32 = (data) => { let c = 0xffffffff; for (const byte of data) c = crc[(c ^ byte) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const zip = (text) => { const name = Buffer.from('index.html'); const data = Buffer.from(text); const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc32(data), 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26); const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(crc32(data), 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28); const offset = local.length + name.length + data.length; const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(central.length + name.length, 12); end.writeUInt32LE(offset, 16); return Buffer.concat([local, name, data, central, name, end]); };
const child = spawn(process.execPath, [new URL('./server.mjs', import.meta.url).pathname], { env: { ...process.env, ARTIFACT_ROOT: root, API_TOKEN_SHA256: hash }, stdio: 'inherit' });
try {
  await new Promise((resolve) => setTimeout(resolve, 200));
  const auth = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/zip' };
  const first = await fetch('http://127.0.0.1:8080/v1/artifacts', { method: 'POST', headers: auth, body: zip('<h1>one</h1>') });
  const created = await first.json(); if (first.status !== 201 || !created.id || !created.revision) throw new Error(`create failed: ${first.status} ${JSON.stringify(created)}`);
  const denied = await fetch('http://127.0.0.1:8080/v1/artifacts', { method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: zip('x') }); if (denied.status !== 401) throw new Error('auth guard failed');
  const corrupt = zip('corrupt'); corrupt.writeUInt32LE(0, 14); corrupt.writeUInt32LE(0, 30 + Buffer.byteLength('index.html') + Buffer.byteLength('corrupt') + 16);
  const bad = await fetch('http://127.0.0.1:8080/v1/artifacts', { method: 'POST', headers: auth, body: corrupt }); if (bad.status !== 400) throw new Error('CRC guard failed');
  const stale = await fetch(`http://127.0.0.1:8080/v1/artifacts/${created.id}`, { method: 'PUT', headers: { ...auth, 'If-Match': '"stale"' }, body: zip('x') }); if (stale.status !== 412) throw new Error('revision guard failed');
  const update = await fetch(`http://127.0.0.1:8080/v1/artifacts/${created.id}`, { method: 'PUT', headers: { ...auth, 'If-Match': `"${created.revision}"` }, body: zip('<h1>two</h1>') }); const updated = await update.json(); if (update.status !== 200 || updated.revision === created.revision) throw new Error('update failed');
  const concurrent = await Promise.all(Array.from({ length: 8 }, (_, index) => fetch(`http://127.0.0.1:8080/v1/artifacts/${created.id}`, { method: 'PUT', headers: { ...auth, 'If-Match': `"${updated.revision}"` }, body: zip(`<h1>race ${index}</h1>`) })));
  const statuses = concurrent.map((response) => response.status); if (statuses.filter((status) => status === 200).length !== 1 || statuses.filter((status) => status === 412).length !== 7) throw new Error(`concurrency guard failed: ${statuses}`);
  const served = await readFile(join(root, 'id', created.id, 'index.html'), 'utf8'); if (!/^<h1>race [0-7]<\/h1>$/.test(served)) throw new Error('stable path failed');
  console.log(JSON.stringify({ passed: true, checks: ['create', 'auth', 'crc', 'revision', 'stable-update', 'concurrency'] }));
} finally { child.kill(); await rm(root, { recursive: true, force: true }); }
