import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { inflateRawSync } from 'node:zlib';
import { mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';

const root = resolve(process.env.ARTIFACT_ROOT ?? '/static');
const publicBaseUrl = new URL(process.env.PUBLIC_BASE_URL ?? 'http://localhost:8080').toString().replace(/\/$/, '');
const tokenHashes = (process.env.API_TOKEN_SHA256 ?? '').split(',').filter(Boolean).map((value) => Buffer.from(value, 'hex'));
const maxBytes = 15 * 1024 * 1024;
const maxExpandedBytes = 40 * 1024 * 1024;
const maxFiles = 200;
const failures = new Map();
const mutations = new Map();

if (!tokenHashes.length || tokenHashes.some((tokenHash) => tokenHash.length !== 32)) throw new Error('API_TOKEN_SHA256 must contain one or more comma-separated SHA-256 digests');

const sha256 = (value) => createHash('sha256').update(value).digest();
const json = (response, status, body, etag) => {
  response.writeHead(status, {
    'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    ...(etag ? { ETag: `"${etag}"` } : {}),
  });
  response.end(JSON.stringify(body));
};
const artifactCsp = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https:; img-src 'self' data: https:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox allow-scripts allow-downloads";
const contentTypes = { '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2' };
async function artifact(request, response) {
  const match = /^\/id\/([23456789abcdefghjkmnpqrstuvwxyz]{12})(?:\/(.*))?$/.exec((request.url ?? '').split('?', 1)[0]);
  if (!match) return false;
  const base = resolve(root, 'id', match[1]); const target = resolve(base, match[2] || 'index.html');
  if (target !== base && !target.startsWith(`${base}${sep}`)) return false;
  try {
    const data = await readFile(target);
    response.writeHead(200, { 'Cache-Control': 'no-store', 'Content-Type': contentTypes[extname(target)] ?? 'application/octet-stream', 'Content-Security-Policy': artifactCsp, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    response.end(data);
  } catch { fail(response, 404, 'not found'); }
  return true;
}
const fail = (response, status, error) => json(response, status, { error });
const artifactPath = (id) => /^[23456789abcdefghjkmnpqrstuvwxyz]{12}$/.test(id);
const inside = (path) => path === root || path.startsWith(`${root}${sep}`);

async function body(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('archive too large'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function entries(archive) {
  const start = Math.max(0, archive.length - 65557);
  const eocd = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < start || eocd + 22 > archive.length) throw new Error('invalid ZIP end record');
  const count = archive.readUInt16LE(eocd + 10);
  const directorySize = archive.readUInt32LE(eocd + 12);
  const directoryOffset = archive.readUInt32LE(eocd + 16);
  if (!count || count > maxFiles || directoryOffset + directorySize > archive.length) throw new Error('invalid ZIP directory');
  const found = []; const names = new Set(); let expanded = 0; let offset = directoryOffset;
  for (let index = 0; index < count; index++) {
    if (archive.readUInt32LE(offset) !== 0x02014b50) throw new Error('invalid ZIP entry');
    if (offset + 46 > directoryOffset + directorySize) throw new Error('invalid ZIP entry');
    const flags = archive.readUInt16LE(offset + 8); const method = archive.readUInt16LE(offset + 10);
    const crc = archive.readUInt32LE(offset + 16); const compressedSize = archive.readUInt32LE(offset + 20); const uncompressedSize = archive.readUInt32LE(offset + 24);
    const nameLength = archive.readUInt16LE(offset + 28); const extraLength = archive.readUInt16LE(offset + 30); const commentLength = archive.readUInt16LE(offset + 32);
    const attributes = archive.readUInt32LE(offset + 38); const localOffset = archive.readUInt32LE(offset + 42);
    if (offset + 46 + nameLength + extraLength + commentLength > directoryOffset + directorySize) throw new Error('invalid ZIP entry');
    const name = archive.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
    const mode = attributes >>> 16;
    if ((flags & 9) || ![0, 8].includes(method) || !name || name.includes('\\') || name.includes('\0') || name.startsWith('/') || name.split('/').some((part) => !part || part === '.' || part === '..') || (mode && (mode & 0o170000) !== 0o100000)) throw new Error('unsafe ZIP entry');
    if (names.has(name) || localOffset + 30 > archive.length || archive.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('duplicate or malformed ZIP entry');
    const localNameLength = archive.readUInt16LE(localOffset + 26); const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    if (archive.readUInt32LE(localOffset + 14) !== crc || archive.subarray(localOffset + 30, localOffset + 30 + localNameLength).toString('utf8') !== name || dataStart + compressedSize > archive.length) throw new Error('ZIP local entry mismatch');
    expanded += uncompressedSize;
    if (expanded > maxExpandedBytes || (compressedSize && uncompressedSize / compressedSize > 100)) throw new Error('ZIP expansion limit');
    names.add(name); found.push({ name, method, crc, compressedSize, uncompressedSize, dataStart });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  if (!names.has('index.html')) throw new Error('archive must contain index.html');
  return found;
}

async function unpack(archive, destination) {
  for (const entry of entries(archive)) {
    const data = archive.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
    const output = entry.method === 0 ? data : inflateRawSync(data, { maxOutputLength: maxExpandedBytes });
    if (output.length !== entry.uncompressedSize || crc32(output) !== entry.crc) throw new Error('ZIP integrity check failed');
    const target = resolve(destination, entry.name);
    if (!inside(target) || !target.startsWith(`${resolve(destination)}${sep}`)) throw new Error('unsafe output path');
    await mkdir(resolve(target, '..'), { recursive: true });
    await writeFile(target, output, { mode: 0o644 });
  }
}

function client(request) { return (request.headers['x-forwarded-for']?.split(',')[0] || request.socket.remoteAddress || 'unknown').trim(); }
function permitted(request) {
  const key = client(request); const prior = failures.get(key);
  if (prior?.until > Date.now()) return { ok: false, limited: true };
  const match = /^Bearer ([A-Za-z0-9_-]{32,})$/.exec(request.headers.authorization ?? '');
  const digest = match ? sha256(match[1]) : null;
  const ok = !!digest && tokenHashes.reduce((allowed, tokenHash) => timingSafeEqual(digest, tokenHash) || allowed, false);
  if (ok) { failures.delete(key); return { ok: true }; }
  const attempts = (prior?.attempts ?? 0) + 1;
  failures.set(key, { attempts, until: attempts >= 5 ? Date.now() + 60_000 : 0 });
  return { ok: false, limited: attempts >= 5 };
}

async function revision(id) {
  try { return (await readFile(join(root, 'meta', `${id}.txt`), 'utf8')).trim(); } catch { return null; }
}
const githubIssuer = 'https://token.actions.githubusercontent.com';
async function deploy(request, response) {
  const webhook = process.env.DEPLOY_WEBHOOK_URL;
  const audience = process.env.GITHUB_OIDC_AUDIENCE;
  const subject = process.env.GITHUB_OIDC_SUBJECT;
  const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? '')?.[1];
  if (!webhook || !audience || !subject || !token) return fail(response, 404, 'not found');
  const [headerPart, payloadPart, signaturePart, ...extra] = token.split('.');
  if (extra.length || !headerPart || !payloadPart || !signaturePart) return fail(response, 401, 'unauthorized');
  let header; let claims;
  try { header = JSON.parse(Buffer.from(headerPart, 'base64url')); claims = JSON.parse(Buffer.from(payloadPart, 'base64url')); } catch { return fail(response, 401, 'unauthorized'); }
  if (header.alg !== 'RS256' || !header.kid || claims.iss !== githubIssuer || claims.aud !== audience || claims.sub !== subject || claims.exp <= Date.now() / 1000 || (claims.nbf && claims.nbf > Date.now() / 1000)) return fail(response, 401, 'unauthorized');
  try {
    const configuration = await fetch(`${githubIssuer}/.well-known/openid-configuration`).then((r) => r.ok ? r.json() : Promise.reject());
    const key = (await fetch(configuration.jwks_uri).then((r) => r.ok ? r.json() : Promise.reject())).keys.find((candidate) => candidate.kid === header.kid && candidate.kty === 'RSA');
    if (!key || !verify('RSA-SHA256', Buffer.from(`${headerPart}.${payloadPart}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(signaturePart, 'base64url'))) return fail(response, 401, 'unauthorized');
    const upstream = await fetch(webhook, { method: 'POST', signal: AbortSignal.timeout(15_000) });
    if (!upstream.ok) throw new Error(`webhook ${upstream.status}`);
    return json(response, 202, { accepted: true });
  } catch { return fail(response, 502, 'deployment unavailable'); }
}
async function publish(id, archive, prior) {
  const next = randomBytes(16).toString('hex'); const stage = join(root, '.staging', `${id}-${next}`); const release = join(root, 'revisions', id, next);
  await mkdir(stage, { recursive: true });
  try {
    await unpack(archive, stage); await mkdir(join(root, 'revisions', id), { recursive: true }); await mkdir(join(root, 'id'), { recursive: true }); await rename(stage, release);
    const link = join(root, 'id', id); const temp = join(root, '.staging', `link-${id}-${next}`);
    await symlink(relative(join(root, 'id'), release), temp); await rename(temp, link);
    await mkdir(join(root, 'meta'), { recursive: true }); await writeFile(join(root, 'meta', `${id}.txt`), next, { mode: 0o600 });
    console.log(JSON.stringify({ event: prior ? 'updated' : 'created', id, revision: next, bytes: archive.length }));
    return next;
  } catch (error) { await rm(stage, { recursive: true, force: true }); throw error; }
}

async function mutate(id, task) {
  const prior = mutations.get(id) ?? Promise.resolve();
  let release;
  const queued = new Promise((resolve) => { release = resolve; });
  const running = prior.then(() => queued);
  mutations.set(id, running);
  await prior;
  try { return await task(); } finally { release(); if (mutations.get(id) === running) mutations.delete(id); }
}

createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/healthz') return json(response, 200, { ok: true });
    if (request.method === 'GET' && request.url === '/version') return json(response, 200, { buildSha: process.env.BUILD_SHA ?? 'unknown' });
    if (request.method === 'GET' && await artifact(request, response)) return;
    if (request.method === 'POST' && request.url === '/v1/deploy') return deploy(request, response);
    const match = /^\/v1\/artifacts(?:\/([23456789abcdefghjkmnpqrstuvwxyz]{12}))?$/.exec(request.url ?? '');
    if (!match || !['POST', 'PUT'].includes(request.method ?? '')) return fail(response, 404, 'not found');
    const auth = permitted(request); if (!auth.ok) return fail(response, auth.limited ? 429 : 401, auth.limited ? 'rate limited' : 'unauthorized');
    if (request.headers['content-type'] !== 'application/zip') return fail(response, 400, 'content-type must be application/zip');
    const archive = await body(request);
    const id = match[1] ?? Array.from(randomBytes(12), (byte) => '23456789abcdefghjkmnpqrstuvwxyz'[byte % 30]).join('');
    return await mutate(id, async () => {
      const existing = match[1] ? await revision(match[1]) : null;
      if (request.method === 'POST' && match[1]) return fail(response, 404, 'not found');
      if (request.method === 'PUT' && (!match[1] || !existing)) return fail(response, 404, 'not found');
      if (request.method === 'PUT' && request.headers['if-match'] !== `"${existing}"`) return fail(response, 412, 'revision mismatch');
      const next = await publish(id, archive, existing);
      return json(response, existing ? 200 : 201, { id, url: `${publicBaseUrl}/id/${id}/`, revision: next }, next);
    });
  } catch (error) { console.log(JSON.stringify({ event: 'rejected', reason: error.message })); return fail(response, error.status ?? 400, error.message === 'archive too large' ? error.message : 'invalid archive'); }
}).listen(8080, '0.0.0.0');
