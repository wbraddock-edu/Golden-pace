'use strict';
/*
 * Golden Pace web server.
 *  - Serves the static site (only an explicit allow-list of files).
 *  - POST /api/subscribe  : someone asks for the free guide. We email them a private, expiring download link.
 *  - GET  /guide/download : checks the signed link, then sends the PDF. The PDF is never a public file.
 *  - Unsubscribe          : one click removes the address (also supports the email "unsubscribe" button).
 *  - GET  /admin/subscribers.csv : the list, protected by the ADMIN_TOKEN password.
 *
 * Settings come from environment variables (see README.md): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
 * MAIL_FROM, ADMIN_TOKEN, SITE_URL (optional), DATA_DIR (optional), SIGNING_SECRET (optional).
 * Until the SMTP_* settings exist, the signup form stays hidden on the website and /api/subscribe refuses.
 */
const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(ROOT, 'data'));
const GUIDE_FILE = path.join(ROOT, 'private', 'Golden-Pace-Guide.pdf');
const GUIDE_NAME = 'Golden-Pace-Guide.pdf';
const LINK_DAYS = 14;
const RESEND_AFTER_MS = 10 * 60 * 1000;
const DAILY_EMAIL_CAP = Number(process.env.DAILY_EMAIL_CAP) || 400;

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------------------------------------------------------- signing secret */
function loadSecret() {
  if (process.env.SIGNING_SECRET) return process.env.SIGNING_SECRET;
  const f = path.join(DATA_DIR, 'signing.key');
  try { return fs.readFileSync(f, 'utf8').trim(); } catch (_) {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(f, s, { mode: 0o600 });
  return s;
}
const SECRET = loadSecret();
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const dlToken = (id, exp) => sign(`dl|${id}|${exp}`);
const unsubToken = id => sign(`unsub|${id}`);

/* ---------------------------------------------------------------- subscriber store (JSON file, atomic writes) */
const STORE = path.join(DATA_DIR, 'subscribers.json');
let records = [];
try { records = JSON.parse(fs.readFileSync(STORE, 'utf8')).records || []; } catch (_) { records = []; }
const byEmail = new Map(records.map(r => [r.email, r]));
const byId = new Map(records.map(r => [r.id, r]));
let writeChain = Promise.resolve();
function persist() {
  writeChain = writeChain.then(async () => {
    const tmp = STORE + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify({ records }, null, 1), { mode: 0o600 });
    await fsp.rename(tmp, STORE);
  }).catch(err => console.error('persist failed:', err.message));
  return writeChain;
}

/* ---------------------------------------------------------------- email */
const smtpReady = () => !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.MAIL_FROM);
const guideReady = () => fs.existsSync(GUIDE_FILE);
const enabled = () => smtpReady() && guideReady();
let transport = null;
function getTransport() {
  if (!transport) {
    const port = Number(process.env.SMTP_PORT) || 587;
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 20000
    });
  }
  return transport;
}
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function siteUrl(req) {
  if (process.env.SITE_URL) return process.env.SITE_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  return `${proto}://${req.headers.host}`;
}

async function sendGuideEmail(base, rec) {
  const exp = Math.floor(Date.now() / 1000) + LINK_DAYS * 86400;
  const link = `${base}/guide/download?id=${rec.id}&x=${exp}&t=${dlToken(rec.id, exp)}`;
  const unsub = `${base}/api/unsubscribe?id=${rec.id}&t=${unsubToken(rec.id)}`;
  const text = [
    'Hello,',
    '',
    'Here is your free guide, "Know Your Numbers, Keep Your Pace: The Golden Pace Guide for Adults 55+".',
    '',
    'Download it here (the link works for ' + LINK_DAYS + ' days):',
    link,
    '',
    'You can read it on your phone, tablet or computer, or print it.',
    '',
    'Golden Pace is a wellness logbook, not medical advice. Check with your primary care physician before starting any exercise program.',
    '',
    'You received this one email because you asked for the guide at Golden Pace. We will not add you to any other list.',
    'To remove your email address from our records, open: ' + unsub,
    '',
    'Written by William T Braddock Jr. Published by Little Red Apple Productions LLC.'
  ].join('\n');
  const html = `<!doctype html><html><body style="margin:0;background:#fcfbfa;font-family:Arial,Helvetica,sans-serif;color:#1c1a16">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border:1px solid #e5e0d6;border-radius:12px">
<tr><td style="background:#163827;color:#ffffff;padding:20px 24px;border-radius:12px 12px 0 0;font-size:22px;font-weight:bold">&#127793; Golden Pace</td></tr>
<tr><td style="padding:24px;font-size:18px;line-height:1.55">
<p style="margin:0 0 14px">Hello,</p>
<p style="margin:0 0 14px">Here is your free guide:<br><b>Know Your Numbers, Keep Your Pace</b><br>The Golden Pace Guide for Adults 55+</p>
<p style="margin:22px 0;text-align:center"><a href="${esc(link)}" style="background:#fbbf24;color:#163827;font-weight:bold;font-size:20px;text-decoration:none;padding:16px 28px;border-radius:10px;display:inline-block">Download my free guide</a></p>
<p style="margin:0 0 14px;font-size:16px;color:#4a463d">The link works for ${LINK_DAYS} days. If the button does not work, copy this address into your browser:<br><a href="${esc(link)}" style="color:#1e4b34;word-break:break-all">${esc(link)}</a></p>
<p style="margin:18px 0 0;padding:12px 14px;background:#fff4d6;border-left:6px solid #f59e0b;border-radius:6px;font-size:16px"><b>Talk to your doctor first.</b> Golden Pace is a wellness logbook, not medical advice. Check with your primary care physician before starting any exercise program.</p>
</td></tr>
<tr><td style="padding:16px 24px 24px;font-size:14px;color:#6b675e;border-top:1px solid #eee8dc">
You received this one email because you asked for the guide at Golden Pace. We will not add you to any other list.<br>
<a href="${esc(unsub)}" style="color:#6b675e">Remove my email address</a><br><br>
Written by William T Braddock Jr &middot; Published by Little Red Apple Productions LLC
</td></tr></table></td></tr></table></body></html>`;
  await getTransport().sendMail({
    from: process.env.MAIL_FROM,
    replyTo: process.env.MAIL_REPLY_TO || undefined,
    to: rec.email,
    subject: 'Your free Golden Pace guide',
    text, html,
    headers: {
      'List-Unsubscribe': `<${unsub}>`,
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
    }
  });
}

/* ---------------------------------------------------------------- rate limiting */
const hits = new Map();           // ip -> [timestamps]
let dayKey = '', dayCount = 0;
function tooMany(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 8;
}
setInterval(() => { const now = Date.now(); for (const [ip, a] of hits) if (!a.some(t => now - t < 15 * 60 * 1000)) hits.delete(ip); }, 10 * 60 * 1000).unref();
function underDailyCap() {
  const k = new Date().toISOString().slice(0, 10);
  if (k !== dayKey) { dayKey = k; dayCount = 0; }
  return dayCount < DAILY_EMAIL_CAP;
}

/* ---------------------------------------------------------------- helpers */
const clientIp = req => ((req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
function send(res, status, body, headers = {}) {
  res.writeHead(status, Object.assign({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Frame-Options': 'SAMEORIGIN'
  }, headers));
  res.end(body);
}
const json = (res, status, obj) => send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
function page(res, status, title, bodyHtml) {
  send(res, status, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} | Golden Pace</title>
<style>body{margin:0;background:#fcfbfa;color:#1c1a16;font:18px/1.6 Arial,Helvetica,sans-serif}header{background:#163827;color:#fff;padding:14px 20px;font-weight:bold;font-size:20px}main{max-width:36rem;margin:0 auto;padding:24px 20px}a.b,button{display:inline-block;background:#fbbf24;color:#163827;font-weight:bold;font-size:18px;border:0;border-radius:10px;padding:14px 22px;text-decoration:none;cursor:pointer}h1{color:#163827}</style></head>
<body><header>&#127793; Golden Pace</header><main>${bodyHtml}</main></body></html>`,
    { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
}
function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function parseBody(req) {
  const raw = await readBody(req);
  const type = (req.headers['content-type'] || '').split(';')[0].trim();
  if (type === 'application/json') { try { return JSON.parse(raw || '{}'); } catch (_) { return {}; } }
  return Object.fromEntries(new URLSearchParams(raw));
}
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch (_) { return false; }
}
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?\.[A-Za-z]{2,}$/;

/* ---------------------------------------------------------------- API handlers */
async function subscribe(req, res) {
  if (!sameOrigin(req)) return json(res, 403, { ok: false, error: 'origin' });
  if (!enabled()) return json(res, 503, { ok: false, error: 'unavailable' });
  if (tooMany(clientIp(req))) return json(res, 429, { ok: false, error: 'slow_down' });
  let body;
  try { body = await parseBody(req); } catch (e) { return json(res, e.status || 400, { ok: false, error: 'bad_request' }); }
  if (body.website) return json(res, 200, { ok: true, state: 'sent' });          // honeypot: bots fill hidden fields
  const email = String(body.email || '').trim().toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email)) return json(res, 400, { ok: false, error: 'invalid_email' });

  let rec = byEmail.get(email);
  if (rec && rec.lastSentAt && Date.now() - rec.lastSentAt < RESEND_AFTER_MS) return json(res, 200, { ok: true, state: 'recent' });
  if (!underDailyCap()) return json(res, 503, { ok: false, error: 'busy' });

  const isNew = !rec;
  if (isNew) rec = { id: crypto.randomBytes(12).toString('base64url'), email, createdAt: Date.now(), sentCount: 0, downloads: 0 };
  try {
    await sendGuideEmail(siteUrl(req), rec);
  } catch (err) {
    console.error('send failed:', err.code || '', err.responseCode || '', (err.message || '').slice(0, 120));
    return json(res, 502, { ok: false, error: 'send_failed' });
  }
  dayCount++;
  rec.lastSentAt = Date.now(); rec.sentCount++;
  if (isNew) { records.push(rec); byEmail.set(email, rec); byId.set(rec.id, rec); }
  await persist();
  console.log('guide emailed, id', rec.id.slice(0, 6), isNew ? '(new)' : '(repeat)');
  return json(res, 200, { ok: true, state: 'sent' });
}

function download(req, res, q) {
  const id = q.get('id') || '', exp = Number(q.get('x')), tok = q.get('t') || '';
  const rec = byId.get(id);
  const good = rec && Number.isFinite(exp) && safeEq(tok, dlToken(id, exp));
  if (!good || exp < Math.floor(Date.now() / 1000) || !guideReady()) {
    return page(res, 403, 'Link not valid', `<h1>This link has expired or is not valid</h1><p>No problem. You can ask for a fresh link and we will email it to you.</p><p><a class="b" href="/welcome.html#guide">Get a new link</a></p>`);
  }
  rec.downloads = (rec.downloads || 0) + 1; rec.lastDownloadAt = Date.now(); persist();
  const stat = fs.statSync(GUIDE_FILE);
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Length': stat.size,
    'Content-Disposition': `attachment; filename="${GUIDE_NAME}"`,
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(GUIDE_FILE).pipe(res);
}

async function unsubscribe(req, res, q) {
  let id = q.get('id') || '', tok = q.get('t') || '';
  if (req.method === 'POST') {
    const b = await parseBody(req).catch(() => ({}));
    id = b.id || id; tok = b.t || tok;       // email "one-click" posts the query string; the confirm page posts the form
  }
  const rec = byId.get(id);
  if (!rec || !safeEq(tok, unsubToken(id))) {
    return page(res, 400, 'Link not valid', `<h1>That link is not valid</h1><p>It may already have been used.</p>`);
  }
  if (req.method !== 'POST') {
    // A link scanner opening the email must not remove anyone, so GET only asks for confirmation.
    return page(res, 200, 'Remove my email', `<h1>Remove your email address?</h1><p>We will delete your address from our records. You will not get any more emails from us.</p>
<form method="post" action="/api/unsubscribe"><input type="hidden" name="id" value="${esc(id)}"><input type="hidden" name="t" value="${esc(tok)}"><button type="submit">Yes, remove my email</button></form>`);
  }
  records = records.filter(r => r.id !== id); byEmail.delete(rec.email); byId.delete(id);
  await persist();
  console.log('removed id', id.slice(0, 6));
  return page(res, 200, 'Removed', `<h1>Done. Your email address has been removed.</h1><p>Thank you. The Golden Pace app itself keeps working exactly as before.</p><p><a class="b" href="/">Open Golden Pace</a></p>`);
}

function adminCsv(req, res) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  const pass = m ? Buffer.from(m[1], 'base64').toString('utf8').split(':').slice(1).join(':') : '';
  if (!m || !safeEq(pass, token)) return send(res, 401, 'Sign in', { 'WWW-Authenticate': 'Basic realm="Golden Pace list"', 'Content-Type': 'text/plain' });
  const cell = v => { let s = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const iso = t => (t ? new Date(t).toISOString() : '');
  const rows = [['email', 'signed_up', 'last_emailed', 'emails_sent', 'downloads', 'last_download']].concat(
    records.map(r => [r.email, iso(r.createdAt), iso(r.lastSentAt), r.sentCount || 0, r.downloads || 0, iso(r.lastDownloadAt)]));
  send(res, 200, '﻿' + rows.map(r => r.map(cell).join(',')).join('\r\n') + '\r\n', {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="golden-pace-subscribers.csv"',
    'Cache-Control': 'no-store'
  });
}

/* ---------------------------------------------------------------- static files */
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json'
};
const COMPRESSIBLE = new Set(['.html', '.css', '.js', '.svg', '.webmanifest']);
const gzCache = new Map();
function resolveStatic(urlPath) {
  let p;
  try { p = decodeURIComponent(urlPath); } catch (_) { return null; }
  if (p.includes('\0') || p.includes('\\')) return null;
  if (p === '/' || p === '') p = '/index.html';
  const segs = p.split('/').filter(Boolean);
  if (!segs.length || segs.some(s => s === '..' || s.startsWith('.'))) return null;
  const rel = segs.join('/');
  const ext = path.extname(rel).toLowerCase();
  if (!TYPES[ext]) return null;
  if (ext === '.js' && !(rel === 'sw.js' || rel.startsWith('vendor/'))) return null;       // never expose server.js
  if (['private', 'tools', 'node_modules', 'data'].includes(segs[0])) return null;
  const abs = path.join(ROOT, rel);
  if (!abs.startsWith(ROOT + path.sep)) return null;
  return { abs, rel, ext };
}
function serveStatic(req, res, pathname) {
  const f = resolveStatic(pathname);
  let st;
  try { st = f && fs.statSync(f.abs); } catch (_) { st = null; }
  if (!f || !st || !st.isFile()) {
    const nf = path.join(ROOT, 'index.html');
    return send(res, 404, '<!doctype html><meta charset="utf-8"><title>Not found</title><body style="font:18px Arial;padding:2rem"><h1>Page not found</h1><p><a href="/">Go to Golden Pace</a></p>', { 'Content-Type': 'text/html; charset=utf-8' });
  }
  const etag = `W/"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
  const noCache = ['.html', '.css', '.webmanifest'].includes(f.ext) || f.rel === 'sw.js';
  const headers = {
    'Content-Type': TYPES[f.ext], ETag: etag, 'Last-Modified': st.mtime.toUTCString(),
    'Cache-Control': noCache ? 'no-cache' : 'public, max-age=86400', Vary: 'Accept-Encoding'
  };
  if (req.headers['if-none-match'] === etag) return send(res, 304, '', headers);
  const wantsGzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && COMPRESSIBLE.has(f.ext) && st.size > 1024;
  if (wantsGzip) {
    let c = gzCache.get(f.abs);
    if (!c || c.etag !== etag) { c = { etag, buf: zlib.gzipSync(fs.readFileSync(f.abs), { level: 9 }) }; gzCache.set(f.abs, c); }
    headers['Content-Encoding'] = 'gzip'; headers['Content-Length'] = c.buf.length;
    return send(res, 200, req.method === 'HEAD' ? '' : c.buf, headers);
  }
  headers['Content-Length'] = st.size;
  if (req.method === 'HEAD') return send(res, 200, '', headers);
  res.writeHead(200, Object.assign({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Frame-Options': 'SAMEORIGIN' }, headers));
  fs.createReadStream(f.abs).pipe(res);
}

/* ---------------------------------------------------------------- router */
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://localhost');
    const p = u.pathname, m = req.method;
    if (p === '/healthz') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });
    if (p === '/api/guide-status' && (m === 'GET' || m === 'HEAD')) return json(res, 200, { enabled: enabled() });
    if (p === '/api/subscribe') return m === 'POST' ? await subscribe(req, res) : json(res, 405, { ok: false });
    if (p === '/api/unsubscribe' && (m === 'GET' || m === 'POST')) return await unsubscribe(req, res, u.searchParams);
    if (p === '/guide/download' && (m === 'GET' || m === 'HEAD')) return download(req, res, u.searchParams);
    if (p === '/admin/subscribers.csv' && m === 'GET') return adminCsv(req, res);
    if (m !== 'GET' && m !== 'HEAD') return send(res, 405, 'Method not allowed', { 'Content-Type': 'text/plain', Allow: 'GET, HEAD' });
    return serveStatic(req, res, p);
  } catch (err) {
    console.error('request error:', err.message);
    if (!res.headersSent) send(res, 500, 'Something went wrong', { 'Content-Type': 'text/plain' });
  }
});

server.listen(PORT, () => {
  console.log(`Golden Pace listening on ${PORT}. Data dir: ${DATA_DIR}. Guide emailing: ${enabled() ? 'ON' : 'OFF (set SMTP_* and MAIL_FROM)'}. Subscribers: ${records.length}.`);
});
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { writeChain.finally(() => server.close(() => process.exit(0))); setTimeout(() => process.exit(0), 5000).unref(); });
