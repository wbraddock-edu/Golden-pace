'use strict';
/*
 * Golden Pace accounts: username + password or PIN, recovery-code reset, and synced records.
 * Storage: SQLite (node:sqlite, built into Node 22) in DATA_DIR/golden-pace.db.
 *
 * Security notes
 *  - Passwords/PINs are never stored. Each is run through HMAC-SHA256 with a server-only secret
 *    (so a stolen database alone cannot be used to guess short PINs) and then scrypt with a random salt.
 *  - Five wrong tries lock the account for 15 minutes. Sign-in attempts are also limited per IP.
 *  - Sessions are random tokens in an HttpOnly, SameSite=Lax cookie; only a hash is stored.
 *  - Every write requires a same-origin request.
 *  - The Gemini API key is never sent to the server. It stays on the person's device.
 */
const crypto = require('crypto');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DAY = 86400000;
const SESSION_DAYS = 30;
const LOCK_AFTER = 5;
const LOCK_MS = 15 * 60 * 1000;
const IMAGE_QUOTA = 150 * 1024 * 1024;   // per person
const VAULT_LIMIT = 8 * 1024 * 1024;
const IMAGE_LIMIT = 3 * 1024 * 1024;
const COOKIE = 'gp_session';

module.exports = function createAccounts({ dataDir, secret, helpers }) {
  const { json, readBody, clientIp } = helpers;
  const db = new DatabaseSync(path.join(dataDir, 'golden-pace.db'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      cred_type TEXT NOT NULL,
      cred_hash TEXT NOT NULL,
      recovery_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_login INTEGER,
      fail_count INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0,
      reset_fail INTEGER NOT NULL DEFAULT 0,
      reset_locked_until INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vaults (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      rev INTEGER NOT NULL,
      data TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS images (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      hash TEXT NOT NULL,
      data TEXT NOT NULL,
      PRIMARY KEY (user_id, hash)
    );
  `);
  const q = {
    userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
    userById: db.prepare('SELECT * FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (username, cred_type, cred_hash, recovery_hash, created_at) VALUES (?,?,?,?,?)'),
    setLogin: db.prepare('UPDATE users SET last_login = ?, fail_count = 0, locked_until = 0 WHERE id = ?'),
    setFail: db.prepare('UPDATE users SET fail_count = ?, locked_until = ? WHERE id = ?'),
    setResetFail: db.prepare('UPDATE users SET reset_fail = ?, reset_locked_until = ? WHERE id = ?'),
    setCred: db.prepare('UPDATE users SET cred_type = ?, cred_hash = ?, recovery_hash = ?, fail_count = 0, locked_until = 0, reset_fail = 0, reset_locked_until = 0 WHERE id = ?'),
    setRecovery: db.prepare('UPDATE users SET recovery_hash = ? WHERE id = ?'),
    insSession: db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)'),
    getSession: db.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
    extendSession: db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?'),
    delSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    delUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
    getVault: db.prepare('SELECT rev, data, updated_at FROM vaults WHERE user_id = ?'),
    insVault: db.prepare('INSERT INTO vaults (user_id, rev, data, updated_at) VALUES (?,?,?,?)'),
    updVault: db.prepare('UPDATE vaults SET rev = ?, data = ?, updated_at = ? WHERE user_id = ? AND rev = ?'),
    hasImage: db.prepare('SELECT 1 FROM images WHERE user_id = ? AND hash = ?'),
    getImage: db.prepare('SELECT data FROM images WHERE user_id = ? AND hash = ?'),
    putImage: db.prepare('INSERT OR IGNORE INTO images (user_id, hash, data) VALUES (?,?,?)'),
    imageBytes: db.prepare('SELECT COALESCE(SUM(LENGTH(data)),0) AS n FROM images WHERE user_id = ?'),
    delUser: db.prepare('DELETE FROM users WHERE id = ?'),
    count: db.prepare('SELECT COUNT(*) AS n FROM users')
  };
  setInterval(() => { try { q.purgeSessions.run(Date.now()); } catch (_) {} }, 60 * 60 * 1000).unref();

  /* ---------------------------------------------------------- crypto helpers */
  const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? no(e) : ok(k))));
  const pepper = v => crypto.createHmac('sha256', secret).update(String(v)).digest();
  async function hashCred(v) {
    const salt = crypto.randomBytes(16);
    const h = await scrypt(pepper(v), salt);
    return `s1$${salt.toString('base64')}$${h.toString('base64')}`;
  }
  async function checkCred(v, stored) {
    const [, s, h] = String(stored).split('$');
    const got = await scrypt(pepper(v), Buffer.from(s || '', 'base64'));
    const want = Buffer.from(h || '', 'base64');
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  }
  const DUMMY = hashCred('dummy-so-unknown-users-take-the-same-time');
  const sha = s => crypto.createHash('sha256').update(s).digest('hex');
  const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no 0/O/1/I
  function newRecoveryCode() {
    const b = crypto.randomBytes(16);
    let s = '';
    for (let i = 0; i < 16; i++) s += ALPHABET[b[i] % 32];
    return s.match(/.{4}/g).join('-');
  }
  const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const hashRecovery = c => crypto.createHmac('sha256', secret).update('rec|' + normCode(c)).digest('hex');
  const eqHex = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };

  /* ---------------------------------------------------------- validation */
  const USER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{2,23}$/;
  const WEAK_PINS = new Set(['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', '1234', '4321', '1212', '2580', '0123', '12345', '123456', '654321', '000000', '111111']);
  function checkNewCred(type, value, username) {
    if (type === 'pin') {
      if (!/^\d{4,6}$/.test(value)) return 'A PIN must be 4 to 6 numbers.';
      if (WEAK_PINS.has(value)) return 'That PIN is too easy to guess. Please pick a different one.';
      return null;
    }
    if (type === 'password') {
      if (typeof value !== 'string' || value.length < 8) return 'A password needs at least 8 characters.';
      if (value.length > 128) return 'That password is too long.';
      if (username && value.toLowerCase() === String(username).toLowerCase()) return 'Your password cannot be the same as your username.';
      if (/^(.)\1+$/.test(value) || /^(password|12345678|qwertyui)/i.test(value)) return 'That password is too easy to guess. Please pick a different one.';
      return null;
    }
    return 'Please choose a password or a PIN.';
  }

  /* ---------------------------------------------------------- sign-in throttling per IP */
  const ipHits = new Map();
  function ipLimited(ip, max, bucket) {
    const key = bucket + '|' + ip;
    const now = Date.now();
    const a = (ipHits.get(key) || []).filter(t => now - t < 15 * 60 * 1000);
    a.push(now); ipHits.set(key, a);
    return a.length > max;
  }
  setInterval(() => { const now = Date.now(); for (const [k, a] of ipHits) if (!a.some(t => now - t < 15 * 60 * 1000)) ipHits.delete(k); }, 10 * 60 * 1000).unref();

  /* ---------------------------------------------------------- sessions & cookies */
  function parseCookies(req) {
    const out = {};
    for (const part of (req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return out;
  }
  const isHttps = req => (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' || !!req.socket.encrypted;
  function cookieHeader(req, token, maxAgeSec) {
    return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${isHttps(req) ? '; Secure' : ''}`;
  }
  function startSession(req, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    q.insSession.run(sha(token), userId, now, now + SESSION_DAYS * DAY);
    return cookieHeader(req, token, SESSION_DAYS * 86400);
  }
  function currentUser(req) {
    const token = parseCookies(req)[COOKIE];
    if (!token) return null;
    const h = sha(token);
    const s = q.getSession.get(h);
    if (!s || s.expires_at < Date.now()) return null;
    if (s.expires_at - Date.now() < (SESSION_DAYS / 2) * DAY) q.extendSession.run(Date.now() + SESSION_DAYS * DAY, h);
    const u = q.userById.get(s.user_id);
    return u ? { user: u, tokenHash: h } : null;
  }
  const pub = u => ({ id: u.id, username: u.username, credType: u.cred_type });
  const clearCookie = req => cookieHeader(req, '', 0);

  function csrfOk(req) {
    const o = req.headers.origin;
    if (o) { try { return new URL(o).host === req.headers.host; } catch (_) { return false; } }
    return req.headers['sec-fetch-site'] === 'same-origin';
  }
  async function body(req, limit) {
    const raw = await readBody(req, limit);
    try { const o = JSON.parse(raw || '{}'); return o && typeof o === 'object' ? o : {}; } catch (_) { return {}; }
  }
  const str = (v, max = 200) => (typeof v === 'string' ? v.slice(0, max) : '');

  /* ---------------------------------------------------------- handlers */
  async function signup(req, res) {
    if (ipLimited(clientIp(req), 10, 'signup')) return json(res, 429, { ok: false, error: 'slow_down', message: 'Too many new accounts from this connection. Please try again later.' });
    const b = await body(req, 8192);
    const username = str(b.username, 40).trim();
    const type = b.credType === 'pin' ? 'pin' : 'password';
    const cred = str(b.credential, 140);
    if (b.consent !== true) return json(res, 400, { ok: false, error: 'consent', message: 'Please tick the box to agree to the Terms and Privacy Policy.' });
    if (!USER_RE.test(username)) return json(res, 400, { ok: false, error: 'username', message: 'A username is 3 to 24 letters or numbers. You may also use . - or _ inside it.' });
    const bad = checkNewCred(type, cred, username);
    if (bad) return json(res, 400, { ok: false, error: 'credential', message: bad });
    if (q.userByName.get(username)) return json(res, 409, { ok: false, error: 'taken', message: 'That username is already used. Please pick another.' });
    const code = newRecoveryCode();
    let id;
    try {
      const r = q.insertUser.run(username, type, await hashCred(cred), hashRecovery(code), Date.now());
      id = Number(r.lastInsertRowid);
    } catch (e) {
      return json(res, 409, { ok: false, error: 'taken', message: 'That username is already used. Please pick another.' });
    }
    q.setLogin.run(Date.now(), id);
    const cookie = startSession(req, id);
    res.setHeader('Set-Cookie', cookie);
    return json(res, 200, { ok: true, user: pub(q.userById.get(id)), recoveryCode: code });
  }

  async function login(req, res) {
    if (ipLimited(clientIp(req), 40, 'login')) return json(res, 429, { ok: false, error: 'slow_down', message: 'Too many tries. Please wait a few minutes and try again.' });
    const b = await body(req, 8192);
    const username = str(b.username, 40).trim();
    const cred = str(b.credential, 140);
    const u = username ? q.userByName.get(username) : null;
    const now = Date.now();
    if (u && u.locked_until > now) {
      const mins = Math.ceil((u.locked_until - now) / 60000);
      return json(res, 429, { ok: false, error: 'locked', message: `Too many wrong tries. Please wait ${mins} minute${mins === 1 ? '' : 's'}, or use "I forgot my password or PIN".` });
    }
    const ok = u ? await checkCred(cred, u.cred_hash) : (await checkCred(cred, await DUMMY), false);
    if (!u || !ok) {
      if (u) {
        const n = u.fail_count + 1;
        q.setFail.run(n, n >= LOCK_AFTER ? now + LOCK_MS : 0, u.id);
        if (n >= LOCK_AFTER) return json(res, 429, { ok: false, error: 'locked', message: 'Too many wrong tries. Please wait 15 minutes, or use "I forgot my password or PIN".' });
      }
      return json(res, 401, { ok: false, error: 'bad_login', message: 'That username or password/PIN is not right.' });
    }
    q.setLogin.run(now, u.id);
    res.setHeader('Set-Cookie', startSession(req, u.id));
    return json(res, 200, { ok: true, user: pub(u) });
  }

  function logout(req, res) {
    const cu = currentUser(req);
    if (cu) q.delSession.run(cu.tokenHash);
    res.setHeader('Set-Cookie', clearCookie(req));
    return json(res, 200, { ok: true });
  }

  async function reset(req, res) {
    if (ipLimited(clientIp(req), 15, 'reset')) return json(res, 429, { ok: false, error: 'slow_down', message: 'Too many tries. Please wait a few minutes.' });
    const b = await body(req, 8192);
    const username = str(b.username, 40).trim();
    const type = b.credType === 'pin' ? 'pin' : 'password';
    const cred = str(b.credential, 140);
    const u = username ? q.userByName.get(username) : null;
    const now = Date.now();
    const generic = { ok: false, error: 'bad_code', message: 'That username and recovery code do not match.' };
    if (u && u.reset_locked_until > now) return json(res, 429, { ok: false, error: 'locked', message: 'Too many wrong tries. Please wait 15 minutes and try again.' });
    const codeOk = u && normCode(b.code).length === 16 && eqHex(hashRecovery(b.code), u.recovery_hash);
    if (!codeOk) {
      if (u) { const n = u.reset_fail + 1; q.setResetFail.run(n, n >= LOCK_AFTER ? now + LOCK_MS : 0, u.id); }
      return json(res, 401, generic);
    }
    const bad = checkNewCred(type, cred, u.username);
    if (bad) return json(res, 400, { ok: false, error: 'credential', message: bad });
    const code = newRecoveryCode();
    q.setCred.run(type, await hashCred(cred), hashRecovery(code), u.id);
    q.delUserSessions.run(u.id);
    res.setHeader('Set-Cookie', startSession(req, u.id));
    return json(res, 200, { ok: true, user: pub(q.userById.get(u.id)), recoveryCode: code });
  }

  // Actions that need the current password/PIN again (change, new recovery code, delete).
  async function reauth(req, res, cu, b) {
    const u = cu.user, now = Date.now();
    if (u.locked_until > now) { json(res, 429, { ok: false, error: 'locked', message: 'Too many wrong tries. Please wait a few minutes.' }); return false; }
    if (await checkCred(str(b.current, 140), u.cred_hash)) return true;
    const n = u.fail_count + 1;
    q.setFail.run(n, n >= LOCK_AFTER ? now + LOCK_MS : 0, u.id);
    json(res, 401, { ok: false, error: 'bad_current', message: 'Your current password or PIN is not right.' });
    return false;
  }
  async function changeCred(req, res, cu) {
    const b = await body(req, 8192);
    if (!(await reauth(req, res, cu, b))) return;
    const type = b.credType === 'pin' ? 'pin' : 'password';
    const bad = checkNewCred(type, str(b.credential, 140), cu.user.username);
    if (bad) return json(res, 400, { ok: false, error: 'credential', message: bad });
    q.setCred.run(type, await hashCred(str(b.credential, 140)), cu.user.recovery_hash, cu.user.id);
    q.delUserSessions.run(cu.user.id);   // signs out every other device
    res.setHeader('Set-Cookie', startSession(req, cu.user.id));
    return json(res, 200, { ok: true, user: pub(q.userById.get(cu.user.id)) });
  }
  async function newRecovery(req, res, cu) {
    const b = await body(req, 8192);
    if (!(await reauth(req, res, cu, b))) return;
    const code = newRecoveryCode();
    q.setRecovery.run(hashRecovery(code), cu.user.id);
    return json(res, 200, { ok: true, recoveryCode: code });
  }
  async function deleteAccount(req, res, cu) {
    const b = await body(req, 8192);
    if (!(await reauth(req, res, cu, b))) return;
    q.delUser.run(cu.user.id);   // cascades to sessions, vault and images
    res.setHeader('Set-Cookie', clearCookie(req));
    return json(res, 200, { ok: true });
  }

  /* ---------------------------------------------------------- synced records */
  function getVault(res, cu) {
    const v = q.getVault.get(cu.user.id);
    if (!v) return json(res, 200, { ok: true, rev: 0, data: null });
    return json(res, 200, { ok: true, rev: v.rev, data: JSON.parse(v.data), updatedAt: v.updated_at });
  }
  async function putVault(req, res, cu) {
    const b = await body(req, VAULT_LIMIT);
    if (!b.data || typeof b.data !== 'object' || Array.isArray(b.data)) return json(res, 400, { ok: false, error: 'bad_data' });
    const baseRev = Number(b.baseRev) || 0;
    const text = JSON.stringify(b.data);
    const now = Date.now();
    const cur = q.getVault.get(cu.user.id);
    if (!cur) {
      if (baseRev !== 0) return json(res, 409, { ok: false, error: 'conflict', rev: 0 });
      q.insVault.run(cu.user.id, 1, text, now);
      return json(res, 200, { ok: true, rev: 1 });
    }
    if (cur.rev !== baseRev) return json(res, 409, { ok: false, error: 'conflict', rev: cur.rev });
    const r = q.updVault.run(cur.rev + 1, text, now, cu.user.id, baseRev);
    if (!r.changes) return json(res, 409, { ok: false, error: 'conflict', rev: cur.rev });
    return json(res, 200, { ok: true, rev: cur.rev + 1 });
  }
  async function missingImages(req, res, cu) {
    const b = await body(req, 200000);
    const list = Array.isArray(b.hashes) ? b.hashes.filter(h => typeof h === 'string' && /^[a-f0-9]{64}$/.test(h)).slice(0, 2000) : [];
    return json(res, 200, { ok: true, missing: list.filter(h => !q.hasImage.get(cu.user.id, h)) });
  }
  async function putImage(req, res, cu, hash) {
    const b = await body(req, IMAGE_LIMIT + 1024);
    const data = str(b.data, IMAGE_LIMIT);
    if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(data)) return json(res, 400, { ok: false, error: 'bad_image' });
    if (sha(data) !== hash) return json(res, 400, { ok: false, error: 'hash_mismatch' });
    if (q.imageBytes.get(cu.user.id).n + data.length > IMAGE_QUOTA) return json(res, 413, { ok: false, error: 'quota', message: 'Your photo storage is full.' });
    q.putImage.run(cu.user.id, hash, data);
    return json(res, 200, { ok: true });
  }
  function getImage(res, cu, hash) {
    const r = q.getImage.get(cu.user.id, hash);
    if (!r) return json(res, 404, { ok: false });
    return json(res, 200, { ok: true, data: r.data });
  }

  /* ---------------------------------------------------------- router */
  async function handle(req, res, u) {
    const p = u.pathname, m = req.method;
    if (!(p.startsWith('/api/') )) return false;
    const isWrite = m !== 'GET' && m !== 'HEAD';
    const mine = /^\/api\/(me|signup|login|logout|reset|account\/|vault|images?\b)/.test(p);
    if (!mine) return false;
    if (isWrite && !csrfOk(req)) { json(res, 403, { ok: false, error: 'origin' }); return true; }

    if (p === '/api/signup' && m === 'POST') { await signup(req, res); return true; }
    if (p === '/api/login' && m === 'POST') { await login(req, res); return true; }
    if (p === '/api/reset' && m === 'POST') { await reset(req, res); return true; }
    if (p === '/api/logout' && m === 'POST') { logout(req, res); return true; }

    const cu = currentUser(req);
    if (!cu) { json(res, 401, { ok: false, error: 'signed_out' }); return true; }
    if (p === '/api/me' && m === 'GET') { json(res, 200, { ok: true, user: pub(cu.user) }); return true; }
    if (p === '/api/account/credential' && m === 'POST') { await changeCred(req, res, cu); return true; }
    if (p === '/api/account/recovery' && m === 'POST') { await newRecovery(req, res, cu); return true; }
    if (p === '/api/account/delete' && m === 'POST') { await deleteAccount(req, res, cu); return true; }
    if (p === '/api/vault' && m === 'GET') { getVault(res, cu); return true; }
    if (p === '/api/vault' && m === 'PUT') { await putVault(req, res, cu); return true; }
    if (p === '/api/images/missing' && m === 'POST') { await missingImages(req, res, cu); return true; }
    const im = p.match(/^\/api\/image\/([a-f0-9]{64})$/);
    if (im && m === 'PUT') { await putImage(req, res, cu, im[1]); return true; }
    if (im && m === 'GET') { getImage(res, cu, im[1]); return true; }
    json(res, 404, { ok: false, error: 'not_found' });
    return true;
  }

  return { handle, count: () => q.count.get().n };
};
