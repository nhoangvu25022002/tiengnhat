// Một hàm duy nhất xử lý toàn bộ API, chọn việc theo tham số ?a=
//
//  Tài khoản (học viên)
//   POST ?a=register   tạo tài khoản mới
//   POST ?a=login      đăng nhập, trả về mã phiên
//   GET  ?a=me         thông tin tài khoản đang đăng nhập
//   POST ?a=logout     đăng xuất
//   POST ?a=chpw       đổi mật khẩu của chính mình
//   POST ?a=submit     nộp bài (máy chủ tự chấm lại)
//   GET  ?a=mine       lịch sử bài làm của chính mình
//  Quản trị (cần mật khẩu quản trị trong tiêu đề x-admin-password)
//   GET  ?a=admin      toàn bộ bài làm và danh sách tài khoản
//   POST ?a=delete     xóa một bài làm
//   POST ?a=resetpw    đặt lại mật khẩu cho một tài khoản (trả về mật khẩu tạm)
//   POST ?a=deluser    xóa một tài khoản cùng toàn bộ bài làm của tài khoản đó
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import net from 'node:net';
import tls from 'node:tls';
import { TABLES } from '../lib/kana.js';

const scrypt = promisify(scryptCb);

const KEY = 'kana:results';          // mọi bài làm: id -> JSON
const USERS = 'kana:users';          // tài khoản: tên đăng nhập -> JSON
const PHONES = 'kana:phones';        // số điện thoại -> tên đăng nhập (mỗi số một tài khoản)
const userHistoryKey = (u) => 'kana:uh:' + u;   // bài làm của một tài khoản: id -> JSON
const MAX_RECORDS = 30000;
const MAX_USERS = 5000;
const MAX_QUESTIONS = 50;
const SESSION_SECONDS = 30 * 24 * 3600;
const DUMMY_SALT = '0'.repeat(32);
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,29}$/;

/* ---------- Kho dữ liệu Redis (không cần cài thêm thư viện) ----------
   Cách 1: Upstash qua REST  (KV_REST_API_URL + KV_REST_API_TOKEN)
   Cách 2: Redis thông thường (KV_REDIS_URL hoặc REDIS_URL, dạng redis:// hoặc rediss://) */
function restCreds() {
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN
  };
}
function tcpUrl() {
  return process.env.KV_REDIS_URL || process.env.REDIS_URL;
}

async function viaRest(cmd, { url, token }) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.error) throw new Error(body.error || 'redis_' + res.status);
  return body.result;
}

/* Bộ đọc giao thức RESP2. Trả về [giá trị, vị trí kế tiếp] hoặc null nếu dữ liệu chưa đủ. */
function parseReply(buf, pos = 0) {
  if (pos >= buf.length) return null;
  const type = String.fromCharCode(buf[pos]);
  const eol = buf.indexOf('\r\n', pos + 1);
  if (eol < 0) return null;
  const line = buf.toString('utf8', pos + 1, eol);
  const next = eol + 2;
  switch (type) {
    case '+': return [line, next];
    case '-': return [Object.assign(new Error(line), { redisReply: true }), next];
    case ':': return [Number(line), next];
    case '$': {
      const n = Number(line);
      if (n < 0) return [null, next];
      if (buf.length < next + n + 2) return null;
      return [buf.toString('utf8', next, next + n), next + n + 2];
    }
    case '*': {
      const n = Number(line);
      if (n < 0) return [null, next];
      const arr = [];
      let p = next;
      for (let i = 0; i < n; i++) {
        const r = parseReply(buf, p);
        if (!r) return null;
        arr.push(r[0]);
        p = r[1];
      }
      return [arr, p];
    }
    default: throw new Error('Phản hồi Redis không hợp lệ');
  }
}
function encodeCommand(cmd) {
  const parts = ['*' + cmd.length + '\r\n'];
  for (const arg of cmd) {
    const s = String(arg);
    parts.push('$' + Buffer.byteLength(s) + '\r\n' + s + '\r\n');
  }
  return Buffer.from(parts.join(''));
}

let tcp = null; // { socket, ready, queue, buf }
function dropTcp(err) {
  const c = tcp;
  tcp = null;
  if (!c) return;
  try { c.socket.destroy(); } catch {}
  for (const p of c.queue.splice(0)) { clearTimeout(p.timer); p.reject(err || new Error('Mất kết nối Redis')); }
}
function sendTcp(c, cmd) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => dropTcp(new Error('Redis phản hồi quá chậm')), 10000);
    c.queue.push({ resolve, reject, timer });
    c.socket.write(encodeCommand(cmd));
  });
}
function openTcp(urlString) {
  const u = new URL(urlString);
  const secure = u.protocol === 'rediss:';
  const port = Number(u.port) || 6379;
  const c = { socket: null, ready: null, queue: [], buf: Buffer.alloc(0) };
  c.ready = new Promise((resolve, reject) => {
    const onConnect = () => {
      const user = decodeURIComponent(u.username || '');
      const pass = decodeURIComponent(u.password || '');
      if (!pass) return resolve();
      sendTcp(c, user ? ['AUTH', user, pass] : ['AUTH', pass]).then(() => resolve(), reject);
    };
    const socket = secure
      ? tls.connect({ host: u.hostname, port, servername: u.hostname }, onConnect)
      : net.connect({ host: u.hostname, port }, onConnect);
    c.socket = socket;
    socket.setTimeout(8000, () => { if (!c.connected) dropTcp(new Error('Kết nối Redis quá chậm')); });
    socket.on('data', (chunk) => {
      c.buf = Buffer.concat([c.buf, chunk]);
      for (;;) {
        let r;
        try { r = parseReply(c.buf); } catch (e) { return dropTcp(e); }
        if (!r) break;
        c.buf = c.buf.subarray(r[1]);
        const p = c.queue.shift();
        if (!p) continue;
        clearTimeout(p.timer);
        if (r[0] instanceof Error) p.reject(r[0]); else p.resolve(r[0]);
      }
    });
    socket.on('error', (e) => { dropTcp(e); reject(e); });
    socket.on('close', () => { dropTcp(); reject(new Error('Kết nối Redis đã đóng')); });
    socket.on('connect', () => { c.connected = true; socket.setTimeout(0); });
  });
  return c;
}
async function viaTcp(cmd, urlString) {
  // Kết nối cũ có thể đã bị Redis đóng khi trang không hoạt động: thử nối lại một lần.
  for (let attempt = 0; ; attempt++) {
    if (!tcp) tcp = openTcp(urlString);
    const c = tcp;
    try {
      await c.ready;
      return await sendTcp(c, cmd);
    } catch (e) {
      if (tcp === c) dropTcp(e);
      if (e && e.redisReply) throw e; // Redis trả lỗi lệnh thật sự, không thử lại
      if (attempt >= 1) throw e;
    }
  }
}

async function redis(cmd) {
  const rest = restCreds();
  if (rest.url && rest.token) return viaRest(cmd, rest);
  const url = tcpUrl();
  if (url) return viaTcp(cmd, url);
  throw Object.assign(new Error('no_db'), { code: 'no_db' });
}

/* ---------- tiện ích chung ---------- */
function send(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
const fail = (error, message, status) => send({ error, message }, status);

function normPhone(v) {
  let p = String(v || '').replace(/[\s.\-()]/g, '');
  if (p.startsWith('+84')) p = '0' + p.slice(3);
  else if (p.startsWith('84') && p.length === 11) p = '0' + p.slice(2);
  return p;
}
const normName = (v) => String(v || '').replace(/\s+/g, ' ').trim().slice(0, 60);
const normUsername = (v) => String(v || '').trim().toLowerCase();
const text = (v) => (typeof v === 'string' ? v : '');
const sha = (s) => createHash('sha256').update(String(s)).digest();
const sha256hex = (s) => createHash('sha256').update(String(s)).digest('hex');
function clientIp(request) {
  return (request.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim().slice(0, 64);
}
function parse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}
async function readJson(request) {
  try {
    const b = await request.json();
    return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
  } catch { return null; }
}
function pairsToRecords(flat) {
  const out = [];
  for (let i = 1; i < (flat || []).length; i += 2) {
    const r = parse(flat[i]);
    if (r && r.id) out.push(r);
  }
  return out;
}
async function allRecords() {
  return pairsToRecords(await redis(['HGETALL', KEY])).sort((a, b) => b.ts - a.ts);
}

/* Giới hạn số lần thử: tăng bộ đếm, tự hết hạn sau ttl giây kể từ lần thử cuối. */
async function hit(key, ttl) {
  const n = Number(await redis(['INCR', key])) || 0;
  await redis(['EXPIRE', key, ttl]);
  return n;
}
async function count(key) {
  return Number(await redis(['GET', key])) || 0;
}

/* ---------- mật khẩu và phiên đăng nhập ---------- */
async function hashPw(password, salt = randomBytes(16).toString('hex')) {
  const buf = await scrypt(String(password).normalize('NFKC'), salt, 64);
  return { salt, hash: buf.toString('hex') };
}
function sameHex(a, b) {
  const x = Buffer.from(String(a), 'hex'), y = Buffer.from(String(b), 'hex');
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}
async function checkPw(password, user) {
  const { hash } = await hashPw(password, user.salt);
  return sameHex(hash, user.hash);
}
function validPassword(pw, username) {
  if (pw.length < 8) return 'Mật khẩu cần ít nhất 8 ký tự.';
  if (pw.length > 128) return 'Mật khẩu quá dài (tối đa 128 ký tự).';
  if (username && pw.toLowerCase() === username) return 'Mật khẩu không được trùng với tên đăng nhập.';
  return '';
}
const publicUser = (u) => ({ username: u.username, name: u.name, phone: u.phone });
async function getUser(username) {
  if (!USERNAME_RE.test(username)) return null;
  const raw = await redis(['HGET', USERS, username]);
  return raw ? parse(raw) : null;
}

const sessKey = (token) => 'kana:s:' + sha256hex(token);
async function newSession(user) {
  const token = randomBytes(32).toString('base64url');
  await redis(['SET', sessKey(token), JSON.stringify({ u: user.username, v: user.ver }), 'EX', SESSION_SECONDS]);
  return token;
}
/* Trả về { user, token } nếu mã phiên còn hiệu lực, ngược lại null.
   Mã phiên cũ mất hiệu lực khi mật khẩu bị đổi hoặc tài khoản bị xóa. */
async function authed(request) {
  const m = /^Bearer (\S{20,100})$/.exec(request.headers.get('authorization') || '');
  if (!m) return null;
  const s = parse(await redis(['GET', sessKey(m[1])]));
  if (!s || typeof s.u !== 'string') return null;
  const user = await getUser(s.u);
  if (!user || user.ver !== s.v) return null;
  return { user, token: m[1] };
}
const needLogin = () => fail('auth', 'Phiên đăng nhập đã hết hạn, hãy đăng nhập lại.', 401);

/* ---------- đăng ký, đăng nhập ---------- */
async function register(request) {
  if ((await hit('kana:rg:' + clientIp(request), 3600)) > 100) {
    return fail('too_many', 'Có quá nhiều lượt đăng ký từ địa chỉ này. Hãy thử lại sau 1 giờ.', 429);
  }
  const b = await readJson(request);
  if (!b) return fail('bad_json', 'Dữ liệu gửi lên không hợp lệ.', 400);

  const username = normUsername(b.username);
  const password = text(b.password);
  const name = normName(b.name);
  const phone = normPhone(b.phone);

  if (!USERNAME_RE.test(username)) {
    return fail('bad_username', 'Tên đăng nhập gồm 3 đến 30 ký tự: chữ thường không dấu, số, dấu chấm, gạch dưới hoặc gạch ngang, và bắt đầu bằng chữ hoặc số.', 400);
  }
  const pwErr = validPassword(password, username);
  if (pwErr) return fail('bad_password', pwErr, 400);
  if (name.length < 2) return fail('bad_name', 'Họ và tên cần ít nhất 2 ký tự.', 400);
  if (!/^0\d{9}$/.test(phone)) return fail('bad_phone', 'Số điện thoại gồm 10 chữ số và bắt đầu bằng 0, ví dụ 0901234567.', 400);

  if ((Number(await redis(['HLEN', USERS])) || 0) >= MAX_USERS) {
    return fail('full', 'Hệ thống đã đủ số tài khoản tối đa, hãy báo quản trị viên.', 507);
  }

  const { salt, hash } = await hashPw(password);
  const user = { username, name, phone, salt, hash, ver: 1, created: Date.now() };

  // Giữ chỗ số điện thoại trước (mỗi số một tài khoản), rồi mới giữ chỗ tên đăng nhập.
  if (!Number(await redis(['HSETNX', PHONES, phone, username]))) {
    return fail('phone_taken', 'Số điện thoại này đã đăng ký một tài khoản. Mỗi người chỉ dùng một tài khoản, hãy đăng nhập hoặc nhờ quản trị viên hỗ trợ.', 409);
  }
  if (!Number(await redis(['HSETNX', USERS, username, JSON.stringify(user)]))) {
    await redis(['HDEL', PHONES, phone]);
    return fail('username_taken', 'Tên đăng nhập này đã có người dùng, hãy chọn tên khác.', 409);
  }

  try { await claimLegacy(user); } catch (e) { console.error('claimLegacy', e); }
  const token = await newSession(user);
  return send({ ok: true, token, user: publicUser(user) });
}

/* Bài làm từ thời chưa có tài khoản (chỉ có số điện thoại) được gắn vào tài khoản có cùng số điện thoại. */
async function claimLegacy(user) {
  const old = (await allRecords()).filter((r) => !r.username && r.phone === user.phone).slice(0, 200);
  for (const r of old) {
    r.username = user.username;
    const s = JSON.stringify(r);
    await redis(['HSET', KEY, r.id, s]);
    await redis(['HSET', userHistoryKey(user.username), r.id, s]);
  }
}

async function login(request) {
  const ip = clientIp(request);
  const b = await readJson(request);
  if (!b) return fail('bad_json', 'Dữ liệu gửi lên không hợp lệ.', 400);
  const username = normUsername(b.username);
  const password = text(b.password);
  if (!username || !password || password.length > 128) {
    return fail('bad_login', 'Tên đăng nhập hoặc mật khẩu không đúng.', 401);
  }

  const kIp = 'kana:lf:ip:' + ip;
  const kUser = 'kana:lf:u:' + username;
  if ((await count(kIp)) >= 30 || (await count(kUser)) >= 10) {
    return fail('too_many', 'Nhập sai quá nhiều lần. Hãy thử lại sau 15 phút.', 429);
  }

  const user = await getUser(username);
  let ok = false;
  if (user) ok = await checkPw(password, user);
  else await hashPw(password, DUMMY_SALT); // tốn thời gian như khi có tài khoản, để không lộ tên nào đã tồn tại
  if (!ok) {
    await hit(kIp, 900);
    await hit(kUser, 900);
    return fail('bad_login', 'Tên đăng nhập hoặc mật khẩu không đúng.', 401);
  }
  await redis(['DEL', kUser]);
  return send({ ok: true, token: await newSession(user), user: publicUser(user) });
}

async function logout(auth) {
  await redis(['DEL', sessKey(auth.token)]);
  return send({ ok: true });
}

async function changePassword(request, auth) {
  const b = await readJson(request);
  if (!b) return fail('bad_json', 'Dữ liệu gửi lên không hợp lệ.', 400);
  const oldPw = text(b.oldPassword), newPw = text(b.newPassword);
  const kUser = 'kana:lf:u:' + auth.user.username;
  if ((await count(kUser)) >= 10) return fail('too_many', 'Nhập sai quá nhiều lần. Hãy thử lại sau 15 phút.', 429);
  if (!oldPw || oldPw.length > 128 || !(await checkPw(oldPw, auth.user))) {
    await hit(kUser, 900);
    return fail('bad_password', 'Mật khẩu hiện tại không đúng.', 400);
  }
  const pwErr = validPassword(newPw, auth.user.username);
  if (pwErr) return fail('bad_password', pwErr, 400);

  const { salt, hash } = await hashPw(newPw);
  const user = { ...auth.user, salt, hash, ver: auth.user.ver + 1 };
  await redis(['HSET', USERS, user.username, JSON.stringify(user)]);
  await redis(['DEL', kUser]);
  const token = await newSession(user); // mọi phiên cũ (kể cả trên máy khác) đều mất hiệu lực
  return send({ ok: true, token });
}

/* ---------- nộp bài và xem lịch sử ---------- */
async function submit(request, auth) {
  const b = await readJson(request);
  if (!b) return fail('bad_json', 'Dữ liệu gửi lên không hợp lệ.', 400);

  const { user } = auth;
  const part = String(b.part || '');
  const table = TABLES[part];
  if (!table) return fail('bad_part', 'Phần thi không hợp lệ.', 400);
  const answers = Array.isArray(b.answers) ? b.answers : [];
  if (answers.length < 1 || answers.length > MAX_QUESTIONS) {
    return fail('bad_answers', 'Số câu trả lời không hợp lệ.', 400);
  }

  const seen = new Set();
  const results = [];
  let score = 0;
  let wrong = '';
  for (const a of answers) {
    const ch = String((a && a.ch) || '');
    const ro = table[ch];
    if (!ro || seen.has(ch)) return fail('bad_answers', 'Câu hỏi không hợp lệ.', 400);
    seen.add(ch);
    const type = a.type === 'r2k' ? 'r2k' : 'k2r';
    const picked = typeof a.picked === 'string' ? a.picked.slice(0, 8) : null;
    const answer = type === 'k2r' ? ro : ch;
    const correct = picked === answer;
    if (correct) score++; else wrong += ch;
    results.push({ ch, ro, type, picked, answer, correct });
  }

  const total = answers.length;
  const pct = Math.round((score / total) * 100);
  const duration = Math.max(0, Math.min(86400, Math.round(Number(b.duration) || 0))); // giây
  const ts = Date.now();
  const id = ts + '-' + Math.random().toString(36).slice(2, 8);

  if ((Number(await redis(['HLEN', KEY])) || 0) >= MAX_RECORDS) {
    return fail('full', 'Kho dữ liệu đã đầy, hãy báo quản trị viên.', 507);
  }

  const rec = JSON.stringify({
    id, username: user.username, name: user.name, phone: user.phone,
    part, score, total, pct, duration, ts, wrong
  });
  await redis(['HSET', KEY, id, rec]);
  await redis(['HSET', userHistoryKey(user.username), id, rec]);
  return send({ ok: true, id, score, total, pct, duration, results });
}

async function mine(auth) {
  const rows = pairsToRecords(await redis(['HGETALL', userHistoryKey(auth.user.username)]))
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 200)
    .map((r) => ({ part: r.part, score: r.score, total: r.total, pct: r.pct, duration: r.duration || 0, ts: r.ts }));
  return send({ attempts: rows });
}

/* ---------- quản trị ---------- */
async function adminGate(request) {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    return fail('not_configured', 'Chưa đặt biến môi trường ADMIN_PASSWORD trên Vercel.', 503);
  }
  const ip = clientIp(request);
  const failKey = 'kana:fail:' + ip;
  const fails = await count(failKey);
  if (fails >= 8) {
    return fail('too_many', 'Nhập sai quá nhiều lần. Hãy thử lại sau 15 phút.', 429);
  }
  const given = request.headers.get('x-admin-password') || '';
  if (!timingSafeEqual(sha(given), sha(expected))) {
    await hit(failKey, 900);
    return fail('bad_password', 'Mật khẩu không đúng.', 401);
  }
  if (fails) await redis(['DEL', failKey]);
  return null;
}

async function admin() {
  const users = [];
  const flat = (await redis(['HGETALL', USERS])) || [];
  for (let i = 1; i < flat.length; i += 2) {
    const u = parse(flat[i]);
    if (u && u.username) users.push({ username: u.username, name: u.name, phone: u.phone, created: u.created || 0 });
  }
  users.sort((a, b) => b.created - a.created);
  return send({ attempts: await allRecords(), users });
}

async function removeResult(url) {
  const id = String(url.searchParams.get('id') || '');
  if (!/^[0-9]+-[a-z0-9]+$/.test(id)) return fail('bad_id', 'Mã bài làm không hợp lệ.', 400);
  const rec = parse(await redis(['HGET', KEY, id]));
  await redis(['HDEL', KEY, id]);
  if (rec && rec.username && USERNAME_RE.test(rec.username)) await redis(['HDEL', userHistoryKey(rec.username), id]);
  return send({ ok: true });
}

function tempPassword() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'; // bỏ các chữ dễ nhầm: i l o 0 1
  return Array.from(randomBytes(10), (x) => alphabet[x % alphabet.length]).join('');
}
async function resetPassword(url) {
  const username = normUsername(url.searchParams.get('username'));
  const user = await getUser(username);
  if (!user) return fail('not_found', 'Không tìm thấy tài khoản này.', 404);
  const temp = tempPassword();
  const { salt, hash } = await hashPw(temp);
  await redis(['HSET', USERS, username, JSON.stringify({ ...user, salt, hash, ver: user.ver + 1 })]);
  await redis(['DEL', 'kana:lf:u:' + username]);
  return send({ ok: true, username, tempPassword: temp });
}

async function removeUser(url) {
  const username = normUsername(url.searchParams.get('username'));
  const user = await getUser(username);
  if (!user) return fail('not_found', 'Không tìm thấy tài khoản này.', 404);
  const hk = userHistoryKey(username);
  const flat = (await redis(['HGETALL', hk])) || [];
  const ids = [];
  for (let i = 0; i < flat.length; i += 2) ids.push(flat[i]);
  for (let i = 0; i < ids.length; i += 100) await redis(['HDEL', KEY, ...ids.slice(i, i + 100)]);
  await redis(['DEL', hk]);
  if ((await redis(['HGET', PHONES, user.phone])) === username) await redis(['HDEL', PHONES, user.phone]);
  await redis(['HDEL', USERS, username]);
  return send({ ok: true, removedResults: ids.length });
}

/* ---------- bộ định tuyến ---------- */
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const a = url.searchParams.get('a');
      const m = request.method;

      if (m === 'POST' && a === 'register') return await register(request);
      if (m === 'POST' && a === 'login') return await login(request);

      const needsAuth = (m === 'GET' && (a === 'me' || a === 'mine')) || (m === 'POST' && (a === 'logout' || a === 'chpw' || a === 'submit'));
      if (needsAuth) {
        const auth = await authed(request);
        if (!auth) return needLogin();
        if (a === 'me') return send({ user: publicUser(auth.user) });
        if (a === 'mine') return await mine(auth);
        if (a === 'logout') return await logout(auth);
        if (a === 'chpw') return await changePassword(request, auth);
        return await submit(request, auth);
      }

      const isAdmin = (m === 'GET' && a === 'admin') || (m === 'POST' && (a === 'delete' || a === 'resetpw' || a === 'deluser'));
      if (isAdmin) {
        const denied = await adminGate(request);
        if (denied) return denied;
        if (a === 'admin') return await admin();
        if (a === 'delete') return await removeResult(url);
        if (a === 'resetpw') return await resetPassword(url);
        return await removeUser(url);
      }

      return fail('not_found', 'Không tìm thấy.', 404);
    } catch (e) {
      if (e && e.code === 'no_db') {
        return fail('no_db', 'Chưa kết nối kho dữ liệu Redis cho dự án.', 503);
      }
      console.error(e);
      return fail('server', 'Máy chủ gặp lỗi, hãy thử lại sau.', 500);
    }
  }
};
