// Một hàm duy nhất xử lý toàn bộ API, chọn việc theo tham số ?a=
//   POST ?a=submit   học viên nộp bài (máy chủ tự chấm lại)
//   GET  ?a=mine     lịch sử điểm của một số điện thoại
//   GET  ?a=admin    toàn bộ bài làm (cần mật khẩu quản trị)
//   POST ?a=delete   xóa một bài làm (cần mật khẩu quản trị)
import { createHash, timingSafeEqual } from 'node:crypto';
import { TABLES } from '../lib/kana.js';

const KEY = 'kana:results';
const MAX_RECORDS = 30000;
const MAX_QUESTIONS = 50;

/* ---------- Upstash Redis qua REST (không cần cài thêm thư viện) ---------- */
function creds() {
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN
  };
}
async function redis(cmd) {
  const { url, token } = creds();
  if (!url || !token) throw Object.assign(new Error('no_db'), { code: 'no_db' });
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.error) throw new Error(body.error || 'redis_' + res.status);
  return body.result;
}

/* ---------- tiện ích ---------- */
function send(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
function normPhone(v) {
  let p = String(v || '').replace(/[\s.\-()]/g, '');
  if (p.startsWith('+84')) p = '0' + p.slice(3);
  else if (p.startsWith('84') && p.length === 11) p = '0' + p.slice(2);
  return p;
}
const sha = (s) => createHash('sha256').update(String(s)).digest();
function clientIp(request) {
  return (request.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim().slice(0, 64);
}
function parse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}
async function allRecords() {
  const flat = (await redis(['HGETALL', KEY])) || [];
  const out = [];
  for (let i = 1; i < flat.length; i += 2) {
    const r = parse(flat[i]);
    if (r && r.id) out.push(r);
  }
  return out.sort((a, b) => b.ts - a.ts);
}

/* ---------- xác thực quản trị ---------- */
async function adminGate(request) {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    return send({ error: 'not_configured', message: 'Chưa đặt biến môi trường ADMIN_PASSWORD trên Vercel.' }, 503);
  }
  const ip = clientIp(request);
  const failKey = 'kana:fail:' + ip;
  const fails = Number(await redis(['GET', failKey])) || 0;
  if (fails >= 8) {
    return send({ error: 'too_many', message: 'Nhập sai quá nhiều lần. Hãy thử lại sau 15 phút.' }, 429);
  }
  const given = request.headers.get('x-admin-password') || '';
  if (!timingSafeEqual(sha(given), sha(expected))) {
    await redis(['INCR', failKey]);
    await redis(['EXPIRE', failKey, 900]);
    return send({ error: 'bad_password', message: 'Mật khẩu không đúng.' }, 401);
  }
  if (fails) await redis(['DEL', failKey]);
  return null;
}

/* ---------- nộp bài ---------- */
async function submit(request) {
  let b;
  try { b = await request.json(); } catch { return send({ error: 'bad_json', message: 'Dữ liệu gửi lên không hợp lệ.' }, 400); }

  const name = String(b.name || '').replace(/\s+/g, ' ').trim().slice(0, 60);
  const phone = normPhone(b.phone);
  const part = String(b.part || '');
  const table = TABLES[part];
  if (name.length < 2) return send({ error: 'bad_name', message: 'Họ tên chưa hợp lệ.' }, 400);
  if (!/^0\d{9}$/.test(phone)) return send({ error: 'bad_phone', message: 'Số điện thoại chưa hợp lệ.' }, 400);
  if (!table) return send({ error: 'bad_part', message: 'Phần thi không hợp lệ.' }, 400);
  const answers = Array.isArray(b.answers) ? b.answers : [];
  if (answers.length < 1 || answers.length > MAX_QUESTIONS) {
    return send({ error: 'bad_answers', message: 'Số câu trả lời không hợp lệ.' }, 400);
  }

  const seen = new Set();
  const results = [];
  let score = 0;
  let wrong = '';
  for (const a of answers) {
    const ch = String(a && a.ch || '');
    const ro = table[ch];
    if (!ro || seen.has(ch)) return send({ error: 'bad_answers', message: 'Câu hỏi không hợp lệ.' }, 400);
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
  const ts = Date.now();
  const id = ts + '-' + Math.random().toString(36).slice(2, 8);

  const size = Number(await redis(['HLEN', KEY])) || 0;
  if (size >= MAX_RECORDS) return send({ error: 'full', message: 'Kho dữ liệu đã đầy, hãy báo quản trị viên.' }, 507);

  await redis(['HSET', KEY, id, JSON.stringify({ id, name, phone, part, score, total, pct, ts, wrong })]);
  return send({ ok: true, id, score, total, pct, results });
}

/* ---------- lịch sử của một số điện thoại ---------- */
async function mine(url) {
  const phone = normPhone(url.searchParams.get('phone'));
  if (!/^0\d{9}$/.test(phone)) return send({ error: 'bad_phone', message: 'Số điện thoại chưa hợp lệ.' }, 400);
  const rows = (await allRecords())
    .filter((r) => r.phone === phone)
    .slice(0, 100)
    .map((r) => ({ part: r.part, score: r.score, total: r.total, pct: r.pct, ts: r.ts }));
  return send({ attempts: rows });
}

/* ---------- quản trị ---------- */
async function admin() {
  return send({ attempts: await allRecords() });
}
async function remove(url) {
  const id = String(url.searchParams.get('id') || '');
  if (!/^[0-9]+-[a-z0-9]+$/.test(id)) return send({ error: 'bad_id', message: 'Mã bài làm không hợp lệ.' }, 400);
  await redis(['HDEL', KEY, id]);
  return send({ ok: true });
}

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const a = url.searchParams.get('a');
      const m = request.method;
      if (m === 'POST' && a === 'submit') return await submit(request);
      if (m === 'GET' && a === 'mine') return await mine(url);
      if (a === 'admin' && m === 'GET') {
        const denied = await adminGate(request);
        return denied || (await admin());
      }
      if (a === 'delete' && m === 'POST') {
        const denied = await adminGate(request);
        return denied || (await remove(url));
      }
      return send({ error: 'not_found', message: 'Không tìm thấy.' }, 404);
    } catch (e) {
      if (e && e.code === 'no_db') {
        return send({ error: 'no_db', message: 'Chưa kết nối kho dữ liệu (Upstash Redis) cho dự án.' }, 503);
      }
      console.error(e);
      return send({ error: 'server', message: 'Máy chủ gặp lỗi, hãy thử lại sau.' }, 500);
    }
  }
};
