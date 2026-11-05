const ALLOWED_ORIGIN = "https://carloscrespomacaya.com";
const MAX_BODY = 8192;
const MAX_SENTENCE = 1000;
const MAX_NOTE = 500;
const MAX_CARD_ROWS = 20;
const MAX_NAME = 80;
const MAX_CHECKED = 4000;
const MAX_CODE_LEN = 80;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function ndjson(lines) {
  return new Response(lines.join("\n") + (lines.length ? "\n" : ""), {
    status: 200,
    headers: { "Content-Type": "application/x-ndjson" },
  });
}

function maskText(value) {
  if (typeof value !== "string") return value;
  let out = value;
  out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]");
  out = out.replace(/https?:\/\/\S+/gi, "[url]");
  out = out.replace(/www\.\S+/gi, "[url]");
  out = out.replace(/\d{9,}/g, "[digits]");
  out = out.replace(/\+?[\d(][\d\s.\-()]*\d/g, (m) =>
    ((m.match(/\d/g) || []).length >= 7 ? "[phone]" : m)
  );
  return out;
}

function maskCard(card) {
  if (!Array.isArray(card)) return card;
  return card.map((row) => {
    if (row && typeof row === "object" && !Array.isArray(row)) {
      const out = {};
      for (const [k, v] of Object.entries(row)) {
        out[k] = typeof v === "string" ? maskText(v) : v;
      }
      return out;
    }
    return row;
  });
}

function checkOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin !== ALLOWED_ORIGIN) return false;
  return true;
}

function tokensEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return false;
  return crypto.subtle.timingSafeEqual(ab, bb);
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token, X-Delete-Key",
    "Access-Control-Max-Age": "86400",
  };
}

async function readBody(request) {
  const len = request.headers.get("Content-Length");
  if (len && parseInt(len, 10) > MAX_BODY) return { error: 413 };
  const text = await request.text();
  if (text.length > MAX_BODY) return { error: 413 };
  return { text };
}

function validateTry(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "bad shape";
  const allowed = new Set([
    "visitor", "page_version", "consent_v", "mode", "card", "sentence",
    "verdict", "codes", "checked", "answer", "beat_checker", "note", "redacted",
    "delete_hash",
  ]);
  for (const k of Object.keys(body)) {
    if (!allowed.has(k)) return "unknown field: " + k;
  }
  const required = ["visitor", "page_version", "consent_v", "mode", "card", "sentence", "verdict", "codes", "checked", "redacted"];
  for (const k of required) {
    if (!(k in body)) return "missing field: " + k;
  }
  if (typeof body.visitor !== "string" || body.visitor.length < 1 || body.visitor.length > 64) return "bad visitor";
  if (typeof body.page_version !== "string" || body.page_version.length < 1 || body.page_version.length > 64) return "bad page_version";
  if (body.consent_v !== 1) return "bad consent_v";
  if (body.mode !== "form" && body.mode !== "game") return "bad mode";
  if (!Array.isArray(body.card) || body.card.length > MAX_CARD_ROWS) return "bad card";
  for (const row of body.card) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return "bad card row";
    for (const [k, v] of Object.entries(row)) {
      if (typeof v !== "string") return "bad card value";
      if (k === "name" && v.length > MAX_NAME) return "name too long";
    }
  }
  if (typeof body.sentence !== "string" || body.sentence.length > MAX_SENTENCE) return "bad sentence";
  if (body.verdict !== "PASS" && body.verdict !== "FAIL") return "bad verdict";
  if (!Array.isArray(body.codes)) return "bad codes";
  for (const c of body.codes) {
    if (typeof c !== "string" || !/^L[0-9A-Z_]+$/.test(c)) return "bad code";
  }
  if (typeof body.checked !== "string" || body.checked.length > MAX_CHECKED) return "bad checked";
  if (body.answer !== undefined && body.answer !== null) {
    if (typeof body.answer !== "string" || body.answer.length > MAX_SENTENCE) return "bad answer";
  }
  if (body.beat_checker !== undefined && body.beat_checker !== null) {
    if (typeof body.beat_checker !== "boolean") return "bad beat_checker";
  }
  if (body.note !== undefined && body.note !== null) {
    if (typeof body.note !== "string" || body.note.length > MAX_NOTE) return "bad note";
  }
  if (typeof body.redacted !== "boolean") return "bad redacted";
  if (body.delete_hash !== undefined && body.delete_hash !== null) {
    if (typeof body.delete_hash !== "string" || !/^[0-9a-f]{64}$/.test(body.delete_hash)) return "bad delete_hash";
  }
  return null;
}

async function handleTries(request, env, ctx) {
  if (!checkOrigin(request)) return json({ error: "forbidden origin" }, 403);
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405, corsHeaders());

  const rb = await readBody(request);
  if (rb.error) return json({ error: "too large" }, 413, corsHeaders());

  let body;
  try {
    body = JSON.parse(rb.text);
  } catch {
    return json({ error: "bad json" }, 400, corsHeaders());
  }

  const vErr = validateTry(body);
  if (vErr) return json({ error: vErr }, 400, corsHeaders());

  // rate limits
  const now = new Date().toISOString();
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const perVisitor = await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM tries WHERE visitor = ? AND saved_at >= ?"
  ).bind(body.visitor, oneHourAgo).first();
  if ((perVisitor?.c || 0) >= 60) return json({ error: "rate limited" }, 429, corsHeaders());
  const total = await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM tries WHERE saved_at >= ?"
  ).bind(oneHourAgo).first();
  if ((total?.c || 0) >= 600) return json({ error: "rate limited" }, 429, corsHeaders());

  // masking
  const maskedSentence = maskText(body.sentence);
  const maskedChecked = maskText(body.checked);
  const maskedNote = body.note != null ? maskText(body.note) : null;
  const maskedAnswer = body.answer != null ? maskText(body.answer) : null;
  const maskedCard = maskCard(body.card);
  const redacted = body.redacted || maskedSentence !== body.sentence || maskedChecked !== body.checked ||
    (body.note != null && maskedNote !== body.note) ||
    (body.answer != null && maskedAnswer !== body.answer) ||
    JSON.stringify(maskedCard) !== JSON.stringify(body.card);

  const result = await env.DB.prepare(
    `INSERT INTO tries (saved_at, visitor, page_version, consent_v, mode, card, sentence, verdict, codes, checked, answer, beat_checker, note, redacted)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    now,
    body.visitor,
    body.page_version,
    body.consent_v,
    body.mode,
    JSON.stringify(maskedCard),
    maskedSentence,
    body.verdict,
    JSON.stringify(body.codes),
    maskedChecked,
    maskedAnswer,
    body.beat_checker == null ? null : (body.beat_checker ? 1 : 0),
    maskedNote,
    redacted ? 1 : 0,
  ).run();

  const id = result.meta.last_row_id;

  // visitors table
  const firstSeen = new Date().toISOString().slice(0, 10);
  if (body.delete_hash) {
    await env.DB.prepare(
      "INSERT INTO visitors (code, delete_hash, first_seen) VALUES (?, ?, ?) ON CONFLICT(code) DO UPDATE SET delete_hash = COALESCE(visitors.delete_hash, excluded.delete_hash)"
    ).bind(body.visitor, body.delete_hash, firstSeen).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO visitors (code, delete_hash, first_seen) VALUES (?, ?, ?) ON CONFLICT(code) DO UPDATE SET delete_hash = COALESCE(visitors.delete_hash, excluded.delete_hash)"
    ).bind(body.visitor, null, firstSeen).run();
  }

  // push
  if (env.NTFY_TOPIC) {
    try {
      const notice = fetch("https://ntfy.sh/" + env.NTFY_TOPIC, {
        method: "POST",
        body: "Ikigai checker: try " + id + " saved (" + body.mode + ", " + body.verdict + ")",
      });
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(notice.catch(() => {}));
      } else {
        await notice;
      }
    } catch (e) {}
  }

  return json({ id }, 201, corsHeaders());
}

async function handleDelete(request, env, code) {
  const adminToken = env.EXPORT_TOKEN;
  const providedAdmin = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || request.headers.get("X-Admin-Token");
  const isAdmin = tokensEqual(providedAdmin, adminToken);
  if (!isAdmin && !checkOrigin(request)) return json({ error: "forbidden origin" }, 403);
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405, corsHeaders());

  const rb = await readBody(request);
  let body = {};
  if (rb.text) {
    try { body = JSON.parse(rb.text); } catch { body = {}; }
  }

  const key = body && body.key ? body.key : (request.headers.get("X-Delete-Key") || null);

  if (!isAdmin) {
    if (!key) return json({ error: "forbidden" }, 403, corsHeaders());
    const visitor = await env.DB.prepare("SELECT delete_hash FROM visitors WHERE code = ?").bind(code).first();
    if (!visitor || !visitor.delete_hash) return json({ error: "forbidden" }, 403, corsHeaders());
    // hash key
    const data = new TextEncoder().encode(key);
    const hashBuf = await crypto.subtle.digest("SHA-256", data);
    const hashHex = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    if (hashHex !== visitor.delete_hash) return json({ error: "forbidden" }, 403, corsHeaders());
  }

  const res = await env.DB.prepare("DELETE FROM tries WHERE visitor = ?").bind(code).run();
  const deleted = res.meta.changes || 0;
  await env.DB.prepare("DELETE FROM visitors WHERE code = ?").bind(code).run();
  return json({ deleted }, 200, corsHeaders());
}

async function handleExport(request, env) {
  const token = env.EXPORT_TOKEN;
  const provided = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || request.headers.get("X-Admin-Token");
  if (!token || !tokensEqual(provided, token)) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const after = parseInt(url.searchParams.get("after") || "0", 10) || 0;
  const rows = await env.DB.prepare(
    "SELECT * FROM tries WHERE id > ? ORDER BY id ASC LIMIT 500"
  ).bind(after).all();
  const lines = (rows.results || []).map((r) => JSON.stringify({
    id: r.id,
    saved_at: r.saved_at,
    visitor: r.visitor,
    page_version: r.page_version,
    consent_v: r.consent_v,
    mode: r.mode,
    card: JSON.parse(r.card),
    sentence: r.sentence,
    verdict: r.verdict,
    codes: JSON.parse(r.codes),
    checked: r.checked,
    answer: r.answer,
    beat_checker: r.beat_checker === null ? null : r.beat_checker === 1,
    note: r.note,
    redacted: r.redacted === 1,
  }));
  return ndjson(lines);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // POST /v1/tries
    if (path === "/v1/tries") {
      return handleTries(request, env, ctx);
    }
    // POST /v1/visitors/{code}/delete
    let m = path.match(/^\/v1\/visitors\/([^/]+)\/delete$/);
    if (m) {
      return handleDelete(request, env, decodeURIComponent(m[1]));
    }
    // GET /v1/export
    if (path === "/v1/export") {
      return handleExport(request, env);
    }
    return json({ error: "not found" }, 404);
  },
  async scheduled(event, env, ctx) {
    const cutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    await env.DB.prepare("DELETE FROM tries WHERE saved_at < ?").bind(cutoff).run();
    await env.DB.prepare(
      "DELETE FROM visitors WHERE first_seen < ? AND NOT EXISTS (SELECT 1 FROM tries WHERE tries.visitor = visitors.code)"
    ).bind(cutoff).run();
  },
};
