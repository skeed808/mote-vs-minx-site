// Password gate for the whole site. Runs on Netlify's edge before any page is served.
// Set SITE_PASSWORD in Netlify: Site configuration > Environment variables.
// Logged-in devices stay logged in for 30 days. Changing the password logs everyone out.

const COOKIE = "mvm_auth";
const DAYS = 30;
const enc = new TextEncoder();

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function readCookie(req) {
  const m = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : "";
}

async function validSession(req, secret) {
  const [exp, sig] = readCookie(req).split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return same(sig, await sign(exp, secret));
}

const page = (wrong) => `<!DOCTYPE html><html lang="en-GB"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>Mote vs Minx</title>
<link href="https://fonts.googleapis.com/css2?family=Doto:wght@500..900&family=Instrument+Sans:wght@400..700&display=swap" rel="stylesheet">
<style>
:root{color-scheme:light dark;--al:light-dark(#e2e2de,#121212);--key:light-dark(#f7f7f4,#1c1c1c);--ink:light-dark(#0b0b0b,#eeeee8);--mute:light-dark(#63635c,#9b9b93);--hair:light-dark(#0b0b0b,#3b3b38);--soft:light-dark(#cfcfca,#2a2a28);--lcd:light-dark(#b8c4a1,#1a2316);--lcdink:light-dark(#1a2313,#b6c89c)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--al);color:var(--ink);font:15.5px/1.55 "Instrument Sans",system-ui,sans-serif;padding:20px}
form{width:min(400px,100%)}
.brand{font-family:Doto,ui-monospace,monospace;font-weight:900;font-size:30px;margin-bottom:14px;display:flex;gap:8px;align-items:center}
.led{width:9px;height:9px;border-radius:50%;border:1px solid var(--hair);display:inline-block;margin-right:6px}
.lcd{background:var(--lcd);color:var(--lcdink);border:1px solid var(--hair);box-shadow:inset 0 2px 0 rgba(0,0,0,.12);padding:10px 12px;font-family:Doto,ui-monospace,monospace;font-weight:800;font-size:19px;margin-bottom:16px}
label{font-weight:600;font-size:13px;display:block;margin-bottom:5px}
input{width:100%;font:inherit;font-size:16px;padding:12px;border:1px solid var(--hair);border-radius:0;background:var(--key);color:var(--ink);box-shadow:inset 0 2px 0 var(--soft);margin-bottom:12px}
button{width:100%;min-height:50px;border:1px solid var(--hair);border-radius:0;background:#ff5c1a;color:#0b0b0b;font:700 17px "Instrument Sans",system-ui,sans-serif;cursor:pointer;box-shadow:inset 0 -3px 0 rgba(0,0,0,.25)}
button:active{transform:translateY(1px);box-shadow:none}
:focus-visible{outline:2px solid #ff5c1a;outline-offset:2px}
</style></head><body>
<form method="post" action="/__login">
<div class="brand"><span><i class="led" style="background:#ff5c1a"></i>mote</span><span style="color:var(--mute);font-size:22px">×</span><span><i class="led" style="background:#2f52ff"></i>minx</span></div>
<div class="lcd">${wrong ? "wrong password. try again" : "locked. password to get in"}</div>
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
<button>unlock</button>
</form></body></html>`;

const html = (body, status = 200, headers = {}) =>
  new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers } });

export default async (req, context) => {
  const secret = Netlify.env.get("SITE_PASSWORD");
  if (!secret) return html("<h1>Locked</h1><p>SITE_PASSWORD isn't set in Netlify's environment variables.</p>", 503);
  const url = new URL(req.url);

  if (url.pathname === "/__logout") {
    return new Response(null, { status: 303, headers: { location: "/", "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  }

  if (url.pathname === "/__login" && req.method === "POST") {
    const form = await req.formData();
    const given = String(form.get("password") || "");
    if (!same(given, secret)) {
      await new Promise((r) => setTimeout(r, 900)); // slows down guessing
      return html(page(true), 401);
    }
    const exp = String(Date.now() + DAYS * 864e5);
    const token = `${exp}.${await sign(exp, secret)}`;
    return new Response(null, { status: 303, headers: {
      location: "/", "cache-control": "no-store",
      "set-cookie": `${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`,
    } });
  }

  if (await validSession(req, secret)) {
    const res = await context.next();
    const out = new Response(res.body, res);
    out.headers.set("cache-control", "no-store");
    return out;
  }
  return html(page(false), 401);
};

export const config = { path: "/*" };
