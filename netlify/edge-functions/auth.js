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
<meta name="theme-color" content="#0f1418">
<title>Mote vs Minx</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Unbounded:wght@600..800&family=Figtree:wght@400..700&display=swap" rel="stylesheet">
<style>
:root{color-scheme:light dark;--bg:light-dark(#eef1f4,#0f1418);--panel:light-dark(#ffffff,#161d23);--raise:light-dark(#e3e8ed,#1f2830);--ink:light-dark(#141b21,#e8edf1);--mute:light-dark(#5c6873,#8d9aa6);--lime:#c4f03a;--limeink:#141b05;--blue:light-dark(#d9e3ee,#2a3947);--blueink:light-dark(#16212c,#e3ebf3);--bluetag:light-dark(#3d5a78,#9fb8d1)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:16px/1.5 Figtree,system-ui,sans-serif;padding:24px 18px}
main{width:min(440px,100%);display:flex;flex-direction:column;gap:12px}
.mark{font-family:Unbounded,sans-serif;font-weight:800;font-size:clamp(30px,9vw,40px);letter-spacing:-.035em;margin:0 0 18px;display:flex;align-items:center;gap:10px}
.mark i{font-style:normal;color:var(--lime);font-size:.7em}
@media (prefers-color-scheme:light){.mark i{color:#4d6b00}}
.msg{max-width:82%;padding:10px 15px 11px;border-radius:20px;animation:in .35s ease-out both}
.msg b{display:block;font-size:12.5px;margin-bottom:1px}
.mote{align-self:flex-start;background:var(--lime);color:var(--limeink);border-bottom-left-radius:6px}
.mote b{color:#3d5200}
.minx{align-self:flex-end;background:var(--blue);color:var(--blueink);border-bottom-right-radius:6px;animation-delay:.45s}
.minx b{color:var(--bluetag)}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
form{margin-top:14px}
.composer{display:flex;align-items:center;gap:10px;background:var(--panel);border-radius:22px;padding:8px 8px 8px 18px;box-shadow:0 1px 2px rgba(0,0,0,.12)}
.composer:focus-within{box-shadow:0 0 0 3px color-mix(in srgb,var(--lime) 55%,transparent)}
label{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
input{flex:1;min-width:0;min-height:48px;border:0;background:transparent;color:var(--ink);font:inherit;font-size:17px}
input::placeholder{color:var(--mute)}
input:focus{outline:none}
button{flex:none;width:52px;height:52px;border:0;border-radius:50%;background:var(--lime);color:var(--limeink);display:grid;place-items:center;cursor:pointer;box-shadow:0 4px 0 #8fb21c;transform:translateY(-2px);transition:transform .08s,box-shadow .08s}
button:hover{background:#d0f55c}
button:active{transform:translateY(2px);box-shadow:0 0 0 #8fb21c}
button:focus-visible{outline:3px solid var(--ink);outline-offset:3px}
.fine{margin:12px 0 0;font-size:13px;color:var(--mute);text-align:center}
@media (prefers-reduced-motion:reduce){.msg{animation:none}button{transition:none}}
</style></head><body>
<main>
<h1 class="mark">Mote <i>×</i> Minx</h1>
${wrong
  ? `<div class="msg minx"><b>Minx</b>Nope. That's not it. Try again, darling.</div><div class="msg mote" style="animation-delay:.45s"><b>Mote</b>She's enjoying this far too much.</div>`
  : `<div class="msg mote"><b>Mote</b>Hold on, who's this?</div><div class="msg minx"><b>Minx</b>Password first. Then we'll talk.</div>`}
<form method="post" action="/__login">
<div class="composer">
<label for="pw">Password</label>
<input id="pw" name="password" type="password" placeholder="Password" autocomplete="current-password" required autofocus>
<button aria-label="Unlock"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 19V5"/><path d="M5 12l7-7 7 7"/></svg></button>
</div>
<p class="fine">Stays unlocked on this device for 30 days.</p>
</form>
</main></body></html>`;

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
