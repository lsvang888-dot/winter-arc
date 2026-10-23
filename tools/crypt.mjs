// Encrypts the app so the public repo only holds ciphertext.
//
//   WA_PASS='…' node tools/crypt.mjs unlock   index.html (encrypted) -> index.src.html (readable, git-ignored)
//   WA_PASS='…' node tools/crypt.mjs lock     index.src.html -> index.html (encrypted, commit this)
//
// Username defaults to "loh" (WA_USER to change). The salt is kept between builds so a device that
// stayed logged in keeps working after an update; the IV is new every time.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import { webcrypto as C } from "node:crypto";

const dir = new URL("..", import.meta.url);
const OUT = new URL("index.html", dir), SRC = new URL("index.src.html", dir), TPL = new URL("tools/wrapper.html", dir);
const ITER = 600000;
const user = (process.env.WA_USER || "loh").trim().toLowerCase(), pass = process.env.WA_PASS;
const cmd = process.argv[2];
if (!pass || !["lock", "unlock"].includes(cmd)) { console.error("usage: WA_PASS='…' node tools/crypt.mjs lock|unlock"); process.exit(2); }

const b64 = u => Buffer.from(u).toString("base64"), unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
async function key(salt) {
  const base = await C.subtle.importKey("raw", new TextEncoder().encode(user + ":" + pass), "PBKDF2", false, ["deriveKey"]);
  return C.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function parts(html) {
  const g = re => (html.match(re) || [])[1];
  return { salt: g(/const SALT="([^"]+)"/), iv: g(/IV="([^"]+)"/), iter: +g(/ITER=(\d+)/), data: g(/id="d">([^<]+)<\/script>/) };
}

if (cmd === "unlock") {
  const p = parts(readFileSync(OUT, "utf8"));
  if (!p.data) { console.error("index.html isn't an encrypted build"); process.exit(1); }
  if (p.iter !== ITER) { console.error(`iterations changed (${p.iter} vs ${ITER})`); process.exit(1); }
  let plain;
  try { plain = await C.subtle.decrypt({ name: "AES-GCM", iv: unb64(p.iv) }, await key(unb64(p.salt)), unb64(p.data.trim())); }
  catch { console.error("Wrong password."); process.exit(1); }
  writeFileSync(SRC, gunzipSync(Buffer.from(plain)));
  console.log("Wrote index.src.html");
} else {
  if (!existsSync(SRC)) { console.error("index.src.html missing — run unlock first"); process.exit(1); }
  const prev = existsSync(OUT) ? parts(readFileSync(OUT, "utf8")) : {};
  const salt = prev.salt ? unb64(prev.salt) : C.getRandomValues(new Uint8Array(16));
  const iv = C.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await C.subtle.encrypt({ name: "AES-GCM", iv }, await key(salt), gzipSync(readFileSync(SRC), { level: 9 })));
  const out = readFileSync(TPL, "utf8").replace("__SALT__", b64(salt)).replace("__IV__", b64(iv)).replace("__ITER__", String(ITER)).replace("__DATA__", b64(data));
  writeFileSync(OUT, out);
  console.log(`Wrote index.html (${(out.length / 1e6).toFixed(2)} MB encrypted)`);
}
