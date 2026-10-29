"use strict";

// vault.bin layout: [version:1][iterations:4 BE][salt:16][nonce:12][ciphertext + 16-byte tag]
// The first 21 bytes are the AES-GCM additional data.
const HEADER_LEN = 21, NONCE_LEN = 12, TAG_LEN = 16;

function parseHeader(buf) {
  const b = new Uint8Array(buf);
  if (b.length < HEADER_LEN + NONCE_LEN + TAG_LEN) throw new Error("file too short");
  if (b[0] !== 1) throw new Error("unknown version " + b[0]);
  return {
    iterations: new DataView(b.buffer, b.byteOffset).getUint32(1),
    salt: b.slice(5, HEADER_LEN),
    header: b.slice(0, HEADER_LEN),
    nonce: b.slice(HEADER_LEN, HEADER_LEN + NONCE_LEN),
    ciphertext: b.slice(HEADER_LEN + NONCE_LEN),
  };
}

async function deriveKey(password, salt, iterations) {
  if (!password) throw new Error("empty password");
  const pw = new TextEncoder().encode(password.normalize("NFKC"));
  const base = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}

// Returns the plaintext bytes; `h` comes from parseHeader.
async function decryptBlob(h, key) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: h.nonce, additionalData: h.header }, key, h.ciphertext));
  } catch {
    throw new Error("wrong password or corrupted file");
  }
}

async function unlockBlob(buf, password) {
  const h = parseHeader(buf);
  return decryptBlob(h, await deriveKey(password, h.salt, h.iterations));
}

// ---- viewer ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);
let blob, notes;  // blob: parsed vault.bin header; notes: [{path, text}] once unlocked

// The derived key is kept in IndexedDB as a non-extractable CryptoKey, next to the header it was
// derived for. The password itself is never stored.
function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("kb", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const req = fn(open.result.transaction("keys", mode).objectStore("keys"));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    };
  });
}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const currentPath = () => decodeURIComponent(location.hash.slice(1)) || "index.md";

function show(bytes) {
  notes = JSON.parse(new TextDecoder().decode(bytes)).notes;
  $("list").replaceChildren(...notes.map(n => {
    const li = document.createElement("li"), a = document.createElement("a");
    a.href = "#" + encodeURI(n.path);
    a.textContent = n.path;
    li.append(a);
    return li;
  }));
  $("login").hidden = true;
  $("app").hidden = false;
  route();
}

// Relative links between notes become hash links, resolved against the current note's path.
function resolve(from, rel) {
  const parts = from.split("/").slice(0, -1);
  for (const p of rel.split("/")) {
    if (p === "..") parts.pop();
    else if (p && p !== ".") parts.push(p);
  }
  return parts.join("/");
}

function route() {
  if (!notes) return;
  const path = currentPath(), note = notes.find(n => n.path === path);
  if (!note) return void ($("note").textContent = "Not found: " + path);
  $("note").innerHTML = marked.parse(note.text);
  for (const a of $("note").querySelectorAll("a[href]")) {
    const href = a.getAttribute("href");
    if (!/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(href))
      a.setAttribute("href", "#" + encodeURI(resolve(path, decodeURI(href.split("#")[0]))));
  }
}

async function start() {
  try {
    const res = await fetch("data/vault.bin", { cache: "no-cache" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    blob = parseHeader(await res.arrayBuffer());
  } catch (e) {
    $("login").hidden = false;
    return void ($("msg").textContent = "Could not load the vault: " + e.message);
  }
  const stored = await idb("readonly", s => s.get("vault")).catch(() => null);
  if (stored && sameBytes(stored.header, blob.header)) {
    try { return show(await decryptBlob(blob, stored.key)); } catch { /* stale key: ask again */ }
  }
  $("login").hidden = false;
}

$("login").addEventListener("submit", async e => {
  e.preventDefault();
  $("msg").textContent = "Unlocking…";
  try {
    const key = await deriveKey($("pw").value, blob.salt, blob.iterations);
    const bytes = await decryptBlob(blob, key);
    await idb("readwrite", s => s.put({ key, header: blob.header }, "vault")).catch(() => {});
    $("pw").value = $("msg").textContent = "";
    show(bytes);
  } catch (err) {
    $("msg").textContent = err.message;
  }
});

$("lock").addEventListener("click", async () => {
  await idb("readwrite", s => s.delete("vault")).catch(() => {});
  notes = null;
  $("note").textContent = "";
  $("app").hidden = true;
  $("login").hidden = false;
});

addEventListener("hashchange", route);
start();
