import { useState, useRef, useEffect, useCallback } from "react";

// ─── Crypto ───────────────────────────────────────────────────────────────────
const ENC = new TextEncoder(), DEC = new TextDecoder();

function u8ToBase64(u8) {
  let s = ""; const C = 8192;
  for (let i = 0; i < u8.length; i += C) s += String.fromCharCode(...u8.subarray(i, i + C));
  return btoa(s);
}

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey("raw", ENC.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" },
    raw, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
}

async function aesEncrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, ENC.encode(text));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return u8ToBase64(out);
}

async function aesDecrypt(b64, key) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv:buf.slice(0,12) }, key, buf.slice(12));
  return DEC.decode(pt);
}

// ─── LocalStorage (salt, verifier, settings only) ─────────────────────────────
const K_SALT = "pm_salt", K_VERIFY = "pm_verify", K_SETTINGS = "pm_settings";
const SENTINEL = "VAULT_OK_V2";

function getOrCreateSalt() {
  const s = localStorage.getItem(K_SALT);
  if (s) { try { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); } catch {} }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(K_SALT, u8ToBase64(salt)); return salt;
}
async function saveVerifier(key) { localStorage.setItem(K_VERIFY, await aesEncrypt(SENTINEL, key)); }
async function verifyKey(key) {
  const enc = localStorage.getItem(K_VERIFY); if (!enc) return false;
  try { return (await aesDecrypt(enc, key)) === SENTINEL; } catch { return false; }
}
function loadSettings() {
  try { return JSON.parse(localStorage.getItem(K_SETTINGS) || "{}"); } catch { return {}; }
}
function saveSettings(s) { localStorage.setItem(K_SETTINGS, JSON.stringify(s)); }

// ─── IndexedDB ────────────────────────────────────────────────────────────────
const DB_NAME = "vaultDB2", DB_VER = 2;
const ST_VAULT = "vault", ST_HISTORY = "history";

function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(ST_VAULT))   db.createObjectStore(ST_VAULT,   { keyPath:"id" });
      if (!db.objectStoreNames.contains(ST_HISTORY)) db.createObjectStore(ST_HISTORY, { keyPath:"id" });
    };
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  });
}

async function idbPut(store, obj) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(obj);
    tx.oncomplete = () => { db.close(); res(); };
    tx.onerror    = e => { db.close(); rej(e.target.error); };
  });
}

async function idbDelete(store, id) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(id);
    tx.oncomplete = () => { db.close(); res(); };
    tx.onerror    = e => { db.close(); rej(e.target.error); };
  });
}

async function idbGetAll(store) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction(store, "readonly").objectStore(store).getAll();
    req.onsuccess = e => { db.close(); res(e.target.result); };
    req.onerror   = e => { db.close(); rej(e.target.error); };
  });
}

async function idbClear(store) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).clear();
    tx.oncomplete = () => { db.close(); res(); };
    tx.onerror    = e => { db.close(); rej(e.target.error); };
  });
}

async function idbSaveItem(item, key) { await idbPut(ST_VAULT, { id:item.id, data: await aesEncrypt(JSON.stringify(item), key) }); }

async function idbLoadAll(key) {
  const rows  = await idbGetAll(ST_VAULT);
  const items = [];
  for (const row of rows) {
    try { items.push(JSON.parse(await aesDecrypt(row.data, key))); } catch {}
  }
  return items.sort((a,b) => (b.updatedAt||0) - (a.updatedAt||0));
}

async function idbClearAll() { await idbClear(ST_VAULT); await idbClear(ST_HISTORY); }

// Password history stored as encrypted blobs
async function saveHistory(itemId, oldPassword, key) {
  if (!oldPassword) return;
  const rec = { id: `${itemId}_${Date.now()}`, itemId, password: oldPassword, savedAt: Date.now() };
  await idbPut(ST_HISTORY, { id: rec.id, data: await aesEncrypt(JSON.stringify(rec), key) });
}

async function loadHistory(itemId, key) {
  const rows = await idbGetAll(ST_HISTORY);
  const recs = [];
  for (const row of rows) {
    try {
      const r = JSON.parse(await aesDecrypt(row.data, key));
      if (r.itemId === itemId) recs.push(r);
    } catch {}
  }
  return recs.sort((a,b) => b.savedAt - a.savedAt).slice(0, 10);
}

// Migrate old DB
async function migrateFromLocalStorage(key) {
  const old = localStorage.getItem("pm_vault");
  if (!old) return;
  try {
    const items = JSON.parse(await aesDecrypt(old, key));
    for (const item of items) await idbSaveItem(item, key);
    localStorage.removeItem("pm_vault");
  } catch { localStorage.removeItem("pm_vault"); }
}

// ─── HIBP breach check (k-anonymity) ──────────────────────────────────────────
async function checkBreach(password) {
  try {
    const hash   = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", ENC.encode(password))))
                       .map(b => b.toString(16).padStart(2,"0")).join("").toUpperCase();
    const prefix = hash.slice(0,5), suffix = hash.slice(5);
    const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text   = await res.text();
    const line   = text.split("\n").find(l => l.startsWith(suffix));
    return line ? parseInt(line.split(":")[1]) : 0;
  } catch { return -1; } // -1 = network error
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────
async function generateTOTP(secret) {
  try {
    const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean  = secret.toUpperCase().replace(/\s/g,"").replace(/=/g,"");
    const bytes  = [];
    let buf = 0, bits = 0;
    for (const ch of clean) {
      const val = base32.indexOf(ch); if (val < 0) continue;
      buf = (buf << 5) | val; bits += 5;
      if (bits >= 8) { bytes.push((buf >> (bits-8)) & 0xff); bits -= 8; }
    }
    const keyBytes = new Uint8Array(bytes);
    let counter     = Math.floor(Date.now() / 30000);
    const msg       = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter = Math.floor(counter / 256); }
    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name:"HMAC", hash:"SHA-1" }, false, ["sign"]);
    const sig    = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, msg));
    const offset = sig[19] & 0x0f;
    const code   = ((sig[offset]&0x7f)<<24|(sig[offset+1]&0xff)<<16|(sig[offset+2]&0xff)<<8|(sig[offset+3]&0xff)) % 1000000;
    return String(code).padStart(6,"0");
  } catch { return "------"; }
}

// ─── Image compression ─────────────────────────────────────────────────────────
function compressImage(dataUrl) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const MAX = 1200; let { width:w, height:h } = img;
      if (w > MAX || h > MAX) { if (w>h) { h=Math.round(h*MAX/w); w=MAX; } else { w=Math.round(w*MAX/h); h=MAX; } }
      const c = document.createElement("canvas"); c.width=w; c.height=h;
      c.getContext("2d").drawImage(img,0,0,w,h);
      resolve(c.toDataURL("image/jpeg",0.75));
    };
    img.onerror = () => resolve(dataUrl);
    img.src = dataUrl;
  });
}

// ─── Backup ───────────────────────────────────────────────────────────────────
async function exportBackup(vault, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await deriveKey(pw, salt);
  const enc  = await aesEncrypt(JSON.stringify(vault), key);
  return JSON.stringify({ v:2, salt:u8ToBase64(salt), data:enc, at:new Date().toISOString() });
}
async function importBackup(text, pw) {
  const b = JSON.parse(text);
  if (b.v!==1 && b.v!==2) throw new Error("Unknown version");
  const salt = Uint8Array.from(atob(b.salt), c => c.charCodeAt(0));
  return JSON.parse(await aesDecrypt(b.data, await deriveKey(pw, salt)));
}

// ─── Password strength ────────────────────────────────────────────────────────
function pwStrength(pw) {
  let s=0;
  if(pw.length>=8)s++; if(pw.length>=14)s++;
  if(/[A-Z]/.test(pw))s++; if(/[0-9]/.test(pw))s++; if(/[^A-Za-z0-9]/.test(pw))s++;
  return s;
}
function genPw(len=16) {
  const c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
  return Array.from(crypto.getRandomValues(new Uint8Array(len))).map(b=>c[b%c.length]).join("");
}

// ─── Password audit ───────────────────────────────────────────────────────────
function auditVault(vault) {
  const issues = [];
  const pwMap  = {};
  for (const item of vault) {
    if (!item.password) continue;
    const s = pwStrength(item.password);
    if (s < 2) issues.push({ id:item.id, name:item.name, type:"weak",   label:"Weak password" });
    if (item.password.length < 8) issues.push({ id:item.id, name:item.name, type:"short", label:"Too short" });
    const exp = item.expiresAt;
    if (exp && Date.now() > exp) issues.push({ id:item.id, name:item.name, type:"expired", label:"Password expired" });
    if (!pwMap[item.password]) pwMap[item.password] = [];
    pwMap[item.password].push(item);
  }
  for (const [, items] of Object.entries(pwMap)) {
    if (items.length > 1) {
      for (const item of items) {
        if (!issues.find(i=>i.id===item.id && i.type==="reused"))
          issues.push({ id:item.id, name:item.name, type:"reused", label:`Reused in ${items.length} entries` });
      }
    }
  }
  return issues;
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const Ic = ({ d, size=20, color="currentColor", sw=1.7, style }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" style={style}>
    <path d={d}/>
  </svg>
);
const I = {
  shield:  "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  lock:    "M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4",
  unlock:  "M11 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2h-2M7 11V7a5 5 0 019.9-1",
  eye:     "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeOff:  "M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24 M1 1l22 22",
  plus:    "M12 5v14M5 12h14",
  search:  "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
  edit:    "M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7 M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z",
  trash:   "M3 6h18M8 6V4h8v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6",
  copy:    "M8 4H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-2 M8 4a2 2 0 012-2h4a2 2 0 012 2v0a2 2 0 01-2 2h-4a2 2 0 01-2-2z",
  check:   "M20 6L9 17l-5-5",
  x:       "M18 6L6 18M6 6l12 12",
  image:   "M21 15a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h4l2-3h4l2 3h4a2 2 0 012 2z M12 13a3 3 0 100-6 3 3 0 000-6z",
  key:     "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
  globe:   "M12 2a10 10 0 100 20A10 10 0 0012 2z M2 12h20 M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z",
  note:    "M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z M14 2v6h6 M16 13H8m8 4H8m2-8H8",
  card:    "M1 4h22v16H1z M1 10h22",
  wifi:    "M5 12.55a11 11 0 0114.08 0 M1.42 9a16 16 0 0121.16 0 M8.53 16.11a6 6 0 016.95 0 M12 20h.01",
  back:    "M19 12H5m7-7l-7 7 7 7",
  logout:  "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4 M16 17l5-5-5-5 M21 12H9",
  spin:    "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
  dl:      "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M7 10l5 5 5-5 M12 15V3",
  ul:      "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M17 8l-5-5-5 5 M12 3v12",
  cog:     "M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
  info:    "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 8h.01 M11 12h1v4h1",
  arr:     "M9 18l6-6-6-6",
  db:      "M12 2C6.48 2 2 4.24 2 7s4.48 5 10 5 10-2.24 10-5-4.48-5-10-5zM2 12c0 2.76 4.48 5 10 5s10-2.24 10-5M2 17c0 2.76 4.48 5 10 5s10-2.24 10-5",
  star:    "M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z",
  starF:   "M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z",
  warn:    "M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z M12 9v4 M12 17h.01",
  finger:  "M12 22s-8-4.5-8-11.8A8 8 0 0112 2a8 8 0 018 8.2c0 7.3-8 11.8-8 11.8z",
  clock:   "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 6v6l4 2",
  history: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
  audit:   "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2 M9 5a2 2 0 002 2h2a2 2 0 002-2 M9 5a2 2 0 012-2h2a2 2 0 012 2 M9 12h6m-6 4h4",
  totp:    "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4",
  tag:     "M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82z M7 7h.01",
  folder:  "M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z",
  moon:    "M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z",
  sun:     "M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42 M12 17a5 5 0 100-10 5 5 0 000 10z",
  pin:     "M12 2a5 5 0 015 5c0 3.5-5 11-5 11S7 10.5 7 7a5 5 0 015-5z M12 9a2 2 0 100-4 2 2 0 000 4z",
  qr:      "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h3v3h-3z M17 17h3v3h-3z M17 14h3",
  breach:  "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M12 8v4 M12 16h.01",
  sort:    "M3 6h18M7 12h10M11 18h4",
  theme:   "M12 3a6 6 0 009 9 9 9 0 11-9-9z",
  exp:     "M8 2v4M16 2v4M3 10h18M5 4h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V6a2 2 0 012-2z",
};

// ─── Categories ───────────────────────────────────────────────────────────────
const CATS = [
  { id:"login", label:"Login", icon:I.key,   color:"#6366f1" },
  { id:"card",  label:"Card",  icon:I.card,  color:"#ec4899" },
  { id:"wifi",  label:"Wi-Fi", icon:I.wifi,  color:"#14b8a6" },
  { id:"note",  label:"Note",  icon:I.note,  color:"#f59e0b" },
  { id:"other", label:"Other", icon:I.globe, color:"#8b5cf6" },
];
const catColor = id => CATS.find(c=>c.id===id)?.color||"#6366f1";
const catIcon  = id => CATS.find(c=>c.id===id)?.icon||I.key;
const catLabel = id => CATS.find(c=>c.id===id)?.label||id;

// ─── CSS ──────────────────────────────────────────────────────────────────────
const makeCSS = (dark) => `
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:${dark?"#0a0a0f":"#f4f4f8"};
  --s1:${dark?"#12121a":"#ffffff"};
  --s2:${dark?"#1a1a26":"#eeeef6"};
  --s3:${dark?"#22223a":"#ddddf0"};
  --bd:${dark?"rgba(255,255,255,0.07)":"rgba(0,0,0,0.09)"};
  --tx:${dark?"#f0f0ff":"#12121a"};
  --mu:${dark?"#6060a0":"#8080b0"};
  --ac:#7c3aed;--ac2:#a78bfa;
  --red:#ef4444;--grn:#22c55e;--ylw:#f59e0b;--blue:#3b82f6;
  --r:16px;--rs:10px;
}
body{background:var(--bg);color:var(--tx);font-family:'Space Grotesk',sans-serif;-webkit-font-smoothing:antialiased}
.app{max-width:420px;min-height:100svh;margin:0 auto;background:var(--bg);display:flex;flex-direction:column;position:relative}

/* Auth */
.auth{min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px;
  background:radial-gradient(ellipse at 50% 0%,rgba(124,58,237,.2) 0%,transparent 60%),var(--bg)}
.auth-logo{width:80px;height:80px;background:linear-gradient(135deg,var(--ac),#6366f1);border-radius:26px;
  display:flex;align-items:center;justify-content:center;margin-bottom:20px;box-shadow:0 0 48px rgba(124,58,237,.4)}
.auth-title{font-size:30px;font-weight:700;letter-spacing:-.5px}
.auth-sub{color:var(--mu);font-size:14px;margin-top:6px;text-align:center;max-width:280px;line-height:1.5}
.auth-card{width:100%;background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:28px;margin-top:24px}

/* PIN pad */
.pin-wrap{display:flex;flex-direction:column;align-items:center;gap:20px;padding-top:16px}
.pin-dots{display:flex;gap:12px}
.pin-dot{width:14px;height:14px;border-radius:50%;background:var(--s3);transition:background .15s}
.pin-dot.filled{background:var(--ac)}
.pin-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;width:100%}
.pin-btn{padding:18px 0;background:var(--s2);border:1px solid var(--bd);border-radius:var(--rs);
  font-size:22px;font-weight:600;cursor:pointer;color:var(--tx);transition:all .15s;font-family:'Space Grotesk',sans-serif}
.pin-btn:active{background:var(--ac);color:#fff;transform:scale(.96)}
.pin-del{background:transparent;border:none;color:var(--mu);font-size:14px;font-family:'Space Grotesk',sans-serif;cursor:pointer;padding:18px 0}

/* Inputs */
.lbl{font-size:11px;color:var(--mu);font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:7px;display:block}
.ig{margin-bottom:14px}
.iw{position:relative;display:flex;align-items:center}
.inp{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:var(--rs);color:var(--tx);
  font-family:'Space Grotesk',sans-serif;font-size:15px;padding:13px 44px 13px 15px;outline:none;transition:border-color .2s}
.inp:focus{border-color:var(--ac)} .inp::placeholder{color:var(--mu)}
textarea.inp{resize:none;min-height:80px;line-height:1.5;padding-right:15px}
select.inp{padding-right:15px;appearance:none}
.eye{position:absolute;right:12px;background:none;border:none;cursor:pointer;color:var(--mu);padding:0;display:flex;align-items:center}
.sbar{display:flex;gap:4px;margin-top:7px}
.sseg{flex:1;height:3px;border-radius:99px;background:var(--s3);transition:background .3s}

/* Buttons */
.btn{width:100%;padding:13px;border:none;border-radius:var(--rs);font-family:'Space Grotesk',sans-serif;
  font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px}
.btn-p{background:linear-gradient(135deg,var(--ac),#6366f1);color:#fff;box-shadow:0 4px 20px rgba(124,58,237,.3)}
.btn-p:hover{transform:translateY(-1px)} .btn-p:active,.btn-p:disabled{transform:none;opacity:.7}
.btn-g{background:var(--s2);color:var(--tx);border:1px solid var(--bd)}
.btn-g:hover{border-color:var(--ac2);color:var(--ac2)}
.btn-d{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.22)}

/* Alerts */
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.22);color:var(--red);border-radius:var(--rs);padding:10px 14px;font-size:13px;margin-top:10px;text-align:center}
.ok-msg{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.22);color:var(--grn);border-radius:var(--rs);padding:10px 14px;font-size:13px;margin-top:10px;text-align:center}
.inf{background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.18);border-radius:var(--rs);padding:14px 15px;font-size:13px;color:var(--mu);line-height:1.6;display:flex;gap:10px;align-items:flex-start}
.wrn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:var(--rs);padding:14px 15px;font-size:13px;color:var(--ylw);line-height:1.6;display:flex;gap:10px;align-items:flex-start}

/* Header */
.hdr{padding:52px 18px 14px;background:linear-gradient(to bottom,var(--s1) 60%,transparent);position:sticky;top:0;z-index:10;backdrop-filter:blur(20px)}
.hdr-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;gap:8px}
.hdr-logo{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.hdr-logobox{width:34px;height:34px;background:linear-gradient(135deg,var(--ac),#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.hdr-title{font-size:19px;font-weight:700;letter-spacing:-.3px;white-space:nowrap}
.hdr-actions{display:flex;gap:7px;flex-shrink:0}
.ibtn{width:36px;height:36px;background:var(--s2);border:1px solid var(--bd);border-radius:9px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--mu);transition:all .2s;flex-shrink:0}
.ibtn:hover{border-color:var(--ac2);color:var(--ac2)}
.ibtn.active{background:rgba(124,58,237,.15);border-color:var(--ac2);color:var(--ac2)}
.sbox{position:relative}
.sico{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--mu);pointer-events:none}
.sinp{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:var(--rs);color:var(--tx);
  font-family:'Space Grotesk',sans-serif;font-size:14px;padding:11px 15px 11px 38px;outline:none;transition:border-color .2s}
.sinp:focus{border-color:var(--ac)} .sinp::placeholder{color:var(--mu)}

/* Tabs row */
.trow{display:flex;gap:7px;padding:4px 18px 10px;overflow-x:auto}
.trow::-webkit-scrollbar{display:none}
.tpill{flex-shrink:0;display:flex;align-items:center;gap:5px;padding:7px 13px;border-radius:99px;
  background:var(--s2);border:1px solid var(--bd);font-size:13px;font-weight:500;cursor:pointer;
  transition:all .2s;color:var(--mu);white-space:nowrap;font-family:'Space Grotesk',sans-serif}

/* Vault list */
.vlist{flex:1;padding:0 18px 100px;overflow-y:auto}
.slbl{font-size:11px;color:var(--mu);font-weight:600;letter-spacing:1px;text-transform:uppercase;margin:14px 0 8px;display:flex;align-items:center;gap:6px}
.vitem{display:flex;align-items:center;gap:13px;padding:13px 15px;background:var(--s1);
  border:1px solid var(--bd);border-radius:var(--r);margin-bottom:9px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.vitem:hover{border-color:rgba(124,58,237,.3);transform:translateX(2px)}
.vico{width:42px;height:42px;flex-shrink:0;border-radius:12px;display:flex;align-items:center;justify-content:center;overflow:hidden}
.vico img{width:100%;height:100%;object-fit:cover}
.vinf{flex:1;min-width:0}
.vname{font-size:15px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vsub{font-size:12px;color:var(--mu);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vtags{display:flex;gap:4px;margin-top:4px;flex-wrap:wrap}
.vtag{font-size:10px;padding:2px 7px;border-radius:99px;background:var(--s2);color:var(--mu);font-weight:500}
.vbadge{font-size:10px;padding:2px 7px;border-radius:99px;font-weight:600}

/* Empty */
.empty{display:flex;flex-direction:column;align-items:center;padding:60px 20px;text-align:center;color:var(--mu)}
.empty svg{opacity:.3;margin-bottom:14px}

/* FAB pair */
.fab-wrap{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);width:100%;max-width:420px;
  display:flex;justify-content:space-between;padding:0 18px;pointer-events:none;z-index:20}
.fab{width:54px;height:54px;border:none;border-radius:16px;display:flex;align-items:center;justify-content:center;
  cursor:pointer;color:#fff;transition:all .2s;pointer-events:all;flex-shrink:0}
.fab-add{background:linear-gradient(135deg,var(--ac),#6366f1);box-shadow:0 6px 24px rgba(124,58,237,.5)}
.fab-add:hover{transform:translateY(-2px) scale(1.05)} .fab-add:active{transform:scale(.97)}
.fab-set{background:var(--s2);border:1px solid var(--bd);box-shadow:0 4px 16px rgba(0,0,0,.25);color:var(--mu)}
.fab-set:hover{border-color:var(--ac2);transform:translateY(-2px)}
.fab-set.on{background:rgba(124,58,237,.2);border-color:var(--ac2);color:var(--ac2)}

/* Modal */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(6px);z-index:50;
  display:flex;align-items:flex-end;justify-content:center;animation:fi .2s ease}
@keyframes fi{from{opacity:0}to{opacity:1}}
.mdl{width:100%;max-width:420px;background:var(--s1);border-radius:var(--r) var(--r) 0 0;
  border:1px solid var(--bd);border-bottom:none;max-height:92svh;overflow-y:auto;
  animation:su .28s cubic-bezier(.34,1.56,.64,1)}
@keyframes su{from{transform:translateY(100%)}to{transform:translateY(0)}}
.mhdl{width:34px;height:4px;background:var(--s3);border-radius:99px;margin:11px auto 0}
.mhdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px 12px;border-bottom:1px solid var(--bd)}
.mtit{font-size:17px;font-weight:700}
.mbdy{padding:18px}

/* Detail */
.dhero{display:flex;align-items:center;gap:15px;padding:16px 18px 18px;border-bottom:1px solid var(--bd)}
.dico{width:54px;height:54px;border-radius:15px;display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0}
.dico img{width:100%;height:100%;object-fit:cover}
.dtit{font-size:19px;font-weight:700}
.dcat{font-size:12px;color:var(--mu);margin-top:3px}
.frow{padding:13px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px}
.flbl{font-size:10px;color:var(--mu);text-transform:uppercase;letter-spacing:.6px;font-weight:700;min-width:68px;flex-shrink:0}
.fval{flex:1;font-size:14px;font-family:'JetBrains Mono',monospace;word-break:break-all;color:var(--tx);line-height:1.4}
.ficb{width:30px;height:30px;background:var(--s2);border:1px solid var(--bd);border-radius:8px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--mu);transition:all .15s;flex-shrink:0}
.ficb:hover{color:var(--ac2);border-color:var(--ac2)}
.igrid{padding:14px 18px;display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.ithumb{aspect-ratio:1;border-radius:10px;overflow:hidden;background:var(--s2);cursor:pointer}
.ithumb img{width:100%;height:100%;object-fit:cover}
.arow{padding:14px 18px;display:flex;gap:9px}

/* TOTP display */
.totp-box{margin:14px 18px;background:linear-gradient(135deg,rgba(124,58,237,.15),rgba(99,102,241,.1));
  border:1px solid rgba(124,58,237,.25);border-radius:var(--rs);padding:16px;text-align:center}
.totp-code{font-family:'JetBrains Mono',monospace;font-size:36px;font-weight:700;letter-spacing:8px;color:var(--ac2)}
.totp-timer{height:3px;background:var(--s3);border-radius:99px;margin-top:10px;overflow:hidden}
.totp-bar{height:100%;background:linear-gradient(90deg,var(--ac),var(--ac2));border-radius:99px;transition:width 1s linear}

/* Form */
.fsec{margin-bottom:18px}
.fsec-t{font-size:11px;color:var(--mu);font-weight:700;letter-spacing:.8px;text-transform:uppercase;margin-bottom:9px}
.upz{border:2px dashed var(--bd);border-radius:var(--rs);padding:18px;text-align:center;cursor:pointer;transition:all .2s;color:var(--mu);font-size:13px}
.upz:hover{border-color:var(--ac);color:var(--ac2)}
.ipgrid{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.ipbox{width:68px;height:68px;border-radius:10px;overflow:hidden;position:relative;background:var(--s2)}
.ipbox img{width:100%;height:100%;object-fit:cover}
.ipdel{position:absolute;top:3px;right:3px;width:17px;height:17px;background:rgba(239,68,68,.9);border-radius:99px;display:flex;align-items:center;justify-content:center;cursor:pointer}
.gbtn{display:flex;align-items:center;gap:6px;background:var(--s3);border:1px solid var(--bd);color:var(--ac2);border-radius:8px;padding:8px 12px;font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;margin-top:8px;font-family:'Space Grotesk',sans-serif;white-space:nowrap;flex-shrink:0}
.prow{display:flex;align-items:flex-start;gap:8px} .prow .iw{flex:1}
.tag-inp-wrap{display:flex;gap:8px;align-items:center}
.tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.tag-chip{display:flex;align-items:center;gap:4px;padding:4px 10px;background:var(--s2);border:1px solid var(--bd);border-radius:99px;font-size:12px;font-weight:500;color:var(--mu)}
.tag-chip button{background:none;border:none;cursor:pointer;color:var(--mu);padding:0;display:flex;align-items:center;font-size:14px;line-height:1}

/* Settings */
.spage{flex:1;overflow-y:auto;padding:0 18px 100px}
.spage-title{font-size:22px;font-weight:700;letter-spacing:-.4px;padding:52px 0 4px}
.shead{font-size:11px;color:var(--mu);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin:22px 0 9px}
.sitem{display:flex;align-items:center;gap:13px;padding:15px;background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:9px;cursor:pointer;transition:all .2s}
.sitem:hover{border-color:rgba(255,255,255,.14)}
.sitem-nc{cursor:default} .sitem-nc:hover{border-color:var(--bd)}
.sicobox{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.slabel{font-size:15px;font-weight:600}
.ssub{font-size:12px;color:var(--mu);margin-top:2px}
.badge{display:inline-flex;align-items:center;gap:5px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.2);border-radius:99px;padding:3px 9px;font-size:11px;color:var(--grn);font-weight:600;margin-top:5px}
.toggle{width:44px;height:24px;background:var(--s3);border-radius:99px;position:relative;cursor:pointer;transition:background .2s;flex-shrink:0;border:none}
.toggle.on{background:var(--ac)}
.toggle-knob{width:18px;height:18px;background:#fff;border-radius:50%;position:absolute;top:3px;left:3px;transition:left .2s;box-shadow:0 1px 4px rgba(0,0,0,.3)}
.toggle.on .toggle-knob{left:23px}

/* Audit */
.audit-item{display:flex;align-items:center;gap:10px;padding:12px 15px;background:var(--s1);border:1px solid var(--bd);border-radius:var(--rs);margin-bottom:8px}
.audit-type-weak,.audit-type-short{color:var(--red)}
.audit-type-reused{color:var(--ylw)}
.audit-type-expired{color:var(--mu)}

/* Breach */
.breach-safe{color:var(--grn);font-size:13px;font-weight:600}
.breach-pwned{color:var(--red);font-size:13px;font-weight:600}

/* Toast */
.toast{position:fixed;bottom:100px;left:50%;transform:translateX(-50%);background:var(--s1);border:1px solid var(--bd);
  border-radius:99px;padding:9px 18px;font-size:13px;font-weight:500;display:flex;align-items:center;gap:7px;
  z-index:200;box-shadow:0 4px 20px rgba(0,0,0,.4);white-space:nowrap;
  animation:tin .2s ease,tout .3s ease 2s forwards;pointer-events:none}
@keyframes tin{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
@keyframes tout{from{opacity:1}to{opacity:0}}

/* Auto-lock overlay */
.lock-overlay{position:fixed;inset:0;background:var(--bg);z-index:500;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px}
.lock-overlay-logo{width:72px;height:72px;background:linear-gradient(135deg,var(--ac),#6366f1);border-radius:22px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 40px rgba(124,58,237,.4)}

/* Loading */
.loading{min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;color:var(--mu)}
.spinner{width:36px;height:36px;border:3px solid var(--s3);border-top-color:var(--ac);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Lightbox */
.lb{position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.96);display:flex;align-items:center;justify-content:center;cursor:pointer;animation:fi .15s ease}
.lb img{max-width:100%;max-height:90svh;border-radius:8px}

/* QR */
.qr-wrap{display:flex;justify-content:center;padding:16px 0}

::-webkit-scrollbar{width:3px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:var(--s3);border-radius:99px}
`;

// ─── Small shared components ──────────────────────────────────────────────────
function StrBar({ pw }) {
  const s=pwStrength(pw), cols=["#ef4444","#f97316","#eab308","#84cc16","#22c55e"];
  const labels=["Very Weak","Weak","Fair","Strong","Very Strong"];
  return (
    <div>
      <div className="sbar">{[0,1,2,3,4].map(i=><div key={i} className="sseg" style={{background:i<s?cols[Math.min(s-1,4)]:undefined}}/>)}</div>
      {pw && <div style={{fontSize:11,color:cols[Math.min(s-1,4)]||"var(--mu)",marginTop:4,fontWeight:600}}>{labels[Math.min(s-1,4)]||"Very Weak"}</div>}
    </div>
  );
}

function PwInp({ value, onChange, placeholder="Password", strength=false }) {
  const [show,setShow]=useState(false);
  return <>
    <div className="iw">
      <input className="inp" type={show?"text":"password"} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}/>
      <button className="eye" type="button" onClick={()=>setShow(v=>!v)}><Ic d={show?I.eyeOff:I.eye} size={17}/></button>
    </div>
    {strength && value && <StrBar pw={value}/>}
  </>;
}

function Toggle({ on, onChange }) {
  return <button className={"toggle"+(on?" on":"")} onClick={()=>onChange(!on)}>
    <div className="toggle-knob"/>
  </button>;
}

function Toast({ msg, type="ok" }) {
  const color=type==="error"?"var(--red)":type==="warn"?"var(--ylw)":"var(--grn)";
  const icon=type==="error"?I.x:type==="warn"?I.warn:I.check;
  return <div className="toast"><Ic d={icon} size={15} color={color}/><span style={{color}}>{msg}</span></div>;
}

// ─── PIN pad ──────────────────────────────────────────────────────────────────
function PinPad({ title, subtitle, onComplete, onCancel, errorMsg }) {
  const [digits, setDigits] = useState([]);
  const PIN_LEN = 6;

  function press(d) {
    if (digits.length >= PIN_LEN) return;
    const next = [...digits, d];
    setDigits(next);
    if (next.length === PIN_LEN) { setTimeout(() => onComplete(next.join("")), 80); }
  }
  function del() { setDigits(d => d.slice(0,-1)); }

  useEffect(() => { if (errorMsg) setDigits([]); }, [errorMsg]);

  return (
    <div className="pin-wrap">
      <div style={{textAlign:"center"}}>
        <div style={{fontWeight:700,fontSize:17}}>{title}</div>
        {subtitle && <div style={{fontSize:13,color:"var(--mu)",marginTop:4}}>{subtitle}</div>}
      </div>
      <div className="pin-dots">
        {Array.from({length:PIN_LEN}).map((_,i)=><div key={i} className={"pin-dot"+(i<digits.length?" filled":"")}/>)}
      </div>
      {errorMsg && <div className="err" style={{marginTop:0,fontSize:12}}>{errorMsg}</div>}
      <div className="pin-grid">
        {[1,2,3,4,5,6,7,8,9].map(n=><button key={n} className="pin-btn" onClick={()=>press(String(n))}>{n}</button>)}
        <div/>
        <button className="pin-btn" onClick={()=>press("0")}>0</button>
        <button className="pin-del" onClick={del}>⌫</button>
      </div>
      {onCancel && <button className="btn btn-g" style={{marginTop:4}} onClick={onCancel}>Use Master Password</button>}
    </div>
  );
}

// ─── Auth Screen ──────────────────────────────────────────────────────────────
function AuthScreen({ onAuth, settings }) {
  const isNew  = !localStorage.getItem(K_VERIFY);
  const hasPin = !!settings.pin;
  const [mode, setMode]   = useState((!isNew && hasPin) ? "pin" : "master");
  const [pw,   setPw]     = useState("");
  const [pw2,  setPw2]    = useState("");
  const [err,  setErr]    = useState("");
  const [busy, setBusy]   = useState(false);
  const [pinErr, setPinErr] = useState("");
  const [failCount, setFailCount] = useState(0);
  const MAX_FAILS = 5;

  async function submitMaster() {
    setErr(""); setBusy(true);
    try {
      const salt = getOrCreateSalt(), key = await deriveKey(pw, salt);
      if (isNew) {
        if (pw.length < 6) { setErr("At least 6 characters required."); setBusy(false); return; }
        if (pw !== pw2)    { setErr("Passwords don't match."); setBusy(false); return; }
        await saveVerifier(key); await onAuth(key, pw);
      } else {
        const ok = await verifyKey(key);
        if (!ok) {
          const f = failCount + 1; setFailCount(f);
          setErr(f >= MAX_FAILS ? `Vault locked after ${MAX_FAILS} failed attempts. Clear site data to reset.` : `Wrong password. ${MAX_FAILS-f} attempts left.`);
          setBusy(false); return;
        }
        await onAuth(key, pw);
      }
    } catch(e) { setErr("Error: "+e.message); }
    setBusy(false);
  }

  async function submitPin(pin) {
    if (pin !== settings.pin) {
      const f = failCount + 1; setFailCount(f);
      setPinErr(f >= MAX_FAILS ? "Too many attempts. Use master password." : `Wrong PIN. ${MAX_FAILS-f} left.`);
      if (f >= MAX_FAILS) setMode("master");
      return;
    }
    setPinErr(""); setBusy(true);
    try {
      const salt = getOrCreateSalt(), key = await deriveKey(settings.masterPwCache||"", salt);
      // PIN auth still needs the real key — re-derive from cached encrypted master
      // We store an encrypted copy of master pw unlockable with PIN
      if (settings.pinKeyEnc) {
        const pinKey = await deriveKey(pin, Uint8Array.from(atob(settings.pinSalt||""), c=>c.charCodeAt(0)));
        const master = await aesDecrypt(settings.pinKeyEnc, pinKey);
        const realKey = await deriveKey(master, salt);
        const ok = await verifyKey(realKey);
        if (ok) { await onAuth(realKey, master); return; }
      }
      setPinErr("PIN auth failed. Use master password.");
      setMode("master");
    } catch { setPinErr("PIN auth failed. Use master password."); setMode("master"); }
    setBusy(false);
  }

  // Biometric
  async function tryBiometric() {
    try {
      const cred = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: settings.bioCredId ? [{ id: Uint8Array.from(atob(settings.bioCredId),c=>c.charCodeAt(0)), type:"public-key" }] : [],
        userVerification: "required", timeout: 60000
      }});
      if (cred && settings.pinKeyEnc) { await submitPin(settings.pin); }
    } catch { setErr("Biometric failed. Enter password."); }
  }

  return (
    <div className="auth">
      <div className="auth-logo"><Ic d={I.shield} size={34} color="#fff" sw={2}/></div>
      <div className="auth-title">Vault</div>
      <div className="auth-sub">{isNew?"Create a master password to protect your vault":mode==="pin"?"Enter your PIN":"Enter master password to unlock"}</div>

      {mode==="pin" && !isNew ? (
        <div className="auth-card">
          <PinPad title="" subtitle="" onComplete={submitPin} onCancel={()=>setMode("master")} errorMsg={pinErr}/>
          {settings.biometric && <button className="btn btn-g" style={{marginTop:10}} onClick={tryBiometric}>
            <Ic d={I.finger} size={17}/>Use Biometric
          </button>}
        </div>
      ) : (
        <div className="auth-card">
          <div className="ig"><label className="lbl">Master Password</label>
            <PwInp value={pw} onChange={setPw} placeholder="Master password" strength={isNew}/></div>
          {isNew && <div className="ig"><label className="lbl">Confirm Password</label>
            <PwInp value={pw2} onChange={setPw2} placeholder="Confirm password"/></div>}
          {err && <div className="err">{err}</div>}
          <button className="btn btn-p" style={{marginTop:16}} onClick={submitMaster} disabled={busy||failCount>=MAX_FAILS}>
            {busy?"Working…":isNew?"Create Vault":"Unlock Vault"}
          </button>
          {!isNew && settings.biometric && (
            <button className="btn btn-g" style={{marginTop:9}} onClick={tryBiometric}>
              <Ic d={I.finger} size={17}/>Use Biometric
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── TOTP Component ───────────────────────────────────────────────────────────
function TotpDisplay({ secret }) {
  const [code, setCode]     = useState("------");
  const [secs, setSecs]     = useState(30);

  useEffect(() => {
    let alive = true;
    async function tick() {
      const c = await generateTOTP(secret);
      const s = 30 - (Math.floor(Date.now()/1000) % 30);
      if (alive) { setCode(c); setSecs(s); }
    }
    tick();
    const id = setInterval(tick, 1000);
    return () => { alive=false; clearInterval(id); };
  }, [secret]);

  const pct = (secs/30)*100;
  const col  = secs <= 5 ? "var(--red)" : secs <= 10 ? "var(--ylw)" : "var(--ac2)";

  return (
    <div className="totp-box">
      <div style={{fontSize:11,color:"var(--mu)",fontWeight:600,letterSpacing:1,textTransform:"uppercase",marginBottom:8}}>2FA Code · {secs}s</div>
      <div className="totp-code" style={{color:col}}>{code.slice(0,3)} {code.slice(3)}</div>
      <div className="totp-timer"><div className="totp-bar" style={{width:pct+"%",background:col}}/></div>
    </div>
  );
}

// ─── Breach checker component ─────────────────────────────────────────────────
function BreachCheck({ password }) {
  const [status, setStatus] = useState("idle"); // idle|checking|safe|pwned|error
  const [count,  setCount]  = useState(0);

  async function check() {
    setStatus("checking");
    const n = await checkBreach(password);
    if (n === -1) setStatus("error");
    else if (n === 0) setStatus("safe");
    else { setStatus("pwned"); setCount(n); }
  }

  return (
    <div className="frow" style={{flexDirection:"column",alignItems:"flex-start",gap:8}}>
      <div className="flbl">Breach Check</div>
      {status==="idle"    && <button className="gbtn" onClick={check}><Ic d={I.breach} size={14}/>Check HaveIBeenPwned</button>}
      {status==="checking"&& <span style={{fontSize:13,color:"var(--mu)"}}>Checking…</span>}
      {status==="safe"    && <span className="breach-safe">✓ Not found in any breaches</span>}
      {status==="pwned"   && <span className="breach-pwned">⚠ Found in {count.toLocaleString()} breaches!</span>}
      {status==="error"   && <span style={{fontSize:13,color:"var(--mu)"}}>Network error — try again</span>}
    </div>
  );
}

// ─── Password History Modal ───────────────────────────────────────────────────
function HistoryModal({ itemId, cryptoKey, onClose }) {
  const [history, setHistory] = useState(null);
  const [copied,  setCopied]  = useState(null);

  useEffect(() => {
    loadHistory(itemId, cryptoKey).then(setHistory);
  }, [itemId, cryptoKey]);

  function copy(pw, i) {
    navigator.clipboard.writeText(pw).catch(()=>{});
    setCopied(i); setTimeout(()=>setCopied(null),2000);
  }

  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">Password History</div>
          <div style={{width:36}}/>
        </div>
        <div className="mbdy">
          {!history ? <div style={{textAlign:"center",color:"var(--mu)",padding:"20px 0"}}>Loading…</div>
           : history.length === 0 ? <div style={{textAlign:"center",color:"var(--mu)",padding:"20px 0"}}>No history yet</div>
           : history.map((r,i)=>(
            <div key={r.id} style={{display:"flex",alignItems:"center",gap:10,padding:"12px 0",borderBottom:"1px solid var(--bd)"}}>
              <div style={{flex:1}}>
                <div style={{fontFamily:"'JetBrains Mono'",fontSize:14,wordBreak:"break-all"}}>{r.password}</div>
                <div style={{fontSize:11,color:"var(--mu)",marginTop:3}}>{new Date(r.savedAt).toLocaleString()}</div>
              </div>
              <div className="ficb" onClick={()=>copy(r.password,i)}>
                <Ic d={copied===i?I.check:I.copy} size={14} color={copied===i?"var(--grn)":undefined}/>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Audit Screen ─────────────────────────────────────────────────────────────
function AuditScreen({ vault, onSelectItem }) {
  const issues  = auditVault(vault);
  const score   = Math.max(0, 100 - issues.length * 8);
  const scoreColor = score >= 80 ? "var(--grn)" : score >= 50 ? "var(--ylw)" : "var(--red)";
  const typeColor  = { weak:"var(--red)", short:"var(--red)", reused:"var(--ylw)", expired:"var(--mu)" };

  return (
    <div className="spage">
      <div className="spage-title">Security Audit</div>

      <div style={{background:"var(--s1)",border:"1px solid var(--bd)",borderRadius:"var(--r)",padding:20,marginBottom:18,textAlign:"center"}}>
        <div style={{fontSize:56,fontWeight:700,color:scoreColor,lineHeight:1}}>{score}</div>
        <div style={{fontSize:13,color:"var(--mu)",marginTop:4}}>Security Score</div>
        <div style={{fontSize:13,marginTop:8,color:issues.length?"var(--ylw)":"var(--grn)",fontWeight:600}}>
          {issues.length===0?"✓ All passwords look good!": `${issues.length} issue${issues.length>1?"s":""} found`}
        </div>
      </div>

      {issues.length > 0 && <>
        <div className="shead">Issues</div>
        {issues.map((issue,i) => (
          <div key={i} className="audit-item" onClick={()=>onSelectItem(issue.id)} style={{cursor:"pointer"}}>
            <Ic d={I.warn} size={18} color={typeColor[issue.type]||"var(--mu)"}/>
            <div style={{flex:1}}>
              <div style={{fontWeight:600,fontSize:14}}>{issue.name}</div>
              <div style={{fontSize:12,color:typeColor[issue.type]||"var(--mu)",marginTop:2}}>{issue.label}</div>
            </div>
            <Ic d={I.arr} size={16} color="var(--mu)"/>
          </div>
        ))}
      </>}

      <div className="shead">Stats</div>
      {[
        ["Total entries", vault.length],
        ["With passwords", vault.filter(v=>v.password).length],
        ["Favourites", vault.filter(v=>v.favourite).length],
        ["With 2FA", vault.filter(v=>v.totpSecret).length],
        ["With images", vault.filter(v=>v.images?.length>0).length],
      ].map(([label,val])=>(
        <div key={label} style={{display:"flex",justifyContent:"space-between",padding:"11px 0",borderBottom:"1px solid var(--bd)",fontSize:14}}>
          <span style={{color:"var(--mu)"}}>{label}</span>
          <span style={{fontWeight:600}}>{val}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Export Modal ─────────────────────────────────────────────────────────────
function ExportModal({ vault, onClose, toast }) {
  const [pw,setPw]=useState(""), [pw2,setPw2]=useState(""), [err,setErr]=useState(""), [busy,setBusy]=useState(false), [done,setDone]=useState(false);
  async function go() {
    setErr("");
    if (pw.length<4){setErr("Min 4 characters.");return;}
    if (pw!==pw2){setErr("Passwords don't match.");return;}
    setBusy(true);
    try {
      const json=await exportBackup(vault,pw);
      const url=URL.createObjectURL(new Blob([json],{type:"application/json"}));
      const a=Object.assign(document.createElement("a"),{href:url,download:`vault-backup-${new Date().toISOString().slice(0,10)}.json`});
      a.click(); URL.revokeObjectURL(url);
      setDone(true); toast("Backup downloaded!");
    } catch { setErr("Export failed."); }
    setBusy(false);
  }
  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">Export Backup</div>
          <div style={{width:36}}/>
        </div>
        <div className="mbdy">
          <div className="inf" style={{marginBottom:16}}>
            <Ic d={I.info} size={16} color="var(--ac2)" sw={2} style={{flexShrink:0,marginTop:1}}/>
            <div>Creates an encrypted <b style={{color:"var(--tx)"}}>vault-backup.json</b> file. Save it to Google Drive, WhatsApp, or email.</div>
          </div>
          <div className="ig"><label className="lbl">Backup Password</label><PwInp value={pw} onChange={setPw} placeholder="Backup password" strength/></div>
          <div className="ig"><label className="lbl">Confirm</label><PwInp value={pw2} onChange={setPw2} placeholder="Confirm backup password"/></div>
          {err && <div className="err">{err}</div>}
          {done && <div className="ok-msg">✓ Downloaded! Keep it safe.</div>}
          <button className="btn btn-p" style={{marginTop:10}} onClick={go} disabled={busy||done}>
            <Ic d={I.dl} size={17}/>{busy?"Encrypting…":done?"Downloaded ✓":"Download Backup"}
          </button>
          <button className="btn btn-g" style={{marginTop:9}} onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ─── Import Modal ─────────────────────────────────────────────────────────────
function ImportModal({ current, onImport, onClose, toast }) {
  const [pw,setPw]=useState(""), [mode,setMode]=useState("merge"), [err,setErr]=useState(""),
        [busy,setBusy]=useState(false), [preview,setPreview]=useState(null), [raw,setRaw]=useState(null),
        [fname,setFname]=useState(""), fileRef=useRef();

  function pickFile(e) {
    const f=e.target.files[0]; if(!f) return; setFname(f.name);
    const r=new FileReader(); r.onload=ev=>setRaw(ev.target.result); r.readAsText(f);
  }
  async function unlock() {
    setErr("");
    if(!raw){setErr("Select a file first.");return;} if(!pw){setErr("Enter backup password.");return;}
    setBusy(true);
    try { setPreview(await importBackup(raw,pw)); } catch { setErr("Wrong password or corrupted file."); }
    setBusy(false);
  }
  async function confirm() {
    const merged=mode==="replace"?preview:[...current,...preview.filter(v=>!current.find(c=>c.id===v.id))];
    await onImport(merged); toast(`Imported ${preview.length} entries!`); onClose();
  }
  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">Import Backup</div>
          <div style={{width:36}}/>
        </div>
        <div className="mbdy">
          {!preview?<>
            <div className="inf" style={{marginBottom:16}}>
              <Ic d={I.info} size={16} color="var(--ac2)" sw={2} style={{flexShrink:0,marginTop:1}}/>
              <div>Select your <b style={{color:"var(--tx)"}}>vault-backup.json</b> and enter the backup password.</div>
            </div>
            <input type="file" accept=".json" ref={fileRef} style={{display:"none"}} onChange={pickFile}/>
            <div className="upz" style={{marginBottom:14}} onClick={()=>fileRef.current.click()}>
              <Ic d={I.ul} size={22}/>
              <div style={{marginTop:7,fontWeight:raw?600:400,color:raw?"var(--grn)":undefined}}>{raw?`✓ ${fname}`:"Tap to select backup file"}</div>
            </div>
            <div className="ig"><label className="lbl">Backup Password</label><PwInp value={pw} onChange={setPw} placeholder="Backup password"/></div>
            {err && <div className="err">{err}</div>}
            <button className="btn btn-p" style={{marginTop:8}} onClick={unlock} disabled={busy}>{busy?"Decrypting…":"Unlock Backup"}</button>
          </>:<>
            <div className="ok-msg" style={{marginBottom:16}}>✓ Found {preview.length} entries</div>
            <div className="fsec">
              <div className="fsec-t">Import Mode</div>
              <div style={{display:"flex",gap:9}}>
                {[{id:"merge",label:"Merge",sub:"Add new only",color:"var(--ac)",bg:"rgba(124,58,237,.14)"},
                  {id:"replace",label:"Replace",sub:"Overwrite vault",color:"var(--red)",bg:"rgba(239,68,68,.12)"}].map(m=>(
                  <div key={m.id} onClick={()=>setMode(m.id)} style={{flex:1,padding:13,borderRadius:"var(--rs)",cursor:"pointer",textAlign:"center",
                    background:mode===m.id?m.bg:"var(--s2)",border:`1px solid ${mode===m.id?m.color:"var(--bd)"}`,transition:"all .2s"}}>
                    <div style={{fontSize:13,fontWeight:700,color:mode===m.id?m.color:"var(--tx)"}}>{m.label}</div>
                    <div style={{fontSize:11,color:"var(--mu)",marginTop:4}}>{m.sub}</div>
                  </div>
                ))}
              </div>
            </div>
            <button className="btn btn-p" onClick={confirm}>Confirm Import ({preview.length})</button>
            <button className="btn btn-g" style={{marginTop:9}} onClick={()=>setPreview(null)}>← Back</button>
          </>}
          <button className="btn btn-g" style={{marginTop:9}} onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ─── Settings Screen ──────────────────────────────────────────────────────────
function SettingsScreen({ vault, settings, onSettings, onImport, toast, onLogout, cryptoKey, masterPw }) {
  const [showExp,  setShowExp]  = useState(false);
  const [showImp,  setShowImp]  = useState(false);
  const [showPin,  setShowPin]  = useState(false);
  const [pinStep,  setPinStep]  = useState("set"); // set | confirm
  const [pinFirst, setPinFirst] = useState("");
  const [pinErr,   setPinErr]   = useState("");

  async function handleSetPin(pin) {
    if (pinStep === "set") { setPinFirst(pin); setPinStep("confirm"); setPinErr(""); }
    else {
      if (pin !== pinFirst) { setPinErr("PINs don't match. Try again."); setPinStep("set"); setPinFirst(""); return; }
      // Encrypt master password with PIN-derived key so biometric/PIN can unlock
      const pinSalt = crypto.getRandomValues(new Uint8Array(16));
      const pinKey  = await deriveKey(pin, pinSalt);
      const pinKeyEnc = await aesEncrypt(masterPw, pinKey);
      onSettings({ ...settings, pin, pinSalt: u8ToBase64(pinSalt), pinKeyEnc });
      toast("PIN set!"); setShowPin(false); setPinStep("set"); setPinFirst("");
    }
  }

  function removePin() { onSettings({ ...settings, pin:"", pinSalt:"", pinKeyEnc:"" }); toast("PIN removed"); }

  async function enableBiometric() {
    try {
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name:"Vault App" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name:"vault-user", displayName:"Vault User" },
        pubKeyCredParams: [{ type:"public-key", alg:-7 }],
        authenticatorSelection: { userVerification:"required" },
        timeout: 60000,
      }});
      onSettings({ ...settings, biometric:true, bioCredId: u8ToBase64(new Uint8Array(cred.rawId)) });
      toast("Biometric enabled!");
    } catch(e) { toast("Biometric not available on this device", "warn"); }
  }

  const autoLockOptions = [
    { v:0,  label:"Never" },
    { v:60, label:"1 minute" },
    { v:300,label:"5 minutes" },
    { v:600,label:"10 minutes" },
    { v:1800,label:"30 minutes" },
  ];

  return (
    <div className="spage">
      <div className="spage-title">Settings</div>

      <div className="shead">Appearance</div>
      <div className="sitem sitem-nc">
        <div className="sicobox" style={{background:"rgba(124,58,237,.12)"}}><Ic d={I.theme} size={20} color="var(--ac2)"/></div>
        <div style={{flex:1}}><div className="slabel">Dark Mode</div><div className="ssub">Toggle dark / light theme</div></div>
        <Toggle on={settings.dark!==false} onChange={v=>onSettings({...settings,dark:v})}/>
      </div>

      <div className="shead">Security</div>
      <div className="sitem sitem-nc">
        <div className="sicobox" style={{background:"rgba(59,130,246,.12)"}}><Ic d={I.clock} size={20} color="var(--blue)"/></div>
        <div style={{flex:1}}><div className="slabel">Auto-Lock</div><div className="ssub">Lock vault after inactivity</div></div>
        <select className="inp" style={{width:"auto",padding:"6px 10px",fontSize:13,background:"var(--s2)"}}
          value={settings.autoLock||300} onChange={e=>onSettings({...settings,autoLock:Number(e.target.value)})}>
          {autoLockOptions.map(o=><option key={o.v} value={o.v}>{o.label}</option>)}
        </select>
      </div>
      <div className="sitem" onClick={()=>{setShowPin(true);setPinStep("set");setPinFirst("");setPinErr("");}}>
        <div className="sicobox" style={{background:"rgba(124,58,237,.12)"}}><Ic d={I.pin} size={20} color="var(--ac2)"/></div>
        <div style={{flex:1}}>
          <div className="slabel">PIN Lock</div>
          <div className="ssub">{settings.pin?"PIN is set · tap to change":"Set a 6-digit PIN shortcut"}</div>
        </div>
        {settings.pin && <button className="btn btn-d" style={{width:"auto",padding:"6px 12px",fontSize:12}} onClick={e=>{e.stopPropagation();removePin();}}>Remove</button>}
        {!settings.pin && <Ic d={I.arr} size={17} color="var(--mu)"/>}
      </div>
      <div className="sitem" onClick={enableBiometric}>
        <div className="sicobox" style={{background:"rgba(34,197,94,.12)"}}><Ic d={I.finger} size={20} color="var(--grn)"/></div>
        <div style={{flex:1}}>
          <div className="slabel">Biometric Unlock</div>
          <div className="ssub">{settings.biometric?"Enabled · tap to re-register":"Use fingerprint to unlock"}</div>
          {settings.biometric && <div className="badge"><Ic d={I.check} size={11} sw={2.5}/>Active</div>}
        </div>
        <Ic d={I.arr} size={17} color="var(--mu)"/>
      </div>

      <div className="shead">Backup & Restore</div>
      <div className="sitem" onClick={()=>setShowExp(true)}>
        <div className="sicobox" style={{background:"rgba(34,197,94,.12)"}}><Ic d={I.dl} size={20} color="var(--grn)"/></div>
        <div style={{flex:1}}><div className="slabel">Export Backup</div><div className="ssub">Download encrypted .json · {vault.length} entries</div></div>
        <Ic d={I.arr} size={17} color="var(--mu)"/>
      </div>
      <div className="sitem" onClick={()=>setShowImp(true)}>
        <div className="sicobox" style={{background:"rgba(99,102,241,.12)"}}><Ic d={I.ul} size={20} color="#6366f1"/></div>
        <div style={{flex:1}}><div className="slabel">Import Backup</div><div className="ssub">Restore from a backup file</div></div>
        <Ic d={I.arr} size={17} color="var(--mu)"/>
      </div>

      <div className="shead">Vault</div>
      <div className="sitem sitem-nc">
        <div className="sicobox" style={{background:"rgba(34,197,94,.1)"}}><Ic d={I.db} size={20} color="var(--grn)"/></div>
        <div style={{flex:1}}><div className="slabel">Storage</div><div className="ssub">{vault.length} entries · IndexedDB · No size limit</div><div className="badge"><Ic d={I.check} size={11} sw={2.5}/>Encrypted</div></div>
      </div>
      <div className="sitem" onClick={onLogout}>
        <div className="sicobox" style={{background:"rgba(239,68,68,.1)"}}><Ic d={I.logout} size={20} color="var(--red)"/></div>
        <div style={{flex:1}}><div className="slabel" style={{color:"var(--red)"}}>Lock Vault</div><div className="ssub">Require password to re-enter</div></div>
      </div>

      {/* PIN setup modal */}
      {showPin && (
        <div className="ov" onClick={e=>e.target===e.currentTarget&&setShowPin(false)}>
          <div className="mdl">
            <div className="mhdl"/>
            <div className="mhdr">
              <button className="ibtn" onClick={()=>setShowPin(false)}><Ic d={I.x} size={17}/></button>
              <div className="mtit">Set PIN</div>
              <div style={{width:36}}/>
            </div>
            <div className="mbdy">
              <PinPad
                title={pinStep==="set"?"Choose a 6-digit PIN":"Confirm your PIN"}
                subtitle={pinStep==="set"?"You'll use this to unlock quickly":"Enter the same PIN again"}
                onComplete={handleSetPin}
                errorMsg={pinErr}
              />
            </div>
          </div>
        </div>
      )}

      {showExp && <ExportModal vault={vault} onClose={()=>setShowExp(false)} toast={toast}/>}
      {showImp && <ImportModal current={vault} onImport={onImport} onClose={()=>setShowImp(false)} toast={toast}/>}
    </div>
  );
}

// ─── Item Form ────────────────────────────────────────────────────────────────
function ItemForm({ initial, onSave, onClose }) {
  const [form, setForm] = useState(initial || {
    name:"",category:"login",username:"",password:"",url:"",note:"",images:[],
    tags:[],favourite:false,totpSecret:"",expiresAt:null,folder:""
  });
  const [compressing, setCompressing] = useState(false);
  const [tagInput,    setTagInput]    = useState("");
  const fileRef = useRef();
  const set = (k,v) => setForm(f=>({...f,[k]:v}));

  async function pickImages(files) {
    setCompressing(true);
    for (const file of Array.from(files)) {
      const r = new FileReader();
      const dataUrl = await new Promise(res=>{r.onload=e=>res(e.target.result);r.readAsDataURL(file);});
      const compressed = await compressImage(dataUrl);
      setForm(f=>({...f,images:[...(f.images||[]),compressed]}));
    }
    setCompressing(false);
  }

  function addTag() {
    const t = tagInput.trim().toLowerCase();
    if (t && !(form.tags||[]).includes(t)) set("tags",[...(form.tags||[]),t]);
    setTagInput("");
  }

  function save() {
    if (!form.name.trim()) return;
    onSave({...form, id:initial?.id||crypto.randomUUID(), updatedAt:Date.now()});
  }

  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">{initial?"Edit Entry":"New Entry"}</div>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <button className="ibtn" onClick={()=>set("favourite",!form.favourite)} style={{color:form.favourite?"#f59e0b":"var(--mu)"}}>
              <Ic d={I.star} size={17} color={form.favourite?"#f59e0b":"currentColor"} style={form.favourite?{fill:"#f59e0b"}:{}}/>
            </button>
            <button className="btn btn-p" style={{width:"auto",padding:"8px 16px",fontSize:14}} onClick={save}>Save</button>
          </div>
        </div>
        <div className="mbdy">
          {/* Category */}
          <div className="fsec">
            <div className="fsec-t">Category</div>
            <div style={{display:"flex",gap:7,flexWrap:"wrap"}}>
              {CATS.map(c=>(
                <button key={c.id} className="tpill" onClick={()=>set("category",c.id)}
                  style={form.category===c.id?{background:c.color+"22",borderColor:c.color,color:c.color}:{}}>
                  <Ic d={c.icon} size={13} color={form.category===c.id?c.color:"currentColor"}/>{c.label}
                </button>
              ))}
            </div>
          </div>

          {/* Core fields */}
          <div className="fsec">
            <div className="fsec-t">Details</div>
            <div className="ig"><label className="lbl">Name *</label>
              <input className="inp" value={form.name} onChange={e=>set("name",e.target.value)} placeholder="e.g. Gmail, Chase, Netflix"/></div>
            <div className="ig"><label className="lbl">Folder</label>
              <input className="inp" value={form.folder||""} onChange={e=>set("folder",e.target.value)} placeholder="e.g. Work, Personal, Banking"/></div>

            {(form.category==="login"||form.category==="other")&&<>
              <div className="ig"><label className="lbl">Username / Email</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="user@example.com"/></div>
              <div className="ig"><label className="lbl">Password</label>
                <div className="prow">
                  <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="Password" strength/>
                  <button className="gbtn" onClick={()=>set("password",genPw())}><Ic d={I.spin} size={14}/>Generate</button>
                </div>
              </div>
              <div className="ig"><label className="lbl">Website URL</label>
                <input className="inp" value={form.url} onChange={e=>set("url",e.target.value)} placeholder="https://example.com"/></div>
              <div className="ig"><label className="lbl">2FA Secret (TOTP)</label>
                <input className="inp" value={form.totpSecret||""} onChange={e=>set("totpSecret",e.target.value)} placeholder="Base32 secret from QR code"/></div>
              <div className="ig"><label className="lbl">Password Expires</label>
                <input className="inp" type="date" value={form.expiresAt?new Date(form.expiresAt).toISOString().slice(0,10):""}
                  onChange={e=>set("expiresAt",e.target.value?new Date(e.target.value).getTime():null)}/></div>
            </>}
            {form.category==="card"&&<>
              <div className="ig"><label className="lbl">Card Number</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="•••• •••• •••• ••••"/></div>
              <div className="ig"><label className="lbl">PIN / CVV</label>
                <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="PIN or CVV"/></div>
            </>}
            {form.category==="wifi"&&<>
              <div className="ig"><label className="lbl">Network Name (SSID)</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="My WiFi Network"/></div>
              <div className="ig"><label className="lbl">Wi-Fi Password</label>
                <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="Wi-Fi password" strength/></div>
            </>}
            <div className="ig"><label className="lbl">Notes</label>
              <textarea className="inp" value={form.note} onChange={e=>set("note",e.target.value)} placeholder="Optional notes…"/></div>
          </div>

          {/* Tags */}
          <div className="fsec">
            <div className="fsec-t">Tags</div>
            <div className="tag-inp-wrap">
              <input className="inp" style={{flex:1}} value={tagInput} onChange={e=>setTagInput(e.target.value)}
                onKeyDown={e=>e.key==="Enter"&&addTag()} placeholder="Add tag…"/>
              <button className="gbtn" style={{marginTop:0}} onClick={addTag}>Add</button>
            </div>
            {(form.tags||[]).length>0 && (
              <div className="tag-list">
                {form.tags.map(t=>(
                  <div key={t} className="tag-chip">#{t}
                    <button onClick={()=>set("tags",form.tags.filter(x=>x!==t))}>×</button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Images */}
          <div className="fsec">
            <div className="fsec-t">Images {compressing&&<span style={{color:"var(--ac2)",fontWeight:400,textTransform:"none",letterSpacing:0}}> — compressing…</span>}</div>
            <input type="file" accept="image/*" multiple ref={fileRef} style={{display:"none"}} onChange={e=>pickImages(e.target.files)}/>
            <div className="upz" onClick={()=>fileRef.current.click()}>
              <Ic d={I.image} size={22}/>
              <div style={{marginTop:7}}>Tap to attach images</div>
              <div style={{fontSize:11,marginTop:3,opacity:.6}}>Auto-compressed · No size limit</div>
            </div>
            {form.images?.length>0&&(
              <div className="ipgrid">
                {form.images.map((img,i)=>(
                  <div key={i} className="ipbox">
                    <img src={img} alt=""/>
                    <div className="ipdel" onClick={()=>set("images",form.images.filter((_,j)=>j!==i))}>
                      <Ic d={I.x} size={9} color="#fff" sw={3}/>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Item Detail ──────────────────────────────────────────────────────────────
function ItemDetail({ item, onEdit, onDelete, onClose, cryptoKey }) {
  const [showPw,    setShowPw]    = useState(false);
  const [copied,    setCopied]    = useState(null);
  const [lb,        setLb]        = useState(null);
  const [showHist,  setShowHist]  = useState(false);
  const color = catColor(item.category);

  function copy(text, tag) {
    navigator.clipboard.writeText(text).catch(()=>{});
    setCopied(tag); setTimeout(()=>setCopied(null),2000);
  }

  const expired = item.expiresAt && Date.now() > item.expiresAt;

  return <>
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.back} size={17}/></button>
          <div className="mtit">Details</div>
          <div style={{display:"flex",gap:7}}>
            {item.favourite&&<Ic d={I.star} size={17} color="#f59e0b" style={{fill:"#f59e0b"}}/>}
            <button className="ibtn" onClick={onEdit}><Ic d={I.edit} size={17}/></button>
          </div>
        </div>

        <div className="dhero">
          <div className="dico" style={{background:color+"22"}}>
            {item.images?.[0]?<img src={item.images[0]} alt=""/>:<Ic d={catIcon(item.category)} size={24} color={color}/>}
          </div>
          <div>
            <div className="dtit">{item.name}</div>
            <div className="dcat" style={{color}}>{catLabel(item.category)}</div>
            {item.folder&&<div style={{fontSize:11,color:"var(--mu)",marginTop:3}}>📁 {item.folder}</div>}
            {(item.tags||[]).length>0&&<div className="vtags" style={{marginTop:4}}>{item.tags.map(t=><span key={t} className="vtag">#{t}</span>)}</div>}
          </div>
        </div>

        {item.totpSecret && <TotpDisplay secret={item.totpSecret}/>}

        {expired && (
          <div className="wrn" style={{margin:"12px 18px 0",borderRadius:"var(--rs)"}}>
            <Ic d={I.warn} size={15} sw={2} style={{flexShrink:0}}/>
            <div>Password expired on {new Date(item.expiresAt).toLocaleDateString()}. Consider updating it.</div>
          </div>
        )}

        {item.username&&<div className="frow">
          <div className="flbl">{item.category==="card"?"Number":item.category==="wifi"?"SSID":"Username"}</div>
          <div className="fval">{item.username}</div>
          <div className="ficb" onClick={()=>copy(item.username,"u")}><Ic d={copied==="u"?I.check:I.copy} size={14} color={copied==="u"?"var(--grn)":undefined}/></div>
        </div>}

        {item.password&&<>
          <div className="frow">
            <div className="flbl">{item.category==="card"?"PIN/CVV":"Password"}</div>
            <div className="fval">{showPw?item.password:"•".repeat(Math.min(item.password.length,14))}</div>
            <div style={{display:"flex",gap:5}}>
              <div className="ficb" onClick={()=>setShowPw(v=>!v)}><Ic d={showPw?I.eyeOff:I.eye} size={14}/></div>
              <div className="ficb" onClick={()=>copy(item.password,"p")}><Ic d={copied==="p"?I.check:I.copy} size={14} color={copied==="p"?"var(--grn)":undefined}/></div>
              <div className="ficb" onClick={()=>setShowHist(true)}><Ic d={I.history} size={14}/></div>
            </div>
          </div>
          <BreachCheck password={item.password}/>
        </>}

        {item.url&&<div className="frow">
          <div className="flbl">URL</div>
          <div className="fval" style={{fontSize:13}}>{item.url}</div>
          <div style={{display:"flex",gap:5}}>
            <div className="ficb" onClick={()=>copy(item.url,"l")}><Ic d={copied==="l"?I.check:I.copy} size={14} color={copied==="l"?"var(--grn)":undefined}/></div>
            <div className="ficb" onClick={()=>window.open(item.url,"_blank")}><Ic d={I.globe} size={14}/></div>
          </div>
        </div>}

        {item.expiresAt&&<div className="frow">
          <div className="flbl">Expires</div>
          <div className="fval" style={{color:expired?"var(--red)":undefined}}>{new Date(item.expiresAt).toLocaleDateString()}</div>
        </div>}

        {item.note&&<div className="frow" style={{flexDirection:"column",alignItems:"flex-start",gap:7}}>
          <div className="flbl">Notes</div>
          <div className="fval" style={{fontFamily:"inherit",letterSpacing:0,lineHeight:1.6}}>{item.note}</div>
        </div>}

        {item.images?.length>0&&<>
          <div style={{padding:"12px 18px 4px",fontSize:11,color:"var(--mu)",fontWeight:700,letterSpacing:1,textTransform:"uppercase"}}>Images ({item.images.length})</div>
          <div className="igrid">{item.images.map((img,i)=><div key={i} className="ithumb" onClick={()=>setLb(img)}><img src={img} alt=""/></div>)}</div>
        </>}

        <div className="arow">
          <button className="btn btn-d" onClick={onDelete} style={{flex:1}}>
            <Ic d={I.trash} size={16}/>Delete
          </button>
        </div>
      </div>
    </div>

    {lb && <div className="lb" onClick={()=>setLb(null)}><img src={lb} alt=""/></div>}
    {showHist && <HistoryModal itemId={item.id} cryptoKey={cryptoKey} onClose={()=>setShowHist(false)}/>}
  </>;
}

// ─── Vault list item component ────────────────────────────────────────────────
function VaultItem({ item, onClick }) {
  const col     = catColor(item.category);
  const expired = item.expiresAt && Date.now() > item.expiresAt;
  return (
    <div className="vitem" onClick={onClick}>
      <div style={{position:"absolute",left:0,top:0,bottom:0,width:3,background:col,borderRadius:"99px 0 0 99px"}}/>
      <div className="vico" style={{background:col+"22"}}>
        {item.images?.[0]?<img src={item.images[0]} alt=""/>:<Ic d={catIcon(item.category)} size={19} color={col}/>}
      </div>
      <div className="vinf">
        <div className="vname">{item.name}
          {item.favourite && <Ic d={I.star} size={12} color="#f59e0b" style={{fill:"#f59e0b",marginLeft:5,verticalAlign:"middle"}}/>}
        </div>
        <div className="vsub">{item.username||item.url||catLabel(item.category)}</div>
        {(item.tags||[]).length>0 && <div className="vtags">{item.tags.slice(0,3).map(t=><span key={t} className="vtag">#{t}</span>)}</div>}
      </div>
      <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:4,flexShrink:0}}>
        {item.totpSecret && <span className="vbadge" style={{background:"rgba(124,58,237,.15)",color:"var(--ac2)"}}>2FA</span>}
        {expired && <span className="vbadge" style={{background:"rgba(239,68,68,.1)",color:"var(--red)"}}>Expired</span>}
        <Ic d={I.arr} size={16} color="var(--mu)"/>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [key,       setKey]       = useState(null);
  const [masterPw,  setMasterPw]  = useState("");
  const [vault,     setVault]     = useState([]);
  const [settings,  setSettingsS] = useState(() => ({ dark:true, autoLock:300, ...loadSettings() }));
  const [loading,   setLoading]   = useState(true);
  const [locked,    setLocked]    = useState(false); // auto-lock overlay
  const [tab,       setTab]       = useState("vault");
  const [search,    setSearch]    = useState("");
  const [catFilt,   setCatFilt]   = useState("all");
  const [sortBy,    setSortBy]    = useState("updated"); // updated|name|fav
  const [showFavs,  setShowFavs]  = useState(false);
  const [detail,    setDetail]    = useState(null);
  const [editing,   setEditing]   = useState(null);
  const [adding,    setAdding]    = useState(false);
  const [toast,     setToast]     = useState(null);
  const [recentIds, setRecentIds] = useState([]);
  const lockTimer = useRef();
  const toastTimer = useRef();

  const dark = settings.dark !== false;
  const CSS  = makeCSS(dark);

  // Persist settings
  function onSettings(s) { setSettingsS(s); saveSettings(s); }

  // Auto-lock
  function resetLockTimer() {
    clearTimeout(lockTimer.current);
    const mins = settings.autoLock || 300;
    if (mins === 0) return;
    lockTimer.current = setTimeout(() => setLocked(true), mins * 1000);
  }

  useEffect(() => {
    if (!key) return;
    resetLockTimer();
    const events = ["touchstart","mousedown","keydown"];
    events.forEach(e => window.addEventListener(e, resetLockTimer));
    return () => { clearTimeout(lockTimer.current); events.forEach(e => window.removeEventListener(e, resetLockTimer)); };
  }, [key, settings.autoLock]);

  useEffect(() => {
    openDB().then(db=>{db.close();setLoading(false);}).catch(()=>setLoading(false));
  }, []);

  function showToast(msg, type="ok") {
    clearTimeout(toastTimer.current);
    setToast({msg,type});
    toastTimer.current = setTimeout(()=>setToast(null), 2600);
  }

  async function handleAuth(derivedKey, pw) {
    await migrateFromLocalStorage(derivedKey);
    const items = await idbLoadAll(derivedKey);
    setKey(derivedKey); setMasterPw(pw); setVault(items); setLocked(false);
  }

  async function persistSave(item, oldPw) {
    if (oldPw && oldPw !== item.password) await saveHistory(item.id, oldPw, key);
    await idbSaveItem(item, key);
    const fresh = await idbLoadAll(key); setVault(fresh);
  }
  async function persistDelete(id) { await idbDelete(ST_VAULT, id); setVault(v=>v.filter(x=>x.id!==id)); }
  async function persistAll(items) {
    await idbClearAll();
    for (const item of items) await idbSaveItem(item, key);
    setVault(await idbLoadAll(key));
  }

  async function handleSave(item) {
    const existing = vault.find(v=>v.id===item.id);
    try {
      await persistSave(item, existing?.password);
      setAdding(false); setEditing(null); setDetail(item);
      setRecentIds(r=>[item.id,...r.filter(x=>x!==item.id)].slice(0,5));
      showToast(existing?"Entry updated ✓":"Entry saved ✓");
    } catch(e) { showToast("Save failed: "+e.message,"error"); }
  }
  async function handleDelete(id) {
    try { await persistDelete(id); setDetail(null); showToast("Entry deleted"); }
    catch(e) { showToast("Delete failed.","error"); }
  }
  async function handleImport(items) {
    try { await persistAll(items); setTab("vault"); showToast(`Imported ${items.length} entries!`); }
    catch(e) { showToast("Import failed.","error"); }
  }
  function handleLogout() {
    clearTimeout(lockTimer.current);
    setKey(null); setMasterPw(""); setVault([]); setDetail(null); setEditing(null); setAdding(false); setTab("vault"); setLocked(false);
  }

  // Filtering + sorting
  let filtered = vault.filter(v => {
    if (showFavs && !v.favourite) return false;
    if (catFilt !== "all" && v.category !== catFilt) return false;
    const q = search.toLowerCase();
    return !q || v.name.toLowerCase().includes(q) || (v.username||"").toLowerCase().includes(q)
      || (v.url||"").toLowerCase().includes(q) || (v.folder||"").toLowerCase().includes(q)
      || (v.tags||[]).some(t=>t.includes(q));
  });

  if (sortBy === "name")    filtered = [...filtered].sort((a,b)=>a.name.localeCompare(b.name));
  if (sortBy === "fav")     filtered = [...filtered].sort((a,b)=>(b.favourite?1:0)-(a.favourite?1:0));
  if (sortBy === "updated") filtered = [...filtered].sort((a,b)=>(b.updatedAt||0)-(a.updatedAt||0));

  // Group by folder if any have folders
  const hasFolders = filtered.some(v=>v.folder);
  const grouped = hasFolders
    ? [...new Set(filtered.map(v=>v.folder||"Other"))].reduce((acc,f)=>{
        const items = filtered.filter(v=>(v.folder||"Other")===f);
        if(items.length) acc[f]=items; return acc;
      },{})
    : CATS.reduce((acc,c)=>{
        const items=filtered.filter(v=>v.category===c.id);
        if(items.length) acc[c.id]=items; return acc;
      },{});

  const recentItems = recentIds.map(id=>vault.find(v=>v.id===id)).filter(Boolean);
  const auditIssues = key ? auditVault(vault) : [];

  // ── Loading ──
  if (loading) return (
    <><style>{CSS}</style>
    <div className="app"><div className="loading"><div className="spinner"/><div style={{fontSize:14}}>Initialising…</div></div></div></>
  );

  // ── Auth ──
  if (!key) return (
    <><style>{CSS}</style><div className="app"><AuthScreen onAuth={handleAuth} settings={settings}/></div></>
  );

  // ── Auto-lock overlay ──
  if (locked) return (
    <><style>{CSS}</style>
    <div className="app">
      <div className="lock-overlay">
        <div className="lock-overlay-logo"><Ic d={I.lock} size={32} color="#fff" sw={2}/></div>
        <div style={{fontWeight:700,fontSize:20}}>Vault Locked</div>
        <div style={{fontSize:13,color:"var(--mu)"}}>Tap to unlock</div>
        <div style={{width:"100%",maxWidth:340,padding:"0 24px",marginTop:8}}>
          {settings.pin ? (
            <PinPad title="Enter PIN" onComplete={async pin=>{
              if(pin===settings.pin){
                if(settings.pinKeyEnc){
                  try{
                    const pinSalt=Uint8Array.from(atob(settings.pinSalt||""),c=>c.charCodeAt(0));
                    const pinKey=await deriveKey(pin,pinSalt);
                    const master=await aesDecrypt(settings.pinKeyEnc,pinKey);
                    const salt=getOrCreateSalt(); const k=await deriveKey(master,salt);
                    if(await verifyKey(k)){setLocked(false);resetLockTimer();return;}
                  }catch{}
                }
                setLocked(false); resetLockTimer();
              }
            }} onCancel={handleLogout}/>
          ) : (
            <button className="btn btn-p" onClick={handleLogout}>Use Master Password</button>
          )}
        </div>
      </div>
    </div></>
  );

  // ── Main app ──
  return (
    <><style>{CSS}</style>
    <div className="app">

      {tab==="vault" && <>
        <div className="hdr">
          <div className="hdr-row">
            <div className="hdr-logo">
              <div className="hdr-logobox"><Ic d={I.shield} size={17} color="#fff" sw={2}/></div>
              <div className="hdr-title">Vault</div>
            </div>
            <div className="hdr-actions">
              {auditIssues.length>0 && (
                <button className="ibtn" onClick={()=>setTab("audit")} title="Security issues" style={{position:"relative"}}>
                  <Ic d={I.warn} size={17} color="var(--ylw)"/>
                  <div style={{position:"absolute",top:4,right:4,width:7,height:7,background:"var(--red)",borderRadius:"50%"}}/>
                </button>
              )}
              <button className={"ibtn"+(showFavs?" active":"")} onClick={()=>setShowFavs(v=>!v)} title="Favourites">
                <Ic d={I.star} size={17} color={showFavs?"#f59e0b":"currentColor"} style={showFavs?{fill:"#f59e0b"}:{}}/>
              </button>
              <button className="ibtn" onClick={()=>setSortBy(s=>s==="name"?"updated":s==="updated"?"fav":"name")} title="Sort">
                <Ic d={I.sort} size={17}/>
              </button>
              <button className="ibtn" onClick={handleLogout} title="Lock">
                <Ic d={I.logout} size={17}/>
              </button>
            </div>
          </div>
          <div className="sbox">
            <div className="sico"><Ic d={I.search} size={15}/></div>
            <input className="sinp" placeholder="Search name, tag, folder…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
        </div>

        <div className="trow">
          {[{id:"all",label:"All",icon:I.shield,color:"#7c3aed"},...CATS].map(c=>(
            <button key={c.id} className="tpill"
              style={catFilt===c.id?{background:c.color+"22",borderColor:c.color,color:c.color}:{}}
              onClick={()=>setCatFilt(c.id)}>
              <Ic d={c.icon} size={12} color={catFilt===c.id?c.color:"currentColor"}/>{c.label}
            </button>
          ))}
        </div>

        <div className="vlist">
          {/* Recently used */}
          {recentItems.length>0 && !search && catFilt==="all" && !showFavs && (
            <div>
              <div className="slbl"><Ic d={I.history} size={12}/>Recently Used</div>
              {recentItems.map(item=><VaultItem key={item.id} item={item} onClick={()=>setDetail(item)}/>)}
            </div>
          )}

          {filtered.length===0 ? (
            <div className="empty">
              <Ic d={I.lock} size={48}/>
              <div style={{fontWeight:600,fontSize:15}}>{search||showFavs?"Nothing found":"Your vault is empty"}</div>
              <div style={{fontSize:13,marginTop:5,opacity:.7}}>{showFavs?"Star entries to see them here":"Tap + to add your first entry"}</div>
            </div>
          ) : Object.entries(grouped).map(([gid,items])=>(
            <div key={gid}>
              <div className="slbl">
                {hasFolders ? <><Ic d={I.folder} size={12}/>{gid}</> : <><Ic d={catIcon(gid)} size={12}/>{catLabel(gid)}</>}
                <span style={{marginLeft:"auto",color:"var(--mu)",fontWeight:400,fontSize:11,textTransform:"none",letterSpacing:0}}>{items.length}</span>
              </div>
              {items.map(item=><VaultItem key={item.id} item={item} onClick={()=>{setDetail(item);setRecentIds(r=>[item.id,...r.filter(x=>x!==item.id)].slice(0,5));}}/>)}
            </div>
          ))}
        </div>
      </>}

      {tab==="audit" && <AuditScreen vault={vault} onSelectItem={id=>{const item=vault.find(v=>v.id===id);if(item){setDetail(item);setTab("vault");}}}/>}
      {tab==="settings" && (
        <SettingsScreen vault={vault} settings={settings} onSettings={onSettings}
          onImport={handleImport} toast={showToast} onLogout={handleLogout}
          cryptoKey={key} masterPw={masterPw}/>
      )}

      {/* FAB pair */}
      <div className="fab-wrap">
        <button className={"fab fab-set"+(tab==="settings"?" on":"")}
          onClick={()=>setTab(t=>t==="settings"?"vault":"settings")} title="Settings">
          <Ic d={I.cog} size={22} color={tab==="settings"?"var(--ac2)":"var(--mu)"}/>
        </button>
        <button className="fab fab-add" onClick={()=>{setTab("vault");setAdding(true);}} title="Add">
          <Ic d={I.plus} size={24} sw={2.2}/>
        </button>
      </div>

      {/* Modals */}
      {detail && !editing && (
        <ItemDetail item={detail} onEdit={()=>{setEditing(detail);setDetail(null);}} onDelete={()=>handleDelete(detail.id)} onClose={()=>setDetail(null)} cryptoKey={key}/>
      )}
      {(adding||editing) && (
        <ItemForm initial={editing} onSave={handleSave} onClose={()=>{setAdding(false);setEditing(null);if(editing)setDetail(editing);}}/>
      )}
      {toast && <Toast msg={toast.msg} type={toast.type}/>}
    </div>
    </>
  );
}

