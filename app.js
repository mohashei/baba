// Cradle: a private baby tracker shared between caregivers.
//
// Security model: people log in with a username and password. The password yields a sign-in
// secret (the only thing Firebase Auth sees) and a key that unwraps the person's private key.
// Each baby has its own data key, sealed separately to every person linked to that baby. Entries,
// timers and profiles are encrypted with AES-GCM before they are written, so Firestore stores only
// ciphertext plus a coarse day number used for range queries.
import { firebaseConfig } from './config.js';
import { WHO } from './who.js';
import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-app.js';
import {
  initializeAuth, indexedDBLocalPersistence, signInWithEmailAndPassword, createUserWithEmailAndPassword,
  onAuthStateChanged, signOut, EmailAuthProvider, reauthenticateWithCredential, updatePassword, connectAuthEmulator,
} from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-auth.js';
import {
  initializeFirestore, persistentLocalCache, persistentMultipleTabManager, doc, collection, query, where,
  onSnapshot, setDoc, deleteDoc, getDoc, getDocs, writeBatch, updateDoc, deleteField, terminate,
  clearIndexedDbPersistence, connectFirestoreEmulator,
} from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-firestore.js';

const ITER = 600000;                      // PBKDF2-SHA256 iterations (OWASP 2023 guidance)
const DAY = 86400000;
const WINDOW_DAYS = 9;                    // entries kept live-synced; older days load on demand
const MIN_PW = 10;

const $ = (sel) => document.querySelector(sel);
const ls = {
  get(k, d = null) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};

// ---------- DOM helpers ----------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  for (const c of kids.flat(Infinity)) if (c != null) el.append(c instanceof Node ? c : String(c));
  return el;
}
const ICONS = {
  nurse: 'M12 3.5c3.2 4.1 6 7.3 6 10.6a6 6 0 0 1-12 0c0-3.3 2.8-6.5 6-10.6z',
  bottle: 'M10 2.5h4M10.5 2.5v3M13.5 2.5v3M8.5 5.5h7l1 3v11a2 2 0 0 1-2 2h-5a2 2 0 0 1-2-2v-11zM8 11.5h3M8 15h3',
  solids: 'M3.5 11.5h17a8.5 8.5 0 0 1-17 0zM9 3.5c-1 1.2-1 2.3 0 3.5M13 3.5c-1 1.2-1 2.3 0 3.5M17 3.5c-1 1.2-1 2.3 0 3.5',
  sleep: 'M19.5 14.5A8 8 0 1 1 9.5 4.5a6.5 6.5 0 0 0 10 10z',
  growth: 'M4 4v16h16M8 15l3.5-4 3 2.5L19 8M15.5 8H19v3.5',
  today: 'M4 6.5h16M4 12h16M4 17.5h10',
  summary: 'M5 20v-8M10 20V5M15 20v-6M20 20V9',
  gear: 'M4 7h9M17 7h3M4 17h3M11 17h9M15 4.5v5M9 14.5v5',
  plus: 'M12 5v14M5 12h14',
  close: 'M6 6l12 12M18 6L6 18',
  left: 'M15 5l-7 7 7 7',
  right: 'M9 5l7 7-7 7',
  down: 'M6 9l6 6 6-6',
  lock: 'M7 11V8a5 5 0 0 1 10 0v3M5.5 11h13v9.5h-13z',
};
function icon(name, size = 22) {
  return s('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': 1.9, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
  s('path', { d: ICONS[name] }));
}
let toastTimer;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg; el.classList.add('on');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('on'), 3200);
}
const fail = (err, where = '') => { console.error(where, err?.code, err); toast(`Sync problem: ${err?.code || err?.message || err}`); };

// ---------- Formatting ----------

const pad = (n) => String(n).padStart(2, '0');
const trim = (n, dp = 1) => String(+(+n).toFixed(dp));
function fmtClock(ms) {
  const t = Math.max(0, Math.floor(ms / 1000)), hr = Math.floor(t / 3600), m = Math.floor(t % 3600 / 60);
  return hr ? `${hr}:${pad(m)}:${pad(t % 60)}` : `${m}:${pad(t % 60)}`;
}
function fmtDur(ms) {
  const m = Math.round(Math.max(0, ms) / 60000);
  if (m < 60) return `${m}m`;
  return m % 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m / 60}h`;
}
function fmtAgo(t) {
  const d = Date.now() - t;
  if (d < 60000) return 'just now';
  if (d < DAY) return `${fmtDur(d)} ago`;
  return `${Math.floor(d / DAY)}d ${Math.floor(d % DAY / 3600000)}h ago`;
}
const fmtTime = (t) => new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const fmtDate = (t, o = { weekday: 'short', month: 'short', day: 'numeric' }) => new Date(t).toLocaleDateString([], o);
function dayStart(offset = 0, from = Date.now()) {
  const d = new Date(from);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + offset).getTime();
}
const dayNum = (t) => Math.floor(t / DAY);
const toDateInput = (t) => { const d = new Date(t); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
const toLocalInput = (t) => { const d = new Date(t); return `${toDateInput(t)}T${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const fromLocalInput = (v) => { const t = v ? new Date(v).getTime() : NaN; return Number.isFinite(t) ? t : null; };
const parseDate = (v) => { const [y, m, d] = v.split('-').map(Number); return new Date(y, m - 1, d).getTime(); };
function ordinal(n) {
  const r = n % 100;
  return n + (r >= 11 && r <= 13 ? 'th' : ['th', 'st', 'nd', 'rd'][n % 10] || 'th');
}

const OZ = 29.5735, LB = 0.45359237, IN = 2.54;
const units = () => S.settings.units;
const fmtVol = (ml) => units().vol === 'oz' ? `${trim(ml / OZ)} oz` : `${Math.round(ml)} ml`;
function fmtWt(kg) {
  if (units().wt === 'kg') return `${trim(kg, 2)} kg`;
  const total = kg / LB * 16;
  let lb = Math.floor(total / 16), oz = +(total - lb * 16).toFixed(1);
  if (oz >= 16) { lb += 1; oz = 0; }
  return `${lb} lb ${trim(oz)} oz`;
}
const fmtLen = (cm) => units().len === 'in' ? `${trim(cm / IN)} in` : `${trim(cm)} cm`;

function ageText(birth, at = Date.now()) {
  const b = parseDate(birth), days = Math.round((dayStart(0, at) - b) / DAY);
  if (days < 0) return 'Due ' + fmtDate(b, { month: 'short', day: 'numeric' });
  if (days < 14) return `${days} day${days === 1 ? '' : 's'} old`;
  if (days < 91) return `${Math.floor(days / 7)} wk${days % 7 ? ` ${days % 7} d` : ''}`;
  const bd = new Date(b), now = new Date(at);
  let months = (now.getFullYear() - bd.getFullYear()) * 12 + now.getMonth() - bd.getMonth();
  if (now.getDate() < bd.getDate()) months -= 1;
  if (months < 24) {
    const rest = Math.round((dayStart(0, at) - new Date(bd.getFullYear(), bd.getMonth() + months, bd.getDate())) / DAY);
    return `${months} mo${rest ? ` ${rest} d` : ''}`;
  }
  return `${Math.floor(months / 12)} yr${months % 12 ? ` ${months % 12} mo` : ''}`;
}

// ---------- Crypto ----------

const te = new TextEncoder(), td = new TextDecoder();
function b64(buf) {
  const a = new Uint8Array(buf); let str = '';
  for (let i = 0; i < a.length; i += 0x8000) str += String.fromCharCode(...a.subarray(i, i + 0x8000));
  return btoa(str);
}
const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const uid = () => b64(rand(15)).replace(/\+/g, '-').replace(/\//g, '_');
const hex = (bytes) => [...bytes].map((x) => pad(x.toString(16))).join('');
const gcm = (iv, aad) => ({ name: 'AES-GCM', iv, additionalData: te.encode(aad) });

async function pbkdf2(pw, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256));
}
// The password is stretched once (salted with the username) and split with HKDF into the Firebase
// sign-in secret and a key-encryption key. Firebase never receives the password or the KEK.
async function deriveKeys(username, pw) {
  const master = await pbkdf2(pw, te.encode(`cradle/v3/${firebaseConfig.projectId}/${username}`), ITER);
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  const bits = async (info, salt = new Uint8Array(0)) =>
    new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, base, 256));
  return {
    auth: 'Aa1!' + b64(await bits('auth')),   // the prefix satisfies any Firebase password policy
    kek: async (salt) => crypto.subtle.importKey('raw', await bits('kek', salt), 'AES-GCM', false, ['encrypt', 'decrypt']),
  };
}
// Each person has an ECDH key pair. The private half is stored on the server only wrapped with
// their password's KEK; the public half lets others share a baby's key with them.
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const PRIV_AAD = 'cradle/private-key/v3';
async function newKeyPair() {
  const kp = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  return { pub: b64(await crypto.subtle.exportKey('raw', kp.publicKey)), pkcs8: new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)) };
}
async function wrapPrivate(pkcs8, keys) {
  const salt = rand(16), iv = rand(12);
  const ct = await crypto.subtle.encrypt(gcm(iv, PRIV_AAD), await keys.kek(salt), pkcs8);
  return { salt: b64(salt), iter: ITER, iv: b64(iv), ct: b64(ct) };
}
async function unwrapPrivate(wrap, keys) {
  if (!wrap) return null;
  try {
    return new Uint8Array(await crypto.subtle.decrypt(gcm(unb64(wrap.iv), PRIV_AAD), await keys.kek(unb64(wrap.salt)), unb64(wrap.ct)));
  } catch { return null; }
}
const importPrivate = (pkcs8) => crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']);
const importPublic = (raw) => crypto.subtle.importKey('raw', unb64(raw), ECDH, true, []);
async function shareKey(shared, epk) {
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(epk), info: te.encode('cradle/share/v3') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// A baby's key reaches each person sealed to their public key (ephemeral ECDH + HKDF + AES-GCM),
// bound to the member document it's stored in.
async function sealTo(pub, raw, aad) {
  const eph = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const epk = b64(await crypto.subtle.exportKey('raw', eph.publicKey));
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPublic(pub) }, eph.privateKey, 256);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt(gcm(iv, aad), await shareKey(shared, epk), raw);
  return { epk, iv: b64(iv), ct: b64(ct) };
}
async function openSealed(box, aad) {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPublic(box.epk) }, S.priv, 256);
  return new Uint8Array(await crypto.subtle.decrypt(gcm(unb64(box.iv), aad), await shareKey(shared, box.epk), unb64(box.ct)));
}
const importDek = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
// Each ciphertext is bound to its document path, so the server can't swap blobs between documents.
async function seal(obj, path, key = S.key) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt(gcm(iv, path), key, te.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(blob, path, key = S.key) {
  return JSON.parse(td.decode(await crypto.subtle.decrypt(gcm(unb64(blob.iv), path), key, unb64(blob.ct))));
}
async function timerId(kind, babyId) {
  const digest = await crypto.subtle.digest('SHA-256', te.encode(`timer/${kind}/${babyId}`));
  return 't' + hex(new Uint8Array(digest).slice(0, 12));
}
function genPassword() {
  const abc = 'abcdefghijkmnpqrstuvwxyz23456789', bytes = rand(20);
  return [...bytes].map((x, i) => (i && i % 5 === 0 ? '-' : '') + abc[x % 32]).join('');
}

// The signed-in person on this phone, with their private key stored as a non-extractable
// CryptoKey (usable here, never readable). Record: { name, uid, pub, priv }.
function keyStore(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('cradle-user', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('k');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('k', mode), req = fn(tx.objectStore('k'));
      tx.oncomplete = () => { open.result.close(); resolve(req.result); };
      tx.onerror = () => { open.result.close(); reject(tx.error); };
    };
  });
}
const loadUser = () => keyStore('readonly', (st) => st.get('me')).catch(() => null);
const saveUser = (rec) => keyStore('readwrite', (st) => st.put(rec, 'me'));
const dropUser = () => keyStore('readwrite', (st) => st.delete('me')).catch(() => {});

const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;
const normUser = (v) => v.trim().toLowerCase();
const emailFor = (name) => `${name}@example.com`;   // Firebase needs an email; nobody ever types it

// ---------- State ----------

const S = {
  me: null, uid: null, pub: null, priv: null, key: null, busy: false, started: false, babiesLoaded: false, linked: [],
  babies: new Map(), babyWatch: new Map(), activeBaby: null, gen: 0,
  settings: { babies: [], units: loadUnits() },
  entries: new Map(), growth: new Map(), timers: new Map(),
  loadedFrom: Infinity, loading: null, rangeRetryAt: 0, unsub: [], babySync: [], pending: {},
  tab: 'track', track: ls.get('track', 'bottle'), range: 7, metric: 'wt',
  babyId: ls.get('baby'),
};
function defaultUnits() {
  return /^en-(US|LR|MM)/i.test(navigator.language || '') ? { vol: 'oz', wt: 'lb', len: 'in' } : { vol: 'ml', wt: 'kg', len: 'cm' };
}
function loadUnits() {
  try { return { ...defaultUnits(), ...JSON.parse(ls.get('units', '{}')) }; } catch { return defaultUnits(); }
}
const baby = () => S.settings.babies.find((b) => b.id === S.babyId) || S.settings.babies[0];
const myName = () => S.me || '';
const forBaby = (map) => { const id = baby()?.id; return [...map.values()].filter((e) => e.baby === id); };
const timerFor = (kind) => forBaby(S.timers).find((t) => t.kind === kind);
function lastOf(type) {
  let best = null;
  for (const e of forBaby(S.entries)) if (e.type === type && (!best || e.start > best.start)) best = e;
  return best;
}
const CAT = { nurse: 'Nursing', bottle: 'Bottle', solids: 'Solids', sleep: 'Sleep', growth: 'Growth' };
const MILK = { breast: 'breast milk', formula: 'formula' };

// ---------- Firebase ----------
//
// usernames/{name}            { uid, pub }               who a username is, for linking
// users/{uid}                 { pub, priv, invite }      my wrapped private key
// users/{uid}/babies/{id}     {}                         the babies I'm linked to
// babies/{id}                 { owner, profile }         encrypted name, birth date, sex
// babies/{id}/members/{uid}   { uid, u, by, key }        the baby's key, sealed to each member
// babies/{id}/{entries,growth,timers}/{id}  { d, v, iv, ct }

const configured = Boolean(firebaseConfig.apiKey && firebaseConfig.projectId);
let auth, db;
if (configured) {
  const fbApp = initializeApp(firebaseConfig);
  auth = initializeAuth(fbApp, { persistence: indexedDBLocalPersistence });
  db = initializeFirestore(fbApp, { localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() }) });
  if (firebaseConfig.emulator) {
    window.__cradle = S;   // test hook; only with the local emulator
    connectAuthEmulator(auth, 'http://127.0.0.1:9099', { disableWarnings: true });
    connectFirestoreEmulator(db, '127.0.0.1', 8080);
  }
}
const userRef = () => doc(db, 'users', S.uid);
const colRef = (col) => collection(db, 'babies', S.babyId, col);
const docRef = (col, id) => doc(db, 'babies', S.babyId, col, id);
const memberPath = (babyId, who) => `babies/${babyId}/members/${who}`;

async function decodeInto(changes, map, col, gen = S.gen) {
  for (const ch of changes) {
    if (gen !== S.gen) return;   // the baby was switched while decrypting
    if (ch.type === 'removed') { map.delete(ch.doc.id); continue; }
    try {
      const e = await unseal(ch.doc.data(), `${col}/${ch.doc.id}`);
      if (gen === S.gen) map.set(ch.doc.id, { ...e, id: ch.doc.id });
    } catch (err) { console.warn(`Could not decrypt ${col}/${ch.doc.id}`, err); }
  }
}
function listen(name, q, map) {
  let chain = Promise.resolve();
  const gen = S.gen;
  S.babySync.push(onSnapshot(q, { includeMetadataChanges: true }, (snap) => {
    S.pending[name] = snap.metadata.hasPendingWrites; updateSync();
    const changes = snap.docChanges();
    if (changes.length) chain = chain.then(() => decodeInto(changes, map, name, gen)).then(render);
  }, (err) => (err?.code === 'permission-denied' ? accessLost() : fail(err, name))));
}
// Level one: the babies I'm linked to. Level two: the selected baby's entries, growth and timers.
function startSync() {
  if (S.started) return;
  S.started = true;
  let chain = Promise.resolve();
  // A link this phone is still writing isn't readable on the server yet, so wait for it to land.
  S.unsub.push(onSnapshot(collection(db, 'users', S.uid, 'babies'), { includeMetadataChanges: true }, (snap) => {
    S.linked = snap.docs.filter((d) => !d.metadata.hasPendingWrites).map((d) => d.id);
    chain = chain.then(() => syncBabies(S.linked)).then(() => { S.babiesLoaded = true; pickBaby(); render(); });
  }, (err) => fail(err, 'linked babies')));
  navigator.storage?.persist?.().catch(() => {});
}
async function syncBabies(ids) {
  for (const id of [...S.babies.keys()]) {
    if (!ids.includes(id)) { S.babyWatch.get(id)?.(); S.babyWatch.delete(id); S.babies.delete(id); }
  }
  let failed = false;
  for (const id of ids) if (!S.babies.has(id) && !(await watchBaby(id))) failed = true;
  refreshBabies();
  if (failed && S.started) setTimeout(() => S.started && syncBabies(S.linked).then(() => { pickBaby(); render(); }), 3000);
}
async function watchBaby(id) {
  try {
    const mine = await getDoc(doc(db, memberPath(id, S.uid)));
    if (!mine.exists()) return true;   // a stale link (access was removed); nothing to show
    const raw = await openSealed(mine.data().key, memberPath(id, S.uid));
    const b = { id, key: await importDek(raw), name: '', owner: null, members: [] };
    S.babies.set(id, b);
    const offs = [
      onSnapshot(doc(db, 'babies', id), async (snap) => {
        if (!snap.exists()) return;
        try { Object.assign(b, await unseal(snap.data().profile, `babies/${id}/profile`, b.key), { owner: snap.data().owner }); } catch {}
        refreshBabies(); render();
      }, (err) => { if (err?.code === 'permission-denied') accessLost(); }),
      onSnapshot(collection(db, 'babies', id, 'members'), (snap) => {
        b.members = snap.docs.map((d) => ({ uid: d.id, u: d.data().u })).sort((x, y) => x.u.localeCompare(y.u));
        render();
      }, (err) => { if (err?.code === 'permission-denied') accessLost(); }),
    ];
    S.babyWatch.set(id, () => offs.forEach((off) => off()));
    return true;
  } catch (err) {
    if (err?.code === 'permission-denied') return true;   // removed from this baby; its link is going away
    console.warn(`Could not open baby ${id}; retrying`, err?.code || err);
    return false;
  }
}
// Losing access to a baby (someone removed you) shows up as a refused listener. A fresh start
// re-reads which babies are still linked, so reload, at most once a minute to rule out loops.
function accessLost() {
  let last = 0;
  try { last = +sessionStorage.getItem('cradle-reload') || 0; sessionStorage.setItem('cradle-reload', Date.now()); } catch {}
  if (Date.now() - last < 60000) return toast("Sync problem: this phone doesn't have access to that baby.");
  location.reload();
}
function refreshBabies() {
  S.settings.babies = [...S.babies.values()].sort((x, y) => (x.name || '').localeCompare(y.name || ''));
}
function pickBaby() {
  const want = [S.babyId, ls.get('baby')].find((id) => S.babies.has(id)) || S.settings.babies[0]?.id || null;
  selectBaby(want);
}
function selectBaby(id) {
  if (S.activeBaby === id && id) return;
  S.babySync.forEach((off) => off()); S.babySync = [];
  S.entries.clear(); S.growth.clear(); S.timers.clear(); S.pending = {};
  S.gen += 1; S.activeBaby = id; S.babyId = id;
  S.key = id ? S.babies.get(id).key : null;
  if (!id) return;
  ls.set('baby', id);
  S.loadedFrom = dayNum(Date.now()) - WINDOW_DAYS;
  listen('entries', query(colRef('entries'), where('d', '>=', S.loadedFrom)), S.entries);
  listen('growth', colRef('growth'), S.growth);
  listen('timers', colRef('timers'), S.timers);
}
function stopSync() {
  S.unsub.forEach((off) => off()); S.unsub = [];
  S.babyWatch.forEach((off) => off()); S.babyWatch.clear(); S.babies.clear();
  selectBaby(null);
  S.started = false; S.babiesLoaded = false; refreshBabies();
}
// Older days are fetched once when someone scrolls back to them.
function ensureRange(fromDay) {
  if (fromDay >= S.loadedFrom || S.loading || Date.now() - S.rangeRetryAt < 30000) return;
  const gen = S.gen;
  S.loading = getDocs(query(colRef('entries'), where('d', '>=', fromDay), where('d', '<', S.loadedFrom)))
    .then(async (snap) => {
      await decodeInto(snap.docs.map((d) => ({ type: 'added', doc: d })), S.entries, 'entries', gen);
      if (gen !== S.gen) return;
      if (snap.metadata.fromCache) S.rangeRetryAt = Date.now();   // offline: show what's cached, retry later
      else S.loadedFrom = fromDay;
    })
    .catch((err) => { S.rangeRetryAt = Date.now(); fail(err); })
    .finally(() => { S.loading = null; render(); });
}

async function saveEntry(e) {
  const now = Date.now();
  e = { ...e, id: e.id || uid(), created: e.created || now, updated: now, by: e.by || myName() };
  const col = e.type === 'growth' ? 'growth' : 'entries';
  const { id, ...payload } = e;
  const blob = await seal(payload, `${col}/${id}`);
  (col === 'growth' ? S.growth : S.entries).set(id, e);
  render();
  setDoc(docRef(col, id), { d: dayNum(e.start), v: 1, ...blob }).catch(fail);
}
function removeEntry(e) {
  const col = e.type === 'growth' ? 'growth' : 'entries';
  (col === 'growth' ? S.growth : S.entries).delete(e.id);
  render();
  deleteDoc(docRef(col, e.id)).catch(fail);
}
async function saveTimer(t) {
  const { id, ...payload } = t;
  const blob = await seal(payload, `timers/${id}`);
  S.timers.set(id, t);
  render();
  setDoc(docRef('timers', id), { d: dayNum(Date.now()), v: 1, ...blob }).catch(fail);
}
function dropTimer(t) {
  S.timers.delete(t.id);
  render();
  deleteDoc(docRef('timers', t.id)).catch(fail);
}
// Turning a timer into an entry is one atomic batch, so no device sees both or neither.
async function commitTimer(t, e) {
  const now = Date.now();
  e = { ...e, id: uid(), created: now, updated: now, by: t.by || myName() };
  const { id, ...payload } = e;
  const blob = await seal(payload, `entries/${id}`);
  S.entries.set(id, e); S.timers.delete(t.id);
  render();
  const batch = writeBatch(db);
  batch.set(docRef('entries', id), { d: dayNum(e.start), v: 1, ...blob });
  batch.delete(docRef('timers', t.id));
  batch.commit().catch(fail);
  toast(`${CAT[e.type]} saved`);
}

// ---------- Babies and sharing ----------

async function createBaby(profile) {
  const id = uid();
  const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', fresh));
  const batch = writeBatch(db);
  batch.set(doc(db, 'babies', id), { v: 1, owner: S.uid, profile: await seal(profile, `babies/${id}/profile`, await importDek(raw)) });
  batch.set(doc(db, memberPath(id, S.uid)), { uid: S.uid, u: S.me, by: S.me, key: await sealTo(S.pub, raw, memberPath(id, S.uid)) });
  batch.set(doc(db, 'users', S.uid, 'babies', id), { v: 1 });
  S.babyId = id;
  await batch.commit();
}
async function saveProfile(b, profile) {
  Object.assign(b, profile); refreshBabies(); render();
  updateDoc(doc(db, 'babies', b.id), { profile: await seal(profile, `babies/${b.id}/profile`, b.key) }).catch(fail);
}
const userError = (msg) => Object.assign(new Error(msg), { userMessage: msg });
// Linking re-seals the baby's key to the other person's public key; only they can open it.
async function linkUser(b, username) {
  const name = normUser(username);
  if (!USERNAME_RE.test(name)) throw userError("That doesn't look like a username.");
  const found = await getDoc(doc(db, 'usernames', name));
  if (!found.exists()) throw userError(`No one has the username “${name}”.`);
  const { uid: them, pub } = found.data();
  if (b.members.some((m) => m.uid === them)) throw userError(`${name} can already see ${b.name}.`);
  const mine = await getDoc(doc(db, memberPath(b.id, S.uid)));
  const raw = await openSealed(mine.data().key, memberPath(b.id, S.uid));
  const batch = writeBatch(db);
  batch.set(doc(db, memberPath(b.id, them)), { uid: them, u: name, by: S.me, key: await sealTo(pub, raw, memberPath(b.id, them)) });
  batch.set(doc(db, 'users', them, 'babies', b.id), { v: 1 });
  await batch.commit();
}
async function unlinkUser(b, m) {
  const batch = writeBatch(db);
  batch.delete(doc(db, memberPath(b.id, m.uid)));
  batch.delete(doc(db, 'users', m.uid, 'babies', b.id));
  await batch.commit();
}

// ---------- Lock screen ----------

function showLock(mode = 'login', message = '', username = '') {
  stopSync();
  $('#boot').hidden = true; $('#app').hidden = true;
  if ($('#sheet').open) $('#sheet').close();
  const lock = $('#lock'); lock.hidden = false;
  const err = h('p', { class: 'err', role: 'alert' }, message);
  const head = [h('div', { class: 'logo' }, icon(mode === 'signup' ? 'nurse' : 'lock', 34)), h('h1', {}, 'Cradle')];

  if (!configured) {
    lock.replaceChildren(h('div', { class: 'lock-box' }, head,
      h('p', { class: 'lede' }, 'Almost there'),
      h('p', {}, 'This copy of the app is not connected to a Firebase project yet. Fill in config.js using the steps in README.md, then reload.')));
    return;
  }
  const user = h('input', { type: 'text', autocomplete: 'username', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false',
    placeholder: 'Username', 'aria-label': 'Username', required: true, value: username });
  const pw = h('input', { type: 'password', autocomplete: mode === 'signup' ? 'new-password' : 'current-password', placeholder: 'Password', 'aria-label': 'Password', required: true });

  if (mode === 'login') {
    const go = h('button', { class: 'btn primary block', type: 'submit' }, 'Log in');
    const form = h('form', { class: 'stack', onsubmit: async (ev) => {
      ev.preventDefault();
      go.disabled = true; go.textContent = 'Logging in…'; err.textContent = '';
      const problem = await login(user.value, pw.value);
      if (problem) { err.textContent = problem; go.disabled = false; go.textContent = 'Log in'; pw.select(); }
    } }, user, pw, go, err);
    lock.replaceChildren(h('div', { class: 'lock-box' }, head,
      h('p', { class: 'lede' }, 'Private baby tracker'), form,
      h('button', { class: 'btn ghost', type: 'button', onclick: () => showLock('signup', '', user.value) }, 'Create an account')));
    setTimeout(() => (username ? pw : user).focus(), 50);
    return;
  }

  const pw2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Password again', 'aria-label': 'Confirm password', required: true });
  const invite = h('input', { type: 'text', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', placeholder: 'Invite code', 'aria-label': 'Invite code', required: true });
  const saved = h('input', { type: 'checkbox', required: true });
  const shown = h('p', { class: 'code', hidden: true });
  const go = h('button', { class: 'btn primary block', type: 'submit' }, 'Create account');
  const form = h('form', { class: 'stack', onsubmit: async (ev) => {
    ev.preventDefault();
    if (!USERNAME_RE.test(normUser(user.value))) { err.textContent = 'Usernames are 3–30 characters: letters, numbers, - or _.'; return; }
    if (pw.value.length < MIN_PW) { err.textContent = `Use at least ${MIN_PW} characters for the password.`; return; }
    if (pw.value !== pw2.value) { err.textContent = "The two passwords don't match."; return; }
    go.disabled = true; go.textContent = 'Creating…'; err.textContent = '';
    const problem = await signup(user.value, pw.value, invite.value.trim());
    if (problem) { err.textContent = problem; go.disabled = false; go.textContent = 'Create account'; }
  } },
  field('Username', user, 'Letters, numbers, - or _. Others use it to share a baby with you.'),
  field('Password', pw), pw2,
  h('button', { class: 'btn secondary', type: 'button', onclick: () => {
    const p = genPassword(); pw.value = pw2.value = p; shown.textContent = p; shown.hidden = false;
  } }, 'Suggest a strong password'),
  shown,
  field('Invite code', invite, 'Ask the person who set up this app.'),
  h('p', { class: 'note' }, 'Your password also unlocks the encryption on your babies’ data. ' +
    'If you forget it, nobody can reset it for you; you can only be re-added as a new user.'),
  h('label', { class: 'check' }, saved, h('span', {}, "I've saved this password in a password manager.")),
  go, err);
  lock.replaceChildren(h('div', { class: 'lock-box' }, head,
    h('p', { class: 'lede' }, 'Create an account'), form,
    h('button', { class: 'btn ghost', type: 'button', onclick: () => showLock('login', '', user.value) }, 'I already have an account')));
  setTimeout(() => user.focus(), 50);
}

function authProblem(err) {
  if (err?.userMessage) return err.userMessage;
  const code = err?.code || '';
  if (/invalid-credential|wrong-password|user-not-found|invalid-login|invalid-email/.test(code)) return "That username and password didn't match.";
  if (code.includes('too-many-requests')) return 'Too many attempts. Wait a few minutes and try again.';
  if (/network-request-failed|unavailable/.test(code)) return 'No connection. Logging in on a phone needs the internet once.';
  if (code.includes('email-already-in-use')) return 'That username is taken.';
  if (code.includes('permission-denied')) return "That invite code isn't right.";
  if (/operation-not-allowed|configuration-not-found|admin-restricted/.test(code)) return 'Email/Password sign-in is not enabled in Firebase (see README).';
  console.error(err);
  return `Something went wrong (${code || err?.message || err}).`;
}

async function login(username, pw) {
  const name = normUser(username);
  if (!USERNAME_RE.test(name) || !pw) return "That username and password didn't match.";
  S.busy = true;
  try {
    const keys = await deriveKeys(name, pw);
    await signInWithEmailAndPassword(auth, emailFor(name), keys.auth);
    const snap = await getDoc(doc(db, 'users', auth.currentUser.uid));
    if (!snap.exists()) {
      await signOut(auth);
      return 'This account was never finished. Choose “Create an account” with the same username, password and an invite code.';
    }
    const data = snap.data();
    let pkcs8 = await unwrapPrivate(data.priv, keys);
    const viaPrev = !pkcs8;
    if (!pkcs8) pkcs8 = await unwrapPrivate(data.prevPriv, keys);
    if (!pkcs8) { await signOut(auth); return "That username and password didn't match."; }
    if (!viaPrev && data.prevPriv) updateDoc(doc(db, 'users', auth.currentUser.uid), { prevPriv: deleteField() }).catch(() => {});
    return await rememberUser(name, data.pub, pkcs8);
  } catch (err) { return authProblem(err); } finally { S.busy = false; }
}
// The invite code is checked by the database rules when the profile is written, so without it
// nothing beyond a bare login exists. A failed attempt can be retried with the same details.
async function signup(username, pw, invite) {
  const name = normUser(username);
  S.busy = true;
  try {
    const keys = await deriveKeys(name, pw);
    try {
      await createUserWithEmailAndPassword(auth, emailFor(name), keys.auth);
    } catch (err) {
      if (!String(err?.code).includes('email-already-in-use')) throw err;
      try { await signInWithEmailAndPassword(auth, emailFor(name), keys.auth); } catch { throw err; }
      if ((await getDoc(doc(db, 'users', auth.currentUser.uid))).exists()) {
        await signOut(auth);
        throw userError('That account already exists. Log in instead.');
      }
    }
    const { pub, pkcs8 } = await newKeyPair();
    const batch = writeBatch(db);
    batch.set(doc(db, 'users', auth.currentUser.uid), { v: 1, pub, priv: await wrapPrivate(pkcs8, keys), invite });
    batch.set(doc(db, 'usernames', name), { uid: auth.currentUser.uid, pub });
    try { await batch.commit(); } catch (err) { await signOut(auth); throw err; }
    return await rememberUser(name, pub, pkcs8);
  } catch (err) { return authProblem(err); } finally { S.busy = false; }
}
async function rememberUser(name, pub, pkcs8) {
  const priv = await importPrivate(pkcs8);
  Object.assign(S, { me: name, uid: auth.currentUser.uid, pub, priv });
  await saveUser({ name, uid: S.uid, pub, priv });
  enterApp();
  return null;
}
function enterApp() {
  $('#boot').hidden = true; $('#lock').hidden = true; $('#app').hidden = false;
  startSync();
  render();
}

// ---------- Rendering ----------

function render() {
  if (!S.priv || $('#app').hidden) return;
  renderTop(); renderTabs();
  const views = { track: viewTrack, summary: viewSummary, growth: viewGrowth };
  $('#main').replaceChildren(S.key && baby()?.name ? views[S.tab]()
    : S.babiesLoaded && !S.settings.babies.length ? welcome() : h('p', { class: 'empty' }, 'Loading…'));
  tick();
}
function renderTop() {
  const b = baby();
  $('#top').replaceChildren(
    h('button', { class: 'baby-btn', 'aria-label': 'Switch baby', onclick: babySwitcher },
      h('span', { class: 'avatar' }, (b?.name || '?').slice(0, 1).toUpperCase()),
      h('span', { class: 'baby-meta' }, h('b', {}, b?.name || 'Cradle'), h('small', {}, b?.birth ? ageText(b.birth) : '')),
      icon('down', 18)),
    h('span', { class: 'sync', id: 'sync' }),
    h('button', { class: 'icon-btn', 'aria-label': 'Settings', onclick: settingsSheet }, icon('gear')));
  updateSync();
}
function updateSync() {
  const el = $('#sync');
  if (!el) return;
  const offline = !navigator.onLine;
  el.textContent = offline ? 'Offline' : Object.values(S.pending).some(Boolean) ? 'Syncing…' : '';
  el.classList.toggle('offline', offline);
}
function renderTabs() {
  const tabs = [['track', 'Track', 'today'], ['summary', 'Summary', 'summary'], ['growth', 'Growth', 'growth']];
  $('#tabs').replaceChildren(...tabs.map(([k, label, ic]) => h('button', {
    class: 'tab' + (S.tab === k ? ' on' : ''), 'aria-current': S.tab === k ? 'page' : null,
    onclick: () => { S.tab = k; window.scrollTo(0, 0); render(); },
  }, icon(ic), h('span', {}, label))));
}
// Live counters: elements carrying data-since are refreshed every second by tick().
function live(since, fmt = 'ago', base = 0, pre = '') {
  return h('span', { 'data-since': since, 'data-fmt': fmt, 'data-base': base, 'data-pre': pre });
}
function tick() {
  const now = Date.now();
  for (const el of document.querySelectorAll('[data-since]')) {
    const since = +el.dataset.since, v = now - since + +el.dataset.base;
    const f = el.dataset.fmt;
    el.textContent = el.dataset.pre + (f === 'clock' ? fmtClock(v) : f === 'dur' ? fmtDur(v) : fmtAgo(since));
  }
}

// ---------- Track ----------
//
// One tracker per activity, like Nara: a tab each for bottle, sleep, solids and nursing, each with
// its own controls and its own day-by-day history.

const KINDS = ['bottle', 'sleep', 'solids', 'nurse'];
const trackKind = () => (KINDS.includes(S.track) ? S.track : 'bottle');
const goTrack = (k) => { S.track = k; ls.set('track', k); window.scrollTo(0, 0); render(); };

function viewTrack() {
  const kind = trackKind(), nt = timerFor('nurse'), st = timerFor('sleep');
  return h('div', {},
    h('div', { class: 'kinds', role: 'tablist' }, KINDS.map(kindTab)),
    nt && kind !== 'nurse' ? banner('nurse', nt.segs[0].a) : null,
    st && kind !== 'sleep' ? banner('sleep', st.start) : null,
    ({ nurse: nurseTracker, bottle: bottleTracker, solids: solidsTracker, sleep: sleepTracker })[kind](),
    historyCard(kind));
}
function kindTab(k) {
  const on = trackKind() === k, timer = timerFor(k), last = lastOf(k);
  const sub = timer ? h('small', { class: 'pulse' }, k === 'sleep' ? 'asleep' : 'now')
    : last ? h('small', {}, live(k === 'sleep' ? last.end : last.start)) : h('small', {}, '–');
  return h('button', { class: `kind c-${k}${on ? ' on' : ''}`, role: 'tab', 'aria-selected': String(on), onclick: () => goTrack(k) },
    h('span', { class: 'kind-icon' }, icon(k, 20)), h('b', {}, CAT[k]), sub);
}
// A timer running on another tab stays visible.
function banner(k, since) {
  return h('button', { class: `banner c-${k}`, onclick: () => goTrack(k) },
    icon(k, 18), h('span', {}, k === 'sleep' ? 'Sleeping' : 'Nursing'), live(since, 'clock'), h('span', { class: 'banner-go' }, 'Open'));
}

function nurseTracker() {
  const t = timerFor('nurse');
  if (t) return nurseTimerCard(t);
  const last = lastOf('nurse'), suggest = last ? (last.last === 'L' ? 'R' : 'L') : null;
  return h('section', { class: 'card timer c-nurse' },
    h('div', { class: 'timer-head' }, icon('nurse'), h('b', {}, 'Start a feed'),
      last ? h('span', { class: 'mute small' }, 'Last ', live(last.end || last.start)) : null),
    h('div', { class: 'start-sides' }, ['L', 'R'].map((k) => h('button', {
      type: 'button', class: 'big-start' + (suggest === k ? ' suggest' : ''), onclick: () => startNurse(k),
    }, h('b', {}, k === 'L' ? 'Left' : 'Right'), h('small', {}, suggest === k ? 'Suggested next' : 'Start timer')))),
    h('button', { class: 'tracker-link', onclick: () => nurseSheet(null) }, '+ Log a past feed'));
}
function sleepTracker() {
  const t = timerFor('sleep');
  if (t) return sleepTimerCard(t);
  const last = lastOf('sleep');
  return h('section', { class: 'card timer c-sleep' },
    h('div', { class: 'timer-head' }, icon('sleep'), h('b', {}, last ? live(last.end, 'dur', 0, 'Awake ') : 'Sleep'),
      last ? h('span', { class: 'mute small' }, `Last sleep ${fmtDur(last.end - last.start)}`) : null),
    h('button', { type: 'button', class: 'big-start wide', onclick: startSleep }, icon('sleep'), h('b', {}, 'Start sleep')),
    h('button', { class: 'tracker-link', onclick: () => sleepSheet(null) }, '+ Log a past sleep'));
}
function bottleTracker() {
  const last = lastOf('bottle');
  return h('section', { class: 'card timer c-bottle' },
    h('div', { class: 'timer-head' }, icon('bottle'), h('b', {}, 'Bottle'),
      last ? h('span', { class: 'mute small' }, `${fmtVol(last.amt)} · `, live(last.start)) : null),
    h('button', { class: 'btn primary block', onclick: () => bottleSheet() }, icon('plus', 20), 'Log a bottle'));
}
function solidsTracker() {
  const last = lastOf('solids');
  return h('section', { class: 'card timer c-solids' },
    h('div', { class: 'timer-head' }, icon('solids'), h('b', {}, 'Solids'),
      last ? h('span', { class: 'mute small' }, `${last.food} · `, live(last.start)) : null),
    h('button', { class: 'btn primary block', onclick: () => solidsSheet() }, icon('plus', 20), 'Log solids'));
}

// History for one activity, grouped by day, newest first. Older days load on demand.
function historyCard(kind) {
  const groups = new Map([[dayStart(0), []]]);
  for (const e of forBaby(S.entries).filter((x) => x.type === kind).sort((a, b) => b.start - a.start)) {
    const d = dayStart(0, e.start);
    if (!groups.has(d)) groups.set(d, []);
    groups.get(d).push(e);
  }
  const days = [...groups.keys()].sort((a, b) => b - a);
  const any = days.some((d) => groups.get(d).length);
  return h('section', { class: 'card' },
    days.map((d) => dayGroup(kind, d, groups.get(d))),
    any ? h('p', { class: 'hint' }, 'Tap an entry to change or delete it.') : null,
    h('button', { class: 'btn ghost block', disabled: Boolean(S.loading), onclick: () => ensureRange(S.loadedFrom - 7) },
      S.loading ? 'Loading…' : 'Show older days'));
}
function dayGroup(kind, d, items) {
  const label = d === dayStart(0) ? 'Today' : d === dayStart(-1) ? 'Yesterday' : fmtDate(d);
  return h('div', { class: 'day-group' },
    h('div', { class: 'day-head' }, h('b', {}, label), h('span', { class: 'mute small' }, daySummary(kind, d, items))),
    items.length ? h('ul', { class: 'timeline' }, items.map(row))
      : h('p', { class: 'empty' }, { nurse: 'No feeds yet.', bottle: 'No bottles yet.', solids: 'No solids yet.', sleep: 'No sleep logged yet.' }[kind]));
}
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
function daySummary(kind, d, items) {
  const sum = (k) => items.reduce((acc, e) => acc + (e[k] || 0), 0);
  if (kind === 'sleep') {
    const total = dayStats(d, dayStart(1, d), withLive()).sleep;
    return total ? `${fmtDur(total)} total · ${plural(items.length, 'sleep')}` : '';
  }
  if (!items.length) return '';
  if (kind === 'nurse') return `${plural(items.length, 'feed')} · ${fmtDur(sum('l') + sum('r'))} (L ${fmtDur(sum('l'))}, R ${fmtDur(sum('r'))})`;
  if (kind === 'bottle') return `${plural(items.length, 'bottle')} · ${fmtVol(sum('amt'))}`;
  return plural(items.length, 'time');
}

function nurseTimerCard(t) {

  const last = t.segs.at(-1), running = last && last.b == null ? last.s : null;
  const closed = { L: 0, R: 0 };
  for (const seg of t.segs) if (seg.b != null) closed[seg.s] += seg.b - seg.a;
  const side = (k, label) => h('button', { class: 'side' + (running === k ? ' on' : ''), onclick: () => nurseTap(t, k) },
    h('span', { class: 'side-label' }, label),
    running === k ? live(last.a, 'clock', closed[k]) : h('span', {}, fmtClock(closed[k])),
    h('small', {}, running === k ? 'Tap to pause' : running ? 'Tap to switch' : 'Tap to resume'));
  return h('section', { class: 'card timer c-nurse', id: 'timer-nurse' },
    h('div', { class: 'timer-head' }, icon('nurse'), h('b', {}, running ? 'Nursing' : 'Nursing (paused)'),
      h('button', { class: 'link', onclick: () => timerStartSheet(t) }, `Started ${fmtTime(t.segs[0].a)}`)),
    h('div', { class: 'sides' }, side('L', 'Left'), side('R', 'Right')),
    h('div', { class: 'timer-foot' },
      h('span', {}, 'Total ', running ? live(last.a, 'clock', closed.L + closed.R) : fmtClock(closed.L + closed.R)),
      h('button', { class: 'btn ghost', onclick: () => confirm('Discard this nursing timer?') && dropTimer(t) }, 'Discard'),
      h('button', { class: 'btn primary', onclick: () => finishNurse(t) }, 'Done')));
}
function sleepTimerCard(t) {
  return h('section', { class: 'card timer c-sleep', id: 'timer-sleep' },
    h('div', { class: 'timer-head' }, icon('sleep'), h('b', {}, 'Sleeping'),
      h('button', { class: 'link', onclick: () => timerStartSheet(t) }, `Since ${fmtTime(t.start)}`)),
    h('div', { class: 'big-clock' }, live(t.start, 'clock')),
    h('div', { class: 'timer-foot' }, h('span'),
      h('button', { class: 'btn ghost', onclick: () => confirm('Discard this sleep timer?') && dropTimer(t) }, 'Discard'),
      h('button', { class: 'btn primary', onclick: () => commitTimer(t, { type: 'sleep', baby: t.baby, start: t.start, end: Date.now(), note: '' }) }, 'Woke up')));
}
async function startNurse(side) {
  const b = baby();
  saveTimer({ id: await timerId('nurse', b.id), kind: 'nurse', baby: b.id, by: myName(), segs: [{ s: side, a: Date.now(), b: null }] });
}
async function startSleep() {
  const b = baby();
  saveTimer({ id: await timerId('sleep', b.id), kind: 'sleep', baby: b.id, by: myName(), start: Date.now() });
}
function nurseTap(t, side) {
  const now = Date.now(), segs = t.segs.map((x) => ({ ...x })), last = segs.at(-1);
  if (last && last.b == null) {
    last.b = now;
    if (last.s === side) return saveTimer({ ...t, segs });
  }
  segs.push({ s: side, a: now, b: null });
  saveTimer({ ...t, segs });
}
function finishNurse(t) {
  const now = Date.now(), segs = t.segs.map((x) => ({ ...x, b: x.b ?? now })), tot = { L: 0, R: 0 };
  for (const seg of segs) tot[seg.s] += seg.b - seg.a;
  commitTimer(t, { type: 'nurse', baby: t.baby, start: segs[0].a, end: segs.at(-1).b, l: tot.L, r: tot.R, last: segs.at(-1).s, note: '' });
}

function dayStats(start, end, list) {
  const st = { feeds: 0, nurseN: 0, bottleN: 0, nurse: 0, bottle: 0, sleep: 0, solids: 0, any: false };
  for (const e of list) {
    if (e.type === 'sleep') {
      const o = Math.min(e.end, end) - Math.max(e.start, start);
      if (o > 0) { st.sleep += o; st.any = true; }
      continue;
    }
    if (e.start < start || e.start >= end) continue;
    st.any = true;
    if (e.type === 'nurse') { st.feeds += 1; st.nurseN += 1; st.nurse += (e.l || 0) + (e.r || 0); }
    if (e.type === 'bottle') { st.feeds += 1; st.bottleN += 1; st.bottle += e.amt || 0; }
    if (e.type === 'solids') st.solids += 1;
  }
  return st;
}
// Entries plus a running sleep timer, so totals include the nap in progress.
function withLive() {
  const list = forBaby(S.entries), st = timerFor('sleep');
  if (st) list.push({ type: 'sleep', start: st.start, end: Date.now(), live: true });
  return list;
}
function describe(e) {
  if (e.type === 'nurse') return [e.l ? `L ${fmtDur(e.l)}` : '', e.r ? `R ${fmtDur(e.r)}` : ''].filter(Boolean).join(' · ') || '0m';
  if (e.type === 'bottle') return `${fmtVol(e.amt)} ${MILK[e.milk] || ''}`.trim();
  if (e.type === 'solids') return e.food || '';
  if (e.type === 'sleep') return `${fmtDur(e.end - e.start)} · until ${fmtTime(e.end)}`;
  return '';
}
function row(e) {
  const meta = [e.note, e.by && `by ${e.by}`].filter(Boolean).join(' · ');
  return h('li', {}, h('button', { class: `row c-${e.type}`, onclick: () => entrySheet(e) },
    h('span', { class: 'row-time' }, fmtTime(e.start)),
    h('span', { class: 'dot' }, icon(e.type, 18)),
    h('span', { class: 'row-body' }, h('b', {}, describe(e)), meta ? h('small', {}, meta) : null)));
}

// ---------- Summary ----------

function viewSummary() {
  const n = S.range, days = [];
  for (let i = n - 1; i >= 0; i -= 1) days.push(dayStart(-i));
  if (dayNum(days[0]) - 1 < S.loadedFrom) ensureRange(dayNum(days[0]) - 1);
  const all = withLive(), per = days.map((d) => dayStats(d, dayStart(1, d), all));
  const done = per.slice(0, -1).filter((p) => p.any), base = done.length ? done : [per.at(-1)];
  const avg = (k) => base.reduce((acc, p) => acc + p[k], 0) / base.length;

  const from = days[0], to = Date.now();
  const sleeps = all.filter((e) => e.type === 'sleep' && e.end > from);
  const longest = sleeps.reduce((m, e) => Math.max(m, e.end - e.start), 0);
  const feeds = all.filter((e) => (e.type === 'nurse' || e.type === 'bottle') && e.start >= from && e.start <= to).map((e) => e.start).sort((a, b) => a - b);
  const gaps = feeds.slice(1).map((t, i) => t - feeds[i]).filter((g) => g < 12 * 3600000);
  const gap = gaps.length ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
  const card = (cls, label, value) => h('div', { class: `avg ${cls}` }, h('small', {}, h('i'), label), h('b', {}, value));

  return h('div', {},
    h('div', { class: 'card' }, seg([[7, '7 days'], [14, '14 days'], [30, '30 days']], S.range, (v) => { S.range = v; render(); })),
    S.loading ? h('p', { class: 'empty' }, 'Loading older days…') : null,
    h('div', { class: 'avg-grid' },
      card('c-nurse', 'Feeds per day', trim(avg('feeds'))),
      card('c-sleep', 'Sleep per day', fmtDur(avg('sleep'))),
      card('c-nurse', 'Nursing per day', fmtDur(avg('nurse'))),
      card('c-bottle', 'Bottle per day', fmtVol(avg('bottle'))),
      card('c-sleep', 'Longest sleep', longest ? fmtDur(longest) : '–'),
      card('c-bottle', 'Time between feeds', gap ? fmtDur(gap) : '–')),
    h('p', { class: 'mute small' }, base === done && done.length ? `Averages use the ${done.length} complete day${done.length === 1 ? '' : 's'} with entries.` : 'Averages use today so far.'),
    h('section', { class: 'card' },
      h('div', { class: 'card-title' }, h('h2', {}, 'Daily rhythm')),
      patternChart(days, all),
      h('div', { class: 'legend' }, h('span', { class: 'c-sleep' }, 'Sleep'), h('span', { class: 'c-nurse' }, 'Nursing'),
        h('span', { class: 'c-bottle' }, 'Bottle'), h('span', { class: 'c-solids' }, 'Solids'))),
    chartCard('Feeds', days, [{ cls: 'f-nurse', v: per.map((p) => p.nurseN) }, { cls: 'f-bottle', v: per.map((p) => p.bottleN) }], String,
      [['c-nurse', 'Nursing'], ['c-bottle', 'Bottle']]),
    chartCard('Sleep', days, [{ cls: 'f-sleep', v: per.map((p) => p.sleep) }], (v) => trim(v / 3600000) + 'h'),
    chartCard('Nursing', days, [{ cls: 'f-nurse', v: per.map((p) => p.nurse) }], fmtDur),
    chartCard('Bottle', days, [{ cls: 'f-bottle', v: per.map((p) => p.bottle) }], (v) => fmtVol(v).replace(' ', '')));
}
function chartCard(title, days, series, fmt, legend) {
  const empty = series.every((x) => x.v.every((v) => !v));
  return h('section', { class: 'card' },
    h('div', { class: 'card-title' }, h('h2', {}, title)),
    empty ? h('p', { class: 'empty' }, 'No data in this range.') : barChart(days, series, fmt),
    legend && !empty ? h('div', { class: 'legend' }, legend.map(([cls, label]) => h('span', { class: cls }, label))) : null);
}
function barChart(days, series, fmt) {
  const W = 340, H = 150, L = 4, R = 4, T = 16, B = 20, n = days.length;
  const totals = days.map((_, i) => series.reduce((acc, x) => acc + x.v[i], 0));
  const max = Math.max(...totals) || 1, bw = (W - L - R) / n, every = Math.ceil(n / 7);
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img' },
    s('line', { x1: L, x2: W - R, y1: H - B + 0.5, y2: H - B + 0.5, class: 'axis' }));
  days.forEach((d, i) => {
    const w = Math.min(bw * 0.62, 28), x = L + i * bw + (bw - w) / 2;
    let y = H - B;
    for (const ser of series) {
      const v = ser.v[i];
      if (!v) continue;
      const ht = Math.max(2, v / max * (H - T - B));
      y -= ht;
      svg.append(s('rect', { x, y, width: w, height: ht, rx: Math.min(4, w / 3), class: ser.cls }));
    }
    if (n <= 7 && totals[i]) svg.append(s('text', { x: x + w / 2, y: y - 4, 'text-anchor': 'middle', class: 'val' }, fmt(totals[i])));
    if ((n - 1 - i) % every === 0) {
      svg.append(s('text', { x: x + w / 2, y: H - 6, 'text-anchor': 'middle' },
        n <= 7 ? fmtDate(d, { weekday: 'short' }) : fmtDate(d, { month: 'numeric', day: 'numeric' })));
    }
  });
  if (n > 7) svg.append(s('text', { x: W - R, y: T - 4, 'text-anchor': 'end', class: 'val' }, `max ${fmt(max)}`));
  return svg;
}
function patternChart(days, all) {
  const W = 340, L = 40, R = 4, T = 16, rowH = days.length > 14 ? 10 : 14, gap = days.length > 14 ? 4 : 6;
  const n = days.length, H = T + n * (rowH + gap), span = W - L - R;
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Sleep and feeds by time of day' });
  ['12a', '6a', '12p', '6p', '12a'].forEach((lbl, i) => {
    const x = L + span * i / 4;
    svg.append(s('line', { x1: x, x2: x, y1: T - 4, y2: H, class: 'grid' }));
    svg.append(s('text', { x, y: T - 6, 'text-anchor': i === 0 ? 'start' : i === 4 ? 'end' : 'middle' }, lbl));
  });
  [...days].reverse().forEach((d0, i) => {
    const d1 = dayStart(1, d0), y = T + i * (rowH + gap), X = (t) => L + (t - d0) / (d1 - d0) * span;
    svg.append(s('text', { x: 0, y: y + rowH - 2 }, i === 0 ? 'Today' : fmtDate(d0, n <= 7 ? { weekday: 'short' } : { month: 'numeric', day: 'numeric' })));
    svg.append(s('rect', { x: L, y, width: span, height: rowH, rx: 3, class: 'lane' }));
    for (const e of all) {
      const span = e.type === 'sleep' || e.type === 'nurse', end = span ? e.end ?? e.start : e.start;
      if (e.start >= d1 || end < d0 || (!span && e.start < d0)) continue;
      const a = Math.max(e.start, d0), b = Math.min(end, d1);
      if (e.type === 'sleep') svg.append(s('rect', { x: X(a), y, width: Math.max(1.5, X(b) - X(a)), height: rowH, rx: 2, class: 'f-sleep' }));
      else svg.append(s('rect', { x: X(a) - 1, y: y + 2, width: Math.max(2.5, X(b) - X(a)), height: rowH - 4, rx: 1, class: `f-${e.type}` }));
    }
  });
  return svg;
}

// ---------- Growth ----------

const Z = { p3: -1.8808, p15: -1.0364, p50: 0, p85: 1.0364, p97: 1.8808 };
const monthsOld = (birth, t) => (t - parseDate(birth)) / DAY / 30.4375;
function lms(table, age) {
  if (age < 0 || age > 24) return null;
  const i = Math.min(23, Math.floor(age)), f = age - i;
  return table[i].map((v, k) => v + (table[i + 1][k] - v) * f);
}
const lmsValue = ([L, M, Sd], z) => (L ? M * (1 + L * Sd * z) ** (1 / L) : M * Math.exp(Sd * z));
function phi(z) {
  const t = 1 / (1 + 0.2316419 * Math.abs(z)), d = 0.3989423 * Math.exp(-z * z / 2);
  const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  return z > 0 ? 1 - p : p;
}
function percentile(metric, value, at) {
  const b = baby();
  if (!b?.sex || !b?.birth) return null;
  const p = lms(WHO[`${b.sex}_${metric}`], monthsOld(b.birth, at));
  if (!p) return null;
  const [L, M, Sd] = p, z = L ? ((value / M) ** L - 1) / (L * Sd) : Math.log(value / M) / Sd;
  const pc = phi(z) * 100;
  return pc < 1 ? 'below 1st' : pc > 99 ? 'above 99th' : `${ordinal(Math.round(pc))} percentile`;
}
const METRICS = { wt: ['Weight', fmtWt], len: ['Length', fmtLen], hc: ['Head', fmtLen] };
// Display-unit conversion for chart axes.
const toDisplay = (metric, v) => (metric === 'wt' ? (units().wt === 'lb' ? v / LB : v) : (units().len === 'in' ? v / IN : v));

function viewGrowth() {
  const b = baby(), list = forBaby(S.growth).sort((x, y) => y.start - x.start);
  const latest = Object.keys(METRICS).map((m) => {
    const e = list.find((x) => x[m] != null);
    const pc = e && percentile(m, e[m], e.start);
    return h('div', { class: 'measure' }, h('small', {}, METRICS[m][0]), h('b', {}, e ? METRICS[m][1](e[m]) : '–'), pc ? h('span', {}, pc) : null);
  });
  return h('div', {},
    h('section', { class: 'card c-growth' },
      h('div', { class: 'card-title' }, h('h2', {}, 'Latest'), list[0] ? h('small', { class: 'mute' }, fmtDate(list[0].start, { month: 'short', day: 'numeric', year: 'numeric' })) : null),
      h('div', { class: 'measures' }, latest)),
    h('section', { class: 'card' },
      seg(Object.entries(METRICS).map(([k, [l]]) => [k, l]), S.metric, (v) => { S.metric = v; render(); }),
      growthChart(S.metric, list, b)),
    h('button', { class: 'btn primary block add', onclick: () => growthSheet() }, icon('plus', 20), 'Add measurement'),
    list.length ? h('section', { class: 'card' },
      h('div', { class: 'card-title' }, h('h2', {}, 'History'), h('small', { class: 'mute' }, 'Tap to edit')),
      h('ul', { class: 'list' }, list.map((e) => h('li', {}, h('button', { class: 'list-row', onclick: () => growthSheet(e) },
        h('span', {}, h('b', {}, fmtDate(e.start, { month: 'short', day: 'numeric', year: 'numeric' })),
          h('small', {}, [e.wt != null && fmtWt(e.wt), e.len != null && fmtLen(e.len), e.hc != null && `head ${fmtLen(e.hc)}`].filter(Boolean).join(' · '))),
        icon('right', 18)))))) : null);
}
function niceTicks(lo, hi, count = 5) {
  const raw = (hi - lo) / count, p = 10 ** Math.floor(Math.log10(raw)), e = raw / p;
  const step = (e >= 7.5 ? 10 : e >= 3.5 ? 5 : e >= 1.5 ? 2 : 1) * p, out = [];
  for (let v = Math.ceil(lo / step) * step; v <= hi + 1e-9; v += step) out.push(+v.toFixed(6));
  return out;
}
function growthChart(metric, list, b) {
  const wrap = h('div', { class: 'stack' });
  if (!b?.birth) { wrap.append(h('p', { class: 'empty' }, "Add a birth date in the baby's settings to see the chart.")); return wrap; }
  const table = b.sex ? WHO[`${b.sex}_${metric}`] : null;
  const pts = list.filter((e) => e[metric] != null).map((e) => ({ x: monthsOld(b.birth, e.start), y: toDisplay(metric, e[metric]) })).sort((p, q) => p.x - q.x);
  const xmax = Math.max(3, Math.ceil(Math.max(monthsOld(b.birth, Date.now()), ...pts.map((p) => p.x)) + 1));
  const curves = {};
  if (table) {
    for (const [k, z] of Object.entries(Z)) {
      curves[k] = [];
      for (let x = 0; x <= Math.min(xmax, 24) + 1e-9; x += 0.25) curves[k].push({ x, y: toDisplay(metric, lmsValue(lms(table, x), z)) });
    }
  }
  const ys = [...pts.map((p) => p.y), ...Object.values(curves).flat().map((p) => p.y)];
  if (!ys.length) { wrap.append(h('p', { class: 'empty' }, 'No measurements yet.')); return wrap; }
  let lo = Math.min(...ys), hi = Math.max(...ys);
  const padY = (hi - lo || hi || 1) * 0.08; lo -= padY; hi += padY;
  const W = 340, H = 230, L = 30, R = 6, T = 8, B = 22;
  const X = (x) => L + x / xmax * (W - L - R), Y = (y) => T + (hi - y) / (hi - lo) * (H - T - B);
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': `${METRICS[metric][0]} chart` });
  for (const v of niceTicks(lo, hi)) {
    svg.append(s('line', { x1: L, x2: W - R, y1: Y(v), y2: Y(v), class: 'grid' }));
    svg.append(s('text', { x: L - 4, y: Y(v) + 3, 'text-anchor': 'end' }, String(v)));
  }
  const xstep = xmax <= 6 ? 1 : xmax <= 12 ? 2 : xmax <= 24 ? 3 : 6;
  for (let m = 0; m <= xmax; m += xstep) svg.append(s('text', { x: X(m), y: H - 6, 'text-anchor': 'middle' }, `${m}m`));
  svg.append(s('line', { x1: L, x2: W - R, y1: H - B + 0.5, y2: H - B + 0.5, class: 'axis' }));
  const band = (lowK, highK, cls) => {
    const a = curves[lowK], c = [...curves[highK]].reverse();
    svg.append(s('path', { class: cls, d: 'M' + [...a, ...c].map((p) => `${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join('L') + 'Z' }));
  };
  if (table) {
    band('p3', 'p97', 'band-out'); band('p15', 'p85', 'band-in');
    svg.append(s('path', { class: 'median', d: 'M' + curves.p50.map((p) => `${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join('L') }));
  }
  if (pts.length > 1) svg.append(s('path', { class: 'pline', d: 'M' + pts.map((p) => `${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join('L') }));
  for (const p of pts) svg.append(s('circle', { cx: X(p.x), cy: Y(p.y), r: 3.5, class: 'pt' }));
  const unit = metric === 'wt' ? units().wt : units().len;
  wrap.append(svg, h('p', { class: 'mute small' }, table
    ? `${unit} by age. Shaded: WHO 3rd–97th and 15th–85th percentiles; dashed line is the median.`
    : `${unit} by age. Set the baby's sex in settings to compare with WHO percentiles.`));
  return wrap;
}

// ---------- Sheets ----------

const sheet = $('#sheet');
sheet.addEventListener('cancel', (ev) => { if (sheet.dataset.locked) ev.preventDefault(); });
sheet.addEventListener('click', (ev) => { if (ev.target === sheet && !sheet.dataset.locked) sheet.close(); });
function openSheet(title, body, { actions = [], locked = false } = {}) {
  const err = h('p', { class: 'err', role: 'alert' });
  sheet.replaceChildren(h('form', { class: 'sheet-inner', onsubmit: (ev) => {
    ev.preventDefault();
    (ev.submitter || sheet.querySelector('button[type=submit]'))?.action?.();
  } },
    h('div', { class: 'sheet-head' }, h('h2', { tabindex: '-1', autofocus: true }, title),
      locked ? null : h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close', onclick: () => sheet.close() }, icon('close'))),
    body, err,
    actions.filter(Boolean).length ? h('div', { class: 'sheet-actions' }, actions) : null));
  sheet.dataset.locked = locked ? '1' : '';
  if (!sheet.open) sheet.showModal();
  sheet.querySelector('.sheet-inner').scrollTop = 0;
  return (msg) => { err.textContent = msg; };
}
const closeSheet = () => sheet.close();
// Only a single text box goes inside a <label>. Safari forwards any tap inside a label to the
// first button in it, which would make the second option of a Girl/Boy switch unselectable.
function field(label, input, hint) {
  const single = input.tagName === 'INPUT' || input.classList.contains('with-unit');
  return h(single ? 'label' : 'div', { class: 'field' }, h('span', {}, label), input, hint ? h('small', {}, hint) : null);
}
// A switch like Girl/Boy. Buttons are updated in place, never rebuilt mid-tap, so the browser
// can't send the tap anywhere else.
function seg(opts, value, onchange) {
  const el = h('div', { class: 'seg', role: 'group' });
  const set = (v) => {
    el.value = v;
    buttons.forEach((b, i) => { const on = opts[i][0] === v; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
  };
  const buttons = opts.map(([v, label]) => h('button', {
    type: 'button', onclick: (ev) => { ev.preventDefault(); ev.stopPropagation(); set(v); onchange?.(v); },
  }, label));
  el.append(...buttons);
  set(value);
  return el;
}
// Day + time picker for entries: a short rolling day list ending today (iPhone shows it as a
// wheel, like the time) plus "Other date…", which opens the compact date picker in the same spot,
// so any date works without a calendar taking up the sheet.
// .value reads and writes 'YYYY-MM-DDTHH:MM', the same as a datetime-local input.
const OTHER = 'other';
const dayLabel = (o, d) => (o === 0 ? 'Today' : o === -1 ? 'Yesterday' : o === 1 ? 'Tomorrow' : fmtDate(d));
function timeInput(t) {
  const day = h('select', { 'aria-label': 'Day' }, h('option', { value: OTHER }, 'Other date…'));
  const addDay = (d) => {
    const v = toDateInput(d);
    if ([...day.options].some((o) => o.value === v)) return;
    const after = [...day.options].find((o) => o.value === OTHER || o.value > v);
    day.insertBefore(h('option', { value: v }, dayLabel(Math.round((d - dayStart(0)) / DAY), d)), after);
  };
  for (let o = -2; o <= 0; o += 1) addDay(dayStart(o));
  const date = h('input', { type: 'date', 'aria-label': 'Date', hidden: true });
  const time = h('input', { type: 'time', 'aria-label': 'Time' });
  let current = '';
  const showList = () => { date.hidden = true; day.hidden = false; day.value = current; };
  day.addEventListener('change', () => {
    if (day.value !== OTHER) { current = day.value; return; }
    date.value = current; day.hidden = true; date.hidden = false; date.focus();
    try { date.showPicker(); } catch {}
  });
  date.addEventListener('change', () => { if (date.value) { addDay(parseDate(date.value)); current = date.value; } showList(); });
  date.addEventListener('blur', () => setTimeout(() => { if (!date.hidden) showList(); }, 200));
  const el = h('div', { class: 'when' }, day, date, time);
  Object.defineProperty(el, 'value', {
    get: () => (current && time.value ? `${current}T${time.value}` : ''),
    set: (v) => { const [d, tm] = v.split('T'); addDay(parseDate(d)); current = d; day.value = d; time.value = tm; },
  });
  el.value = toLocalInput(t);
  return el;
}
const noteInput = (v) => h('input', { type: 'text', maxlength: 300, value: v || '', placeholder: 'Optional' });
const numInput = (v, step = 'any', unit = '') => {
  const input = h('input', { type: 'number', inputmode: 'decimal', min: 0, step, value: v ?? '' });
  return unit ? h('div', { class: 'with-unit' }, input, h('em', {}, unit)) : input;
};
const num = (el) => { const input = el.tagName === 'INPUT' ? el : el.querySelector('input'); const v = parseFloat(input.value); return Number.isFinite(v) ? v : null; };
const deleteButton = (e) => h('button', { type: 'button', class: 'btn danger', onclick: () => {
  if (confirm('Delete this entry?')) { removeEntry(e); closeSheet(); }
} }, 'Delete');
function submitButton(label, fn) {
  const b = h('button', { type: 'submit', class: 'btn primary' }, label);
  b.action = fn;
  return b;
}
const saveButton = (fn) => submitButton('Save', fn);
function entrySheet(e) {
  ({ nurse: nurseSheet, bottle: bottleSheet, solids: solidsSheet, sleep: sleepSheet, growth: growthSheet })[e.type](e);
}

function nurseSheet(e) {
  const start = timeInput(e?.start ?? Date.now() - 20 * 60000);
  const lm = numInput(e ? Math.round(e.l / 60000) : '', 1, 'min'), rm = numInput(e ? Math.round(e.r / 60000) : '', 1, 'min');
  const ended = seg([['L', 'Left'], ['R', 'Right']], e?.last || 'L');
  const note = noteInput(e?.note);
  let error;
  const save = () => {
    const t = fromLocalInput(start.value), l = (num(lm) || 0) * 60000, r = (num(rm) || 0) * 60000;
    if (t == null) return error('Pick a start time.');
    if (!l && !r) return error('Enter minutes for at least one side.');
    saveEntry({ ...e, type: 'nurse', baby: e?.baby ?? baby().id, start: t, end: t + l + r, l, r, last: ended.value, note: note.value.trim() });
    closeSheet();
  };
  const body = h('div', { class: 'stack' },
    field('Started', start), h('div', { class: 'row2' }, field('Left', lm), field('Right', rm)),
    field('Finished on', ended), field('Note', note));
  error = openSheet(e ? 'Edit nursing' : 'Log a past feed', body, { actions: [e && deleteButton(e), saveButton(save)] });
}

// Quick-pick amounts: the five most recent different amounts for this baby, newest first (a new
// amount pushes out the oldest), topped up with common sizes while there's little history.
function recentAmounts(oz, show) {
  const out = [];
  const bottles = forBaby(S.entries).filter((x) => x.type === 'bottle').sort((a, b) => b.start - a.start);
  for (const b of bottles) {
    const v = show(b.amt);
    if (+v > 0 && !out.includes(v)) out.push(v);
    if (out.length === 5) return out;
  }
  for (const d of oz ? ['2', '3', '4', '5', '6'] : ['60', '90', '120', '150', '180']) if (out.length < 5 && !out.includes(d)) out.push(d);
  return out;
}
function bottleSheet(e) {
  const oz = units().vol === 'oz', last = lastOf('bottle'), unit = oz ? 'oz' : 'ml';
  const show = (ml) => (oz ? trim(ml / OZ) : String(Math.round(ml)));
  const amount = numInput(e ? show(e.amt) : last ? show(last.amt) : '', oz ? 0.5 : 5, unit);
  const input = amount.querySelector('input');
  const presets = recentAmounts(oz, show);
  const mark = () => chips.querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', c.dataset.v === String(+input.value)));
  const chips = h('div', { class: 'chips' }, presets.map((p) => h('button', {
    type: 'button', class: 'chip', 'data-v': p, onclick: () => { input.value = p; mark(); },
  }, `${p} ${unit}`)));
  input.addEventListener('input', mark);
  mark();
  const milk = seg([['breast', 'Breast milk'], ['formula', 'Formula']], e?.milk || last?.milk || 'breast');
  const time = timeInput(e?.start ?? Date.now()), note = noteInput(e?.note);
  let error;
  const save = () => {
    const t = fromLocalInput(time.value), v = num(amount);
    if (t == null) return error('Pick a time.');
    if (!v || v <= 0) return error('Enter an amount.');
    saveEntry({ ...e, type: 'bottle', baby: e?.baby ?? baby().id, start: t, amt: +(oz ? v * OZ : v).toFixed(1), milk: milk.value, note: note.value.trim() });
    closeSheet();
  };
  error = openSheet(e ? 'Edit bottle' : 'Bottle', h('div', { class: 'stack' },
    field('Amount', amount), chips, field('Milk', milk), field('Time', time), field('Note', note)),
  { actions: [e && deleteButton(e), saveButton(save)] });
}

function solidsSheet(e) {
  const food = h('input', { type: 'text', maxlength: 120, value: e?.food || '', placeholder: 'e.g. mashed banana' });
  const time = timeInput(e?.start ?? Date.now()), note = noteInput(e?.note);
  let error;
  const save = () => {
    const t = fromLocalInput(time.value);
    if (t == null) return error('Pick a time.');
    if (!food.value.trim()) return error('What did they eat?');
    saveEntry({ ...e, type: 'solids', baby: e?.baby ?? baby().id, start: t, food: food.value.trim(), note: note.value.trim() });
    closeSheet();
  };
  error = openSheet(e ? 'Edit solids' : 'Solids', h('div', { class: 'stack' }, field('Food', food), field('Time', time), field('Note', note)),
    { actions: [e && deleteButton(e), saveButton(save)] });
}

function sleepSheet(e) {
  const start = timeInput(e?.start ?? Date.now() - 3600000), end = timeInput(e?.end ?? Date.now()), note = noteInput(e?.note);
  let error;
  const save = () => {
    const a = fromLocalInput(start.value), b = fromLocalInput(end.value);
    if (a == null || b == null) return error('Pick both times.');
    if (b <= a) return error('Wake-up must be after falling asleep.');
    if (b - a > DAY) return error('That is longer than 24 hours. Check the dates.');
    saveEntry({ ...e, type: 'sleep', baby: e?.baby ?? baby().id, start: a, end: b, note: note.value.trim() });
    closeSheet();
  };
  error = openSheet(e ? 'Edit sleep' : 'Log a past sleep', h('div', { class: 'stack' },
    field('Fell asleep', start), field('Woke up', end), field('Note', note)),
  { actions: [e && deleteButton(e), saveButton(save)] });
}

function timerStartSheet(t) {
  const first = t.kind === 'nurse' ? t.segs[0].a : t.start;
  const input = timeInput(first);
  let error;
  const save = () => {
    const v = fromLocalInput(input.value), limit = t.kind === 'nurse' ? (t.segs[0].b ?? Date.now()) : Date.now();
    if (v == null || v >= limit) return error('The start has to be before now.');
    saveTimer(t.kind === 'nurse' ? { ...t, segs: [{ ...t.segs[0], a: v }, ...t.segs.slice(1)] } : { ...t, start: v });
    closeSheet();
  };
  error = openSheet('Change start time', h('div', { class: 'stack' }, field('Started', input)), { actions: [saveButton(save)] });
}

function growthSheet(e) {
  const imperialWt = units().wt === 'lb', imperialLen = units().len === 'in';
  let lbIn, ozIn, kgIn;
  if (imperialWt) {
    const total = e?.wt != null ? e.wt / LB * 16 : null;
    lbIn = numInput(total != null ? Math.floor(total / 16) : '', 1, 'lb');
    ozIn = numInput(total != null ? trim(total - Math.floor(total / 16) * 16) : '', 'any', 'oz');
  } else kgIn = numInput(e?.wt != null ? trim(e.wt, 3) : '', 'any', 'kg');
  const lenUnit = imperialLen ? 'in' : 'cm', toLen = (v) => (v == null ? '' : trim(imperialLen ? v / IN : v, 2));
  const len = numInput(toLen(e?.len), 'any', lenUnit), hc = numInput(toLen(e?.hc), 'any', lenUnit);
  const date = h('input', { type: 'date', value: toDateInput(e?.start ?? Date.now()) }), note = noteInput(e?.note);
  let error;
  const save = () => {
    if (!date.value) return error('Pick a date.');
    let wt = null;
    if (imperialWt) { const lb = num(lbIn), oz = num(ozIn); if (lb != null || oz != null) wt = ((lb || 0) * 16 + (oz || 0)) / 16 * LB; }
    else wt = num(kgIn);
    const cm = (v) => (v == null ? null : imperialLen ? v * IN : v);
    const out = { wt, len: cm(num(len)), hc: cm(num(hc)) };
    for (const k of Object.keys(out)) out[k] = out[k] > 0 ? +out[k].toFixed(3) : null;
    if (!out.wt && !out.len && !out.hc) return error('Enter at least one measurement.');
    saveEntry({ ...e, type: 'growth', baby: e?.baby ?? baby().id, start: parseDate(date.value) + 12 * 3600000, ...out, note: note.value.trim() });
    closeSheet();
  };
  error = openSheet(e ? 'Edit measurement' : 'Add measurement', h('div', { class: 'stack' },
    field('Date', date),
    imperialWt ? field('Weight', h('div', { class: 'row2' }, lbIn, ozIn)) : field('Weight', kgIn),
    h('div', { class: 'row2' }, field('Length', len), field('Head', hc)),
    field('Note', note)),
  { actions: [e && deleteButton(e), saveButton(save)] });
}

function babySheet(b) {
  const name = h('input', { type: 'text', maxlength: 40, value: b?.name || '', placeholder: 'Name', autocomplete: 'off' });
  const birth = h('input', { type: 'date', value: b?.birth || '' });
  const sex = seg([['f', 'Girl'], ['m', 'Boy']], b?.sex || null);
  let error;
  const save = async () => {
    if (!name.value.trim()) return error('Add a name.');
    const profile = { name: name.value.trim(), birth: birth.value || null, sex: sex.value || null };
    if (b) { saveProfile(b, profile); closeSheet(); return; }
    error('Saving…');
    try { await createBaby(profile); closeSheet(); } catch (err) { error(authProblem(err)); }
  };
  error = openSheet(b ? `Edit ${b.name}` : 'Add a baby', h('div', { class: 'stack' },
    field('Name', name), field('Birth date', birth), field('Sex', sex, 'Used only to pick the right WHO growth chart.'),
    b ? peopleSection(b) : h('p', { class: 'mute small' }, 'Only you can see a new baby until you share it with someone’s username.')),
  { actions: [saveButton(save)] });
}
// Who can see this baby. Anyone linked can add people; the person who added the baby can remove
// people; everyone can remove themselves.
function peopleSection(b) {
  const owner = b.owner === S.uid;
  const who = h('input', { type: 'text', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', placeholder: 'Their username' });
  const msg = h('p', { class: 'err', role: 'alert' });
  const add = h('button', { type: 'button', class: 'btn secondary', onclick: async () => {
    if (!who.value.trim()) return;
    add.disabled = true; msg.textContent = '';
    try {
      await linkUser(b, who.value);
      toast(`${normUser(who.value)} can now see ${b.name}`);
      who.value = '';
      list.replaceChildren(...rows());
    } catch (err) { msg.textContent = authProblem(err); }
    add.disabled = false;
  } }, 'Share');
  const rows = () => b.members.map((m) => h('li', {}, h('div', { class: 'list-row' },
    h('span', {}, h('b', {}, m.uid === S.uid ? `${m.u} (you)` : m.u), m.uid === b.owner ? h('small', {}, 'Added this baby') : null),
    (m.uid === S.uid ? b.members.length > 1 && !owner : owner) ? h('button', { type: 'button', class: 'link danger-text', onclick: async () => {
      const self = m.uid === S.uid;
      if (!confirm(self ? `Stop seeing ${b.name}? Someone will have to share it with you again.` : `Remove ${m.u}? They will no longer see ${b.name}.`)) return;
      try { await unlinkUser(b, m); if (self) closeSheet(); else { b.members = b.members.filter((x) => x.uid !== m.uid); list.replaceChildren(...rows()); } } catch (err) { msg.textContent = authProblem(err); }
    } }, m.uid === S.uid ? 'Leave' : 'Remove') : null)));
  const list = h('ul', { class: 'list' }, rows());
  return h('div', { class: 'stack' },
    h('h3', {}, `People who can see ${b.name}`), list,
    h('div', { class: 'share-row' }, who, add), msg);
}
function babySwitcher() {
  const pick = (b) => { selectBaby(b.id); closeSheet(); render(); };
  openSheet('Babies', h('div', { class: 'stack' },
    S.settings.babies.length ? h('ul', { class: 'list' }, S.settings.babies.map((b) => h('li', {},
      h('button', { type: 'button', class: 'list-row', onclick: () => pick(b) },
        h('span', {}, h('b', {}, b.name || '…'), b.birth ? h('small', {}, ageText(b.birth)) : null),
        b.id === baby()?.id ? '✓' : icon('right', 18)))))
      : h('p', { class: 'mute' }, 'No babies yet.'),
    baby() ? h('button', { type: 'button', class: 'btn secondary', onclick: () => babySheet(baby()) }, `Edit ${baby().name}'s details`) : null,
    h('button', { type: 'button', class: 'btn secondary', onclick: () => babySheet() }, 'Add a baby'),
    h('p', { class: 'mute small' }, `To see a baby someone else added, ask them to share it with your username: ${S.me}.`)));
}
function welcome() {
  return h('section', { class: 'card stack' },
    h('h2', {}, `Welcome, ${S.me}`),
    h('p', {}, 'Add your baby to start tracking.'),
    h('button', { class: 'btn primary block', onclick: () => babySheet() }, icon('plus', 20), 'Add a baby'),
    h('p', { class: 'mute small' }, 'Is someone else already tracking your baby in Cradle? Ask them to open the baby’s settings and share it with your username:'),
    h('p', { class: 'code' }, S.me));
}

function settingsSheet() {
  const un = (k, v) => { S.settings.units = { ...S.settings.units, [k]: v }; ls.set('units', JSON.stringify(S.settings.units)); render(); };
  const theme = seg([['auto', 'Auto'], ['light', 'Light'], ['dark', 'Dark']], ls.get('theme', 'auto'), (v) => { ls.set('theme', v); applyTheme(); });
  const st = S.settings;
  openSheet('Settings', h('div', { class: 'stack' },
    h('p', { class: 'mute small' }, `Logged in as ${S.me}`),
    h('h3', {}, 'Babies'),
    st.babies.length ? h('ul', { class: 'list' }, st.babies.map((b) => h('li', {}, h('button', { type: 'button', class: 'list-row', onclick: () => babySheet(b) },
      h('span', {}, h('b', {}, b.name || '…'), h('small', {}, `${b.members.length} ${b.members.length === 1 ? 'person' : 'people'} can see ${b.sex === 'm' ? 'him' : b.sex === 'f' ? 'her' : 'this baby'}`)),
      icon('right', 18))))) : null,
    h('button', { type: 'button', class: 'btn secondary', onclick: () => babySheet() }, 'Add a baby'),
    h('h3', {}, 'Units · this phone'),
    h('div', { class: 'row2' }, field('Volume', seg([['oz', 'oz'], ['ml', 'ml']], st.units.vol, (v) => un('vol', v))),
      field('Weight', seg([['lb', 'lb'], ['kg', 'kg']], st.units.wt, (v) => un('wt', v)))),
    field('Length', seg([['in', 'in'], ['cm', 'cm']], st.units.len, (v) => un('len', v))),
    field('Appearance', theme),
    h('h3', {}, 'Privacy & data'),
    h('p', { class: 'mute small' }, 'Everything about your babies is encrypted on this phone before it syncs. The server only stores scrambled data; only people you share a baby with can read it.'),
    h('button', { type: 'button', class: 'btn secondary', onclick: passwordSheet }, 'Change my password'),
    baby() ? h('button', { type: 'button', class: 'btn secondary', onclick: exportData }, `Export a backup of ${baby().name}`) : null,
    baby() ? h('button', { type: 'button', class: 'btn secondary', onclick: importData }, `Restore a backup into ${baby().name}`) : null,
    h('button', { type: 'button', class: 'btn danger', onclick: signOutDevice }, 'Log out on this phone')));
}

function passwordSheet() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Current password' });
  const n1 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: `At least ${MIN_PW} characters` });
  const n2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Type it again' });
  const shown = h('p', { class: 'code', hidden: true });
  let error;
  const go = submitButton('Change password', async () => {
    if (n1.value.length < MIN_PW) return error(`Use at least ${MIN_PW} characters.`);
    if (n1.value !== n2.value) return error("The new passwords don't match.");
    if (!navigator.onLine) return error('Changing the password needs a connection.');
    go.disabled = true; go.textContent = 'Changing…'; error('');
    try {
      await changePassword(cur.value, n1.value);
      closeSheet();
      toast('Password changed. Your other phones will ask you to log in again.');
    } catch (err) {
      error(authProblem(err));
      go.disabled = false; go.textContent = 'Change password';
    }
  });
  error = openSheet('Change my password', h('div', { class: 'stack' },
    h('p', { class: 'mute small' }, 'Your other phones will ask you to log in again within about an hour. Nobody else is affected.'),
    field('Current password', cur), field('New password', n1), n2,
    h('button', { type: 'button', class: 'btn secondary', onclick: () => { const p = genPassword(); n1.value = n2.value = p; shown.textContent = p; shown.hidden = false; } }, 'Suggest a strong password'),
    shown),
  { actions: [go] });
}
// Order matters: the new wrap is stored next to the old one before Auth changes, so whichever
// password Auth ends up accepting can still unwrap the private key if a step fails midway.
async function changePassword(oldPw, newPw) {
  const [oldKeys, newKeys] = [await deriveKeys(S.me, oldPw), await deriveKeys(S.me, newPw)];
  const data = (await getDoc(userRef())).data();
  let pkcs8 = await unwrapPrivate(data.priv, oldKeys), current = data.priv;
  if (!pkcs8) { pkcs8 = await unwrapPrivate(data.prevPriv, oldKeys); current = data.prevPriv; }
  if (!pkcs8) throw userError('The current password is wrong.');
  await reauthenticateWithCredential(auth.currentUser, EmailAuthProvider.credential(emailFor(S.me), oldKeys.auth));
  await updateDoc(userRef(), { priv: await wrapPrivate(pkcs8, newKeys), prevPriv: current });
  await updatePassword(auth.currentUser, newKeys.auth);
  await updateDoc(userRef(), { prevPriv: deleteField() });
}

async function exportData() {
  if (!confirm('The backup file is NOT encrypted. Keep it somewhere private. Continue?')) return;
  try {
    const b = baby();
    const decode = async (col) => {
      const out = [];
      for (const d of (await getDocs(colRef(col))).docs) {
        try { out.push({ ...(await unseal(d.data(), `${col}/${d.id}`)), id: d.id }); } catch {}
      }
      return out;
    };
    const data = { app: 'cradle', version: 3, exported: new Date().toISOString(),
      baby: { name: b.name, birth: b.birth, sex: b.sex }, entries: await decode('entries'), growth: await decode('growth') };
    const file = new File([JSON.stringify(data, null, 1)], `cradle-${b.name.toLowerCase().replace(/\W+/g, '-')}-${toDateInput(Date.now())}.json`, { type: 'application/json' });
    if (navigator.canShare?.({ files: [file] })) {
      await navigator.share({ files: [file] }).catch(() => {});
    } else {
      const a = h('a', { href: URL.createObjectURL(file), download: file.name });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    }
  } catch (err) { fail(err); }
}
function importData() {
  const input = h('input', { type: 'file', accept: 'application/json,.json' });
  input.addEventListener('change', async () => {
    try {
      const b = baby(), data = JSON.parse(await input.files[0].text());
      if (data?.app !== 'cradle' || !Array.isArray(data.entries)) throw new Error('This is not a Cradle backup file.');
      const valid = (e) => e && typeof e.id === 'string' && /^[\w-]{1,40}$/.test(e.id) && CAT[e.type] && Number.isFinite(e.start);
      const entries = data.entries.filter(valid), growth = (data.growth || []).filter(valid);
      if (!confirm(`Restore ${entries.length} entries and ${growth.length} measurements into ${b.name}? Entries that already exist are overwritten with the backup's version.`)) return;
      const all = [...entries.map((e) => ['entries', e]), ...growth.map((e) => ['growth', e])];
      for (let i = 0; i < all.length; i += 400) {
        const batch = writeBatch(db);
        for (const [col, { id, ...rest }] of all.slice(i, i + 400)) {
          const payload = { ...rest, baby: b.id };
          batch.set(docRef(col, id), { d: dayNum(payload.start), v: 1, ...(await seal(payload, `${col}/${id}`)) });
          (col === 'growth' ? S.growth : S.entries).set(id, { ...payload, id });
        }
        await batch.commit();
      }
      closeSheet(); render();
      toast(`Restored ${all.length} items.`);
    } catch (err) { fail(err); }
  });
  input.click();
}
async function signOutDevice() {
  if (!confirm('Log out on this phone? You will need your username and password to log back in.')) return;
  S.busy = true;
  stopSync();
  await dropUser();
  await signOut(auth).catch(() => {});
  await terminate(db).catch(() => {});
  await clearIndexedDbPersistence(db).catch(() => {});
  location.reload();
}

// ---------- Boot ----------

function applyTheme() {
  const t = ls.get('theme', 'auto');
  if (t === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}
applyTheme();
setInterval(tick, 1000);
setInterval(() => { if (!sheet.open) render(); }, 60000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) render(); });
addEventListener('online', updateSync);
addEventListener('offline', updateSync);
if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});

// Stay logged in: Firebase keeps the session and the private key stays on this phone, so the app
// opens straight in until someone logs out here or the password is changed on another phone.
async function boot() {
  if (!configured) return showLock();
  const rec = await loadUser();
  if (rec) Object.assign(S, { me: rec.name, uid: rec.uid, pub: rec.pub, priv: rec.priv });
  onAuthStateChanged(auth, async (user) => {
    if (S.busy) return;               // login()/signup() finish the job themselves
    if (user && S.priv && user.uid === S.uid) return enterApp();
    if (user) { await signOut(auth); return; }   // a session without a key on this phone: start over
    if (S.priv) {
      const name = S.me;
      await dropUser();
      Object.assign(S, { me: null, uid: null, pub: null, priv: null });
      return showLock('login', 'You were logged out, probably because your password was changed on another phone.', name);
    }
    showLock('login');
  });
}
boot();
