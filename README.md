# 🔐 Vault — Encrypted Password Manager

A fully encrypted, offline-first password manager built as a Progressive Web App (PWA). No servers. No accounts. No ads. Your data never leaves your device.

---

## ✨ Features

### 🔐 Security
- **AES-256-GCM encryption** — every entry is encrypted using military-grade AES-256 via the Web Crypto API
- **PBKDF2 key derivation** — your master password is stretched with 200,000 iterations of SHA-256 before use
- **Master password** — single password protects your entire vault; wrong password = no access
- **6-digit PIN lock** — set a quick PIN as a shortcut to unlock instead of typing your full password
- **Biometric unlock** — use your fingerprint to unlock on supported devices
- **Auto-lock** — vault automatically locks after a period of inactivity (15s, 30s, 1min, 5min, 10min, 30min, 1hr)
- **Failed login lockout** — after 5 wrong attempts, the vault locks for a configurable duration (5min, 15min, 30min, 1hr, 6hrs, 12hrs, or 1Day) to protect against brute force attacks. Toggle on/off in Settings
- **Password breach check** — checks passwords against the HaveIBeenPwned database using k-anonymity (your password is never sent)
- **Password strength meter** — live visual indicator as you type

### 🗂 Vault
- **5 entry types** — Login, Card, Wi-Fi, Note, Other
- **Folders** — organise entries into custom folders like Work, Banking, Personal
- **Tags** — add multiple tags to entries for flexible filtering
- **Favourites** — star important entries to surface them quickly
- **Archive** — hide entries from the main vault without deleting them
- **Sort options** — sort by most recent, name A–Z, or favourites first
- **Search** — search across name, username, URL, folder, and tags instantly
- **Recently used** — quick access to your last 5 opened entries

### 🔑 Password Tools
- **Password generator** — one-tap strong password generation (16 chars, mixed case, numbers, symbols)
- **TOTP / 2FA codes** — generate time-based one-time passwords right inside the app with a live countdown timer
- **Password history** — view up to 10 previous passwords for each entry
- **Password expiry** — set an expiry date on passwords; expired ones are flagged automatically
- **Copy to clipboard** — tap to copy username, password, or URL instantly

### 🛡 Security Audit
- **Security score** — overall vault health score out of 100
- **Issue detection** — flags weak, short, reused, and expired passwords
- **Live stats** — see total entries, how many have 2FA, images, favourites, and more

### 💾 Backup & Restore
- **Export backup** — download an encrypted `.json` backup file protected by a separate backup password
- **Import backup** — restore from a backup file; choose to merge with existing entries or replace the vault entirely
- **Backup is portable** — send your backup file via WhatsApp, email, or Google Drive and restore on any device

### 🖼 Images
- **Attach images** to any entry — screenshots, card photos, documents
- **Auto-compression** — images are compressed to max 1200px / JPEG 75% before saving to keep storage small
- **Lightbox viewer** — tap any attached image to view it full screen

### 👆 Long-Press Quick Actions
Hold any entry for half a second to get a quick action sheet:
- ✏️ Edit
- ⭐ Favourite / Unfavourite
- 📦 Archive / Unarchive
- 🗑 Delete

### 🎨 Experience
- **Dark & Light theme** — toggle in Settings
- **PWA installable** — installs on your home screen on Android and iOS
- **Offline-first** — works with no internet connection after first load
- **Mobile-first design** — built for phone screens with touch-friendly interactions

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + Vite |
| Encryption | Web Crypto API (AES-256-GCM + PBKDF2) |
| Storage | IndexedDB (no size limits) |
| PWA | vite-plugin-pwa + Workbox |
| Hosting | Vercel |
| Styling | Plain CSS (no UI library) |
| Fonts | Space Grotesk + JetBrains Mono |

---

## 📁 Project Structure

```
vault-app/
├── public/
│   ├── icon.svg
│   ├── icon-72x72.png
│   ├── icon-96x96.png
│   ├── icon-128x128.png
│   ├── icon-144x144.png
│   ├── icon-152x152.png
│   ├── icon-192x192.png
│   ├── icon-384x384.png
│   ├── icon-512x512.png
│   └── icon-maskable-512x512.png
├── src/
│   ├── main.jsx
│   └── App.jsx
├── index.html
├── vite.config.js
├── package.json
└── README.md
```

---

## 🚀 Deploying Your Own Copy

### Prerequisites
- A [GitHub](https://github.com) account
- A [Vercel](https://vercel.com) account (free)

### Steps

**1. Fork or create a new repository**

Create a new GitHub repository and upload all project files maintaining the folder structure above.

**2. Deploy to Vercel**

- Go to [vercel.com](https://vercel.com)
- Click **Add New Project**
- Import your GitHub repository
- Vercel auto-detects Vite — no settings to change
- Click **Deploy**

Your app will be live at `https://your-repo-name.vercel.app` within about a minute.

**3. Install on your phone**

*Android (Chrome):*
1. Open your Vercel URL in Chrome
2. Tap the 3-dot menu → **Add to Home Screen**
3. Tap **Add**

*iPhone (Safari):*
1. Open your Vercel URL in Safari
2. Tap the Share button
3. Tap **Add to Home Screen**
4. Tap **Add**

**4. Generate an APK (optional)**

1. Go to [pwabuilder.com](https://pwabuilder.com)
2. Enter your Vercel URL
3. Tap **Package for stores → Android**
4. Download and install the `.apk`

---

## 🔒 Security Model

| What is stored | Where | Encrypted? |
|---|---|---|
| Vault entries | IndexedDB | ✅ AES-256-GCM |
| Images | IndexedDB (inside entry) | ✅ AES-256-GCM |
| Password history | IndexedDB | ✅ AES-256-GCM |
| Backup file | Your device / cloud | ✅ AES-256-GCM (separate key) |
| Salt | localStorage | Plaintext (not sensitive) |
| Verifier token | localStorage | ✅ AES-256-GCM |
| Settings | localStorage | Plaintext (no passwords) |

**Your master password is never stored anywhere.** It is used to derive an encryption key in memory and then discarded. If you forget your master password, your data cannot be recovered — there is no reset mechanism by design.

---

## ⚠️ Important Notes

- **Backup regularly** — your vault lives on your device. If you clear your browser data or uninstall the app, your vault will be deleted. Always keep an exported backup saved somewhere safe.
- **Remember your master password** — there is no password recovery. If you forget it, the vault cannot be opened.
- **Remember your backup password** — the backup file is encrypted with a separate password you choose at export time. Keep it somewhere safe.
- **This app is not a replacement for a professional password manager** if you need enterprise-grade features like team sharing, cloud sync, or account recovery.

---

## 📄 License

MIT — free to use, modify, and distribute.

---

*Built with ❤️ using React, Web Crypto API, and IndexedDB.*
