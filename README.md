# Server Toolkit

A **secure, single-file PHP toolkit** that bundles essential **server diagnostics and maintenance tools** into one auditable file.

No frameworks. No dependencies. No shell access.  
Built for **quick debugging, emergency access, and shared hosting environments**.

www.mehranshahmiri.com

---

## 🧰 Included Tools

### ✅ Enabled by Default (Safe)
- **Server Health** – CPU, RAM, disk, uptime, OS, PHP info
- **Network / IP Debug** – Client IP, headers, IPv4/IPv6
- **SSL Inspector** – Certificate expiry, issuer, validity
- **Environment Viewer** – PHP ini & server vars (secrets masked)

### ⚠️ Disabled by Default (Feature-Gated)
- **File Manager & Editor** – Text files only
- **Log Viewer** – Read-only, whitelisted paths
- **Backup Tool** – Zip site files (optional DB export)
- **Permissions Inspector** – Detect common permission issues
- **Database Viewer** – SQLite / MySQL (read-only)
- **Emergency Recovery Panel** – Safe preset fixes

---

## 🔐 Security First

Server Toolkit is designed to be **safe by default**:

- Single-file architecture (easy to audit & delete)
- Password-protected access
- Hard `BASE_PATH` restriction
- No shell execution or system calls
- CSRF protection for all write actions
- XSS-safe output escaping
- Login rate limiting
- Optional IP allowlist
- Dangerous tools must be explicitly enabled

> This is a **utility toolkit**, not a hosting control panel.

---

## 🚀 Installation

1. Upload `server-toolkit.php` to your server
2. Open in your browser: https://yourdomain[dot]com/server-toolkit.php
3. Set a strong password inside the file
4. Enable only the tools you need
5. Delete the file when finished

---

## 🛠 Requirements

- PHP 7.4+
- Linux server (shared hosting or VPS)
- Standard file permissions

---

## ❌ What This Tool Will Never Do

- Execute shell commands
- Run arbitrary PHP code
- Modify system users
- Break out of `BASE_PATH`
- Act as a persistent backdoor

If you need those, this is **not** the right tool.

---

## 📦 Ideal Use Cases

- Emergency production debugging
- Shared hosting without SSH
- Quick server audits
- Mobile-friendly server access
- Teaching & demonstrations

---

## 🧹 Cleanup & Best Practices

- Disable dangerous tools when not in use
- Use strong passwords
- Restrict by IP if possible
- **Delete the file after work is done**

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## ❤️ Philosophy

Minimal surface area.  
Maximum usefulness.  
Nothing that shouldn’t exist forever.
