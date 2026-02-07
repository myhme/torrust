# Security Policy

## Supported Versions

Torrust is currently developed as a **single active release line**.

Only the **latest released version** is supported with security updates.

| Version            | Supported |
|--------------------|-----------|
| Latest release     | ✅ Yes    |
| Older releases     | ❌ No     |
| Development builds | ❌ No     |

Users are strongly encouraged to run the latest release and keep dependencies up to date.

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Torrust, **please report it responsibly**.

### 📫 How to Report

Please report vulnerabilities **privately** using one of the following methods:

- **GitHub Security Advisories** (preferred)  
  Open a private security advisory for this repository.

- **Email (if GitHub advisories are unavailable)**  
  Contact the maintainer directly at:  
  **`security@<your-domain-or-github-username>`**

> ⚠️ **Do not open public GitHub issues for security vulnerabilities.**

---

## 📋 What to Include

To help us assess and fix the issue quickly, please include:

- A clear description of the vulnerability
- Affected versions or commit hash
- Steps to reproduce (if applicable)
- Impact assessment (what could an attacker gain?)
- Any relevant logs or proof-of-concept code

---

## ⏱️ Response Timeline

We aim to follow this general process:

- **Acknowledgement:** within 72 hours  
- **Initial assessment:** within 7 days  
- **Fix or mitigation:** as soon as reasonably possible

Timelines may vary depending on complexity and severity.

---

## 🔒 Scope of Security Issues

This security policy covers issues related to:

- Remote code execution
- Privilege escalation
- Information disclosure
- Tor / network isolation bypass
- DNS or proxy leakage
- Memory safety issues
- Container hardening regressions

This policy **does not** cover:

- Browser fingerprinting
- Misuse of Tor or SOCKS proxies
- Threats outside the documented threat model
- Issues caused by insecure host systems

---

## 🤝 Responsible Disclosure

We follow **responsible disclosure** practices:

- Please give us reasonable time to investigate and patch
- Coordinated disclosure is encouraged
- Credit will be given if desired

---

## 🧠 Important Note

Torrust is a **privacy and anonymity support tool**, not a complete anonymity solution.

Security depends on:

- Correct deployment
- Host system hardening
- User behavior
- Up-to-date dependencies

No software can guarantee anonymity on its own.

---

## 📜 License

This project is licensed under the MIT License.  
Security reports do not change licensing terms.
