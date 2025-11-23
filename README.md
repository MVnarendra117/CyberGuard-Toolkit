CyberGuard-Toolkit

<img width="1918" height="935" alt="image" src="https://github.com/user-attachments/assets/02610979-280d-44bd-ac42-24c39d3ee71d" />

Live preview - https://magenta-macaron-e7dbc8.netlify.app/

-----------------------------------------------------------------------------------

Features-

URL security scanner (simulated)

File malware scan simulation

Cryptography toolkit

Hash generation (Web Crypto API)

Hash identification

Base64 encode / decode

Steganography (LSB image hiding + extraction)

Password strength checker with suggestions

Responsive UI using Tailwind CSS

Lucide icons for UI affordances

-----------------------------------------------------------------------------------

Tech Stack-

React (functional components + hooks)

Tailwind CSS

Vite (dev build tooling)

Browser Web Crypto API (crypto.subtle)

Lucide React icons

-----------------------------------------------------------------------------------

Requirements-

Node.js (v16+ recommended)

npm or yarn

Modern browser (for crypto.subtle and canvas APIs)

-----------------------------------------------------------------------------------

Usage Notes-

Hashing: Uses browser crypto.subtle.digest for supported algorithms (SHA family). MD5 / MD4 / MD2 are not supported by crypto.subtle.

Steganography: LSB-based text hiding modifies image data in the browser. Keep messages short; large messages will fail due to capacity limits. The code uses a simple EOF sentinel (1111111111111110) to mark message end.

File scanning: Simulated only — no real malware scanning happens client-side.

Base64: Uses btoa / atob — these are not safe for arbitrary Unicode without proper encoding/decoding.

-----------------------------------------------------------------------------------

Security & Ethical Notice-

This project is educational. Do not use the steganography or simulated scanning features to perform covert or malicious activities.

Do not attempt to scan other people's systems without explicit permission.

The app does not provide production-grade malware detection or real threat intelligence.
