# HostelGrievance 🛡️
Centralized & Hardened University Hostel Grievance Portal
HostelGrievance is a secure, high-performance, and production-ready grievance management platform. It allows university students to securely sign in, submit, track, and comment on grievances, and attach files, while wardens can manage complaints, communicate with students, and update grievance status.

Unlike standard student portals which are highly vulnerable to basic hacks, HostelGrievance is hardened to enterprise standards, utilizing a defense-in-depth security model at the browser, network, application, and database layers.

# 🚀 Quick Start & Installation
1. Install Node Modules
Ensure you have Node.js installed, then run the following command in the project root to install all required dependencies:

# bash

npm install
2. Initialize and Seed Database
Reset and seed the SQLite database with default test accounts, sample grievances, comments, and attachments:

# bash

npm run db:reset
Note: A security warning will alert you to define environment variables for production passwords. This is normal.

3. Run the Project
To start both the frontend interface and the backend API server concurrently:

# bash

npm run dev:all
Frontend UI (Svelte 5 / Vite): Typically runs at http://localhost:5173 (check your terminal output for exact port)
Backend API (Hono Server): Runs at http://127.0.0.1:3001
4. Running Tests & Code Check
Verify the code structure and run the automated security/behavior checks:

# bash

# Verify TypeScript compilation
npm run typecheck
# Run the 28 automated tests (Vitest)
npm run test
🔐 Deploy-Ready Login Credentials
The system has been seeded with secure, GIET-branded login credentials instead of weak example strings:
# Student mail-	student.portal@giet.edu
# Password- GIET_Student_2026!
# Warden Email-	warden.portal@giet.edu	
# Password: GIET_Warden_2026!
Additional Seeded Students:
Priya Nair: priya.nair@giet.edu (Password: GIET_Student_2026!)
Rohan Das: rohan.das@giet.edu (Password: GIET_Student_2026!)
🛡️ Enterprise Security Hardening Features
HostelGrievance incorporates advanced security protections that mitigate the OWASP Top 10 vulnerabilities:

Multi-Layered Access Controls (IDOR Defense): Grievance details, comments, and attachments are strictly validated on the backend. A student cannot read, edit, or append comments to another student's complaints, even if they alter browser URLs or API requests.

CSRF Origin & Referer Verification: Prevents Cross-Site Request Forgery by verifying both the Origin and Referer headers for all mutating (POST, PATCH, DELETE) requests, blocking unauthorized third-party actions.

Strict Transport Security (HSTS): Response headers enforce SSL/TLS globally (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload) so browsers always connect securely.

Automatic HTTP-to-HTTPS Redirection: Built-in server middleware automatically detects unencrypted traffic (using X-Forwarded-Proto) and redirects users to secure https:// URLs in production.

Hashed Session Storage: Active session tokens are stored hashed (SHA-256) in the database and mapped via HttpOnly, SameSite=Lax, and Secure cookies. If the database file is compromised, session hijacking is impossible.

Secure Client IP Verification: IP addresses are resolved directly via network socket mapping (@hono/node-server/conninfo) rather than trusting user-controllable forwarded headers, rendering spoofing attacks obsolete.

Upload File Malware Signature Check: Prevents polyglot malware uploads (scripts masked inside image metadata) by scanning uploaded file binary buffers for execution tags like <?php, <?=, and <script>.

# Why This Project
This project goes far beyond typical university portal designs. Here is why it stands out:

# Cryptographically Secure Random IDs: 
Most systems use sequential IDs (GRV-0001, GRV-0002), which allows malicious crawling and scraping. HostelGrievance uses cryptographically secure random identifiers (e.g., GRV-A4C8F1B9), completely eliminating resource enumeration.

# OOM-Immune Memory Limiters: 
Standard memory-based rate limiters will crash a server (Out of Memory Denial of Service) if flooded by unique IP addresses. Our custom rate limiter implements LRU (Least Recently Used) size-bound eviction (capped at 10,000 entries), keeping the memory footprint completely flat and secure.

# Centralized Cloud-Native Logging:
Audit logs are simultaneously written to local storage and outputted to standard console (stdout) as structured JSON. This makes the application immediately ready for enterprise log-shippers (like Fluentd, Logstash, AWS CloudWatch, Datadog) to aggregate log records off-server securely.

# Sandboxed Attachment Rendering:
Attached files are renamed to randomized 128-bit hashes on disk, and served with X-Content-Type-Options: nosniff and sandboxed Content-Security-Policy: default-src 'none'; sandbox headers. Even if a script somehow gets uploaded, the browser is completely locked down from executing it.
