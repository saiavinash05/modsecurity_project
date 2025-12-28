# ModSecurity WAF Hardening on Legacy Web Application (DVWA) using OWASP CRS + Custom Virtual Patches

Deployment and hardening of a Web Application Firewall (WAF) for a deliberately vulnerable legacy web application (DVWA) using **ModSecurity v2.9** and **OWASP Core Rule Set (CRS) v3.x**, validated through **OWASP ZAP** scans and evidence logs.

---

## Table of Contents
- Overview
- Key Outcomes
- Tech Stack
- Lab Architecture
- Repository Structure
- Setup & Usage
  - Environment Prerequisites
  - ModSecurity + CRS Enablement
  - Custom Rules (Virtual Patching & Tuning)
  - Telemetry / Logging
  - Validation with OWASP ZAP
- Quantitative Results
- Security Controls Implemented
  - CRS Reconnaissance Blocking
  - Custom Virtual Patching Rules
  - Policy Tuning for False Positives
  - HTTP Response Header Hardening
- Challenges Faced (STAR)
- Gap Analysis (Remaining Risks)
- Roadmap / Improvements
- MITRE ATT&CK Mapping
- Demo Video
- Credits

---

## Overview
This project demonstrates an end-to-end security engineering lifecycle to protect a vulnerable legacy web application (DVWA) using a defense-in-depth approach at the HTTP layer.

The solution installs and enables:
- **ModSecurity v2.9** (Apache WAF engine)
- **OWASP CRS v3.x** (baseline rules for OWASP Top 10 protection)
- **Custom ModSecurity rules** for surgical "virtual patching" and protocol hardening
- **OWASP ZAP** for DAST validation and measurable improvements

The underlying application remains vulnerable by design, but exploitability is reduced at the network edge using WAF enforcement.

---

## Key Outcomes
- Transitioned from a vulnerable baseline to a hardened state using layered controls.
- Achieved **27% reduction in total ZAP alerts** after CRS + custom rule tuning.
- Implemented **virtual patching** to block:
  - OS command injection reconnaissance strings (example: `whoami`)
  - Reflected XSS payload patterns (example: `<script>`)
  - Non-numeric parameter injection attempts using a positive security model
- Enforced security headers to address baseline HTTP hardening findings.

---

## Tech Stack
- **Target Host (Blue Team):**
  - WSL2 (Ubuntu 22.04)
  - Apache2
  - PHP
  - MariaDB
  - DVWA (Damn Vulnerable Web Application)
- **WAF:**
  - ModSecurity v2.9
  - OWASP CRS v3.x
  - Custom rules (virtual patches + tuning)
- **Attacker / Tester (Red Team):**
  - Kali Linux VM
  - OWASP ZAP Proxy

---

## Lab Architecture
- **Target (Blue Team):** WSL2 hosting Apache + DVWA
  - Network configured to listen on `0.0.0.0` to allow the Kali VM to reach the host.
- **Attacker (Red Team):** Kali Linux VM running OWASP ZAP for automated and manual testing.
- **Telemetry:** ModSecurity audit logs captured to:
  - `/var/log/apache2/modsec_audit.log`

---

## Repository Structure
Current repository layout (as submitted):
```
    Modsecurity Project/
    ├── Config files/
    │   ├── modsecurity.conf
    │   └── RESPONSE-999-CUSTOM.conf
    │
    ├── Report/
    │   └── SECURITY REPORT.docx
    │
    ├── Screenshots/
    │   ├── Apache_mariadb_running.png
    │   ├── Custom_Rules.png
    │   ├── DVWA_setup_page_evidence_for_rule_10002.png
    │   ├── Forbidden_web_page_post_custom_rules_implementation.png
    │   ├── Forbidden_web_page_sql_injection.png
    │   ├── Forbidden_web_page_xss_reflected_Attack.png
    │   ├── Modesecurity_config.png
    │   ├── Rule_10001_log.png
    │   ├── Rule_10003_log.png
    │   ├── Rule_10004_log.png
    │   ├── XSS-reflected_attack.png
    │   ├── ZAP_Scan_alert_section.png
    │   └── ZAP_scan_running.png
    │
    └── ZAP Scan Reports/
        ├── Baseline Scan Report.pdf
        ├── ZAP Scan with CRS.pdf
        └── ZAP Scan with Custom rules.pdf
```
Suggested optional cleanup (not required, but professional):
- rename folders to lowercase (`config/`, `report/`, `screenshots/`, `zap-reports/`)
- consider exporting the report to PDF for consistent viewing

---

## Setup & Usage

### Environment Prerequisites
- WSL2 with Ubuntu 22.04 (or any Ubuntu/Debian-based Linux)
- Apache2, PHP, MariaDB (LAMP stack)
- DVWA installed and configured
- ModSecurity v2.9 installed and enabled for Apache
- OWASP CRS v3.x installed and included
- Kali Linux VM with OWASP ZAP installed

---

### ModSecurity + CRS Enablement
High-level steps:
1. Install and enable ModSecurity for Apache.
2. Set ModSecurity engine to enforcement:
   - `SecRuleEngine On`
3. Install OWASP CRS v3.x and include CRS configuration in Apache/ModSecurity setup.
4. Restart Apache after changes and verify config.

Useful verification command:
    sudo apache2ctl configtest

---

### Custom Rules (Virtual Patching & Tuning)
Custom rules are provided in:
- `Config files/RESPONSE-999-CUSTOM.conf`

These rules provide:
- reconnaissance blocking (example: OS command probing)
- strict input validation via positive security model
- XSS virtual patching
- CRS tuning to reduce false positives during administrative tasks (DVWA setup)

Note: Custom rules should be included in the correct order so they are not shadowed by CRS defaults during testing.

---

### Telemetry / Logging
Primary audit log:
- `/var/log/apache2/modsec_audit.log`

This is used as a chain-of-evidence to confirm that:
- CRS rules are triggering correctly (e.g., reconnaissance rules)
- custom rules are firing with their IDs (e.g., 10001, 10003, 10004)
- tuning rules are correctly applied for specific endpoints

---

### Validation with OWASP ZAP
Testing workflow:
1. Run baseline scan against DVWA with ModSecurity in DetectionOnly mode (or without WAF enforcement) to capture initial alerts.
2. Enable CRS and repeat scan to observe reductions.
3. Enable custom rules and repeat scan for tuned protection and further reduction.
4. Collect PDF reports and screenshots as evidence.

Reports available in:
- `ZAP Scan Reports/`

---

## Quantitative Results
Alert counts observed via OWASP ZAP across stages:

- Baseline (No WAF): 15 total alerts
- Stage 1 (CRS Active): 13 total alerts
- Stage 2 (Custom Rules): 11 total alerts

Improvements:
- Total alerts reduced by **27%** (15 → 11)
- Medium severity alerts reduced by **60%** (5 → 2)
- Low severity alerts reduced by **25%** (4 → 3)
- Informational alerts remained unchanged (6)

Important note:
- High risks like SQLi/XSS exist in DVWA but can appear as "clean" confirmations in ZAP when the WAF drops exploit attempts before ZAP can confirm them.

---

## Security Controls Implemented

### 1) CRS Effectiveness (Blocking Reconnaissance)
- CRS blocked attempts to probe sensitive paths / files (examples: `.git`, `.htaccess`, `config.inc`)
- Example CRS behavior:
  - matched reconnaissance requests (e.g., Sensitive Path Probing)
  - returned `403 Forbidden`
  - prevented directory mapping and file discovery

---

### 2) Custom Virtual Patching Rules (Key Rule IDs)
Custom rules implemented to provide targeted control:

- Rule 10001: OS reconnaissance / command probing
  - blocks strings like `whoami` to prevent attackers from confirming execution context

- Rule 10003: Positive security model for parameter hardening
  - enforces strict numeric-only validation (example: `id` must be digits only)
  - prevents injection payloads by rejecting non-numeric input at the WAF layer

- Rule 10004: Reflected XSS virtual patch
  - blocks `<script>` patterns in user input fields (example: `name`)
  - prevents reflected XSS payloads from being echoed back to the browser

Evidence screenshots for logs and blocks are available under:
- `Screenshots/Rule_10001_log.png`
- `Screenshots/Rule_10003_log.png`
- `Screenshots/Rule_10004_log.png`
- and related forbidden response captures

---

### 3) Policy Tuning for Availability (False Positive Management)
- Rule 10002: strategic tuning for DVWA administrative setup
  - example: allow `setup.php` workflows by disabling a conflicting CRS rule only for that endpoint
  - goal: maintain security without breaking business-critical/admin functionality

Evidence available:
- `Screenshots/DVWA_setup_page_evidence_for_rule_10002.png`

---

### 4) HTTP Response Header Hardening
To address baseline medium severity findings, these headers were enforced:

- `X-Frame-Options: DENY`
  - prevents clickjacking via iframe embedding

- `X-Content-Type-Options: nosniff`
  - prevents MIME sniffing / content-type confusion

- `X-XSS-Protection: 1; mode=block`
  - enables built-in browser protection (where supported)
  - blocks rendering if reflected XSS is detected

---

## Challenges Faced (STAR)
Situation:
- After deploying the custom rules file, Apache failed to start with an `AH00526` syntax error.
- During early testing, CRS rules appeared to shadow custom rules.

Task:
- Restore Apache service availability.
- Ensure custom virtual patches were correctly prioritized and logged.

Action:
- Used `sudo apache2ctl configtest` to isolate syntax errors.
- Identified CRLF (Windows line endings) causing invalid commands in Linux.
  - fixed using:
        sed -i 's/\r//' [filename]
- Temporarily isolated CRS rule files to confirm custom rule IDs were triggering.
- Restarted Apache after each change to validate rule load order and integrity.

Result:
- Apache restored with "Syntax OK".
- Evidence chain established in `modsec_audit.log` proving both CRS + custom rules were active and effective.

---

## Gap Analysis (Remaining Risks)
Known remaining alerts and recommended mitigations:

- CSP Header Not Set (Medium)
  - Add a Content-Security-Policy header to reduce XSS impact even if WAF is bypassed.

- HTTP Only Site (Medium)
  - Upgrade to HTTPS (TLS 1.3) to prevent MITM attacks and protect traffic confidentiality.

- Cookie without SameSite (Low)
  - Update PHP session settings, for example:
        session.cookie_samesite = Lax
  - reduces CSRF risk by limiting cookie cross-site behavior.

---

## Roadmap / Improvements
Planned enhancements:
- SIEM Forwarding
  - forward `/var/log/apache2/modsec_audit.log` into Wazuh or ELK for correlation with broader telemetry

- Zero Trust WAF Posture
  - shift from detection to strict allow-listing for critical endpoints (example: login)
  - enforce strict character sets per parameter

- CI/CD Integration
  - integrate OWASP ZAP scanning into pipeline so each application change re-validates WAF protection

---

## MITRE ATT&CK Mapping
| Technique | MITRE ID | Mitigation in this Project |
|----------|----------|----------------------------|
| Exploit Public-Facing Application | T1190 | ModSecurity + CRS request inspection |
| Directory / File Discovery | T1083 | CRS reconnaissance signatures |
| OS Command Injection | T1059 | Custom virtual patch (Rule 10001) |
| MIME-Type Abuse | T1036 | X-Content-Type-Options header hardening |
| Clickjacking (UI Redressing) | T1189 | X-Frame-Options header enforcement |

---

Suggested demo flow (2–3 minutes):
1. Show baseline ZAP scan alerts (PDF or screenshot)
2. Enable CRS and re-scan (show reduced alerts)
3. Enable custom rules and re-scan (show further reduction)
4. Trigger one blocked payload (SQLi/XSS/command probing)
5. Show evidence in `modsec_audit.log` and a screenshot of `403 Forbidden`

---

## Credits
- Analyst / Author: Sai Avinash Sirasapalli
- GitHub: @saiavinash05(https://github.com/saiavinash05)
- Email: [sirasapalliavinash@gmail.com](url)
- Project Context: Deployment and Hardening of WAF on Legacy Infrastructure (DVWA)
- Date: December 28, 2025

Report (full details, evidence, and analysis):
- `Report/SECURITY REPORT.docx`
