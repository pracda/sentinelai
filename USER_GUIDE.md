# SentinelAI — User Guide

A step-by-step walkthrough for every feature, from first login to API automation.

---

## Table of contents

1. [Accessing the application](#1-accessing-the-application)
2. [Creating your account](#2-creating-your-account)
3. [Signing in](#3-signing-in)
4. [Dashboard overview](#4-dashboard-overview)
5. [Running a security scan](#5-running-a-security-scan)
6. [Analysing logs](#6-analysing-logs)
7. [Generating reports](#7-generating-reports)
8. [Scheduled scans](#8-scheduled-scans)
9. [Alert rules](#9-alert-rules)
10. [MITRE ATT&CK heatmap](#10-mitre-attck-heatmap)
11. [API key management](#11-api-key-management)
12. [Your activity history](#12-your-activity-history)
13. [Admin panel](#13-admin-panel)
14. [Using the REST API directly](#14-using-the-rest-api-directly)

---

## 1. Accessing the application

| Environment | URL |
|---|---|
| Local (Docker) | `http://localhost:8000` |
| AWS (production) | `http://sentinelai-prod.us-east-1.elasticbeanstalk.com` |
| Interactive API docs | `<base-url>/docs` |

Opening the base URL automatically redirects to the dashboard UI.

---

## 2. Creating your account

1. Go to the application URL.
2. Click **Sign Up** on the login screen.
3. Fill in:
   - **Username** — display name (letters, numbers, underscore)
   - **Email** — used to log in and receive alerts
   - **Password** — minimum 8 characters
4. Click **Create Account**.

You are automatically signed in after registration and a JWT token is issued for your session (valid 24 hours).

> **Admin note:** The first registered user is automatically made an admin. If the database is restored from a backup, any email listed in the `ADMIN_EMAILS` environment variable is promoted to admin on the next startup.

---

## 3. Signing in

1. Enter your **email** and **password**.
2. Click **Sign In**.
3. Your session lasts 24 hours. After expiry the app will show a "Session expired" message and return you to the login screen — just sign in again.

---

## 4. Dashboard overview

After login you land on the **Dashboard** tab. It shows:

| Card | What it means |
|---|---|
| Total Scans | All scans you have run since account creation |
| Threats Found | Total findings across all your scans |
| Active API Keys | Number of API keys currently enabled |
| Recent Scans | Last 10 scans with status, target, and type |

Click any scan row to view its full results.

---

## 5. Running a security scan

Navigate to the **Scanner** tab. Three scan types are available.

### Recon scan

Performs DNS enumeration, port scanning, and service fingerprinting, then sends everything to the LLM for attack-surface analysis.

1. Select **Recon** from the scan type dropdown.
2. Enter the **Target** — a domain name (e.g. `example.com`) or IP address.
3. Optionally adjust **Ports** (default: top 1000).
4. Enter **Authorized by** — your name or the name of the engagement owner. This is a legal acknowledgement that you have permission to scan the target.
5. Tick **I confirm this scan is authorized**.
6. Click **Start Scan**.

The scan runs in the background. Status updates every few seconds. Results appear automatically when the scan completes.

### Vulnerability scan

Takes a known list of open ports and services and looks up CVEs, CVSS scores, and LLM exploitability assessments.

1. Select **Vulnerability** from the dropdown.
2. Enter the **Target**.
3. Enter **Open ports** (comma-separated, e.g. `22,80,443,8080`).
4. Confirm authorization and click **Start Scan**.

### Full scan

Runs Recon → Vulnerability analysis → Report generation in a single pipeline.

1. Select **Full Scan**.
2. Enter target and confirm authorization.
3. Click **Start Scan** — this takes longer than individual scans (typically 3–10 minutes depending on the target).

### Viewing results

After a scan completes:

- The **Scanner** tab lists all your scans.
- Click a scan row or the **View** button to open the full results panel showing:
  - Summary and LLM assessment
  - Findings table (severity, service, description, CVE where applicable)
  - IOCs (IP addresses, domains, hashes) extracted during analysis
  - MITRE ATT&CK techniques mapped from the findings

---

## 6. Analysing logs

Navigate to the **Log Analysis** tab.

1. Paste raw log content into the text area (Apache/Nginx access logs, auth logs, firewall logs, Windows Event logs, etc.).
2. Optionally specify a **Log type** hint (e.g. `nginx`, `syslog`, `windows`).
3. Click **Analyse Logs**.

The LLM scans for:
- Anomalous patterns and outliers
- Authentication failures and brute-force attempts
- IOCs (IPs, domains, hashes)
- Timeline of suspicious events

Results show a threat summary, extracted IOCs, and a reconstructed attack timeline.

### Log correlation

Use **Correlate** to cross-reference log findings against previous scan data and known IOCs in your database, linking log events to specific vulnerabilities or attack chains.

---

## 7. Generating reports

Reports can be generated for any completed scan.

1. Go to **Scans** and open a completed scan.
2. Click **Generate Report**.
3. Choose format: **Markdown** or **PDF**.
4. The report is generated by the LLM and includes:
   - Executive summary
   - Findings ranked by severity
   - Exploitability assessment per finding
   - Prioritised mitigation steps
5. Click **Download** to save the file.

---

## 8. Scheduled scans

Navigate to the **Schedules** tab to automate recurring scans.

### Creating a schedule

1. Click **New Schedule**.
2. Fill in:
   - **Name** — e.g. "Weekly prod recon"
   - **Target** — domain or IP
   - **Scan type** — recon, vuln, or full
   - **Cron expression** — e.g. `0 2 * * 1` (every Monday at 2 AM UTC)
   - **Authorized by** — name of the authorizing party
3. Click **Save**.

The schedule is enabled immediately and will fire at the next matching cron time.

### Managing schedules

| Action | How |
|---|---|
| Pause a schedule | Click the toggle switch in the schedule row |
| Resume a schedule | Click the toggle switch again |
| Delete a schedule | Click the trash icon and confirm |

> Schedules run server-side. They continue even when you are not logged in.

---

## 9. Alert rules

Navigate to the **Alerts** tab to be notified when scans find threats above a threshold.

### Creating an alert rule

1. Click **New Alert Rule**.
2. Fill in:
   - **Name** — e.g. "Critical findings → Slack"
   - **Trigger** — choose when the rule fires:
     - `any` — fires on every finding
     - `high` — fires on high or critical severity findings
     - `critical` — fires only on critical findings
   - **Notify email** — email address to send alerts to (leave blank to skip)
   - **Notify webhook** — webhook URL (Slack, Teams, Discord, or any HTTP endpoint) to POST alerts to (leave blank to skip)
3. At least one of email or webhook is required.
4. Click **Create Rule**.

### Managing rules

| Action | How |
|---|---|
| Pause a rule | Click the toggle in the rule row |
| Resume a rule | Click the toggle again |
| Delete a rule | Click the delete button |

---

## 10. MITRE ATT&CK heatmap

Navigate to the **MITRE** tab.

The heatmap shows which ATT&CK techniques and sub-techniques have been identified across all your scans. Each cell shows the technique ID, name, and count of findings that mapped to it. Darker cells indicate higher frequency.

Use this to identify which attack patterns your infrastructure is most exposed to.

---

## 11. API key management

Navigate to the **API Keys** tab to create keys for programmatic access (scripts, CI pipelines, integrations).

### Creating a key

1. Click **New API Key**.
2. Enter a **Key name** (e.g. "CI pipeline", "Terraform scanner").
3. Click **Create**.
4. **Copy the key immediately** — it is shown only once and cannot be retrieved again. Store it in a secrets manager or `.env` file.

The key prefix (first 8 characters) is displayed in the table so you can identify it later.

### Using a key

Pass the key in the `X-API-Key` header on any API request:

```
X-API-Key: sal_YourKeyHere
```

### Rotating a key

Rotation generates a new secret while preserving the same key name and ID.

1. Click **Rotate** next to the key.
2. Copy the new key shown in the dialog — it replaces the old one immediately. The old key stops working.
3. Update any systems that used the old key.

### Revoking a key

Click **Revoke** to permanently disable a key. This cannot be undone — create a new key if needed.

---

## 12. Your activity history

Navigate to the **Activity** tab (or **Profile → Activity**) to see a timestamped log of everything your account has done: scans run, keys created, schedules toggled, reports generated, logins, etc.

---

## 13. Admin panel

Only accounts with admin access see the **Admin** menu.

### Users tab

Shows all registered users with:
- Status (active / disabled)
- Number of active API keys
- Total API requests made
- **Services used** — a badge per activity type showing how many times that user has used each feature (scans, log analysis, reports, keys, schedules, alerts)
- Last seen timestamp

**Actions per user:**
- **Activity** button — opens a modal with the user's full event history and a service usage breakdown
- **Disable / Enable** — toggles the user's account. Disabled users cannot log in.

### Analytics tab

Platform-wide charts:
- Scan volume over time
- Findings by severity distribution
- Most active users
- API usage trends

### Usage tab

Raw API request log across all users: endpoint, method, user, timestamp, response status.

### Security Events tab

Security-relevant events logged by the system: failed logins, brute-force attempts, rate limit violations.

---

## 14. Using the REST API directly

All features available in the UI are also accessible via the REST API. Interactive documentation is at `<base-url>/docs`.

### Authentication

**JWT (for scripts that can handle login flows):**

```bash
# 1. Login and capture the token
TOKEN=$(curl -s -X POST https://your-host/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"yourpass"}' \
  | jq -r .token)

# 2. Use the token in subsequent requests
curl -H "Authorization: Bearer $TOKEN" https://your-host/api/v1/stats
```

**API key (simpler for automation):**

```bash
curl -H "X-API-Key: sal_YourKeyHere" https://your-host/api/v1/stats
```

### Common API calls

**Start a recon scan:**
```bash
curl -X POST https://your-host/api/v1/scan/recon \
  -H "X-API-Key: sal_YourKeyHere" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "ports": "1-1000",
    "authorization": {
      "confirm": true,
      "authorized_by": "Jane Smith"
    }
  }'
```

**Poll scan status:**
```bash
curl -H "X-API-Key: sal_YourKeyHere" \
  https://your-host/api/v1/scans/<scan_id>
```

**Analyse logs:**
```bash
curl -X POST https://your-host/api/v1/logs/analyse \
  -H "X-API-Key: sal_YourKeyHere" \
  -H "Content-Type: application/json" \
  -d '{
    "log_content": "... paste log lines here ...",
    "log_type": "nginx"
  }'
```

**List your scans:**
```bash
curl -H "X-API-Key: sal_YourKeyHere" \
  "https://your-host/api/v1/scans?limit=20&offset=0"
```

**Download a report (PDF):**
```bash
curl -H "X-API-Key: sal_YourKeyHere" \
  "https://your-host/api/v1/scans/<scan_id>/report?format=pdf" \
  -o report.pdf
```

---

## Rate limits

The API enforces a rate limit of **120 requests per minute** per API key. If you exceed this you receive a `429 Too Many Requests` response. Back off and retry after 60 seconds.

---

## Security and ethical use

- Only scan systems you own or have **explicit written authorization** to test.
- All scan endpoints require `authorization.confirm: true` and an `authorized_by` name — this is not optional.
- Unauthorized scanning is illegal in most jurisdictions.
- The platform logs all scan activity. Admin users can audit who scanned what and when.
