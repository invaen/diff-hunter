<p align="center">
  <h1 align="center">Diff Hunter</h1>
  <p align="center">
    <b>Catch new attack surface before anyone else.</b>
    <br />
    <i>Continuous monitoring for subdomain changes, endpoint exposure, and configuration drift.</i>
  </p>
</p>

<p align="center">
  <a href="#why">Why</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#what-it-monitors">What It Monitors</a> &bull;
  <a href="#output">Output</a>
</p>

---

In bug bounty, timing is everything. When a target deploys a new subdomain, exposes a new endpoint, or changes their infrastructure — that's a window of opportunity. Diff Hunter monitors your targets continuously and alerts you the moment something changes.

```
[🚨] NEW SUBDOMAINS FOUND!
[NEW]   staging-v2.target.com
[NEW]   api-beta.target.com

[!] Content change on admin.target.com
[🚨] NEW ENDPOINTS FOUND!
[NEW]   + /swagger.json
[NEW]   + /actuator/health
```

## Why

- **New subdomains** often mean new features deployed with less scrutiny
- **Status code changes** (e.g., 403 → 200) can indicate exposed admin panels
- **New endpoints** like `/swagger.json` or `/.env` may appear during deployments
- **Content changes** can signal new functionality worth testing

Being first to a new attack surface is a competitive advantage. Diff Hunter automates the watching.

## Install

```bash
git clone https://github.com/invaen/diff-hunter.git
cd diff-hunter
python diff_hunter.py add target.com

# Or install with pip
pip install .
diff-hunter add target.com
```

**Requirements:** Python 3.8+. No external packages.

## Usage

```bash
# Add a target (runs initial baseline scan)
diff-hunter add target.com

# Run a one-time scan against all targets
diff-hunter scan

# Scan a specific target
diff-hunter scan target.com

# Continuous monitoring (default: hourly)
diff-hunter watch

# Continuous monitoring with custom interval (seconds)
diff-hunter watch -i 1800    # every 30 minutes

# View recent changes
diff-hunter report

# Show changes from last 30 days
diff-hunter report -d 30

# List all monitored targets
diff-hunter list

# Remove a target
diff-hunter remove target.com
```

## What It Monitors

### 1. Subdomain Changes
Queries Certificate Transparency logs (crt.sh) to detect new subdomain registrations. Compares against previous scan to identify additions and removals.

### 2. Response Fingerprint Changes
For each known host, tracks:
- **HTTP status codes** — detects when pages go live, get restricted, or disappear
- **Response body hash** — detects content changes (new deployments, features)
- **Server header** — detects infrastructure changes

### 3. Sensitive Endpoint Exposure
Checks 27 high-value paths on the main domain:
```
/.git/HEAD          /.env               /robots.txt
/sitemap.xml        /swagger.json       /api/swagger.json
/graphql            /actuator/health    /debug
/.well-known/security.txt              /openapi.json
/api-docs           /api/v1/docs        /.DS_Store
/wp-json/wp/v2/users /server-status    /server-info
/elmah.axd          /trace.axd          /actuator/env
/actuator/configprops /admin            /admin/login
/phpinfo.php        /.htaccess          /crossdomain.xml
/clientaccesspolicy.xml
```

## Output

All data persists in `~/.bounty/diff-hunter/`:

```
diff-hunter/
├── targets.json                    # Current state of all targets
├── alerts.json                     # All detected changes
└── history/
    ├── target.com_20260127_120000.json
    └── target.com_20260128_120000.json
```

### Alert Types

| Type | Trigger |
|------|---------|
| `new_subdomain` | Previously unseen subdomain in CT logs |
| `status_change` | HTTP status code changed (e.g., 403 → 200) |
| `content_change` | Response body hash differs from previous scan |
| `new_endpoint` | Sensitive path now returns 200 |

### Workflow Integration

```bash
# Cron job for scheduled monitoring
# Add to crontab: runs every 6 hours
0 */6 * * * python /path/to/diff_hunter.py scan >> /var/log/diff-hunter.log 2>&1

# Pipe new subdomains into nuclei
diff-hunter scan
cat ~/.bounty/diff-hunter/alerts.json | jq -r '.[] | select(.type=="new_subdomain") | .subdomain' | httpx -silent | nuclei

# Monitor + notify (example with ntfy.sh)
diff-hunter scan && \
  jq -r '.[-1] | "\(.type): \(.subdomain // .host)"' ~/.bounty/diff-hunter/alerts.json | \
  curl -d @- ntfy.sh/your-topic
```

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Only monitor targets you have explicit permission to test. The author assumes no liability for misuse.

## License

MIT
