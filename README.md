# Domain Command Center v1

Lightweight enrichment pipeline that reads a flat list of domains, collects public signals for each one, scores them by "worth reviewing" priority, and outputs a Google-Sheets-ready CSV + a markdown summary report.

---

## Setup & Run

```bash
pip install -r requirements.txt

# Full run — all 100 domains
python enrich.py

# Test with 10 domains first
python enrich.py --limit 10

# See what would be fetched without hitting any URLs
python enrich.py --dry-run

# Re-fetch only domains that previously failed (dead / error)
python enrich.py --rerun-failed

# Clear cache and start fresh
python enrich.py --clear-cache
```

All flags can be combined: `python enrich.py --rerun-failed --limit 20`

---

## Output Files

| File | Description |
|------|-------------|
| `output.csv` | Main output — one row per domain, sorted priority desc |
| `report.md` | Markdown summary: status breakdown, top domains, failed list |
| `cache.json` | Result cache keyed by domain — enables resumable runs |
| `run.log` | Full timestamped log |

### CSV Columns

| Column | Description |
|--------|-------------|
| `domain` | Input domain |
| `status` | `active` / `dead` / `parked` / `redirect` / `platform` / `suspicious` / `error` |
| `score` | 1–10 (10 = highest value for manual review) |
| `reason` | Short human-readable explanation of the score |
| `http_code` | Final HTTP status code |
| `final_url` | URL after all redirects |
| `response_ms` | Time to first byte in milliseconds |
| `redirect_count` | Number of redirects followed |
| `ssl_valid` | `True` / `False` / empty |
| `ssl_days_left` | Days until SSL certificate expires |
| `page_title` | `<title>` tag content (first 200 chars) |
| `next_action` | `contact` / `investigate` / `skip` |
| `notes` | Free-form notes (e.g. "potential acquisition target") |
| `error` | Error message if request failed |
| `checked_at` | ISO 8601 UTC timestamp |

---

## Assumptions

The task spec was intentionally vague. Here is what I decided and why:

1. **"Useful public information" = HTTP-level signals only.** WHOIS (domain age, registrar) was considered but dropped — WHOIS servers are inconsistent, rate-limited, and blocked without a proxy pool. The HTTP layer (status, redirect chain, SSL, page title, body keywords) gives enough signal to classify domains in a first pass.

2. **Priority = "how interesting is this domain for manual review by an outreach team."** Not technical health, not SEO score — the goal is to surface real business websites and de-prioritize dead, spam, parked, or infrastructure domains.

3. **SSL is checked with a separate connection using a strict context.** The main HTTP fetch uses `ssl=False` so that domains with expired/self-signed certificates still yield content and can be classified rather than erroring out.

4. **Known platforms (Stripe, Notion, AWS, etc.) are classified as `platform`, priority 2.** They are real and healthy, but they are not outreach prospects. A human reviewer can skip them quickly.

5. **Concurrency = 15.** High enough to process 100 domains in ~30–60 seconds on a typical connection; low enough to avoid getting rate-limited or IP-blocked on the first run.

6. **Timeout = 10 seconds per domain.** Long enough for slow servers; short enough that parked/dead domains don't stall the pipeline.

---

## Scoring Logic

Classification is applied in priority order (first match wins):

| Condition | Status | Score | Next Action |
|-----------|--------|-------|-------------|
| Spam / scam keywords in domain name | `suspicious` | 1 | skip |
| DNS failure / timeout / HTTP 4xx+ | `dead` | 1 | skip |
| Parking-page keywords in title or body | `parked` | 4 | investigate |
| Domain is a known platform / infrastructure | `platform` | 3 | skip |
| Redirects to a different domain | `redirect` | 5 | investigate |
| Live site (HTTP 200) — baseline | `active` | 5 | investigate |
| + valid SSL certificate (> 30 days left) | | +2 | |
| + business content signals in title/body | | +2 | |
| + fast response (< 400 ms) | | +1 | |
| + no valid SSL | | −1 | |
| + high-risk TLD (.click, .bid, .win) | | −3 | |
| + medium-risk TLD (.biz, .info, .xyz …) | | −2 | |

Score is clamped to the **1–10** range.

**Score 7–10** → `next_action = contact`  
**Score 4–6** → `next_action = investigate`  
**Score 1–3** → `next_action = skip`

---

## What Breaks at Scale (1 000+ domains)

| Problem | At 100 domains | At 1 000+ domains |
|---------|---------------|-------------------|
| **IP rate-limiting** | Unlikely | High probability — need rotating proxies or residential IPs |
| **Concurrency** | 15 works fine | Need a proper queue (pg-boss, BullMQ) and multiple workers |
| **SSL checks** | Cheap | Each check opens a separate TCP connection — pool or batch |
| **Cache size** | ~100 KB JSON | Fine for 10K domains; beyond that use SQLite or PostgreSQL |
| **WHOIS** | Skipped | At scale, WHOIS APIs (WhoisXML, DomainIQ) become necessary for domain age |
| **JavaScript-rendered pages** | Missed | Need Playwright or Browserless to handle SPAs |
| **Anti-bot detection** | Rare | Need real browser fingerprints, delays, and proxy rotation |

---

## v2: Connecting to n8n / Make / Slack / Email / CRM

The v1 script is a standalone CLI tool. In v2 it becomes a service node inside a larger workflow:

```
[Trigger: new CSV uploaded to Google Drive]
    └─► n8n HTTP Request node → POST /enrich  (FastAPI wrapper around enrich.py)
            └─► Results → Google Sheets (append rows via Sheets API node)
            └─► Filter priority >= 4 → Slack message to #leads channel
                    ("New high-priority domain: {domain} — {priority_reason}")
            └─► Filter priority >= 4 → HubSpot / Airtable: create Contact record
            └─► Filter status == "parked" → Email alert: "Acquisition opportunity: {domain}"
            └─► Scheduled rerun: n8n Cron → --rerun-failed every 24h
```

**Concrete integration points:**

- **n8n / Make**: wrap `enrich.py` in a FastAPI endpoint (`POST /enrich` accepts `{"domains": [...]}`, returns JSON). n8n calls it via HTTP Request node.
- **Google Sheets**: use the Google Sheets node in n8n or call the Sheets API directly to append `output.csv` rows after each run.
- **Slack**: post top-priority domains to a channel with `next_action = contact` filter. Attach `report.md` as a snippet.
- **Email**: send the markdown report as an HTML email after each run (n8n Send Email node / Resend API).
- **CRM (HubSpot / Apollo)**: create Company records for domains with priority ≥ 4. Map `domain → website`, `page_title → name`, `notes → description`.
- **Persistence**: replace `cache.json` with a PostgreSQL table (`domain TEXT PRIMARY KEY, result JSONB, updated_at TIMESTAMPTZ`). Enables multi-worker parallel enrichment and proper retry queuing (pg-boss).
