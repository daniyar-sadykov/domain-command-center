#!/usr/bin/env python3
"""
Domain Command Center v1
Enriches domains from seeds.csv with public signals and scores them for manual review.
"""

import asyncio
import aiohttp
import csv
import json
import ssl as ssl_module
import argparse
import re
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────────
SEEDS_FILE  = Path("seeds.csv")
OUTPUT_FILE = Path("output.csv")
CACHE_FILE  = Path("cache.json")
REPORT_FILE = Path("report.md")
LOG_FILE    = Path("run.log")

# ── Tuning ─────────────────────────────────────────────────────────────────────
TIMEOUT_S      = 10
MAX_CONCURRENT = 15
USER_AGENT     = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# ── Classification helpers ─────────────────────────────────────────────────────
# Well-known platforms / infrastructure — not outreach prospects
KNOWN_PLATFORMS = {
    "amazonaws.com", "cloudflare.com", "github.com", "render.com",
    "fly.io", "heroku.com", "vercel.com", "digitalocean.com",
    "linode.com", "namecheap.com", "godaddy.com", "bing.com",
    "linkedin.com", "medium.com", "substack.com", "nytimes.com",
    "techcrunch.com", "producthunt.com", "indiehackers.com",
    "ycombinator.com", "linktr.ee", "discord.com", "slack.com",
    "loom.com", "cal.com", "fathom.video", "ghost.org",
    # IANA reserved / documentation domains — not real outreach prospects
    "example.com", "example.org", "example.net",
    # Major AI/tech companies that block scrapers — known to be alive
    "openai.com",
    # Major SaaS platforms — not outreach prospects
    "airtable.com", "notion.so",
    "stripe.com", "shopify.com", "hubspot.com", "salesforce.com",
    "mailchimp.com", "trello.com", "twilio.com", "typeform.com",
    "webflow.com", "miro.com", "clearbit.com", "clickup.com",
    "intercom.com", "calendly.com", "asana.com", "figma.com",
    "framer.com", "zapier.com", "retool.com", "freshdesk.com",
    "hostinger.com", "langchain.com",
}

# Parking / for-sale page signals
PARKING_RE = re.compile(
    r"(domain for sale|domain is for sale|parked|buy this domain|"
    r"domain is available|sedoparking|afternic|sedo\.com|dan\.com|"
    r"domain.*available.*purchase|domain.*expired|domain.*auction)",
    re.IGNORECASE,
)

# Spam / scam signals in the domain name itself
SPAM_NAME_RE = re.compile(
    r"(airdrop|nft.?mint|get.?rich|fast.?cash|instant.?loan|"
    r"crypto.*202[0-9]|buy.?followers|cheap.?backlink|"
    r"discount.?med|best.?deal|super.?deal|instant.?cash|"
    r"loan.?approval|make.?money.?fast|free.?bitcoin|free.?crypto)",
    re.IGNORECASE,
)

# Active business content signals
BUSINESS_RE = re.compile(
    r"(pricing|sign.?up|get started|dashboard|documentation|docs|"
    r"enterprise|contact us|about us|free trial|platform|"
    r"solution|features|our product|book a demo|request a demo)",
    re.IGNORECASE,
)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

HIGH_RISK_TLDS = {".click", ".bid", ".win"}
MEDIUM_RISK_TLDS = {".biz", ".info", ".xyz", ".site", ".online", ".life"}

# Valid hostname: labels of 1–63 alnum/hyphen chars separated by dots, TLD ≥ 2 letters
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")

# ── Output schema ──────────────────────────────────────────────────────────────
OUTPUT_COLS = [
    "domain", "status", "score", "reason",
    "http_code", "final_url", "response_ms", "redirect_count",
    "ssl_valid", "ssl_days_left", "page_title",
    "next_action", "notes", "error", "checked_at",
]


# ── SSL checker ────────────────────────────────────────────────────────────────
async def check_ssl(domain: str) -> tuple[Optional[bool], Optional[int]]:
    """Return (is_valid, days_until_expiry) for the domain's SSL certificate."""
    try:
        ctx = ssl_module.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=TIMEOUT_S,
        )
        cert = writer.get_extra_info("ssl_object").getpeercert()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        expires_str = cert.get("notAfter", "")
        if expires_str:
            try:
                expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                logging.debug(f"SSL cert date parse failed for {domain}: {expires_str!r}")
                return True, None
            days_left = (expires - datetime.now(timezone.utc)).days
            return True, days_left
        return True, None
    except Exception:
        return False, None


# ── Domain classifier / scorer ─────────────────────────────────────────────────
def classify(result: dict, domain: str, body: str) -> None:
    """Classify domain and set status/score/reason/next_action on result in-place."""
    domain_lower = domain.lower()
    snippet = body[:8000].lower()
    title = (result.get("page_title") or "").lower()
    final_url = (result.get("final_url") or "").lower()
    http_code = result.get("http_code") or 0

    # ── 1. Infrastructure / known platforms ──────────────────────────────────
    if domain_lower in KNOWN_PLATFORMS:
        result.update(
            status="platform",
            score=3,
            reason="Known platform — not an outreach prospect",
            next_action="skip",
        )
        return

    # ── 2. Spam signals in domain name ───────────────────────────────────────
    if SPAM_NAME_RE.search(domain_lower):
        result.update(
            status="suspicious",
            score=1,
            reason="Spam / scam keywords in domain name",
            next_action="skip",
        )
        return

    # ── 3. HTTP error or no response ─────────────────────────────────────────
    if not http_code or http_code >= 400:
        # 403 with Cloudflare "Just a moment..." challenge = site is alive but blocks bots
        if http_code == 403 and "just a moment" in snippet[:500]:
            result.update(
                status="active",
                score=3,
                reason="Active site (Cloudflare bot protection — 403)",
                next_action="investigate",
            )
            return
        result.update(
            status="dead",
            score=1,
            reason=f"HTTP {http_code or 'no response'}",
            next_action="skip",
        )
        return

    # ── 4. Parked / for-sale ─────────────────────────────────────────────────
    if PARKING_RE.search(title + " " + snippet[:2000]):
        result.update(
            status="parked",
            score=4,
            reason="Parking page or for-sale signals detected",
            next_action="investigate",
            notes="Potential acquisition target — check price",
        )
        return

    # ── 5. Cross-domain redirect ─────────────────────────────────────────────
    redirect_count = result.get("redirect_count", 0)
    if redirect_count:
        # Strip scheme + www for comparison
        def bare(url: str) -> str:
            return re.sub(r"^(https?://)?(www\.)?", "", url).split("/")[0]

        if bare(final_url) != bare(domain_lower):
            dest = final_url[:80]
            result.update(
                status="redirect",
                score=5,
                reason=f"Redirects to a different domain ({dest})",
                next_action="investigate",
                notes=f"Follow redirect: {dest}",
            )
            return

    # ── 6. Active site — score quality ───────────────────────────────────────
    # Scoring 1–10:
    #   Baseline 5 for any live 200 site
    #   +2 valid SSL (>30 days left)
    #   +2 business content signals in title/body
    #   +1 fast response (<400 ms)
    #   −1 no valid SSL
    #   −3 high-risk TLD (.click/.bid/.win)
    #   −2 medium-risk TLD (.biz/.info/.xyz/…)
    score = 5  # baseline for any live 200 site
    reasons: list[str] = []

    ssl_valid = result.get("ssl_valid")
    ssl_days = result.get("ssl_days_left") or 0

    if ssl_valid and ssl_days > 30:
        score += 2
        reasons.append("valid SSL")
    elif not ssl_valid:
        score -= 1
        reasons.append("no valid SSL")

    if BUSINESS_RE.search(title + " " + snippet[:3000]):
        score += 2
        reasons.append("business content signals")

    tld = "." + domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
    if tld in HIGH_RISK_TLDS:
        score -= 3
        reasons.append(f"high-risk TLD ({tld})")
    elif tld in MEDIUM_RISK_TLDS:
        score -= 2
        reasons.append(f"medium-risk TLD ({tld})")

    response_ms = result.get("response_ms") or 9999
    if response_ms < 400:
        score += 1
        reasons.append("fast response")

    score = max(1, min(10, score))
    reason_str = "Active site" + ("; " + ", ".join(reasons) if reasons else "")

    result.update(
        status="active",
        score=score,
        reason=reason_str,
        next_action="contact" if score >= 7 else "investigate",
    )


# ── Per-domain enrichment ──────────────────────────────────────────────────────
async def enrich(session: aiohttp.ClientSession, domain: str) -> dict:
    """Fetch and classify a single domain; returns a result dict with all signals."""
    result: dict = {
        "domain": domain,
        "status": "unknown",
        "score": 1,
        "reason": "",
        "http_code": None,
        "final_url": None,
        "response_ms": None,
        "redirect_count": 0,
        "ssl_valid": None,
        "ssl_days_left": None,
        "page_title": None,
        "next_action": "skip",
        "notes": "",
        "error": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    # Fast-exit on known platforms — no HTTP needed, answer is always the same
    if domain.lower() in KNOWN_PLATFORMS:
        result.update(
            status="platform",
            score=3,
            reason="Known platform — not an outreach prospect",
            next_action="skip",
        )
        return result

    # Fast-exit on domain-name spam (no HTTP needed)
    if SPAM_NAME_RE.search(domain):
        result.update(
            status="suspicious",
            score=1,
            reason="Spam / scam keywords in domain name",
        )
        return result

    url = f"https://{domain}"
    loop = asyncio.get_running_loop()
    t0 = loop.time()

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_S),
            allow_redirects=True,
            max_redirects=5,
            ssl=False,  # we validate SSL separately so expired certs still yield content
            headers={"User-Agent": USER_AGENT},
        ) as resp:
            elapsed_ms = int((loop.time() - t0) * 1000)
            raw_bytes = await resp.content.read(1_000_000)
            body = raw_bytes.decode(errors="replace")

            title_match = TITLE_RE.search(body[:6000])
            raw_title = title_match.group(1) if title_match else ""
            title = re.sub(r"\s+", " ", raw_title).strip()[:200]

            result.update(
                http_code=resp.status,
                final_url=str(resp.url),
                response_ms=elapsed_ms,
                redirect_count=len(resp.history),
                page_title=title,
            )

            ssl_valid, ssl_days = await check_ssl(domain)
            result["ssl_valid"] = ssl_valid
            result["ssl_days_left"] = ssl_days

            classify(result, domain, body)

    except aiohttp.TooManyRedirects:
        # Redirect loop — site is alive but misconfigured
        ssl_valid, ssl_days = await check_ssl(domain)
        result.update(
            status="redirect",
            score=3,
            reason="Active site (redirect loop detected)",
            next_action="investigate",
            ssl_valid=ssl_valid,
            ssl_days_left=ssl_days,
            error="TooManyRedirects",
        )
    except aiohttp.ClientConnectorError as exc:
        msg = str(exc)
        reason = "DNS lookup failed" if "getaddrinfo" in msg else "Connection refused or network error"
        result.update(status="dead", score=1, reason=reason, error=msg[:200])
    except aiohttp.ServerDisconnectedError:
        # Server reset the connection — likely bot protection; site is alive
        ssl_valid, ssl_days = await check_ssl(domain)
        result.update(
            status="active",
            score=3,
            reason="Active site (connection reset — possible bot protection)",
            next_action="investigate",
            ssl_valid=ssl_valid,
            ssl_days_left=ssl_days,
            error="ServerDisconnected (bot protection suspected)",
        )
    except asyncio.TimeoutError:
        result.update(status="dead", score=1, reason=f"Timed out after {TIMEOUT_S}s", error="timeout")
    except Exception as exc:
        msg = str(exc)
        # aiohttp header buffer overflow: server IS alive, just uses oversized headers
        if "8190 bytes" in msg or "Got more than" in msg:
            ssl_valid, ssl_days = await check_ssl(domain)
            result.update(
                status="active",
                score=3,
                reason="Active site (response headers too large to parse fully)",
                next_action="investigate",
                ssl_valid=ssl_valid,
                ssl_days_left=ssl_days,
                error=msg[:120],
            )
        else:
            result.update(status="error", score=1, reason="Unexpected error", error=msg[:200])

    return result


# ── Pipeline ───────────────────────────────────────────────────────────────────
async def run_pipeline(domains: list[str], rerun_failed: bool) -> list[dict]:
    """Run enrichment pipeline with cache; returns all results (cached + freshly fetched)."""
    cache: dict = {}
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            logging.warning(f"Cache file corrupt — ignoring ({e})")

    to_process: list[str] = []
    results: list[dict] = []

    for d in domains:
        if d in cache:
            cached = cache[d]
            # rerun_failed: re-process dead/error, use cache for everything else
            if rerun_failed and cached.get("status") in ("dead", "error", "unknown"):
                to_process.append(d)
            else:
                results.append(cached)
        else:
            to_process.append(d)

    logging.info(
        f"Domains: {len(domains)} total | {len(results)} from cache | {len(to_process)} to fetch"
    )

    if not to_process:
        return results

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    # max_line_size / max_field_size raise aiohttp's internal HTTP parser limits
    # (default 8190 bytes) so sites with large headers (Notion, etc.) don't error out
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)

    async def bounded(session: aiohttp.ClientSession, domain: str) -> dict:
        async with sem:
            r = await enrich(session, domain)
            cache[domain] = r
            return r

    async with aiohttp.ClientSession(
        connector=connector,
        max_line_size=65536,
        max_field_size=65536,
    ) as session:
        tasks = [bounded(session, d) for d in to_process]
        done: list[dict] = []
        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            r = await coro
            done.append(r)
            if i % 10 == 0 or i == len(tasks):
                logging.info(f"  {i}/{len(tasks)} fetched ...")

    CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.info(f"Cache saved -> {CACHE_FILE}")

    return results + done


# ── Output writers ─────────────────────────────────────────────────────────────
def write_csv(results: list[dict]) -> None:
    """Sort results by score descending and write to OUTPUT_FILE as CSV."""
    results.sort(key=lambda r: (-r.get("score", 1), r.get("domain", "")))
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    logging.info(f"Output -> {OUTPUT_FILE}")


def write_report(results: list[dict]) -> None:
    """Generate markdown summary report with status breakdown and top prospects."""
    by_status: dict[str, int] = {}
    by_priority: dict[int, int] = {}
    errors: list[dict] = []

    for r in results:
        s = r.get("status", "unknown")
        p = r.get("score", 1)
        by_status[s] = by_status.get(s, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1
        if r.get("error"):
            errors.append(r)

    top = [r for r in results if r.get("score", 1) >= 7]
    top.sort(key=lambda r: -r.get("score", 1))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# Domain Command Center — Run Report",
        f"",
        f"**Generated:** {now}  ",
        f"**Total domains processed:** {len(results)}",
        f"",
        f"## Status Breakdown",
        f"",
        f"| Status | Count |",
        f"|--------|-------|",
    ]
    for s, c in sorted(by_status.items()):
        lines.append(f"| {s} | {c} |")

    lines += [
        f"",
        f"## Score Distribution",
        f"",
        f"| Score | Count | Meaning |",
        f"|-------|-------|---------|",
        f"| 9–10 | {by_priority.get(10, 0) + by_priority.get(9, 0)} | Top prospect — contact immediately |",
        f"| 7–8  | {by_priority.get(8, 0) + by_priority.get(7, 0)} | Strong prospect — contact |",
        f"| 5–6  | {by_priority.get(6, 0) + by_priority.get(5, 0)} | Investigate before acting |",
        f"| 3–4  | {by_priority.get(4, 0) + by_priority.get(3, 0)} | Low relevance (platform / parked / redirect) |",
        f"| 1–2  | {by_priority.get(2, 0) + by_priority.get(1, 0)} | Skip (dead / spam / error) |",
        f"",
        f"## Top Domains for Review (Score ≥ 7)",
        f"",
        f"| Domain | Score | Reason | Next Action |",
        f"|--------|-------|--------|------------|",
    ]
    for r in top[:15]:
        reason = (r.get("reason") or "")[:65]
        lines.append(f"| {r['domain']} | {r['score']} | {reason} | {r.get('next_action','')} |")

    if errors:
        lines += [
            f"",
            f"## Failed / Error Domains ({len(errors)})",
            f"",
        ]
        for r in errors[:20]:
            lines.append(f"- `{r['domain']}`: {(r.get('error') or '')[:120]}")

    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")
    logging.info(f"Report -> {REPORT_FILE}")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main() -> None:
    """CLI entry point: parse args, load seeds, run pipeline, write outputs."""
    parser = argparse.ArgumentParser(description="Domain Command Center v1")
    parser.add_argument("--seeds", default=str(SEEDS_FILE), help="Seeds file (default: seeds.csv)")
    parser.add_argument("--rerun-failed", action="store_true", help="Re-fetch domains cached as dead/error")
    parser.add_argument("--dry-run", action="store_true", help="List what would be fetched, then exit")
    parser.add_argument("--clear-cache", action="store_true", help="Delete cache before running")
    parser.add_argument("--limit", type=int, default=0, help="Process only first N domains (0 = all)")
    args = parser.parse_args()

    # Reconfigure stdout to UTF-8 on Windows to avoid cp1251 encode errors
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    seeds_path = Path(args.seeds)
    if not seeds_path.exists():
        logging.error(f"Seeds file not found: {seeds_path}")
        sys.exit(1)

    raw = seeds_path.read_text(encoding="utf-8").splitlines()
    domains = list(dict.fromkeys(
        d for line in raw
        if (d := line.strip()) and DOMAIN_RE.match(d)
    ))
    if args.limit:
        domains = domains[: args.limit]
    logging.info(f"Loaded {len(domains)} domains from {seeds_path}")

    if args.clear_cache and CACHE_FILE.exists():
        CACHE_FILE.unlink()
        logging.info("Cache cleared")

    if args.dry_run:
        cache: dict = {}
        if CACHE_FILE.exists():
            try:
                cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                logging.warning(f"Cache file corrupt — ignoring ({e})")
        pending = [d for d in domains if d not in cache]
        print(f"Dry run: {len(pending)} to fetch, {len(domains) - len(pending)} cached")
        for d in pending:
            print(f"  {d}")
        return

    results = asyncio.run(run_pipeline(domains, rerun_failed=args.rerun_failed))

    write_csv(results)
    write_report(results)

    by_p: dict[int, int] = {}
    for r in results:
        p = r.get("score", 1)
        by_p[p] = by_p.get(p, 0) + 1

    sep = "-" * 50
    print(f"\n{sep}")
    print(f"  Done - {len(results)} domains")
    print(f"  Score 7-10 (contact):     {sum(by_p.get(s,0) for s in range(7,11))}")
    print(f"  Score 4-6  (investigate): {sum(by_p.get(s,0) for s in range(4,7))}")
    print(f"  Score 1-3  (skip):        {sum(by_p.get(s,0) for s in range(1,4))}")
    print(sep)
    print(f"  {OUTPUT_FILE}  <- open in Sheets")
    print(f"  {REPORT_FILE}   <- markdown summary")
    print(f"  {CACHE_FILE}   <- cache (reuse with --rerun-failed)")
    print(f"  {LOG_FILE}    <- full run log")


if __name__ == "__main__":
    main()
