"""
Fenceline OT advisory updater.

CISA's own site blocks automated/datacenter requests (bot detection), so
this pulls from the ICS Advisory Project's community-maintained CSV mirror
of CISA ICS Advisories instead:
https://github.com/icsadvprj/ICS-Advisory-Project

Each new row is run through the Claude enrichment prompt, using the
structured fields already present in the CSV (title, vendor, product, CVE,
CVSS, sector, CWE) as the source text, and writes the results to
data/advisories.json. Designed to run on a schedule via GitHub Actions
(see .github/workflows/update-advisories.yml).
"""

import csv
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests

CSV_URL = "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "advisories.json")
MAX_RECORDS = 150
MAX_NEW_PER_RUN = 15          # cap API calls per run
LOOKBACK_DAYS = 60            # ignore advisories older than this on a fresh backlog
MODEL = "claude-sonnet-5"
API_KEY = os.environ.get("ANTHROPIC_API_KEY")

SYSTEM_PROMPT = """You are an OT/ICS cybersecurity analyst. You convert raw vulnerability
advisories into a structured record for a dashboard read by two audiences:
mid-level to executive leadership, and technical OT security staff.

Rules:
- Do not invent facts. If the source text does not support a field, use
  null and do not guess. Never fabricate a CVE ID, CVSS score, or ATT&CK
  technique that is not stated or clearly implied by the source.
- The exec_headline and business_impact fields must contain zero jargon:
  no CVE IDs, no CVSS, no protocol names. Plain business consequence only.
- ot_risk_rating is NOT the CVSS score. Derive it from: exploit maturity,
  reachability (is the affected component typically internet-facing,
  IT-adjacent, or air-gapped), and consequence (safety, availability,
  integrity). State the rating and a one-sentence rationale.
- purdue_level_estimate reflects the TYPICAL deployment layer for this
  class of product (per vendor documentation and common practice), not a
  claim about any specific customer's network. Label it accordingly, e.g.
  "Typically Level 1, basic control".
- known_mitigation should be an interim compensating control an OT team
  can apply before patching is feasible (network restriction, monitoring,
  disabling a feature, physical access control) -- not just "apply the
  patch." If the source gives no such guidance, propose one general,
  clearly-labeled precaution appropriate to the technique, and mark it
  as "suggested" rather than "vendor-confirmed" via mitigation_confidence.
- attack_ics_technique: map to a MITRE ATT&CK for ICS technique ID only
  if the behavior described clearly matches a known technique. Include
  the canonical MITRE URL. If no clear match, return null for this field.
- severity_tier is one of: critical, high, medium, low -- based on your
  ot_risk_rating, not raw CVSS.
- The input you receive is a structured summary (title, vendor, product,
  CVE, CVSS, CWE, sector, dates) rather than the full advisory narrative.
  Work only from what's given; do not assume additional detail exists.
- Output ONLY valid JSON matching this schema. No preamble, no markdown
  fences, no commentary:

{
  "exec_headline": string,
  "business_impact": string,
  "sector": string,
  "cve_ids": [string],
  "vendor": string,
  "product": string,
  "attack_ics_technique": {"id": string, "name": string, "url": string} | null,
  "exploit_maturity": string,
  "cvss_score": number | null,
  "ot_risk_rating": string,
  "ot_risk_rationale": string,
  "patch_status": string,
  "known_mitigation": string,
  "mitigation_confidence": "vendor-confirmed" | "suggested",
  "purdue_level_estimate": string,
  "severity_tier": "critical" | "high" | "medium" | "low"
}
"""


def load_existing():
    if not os.path.exists(DATA_PATH):
        return []
    with open(DATA_PATH) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save(records):
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        json.dump(records, f, indent=2)


def fetch_rows():
    resp = requests.get(CSV_URL, timeout=30)
    resp.raise_for_status()
    resp.encoding = "utf-8-sig"
    reader = csv.DictReader(io.StringIO(resp.text))
    return list(reader)


def row_is_recent(row):
    date_str = (row.get("Original_Release_Date") or "").strip()
    if not date_str:
        return True  # if the date is missing, don't silently drop it
    try:
        released = datetime.strptime(date_str, "%m/%d/%Y")
    except ValueError:
        return True
    return released >= datetime.now() - timedelta(days=LOOKBACK_DAYS)


def row_to_source_text(row):
    advisory_id = (row.get("ICS-CERT_Number") or "").strip()
    link = f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}" if advisory_id else ""
    lines = [
        f"Advisory ID: {advisory_id}",
        f"Title: {row.get('ICS-CERT_Advisory_Title', '')}",
        f"Vendor: {row.get('Vendor', '')}",
        f"Product: {row.get('Product', '')}",
        f"Affected versions: {row.get('Products_Affected', '')}",
        f"CVE(s): {row.get('CVE_Number', '')}",
        f"CVSS score: {row.get('Cumulative_CVSS', '')} ({row.get('CVSS_Severity', '')})",
        f"CWE(s): {row.get('CWE_Number', '')}",
        f"Critical infrastructure sector(s): {row.get('Critical_Infrastructure_Sector', '')}",
        f"Original release date: {row.get('Original_Release_Date', '')}",
        f"Last updated: {row.get('Last_Updated', '')}",
    ]
    return "\n".join(lines), link


def enrich(raw_text, source_url):
    body = {
        "model": MODEL,
        "max_tokens": 1000,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": f"Source URL: {source_url}\n\n{raw_text[:12000]}"}],
    }
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=body,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    text = "".join(block.get("text", "") for block in data.get("content", []))
    text = re.sub(r"^```json|```$", "", text.strip(), flags=re.MULTILINE).strip()
    return json.loads(text)


def main():
    if not API_KEY:
        print("ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    existing = load_existing()
    known_ids = {r.get("advisory_row_id") for r in existing if r.get("advisory_row_id")}

    rows = fetch_rows()
    candidates = [
        row for row in rows
        if row.get("icsad_ID") not in known_ids and row_is_recent(row)
    ][:MAX_NEW_PER_RUN]

    new_records = []
    for row in candidates:
        source_text, link = row_to_source_text(row)
        title = row.get("ICS-CERT_Advisory_Title", "(untitled)")

        try:
            enriched = enrich(source_text, link)
        except Exception as exc:  # noqa: BLE001 -- log and continue, don't kill the run
            print(f"Skipping {row.get('icsad_ID')} ({title}): enrichment failed ({exc})", file=sys.stderr)
            continue

        enriched["advisory_row_id"] = row.get("icsad_ID")
        enriched["source_url"] = link
        enriched["published"] = row.get("Original_Release_Date", "")
        enriched["fetched_at"] = datetime.now(timezone.utc).isoformat()
        new_records.append(enriched)
        print(f"Enriched: {title}")

    if not new_records:
        print("No new advisories.")
        return

    combined = (new_records + existing)[:MAX_RECORDS]
    save(combined)
    print(f"Added {len(new_records)} new record(s). Total stored: {len(combined)}")


if __name__ == "__main__":
    main()
