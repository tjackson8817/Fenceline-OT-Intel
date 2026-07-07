Fenceline OT advisory updater.

Fetches CISA's ICS advisories feed, finds items not already in
data/advisories.json, runs each through the Claude enrichment prompt,
and writes the results back. Designed to run on a schedule via GitHub
Actions (see .github/workflows/update-advisories.yml).
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests

FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "advisories.json")
MAX_RECORDS = 150
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


def fetch_feed_items():
    resp = requests.get(FEED_URL, timeout=30, headers={"User-Agent": "fenceline-ot-intel/1.0"})
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    items = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        guid = (item.findtext("guid") or link).strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        description = (item.findtext("description") or "").strip()
        items.append({"title": title, "link": link, "guid": guid, "pub_date": pub_date, "description": description})
    return items


def fetch_full_advisory_text(url):
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": "fenceline-ot-intel/1.0"})
        resp.raise_for_status()
        return resp.text
    except requests.RequestException:
        return ""


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
    known_guids = {r.get("guid") for r in existing if r.get("guid")}

    items = fetch_feed_items()
    new_records = []

    for item in items:
        if item["guid"] in known_guids:
            continue

        full_text = fetch_full_advisory_text(item["link"]) or item["description"]
        if not full_text:
            print(f"Skipping {item['guid']}: no text available", file=sys.stderr)
            continue

        try:
            enriched = enrich(full_text, item["link"])
        except Exception as exc:  # noqa: BLE001 -- log and continue, don't kill the run
            print(f"Skipping {item['guid']}: enrichment failed ({exc})", file=sys.stderr)
            continue

        enriched["guid"] = item["guid"]
        enriched["source_url"] = item["link"]
        enriched["published"] = item["pub_date"]
        enriched["fetched_at"] = datetime.now(timezone.utc).isoformat()
        new_records.append(enriched)
        print(f"Enriched: {item['title']}")

    if not new_records:
        print("No new advisories.")
        return

    combined = (new_records + existing)[:MAX_RECORDS]
    save(combined)
    print(f"Added {len(new_records)} new record(s). Total stored: {len(combined)}")


if __name__ == "__main__":
    main()
