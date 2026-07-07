# Fenceline — OT threat intel dashboard

Live setup checklist:

1. **Create a new GitHub repo** and push everything in this folder to it.

2. **Add your Anthropic API key as a secret.**
   Repo → Settings → Secrets and variables → Actions → New repository secret
   Name: `ANTHROPIC_API_KEY`

3. **Enable GitHub Pages.**
   Repo → Settings → Pages → Source: "Deploy from a branch" → Branch: `main`, folder: `/ (root)`
   Your dashboard will be live at `https://<username>.github.io/<repo-name>/`

4. **Run the workflow once manually** to populate data before waiting for the schedule.
   Repo → Actions → "Update OT advisories" → Run workflow

5. That's it. The workflow runs every 6 hours (`.github/workflows/update-advisories.yml`),
   pulls CISA's ICS advisory feed, runs new items through the enrichment prompt in
   `scripts/update_advisories.py`, and commits the result to `data/advisories.json`.
   The dashboard (`index.html`) reads from that file and auto-checks every 15 minutes,
   plus has a manual Refresh button.

## Adjusting the schedule

Edit the cron line in `.github/workflows/update-advisories.yml`. CISA typically
posts advisories a few times a week, so every 6 hours is generous; every 12-24
hours is also reasonable and uses less of your API budget.

## Adjusting the model

`scripts/update_advisories.py` uses `claude-sonnet-5` by default. Swap in a
different model string if you want a faster/cheaper option for this
structured-extraction task, or a stronger one if you find it's missing ATT&CK
mappings it should catch.

## Known limitations to be aware of

- The updater fetches full advisory text from CISA. If CISA changes their page
  structure, the underlying text passed to Claude may become messier — worth
  spot-checking output after any CISA site changes.
- `purdue_level_estimate` is a generic estimate based on product class, not your
  actual network. Don't treat it as a confirmed segmentation fact.
- `known_mitigation` is marked `vendor-confirmed` or `suggested` — treat
  `suggested` mitigations as a starting point for your team's own judgment, not
  an authoritative fix.
- This pulls CISA ICS advisories only. Vendor PSIRTs that CISA hasn't
  republished yet, and non-CISA sources (ISACs, Dragos/Claroty blogs), are not
  covered — worth adding as a second feed source later if useful.
