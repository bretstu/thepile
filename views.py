"""
Daily page views of thepile.space from real people, from Cloudflare Web
Analytics.

    python views.py            # last 30 days
    python views.py 90         # last 90 days

HOW IT WORKS

  Cloudflare Web Analytics is a small script on the page that reports a
  page load to Cloudflare. No cookies, nothing stored on the visitor.
  Cloudflare tags each load as bot or human from the request itself; this
  script asks only for the human ones. Each row is one day:

    views   page loads by people
    visits  arrivals from outside the site (a new tab, a link, a search
            result) — the closest thing to "people" without tracking them
    ~       the day's figure is sampled, so it is rounded, not exact
            (Cloudflare samples data more than a few days old)

ONE-TIME SETUP

  1. Turn the beacon on. Cloudflare dashboard -> Workers & Pages -> the
     thepile project -> Metrics -> Web Analytics -> Enable. Cloudflare
     injects the script into every page it serves; nothing to commit.
     (Or add the snippet it shows you to index.html by hand.)
  2. Make an API token. My Profile -> API Tokens -> Create Token ->
     Custom token, with the permission  Account / Account Analytics / Read
     scoped to your account.
  3. Add to .env:
       CF_API_TOKEN=...
     The account id is already there as R2_ACCOUNT_ID.
"""

import os
import sys
from datetime import date, timedelta

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT = os.getenv("CF_ACCOUNT_ID") or os.getenv("R2_ACCOUNT_ID")
# Optional. Without it the script looks the site up by hostname.
SITE_TAG = os.getenv("CF_WEB_ANALYTICS_SITE_TAG")
HOST = "thepile.space"

API = "https://api.cloudflare.com/client/v4"

QUERY = """
query($account: String!, $site: String!, $since: Date!, $until: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      days: rumPageloadEventsAdaptiveGroups(
        limit: 1000,
        filter: {siteTag: $site, bot: 0, date_geq: $since, date_leq: $until},
        orderBy: [date_ASC]
      ) {
        count
        sum { visits }
        avg { sampleInterval }
        dimensions { date }
      }
    }
  }
}
"""


def headers():
    return {"Authorization": f"Bearer {TOKEN}"}


def find_site_tag():
    """The site tag identifies this site inside Web Analytics. Cloudflare
    shows it in the dashboard URL; this looks it up instead."""
    r = requests.get(f"{API}/accounts/{ACCOUNT}/rum/site_info/list",
                     headers=headers(), timeout=30)
    body = r.json()
    if not body.get("success"):
        sys.exit(f"Could not list Web Analytics sites: {body.get('errors')}\n"
                 f"Set CF_WEB_ANALYTICS_SITE_TAG in .env instead (it is in "
                 f"the dashboard URL under Analytics & Logs -> Web Analytics).")
    sites = body.get("result") or []
    for s in sites:
        if HOST in (s.get("host") or ""):
            return s["site_tag"]
    if len(sites) == 1:
        return sites[0]["site_tag"]
    names = ", ".join(s.get("host") or "?" for s in sites) or "none"
    sys.exit(f"No Web Analytics site for {HOST} (found: {names}). "
             f"Enable it under the Pages project -> Metrics first.")


def fetch(site, since, until):
    r = requests.post(f"{API}/graphql", headers=headers(), timeout=60, json={
        "query": QUERY,
        "variables": {"account": ACCOUNT, "site": site,
                      "since": since.isoformat(), "until": until.isoformat()},
    })
    body = r.json()
    if body.get("errors"):
        sys.exit(f"Query failed: {body['errors']}")
    return body["data"]["viewer"]["accounts"][0]["days"]


def main(days):
    if not TOKEN or not ACCOUNT:
        sys.exit("CF_API_TOKEN and R2_ACCOUNT_ID (or CF_ACCOUNT_ID) must be "
                 "set in .env — see the top of this file.")
    site = SITE_TAG or find_site_tag()
    until = date.today()
    since = until - timedelta(days=days - 1)
    rows = {r["dimensions"]["date"]: r for r in fetch(site, since, until)}

    print(f"{HOST} — page views by people, last {days} days\n")
    print(f"{'date':<12}{'views':>8}{'visits':>8}")
    tot_views = tot_visits = 0
    for i in range(days):
        d = since + timedelta(days=i)
        r = rows.get(d.isoformat())
        if not r:
            print(f"{d.isoformat():<12}{0:>8}{0:>8}")
            continue
        views = r["count"]
        visits = r["sum"]["visits"]
        sampled = (r["avg"]["sampleInterval"] or 1) > 1
        tot_views += views
        tot_visits += visits
        print(f"{d.isoformat():<12}{views:>8}{visits:>8}{'  ~' if sampled else ''}")
    print()
    print(f"{'total':<12}{tot_views:>8}{tot_visits:>8}")
    print(f"{'per day':<12}{tot_views / days:>8.1f}{tot_visits / days:>8.1f}")
    print("\n~ sampled by Cloudflare: rounded, not exact. "
          "Bots are excluded from every figure.")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 30)
