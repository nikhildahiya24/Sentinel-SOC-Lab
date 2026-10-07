"""
Synthetic identity log generator for the Sentinel SOC lab.

Writes fake sign-in / role-assignment rows to the SOCLabAuth_CL custom table using the
Azure Monitor Logs Ingestion API. These rows are only log records; nothing here touches any
real account or system. IPs come from the RFC 5737 documentation ranges.

Usage:
    export DCE_ENDPOINT=...        # terraform output -raw dce_endpoint
    export DCR_IMMUTABLE_ID=...    # terraform output -raw dcr_immutable_id
    python generate_logs.py --scenario baseline|bruteforce|spray|travel|privrole|all
    python generate_logs.py --scenario all --dry-run     # print rows instead of sending
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

STREAM = os.environ.get("STREAM_NAME", "Custom-SOCLabAuth_CL")
DOMAIN = "contoso-lab.com"

USERS = [f"{n}@{DOMAIN}" for n in (
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "rupert", "sybil",
)]
APPS = ["Office 365", "Azure Portal", "SharePoint", "Teams", "Outlook"]

# Home locations (benign) and "suspicious" locations, all documentation IPs.
HOME = [("United States", "Seattle", "198.51.100."), ("United States", "Austin", "198.51.100.")]
FOREIGN = [("Netherlands", "Amsterdam", "203.0.113."), ("Brazil", "Sao Paulo", "203.0.113."),
           ("Singapore", "Singapore", "203.0.113.")]


def now() -> datetime:
    return datetime.now(timezone.utc)


def row(ts, user, ip, country, city, result="Success", reason="", app=None,
        event="SignIn", role="", initiated_by=""):
    return {
        "TimeGenerated": ts.isoformat(),
        "EventType": event,
        "UserPrincipalName": user,
        "SourceIP": ip,
        "Country": country,
        "City": city,
        "Result": result,
        "FailureReason": reason,
        "Application": app or random.choice(APPS),
        "DeviceName": f"LAPTOP-{abs(hash(user)) % 9000 + 1000}",
        "TargetRole": role,
        "InitiatedBy": initiated_by,
    }


def home_ip():
    country, city, prefix = random.choice(HOME)
    return country, city, prefix + str(random.randint(10, 200))


# ---------------------------------------------------------------- scenarios
def baseline(n=150):
    """Normal working-hours activity with a few typo'd passwords."""
    rows, t0 = [], now() - timedelta(minutes=50)
    for _ in range(n):
        country, city, ip = home_ip()
        ts = t0 + timedelta(seconds=random.randint(0, 3000))
        if random.random() < 0.05:
            rows.append(row(ts, random.choice(USERS), ip, country, city, "Failure", "InvalidPassword"))
        else:
            rows.append(row(ts, random.choice(USERS), ip, country, city))
    return rows


def bruteforce():
    """25 failures against one account from one IP, then a success (Rule 01)."""
    user, ip = f"mallory@{DOMAIN}", "203.0.113.50"
    t0 = now() - timedelta(minutes=12)
    rows = [row(t0 + timedelta(seconds=i * 20), user, ip, "Netherlands", "Amsterdam",
                "Failure", "InvalidPassword", app="Azure Portal") for i in range(25)]
    rows.append(row(t0 + timedelta(seconds=25 * 20 + 30), user, ip, "Netherlands", "Amsterdam",
                    app="Azure Portal"))
    return rows


def spray():
    """One IP, one failure per user across 12 users (Rule 02)."""
    ip, t0 = "203.0.113.77", now() - timedelta(minutes=10)
    return [row(t0 + timedelta(seconds=i * 15), u, ip, "Brazil", "Sao Paulo",
                "Failure", "InvalidPassword", app="Outlook")
            for i, u in enumerate(USERS[:12])]


def travel():
    """Same user: Seattle, then Singapore 20 minutes later (Rule 03)."""
    user, t0 = f"grace@{DOMAIN}", now() - timedelta(minutes=30)
    return [
        row(t0, user, "198.51.100.25", "United States", "Seattle"),
        row(t0 + timedelta(minutes=20), user, "203.0.113.120", "Singapore", "Singapore"),
    ]


def privrole():
    """Global Administrator granted by a suspicious initiator (Rule 04).

    Rule 04 only fires outside 08:00-18:00 UTC Mon-Fri, so run this off-hours
    (or temporarily widen the hour range in the rule while testing).
    """
    ts = now() - timedelta(minutes=5)
    if 8 <= ts.hour < 18 and ts.weekday() < 5:
        print("[privrole] Warning: it is business hours (UTC) on a weekday, so Rule 04 will not fire. "
              "Run this off-hours or on a weekend.", file=sys.stderr)
    return [row(ts, f"rupert@{DOMAIN}", "203.0.113.50", "Netherlands", "Amsterdam",
                event="RoleAssignment", role="Global Administrator",
                initiated_by=f"mallory@{DOMAIN}", app="Azure Portal")]


SCENARIOS = {
    "baseline": baseline,
    "bruteforce": bruteforce,
    "spray": spray,
    "travel": travel,
    "privrole": privrole,
}


def send(rows):
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient
    from azure.core.exceptions import HttpResponseError

    endpoint = os.environ.get("DCE_ENDPOINT")
    rule_id = os.environ.get("DCR_IMMUTABLE_ID")
    if not endpoint or not rule_id:
        sys.exit("Set DCE_ENDPOINT and DCR_IMMUTABLE_ID (see README step 3).")

    client = LogsIngestionClient(endpoint=endpoint, credential=DefaultAzureCredential())
    try:
        client.upload(rule_id=rule_id, stream_name=STREAM, logs=rows)
    except HttpResponseError as e:
        sys.exit(f"Upload failed: {e.message}\n(403 right after deploy = RBAC still propagating; wait ~10 min.)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="baseline")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    rows = [r for name in names for r in SCENARIOS[name]()]

    if args.dry_run:
        print(json.dumps(rows, indent=2))
        return
    send(rows)
    print(f"Sent {len(rows)} rows ({', '.join(names)}) to {STREAM}.")


if __name__ == "__main__":
    main()
