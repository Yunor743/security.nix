"""Helpers of security.sbomnix (stdlib only).

whitelist ENTRIES_JSON
    Print the vulnxscan whitelist CSV, without the entries whose `until`
    date has passed (vulnxscan's whitelist has no expiry).

lines TARGET REPORT_CSV TRIAGE_CSV STDERR
    Print the journal lines of one vulnxscan run (format in vulnscan-lib.nix):
    one `vulnerable` line per package, `scan_done`, and a `scan_failed` line
    for vulnix when vulnxscan dropped its results. Missing files are fine:
    vulnxscan writes no report when it finds nothing.
"""

import csv
import datetime
import json
import os
import re
import sys

SCANNERS = ("grype", "osv", "vulnix")
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
WORDS = {"moderate": "medium", "important": "high"}


def kv(key, value):
    return f" {key}={json.dumps(str(value))}"


def score(value):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    return f if 0 <= f <= 10 else 0.0


def severity(value):
    s = score(value)
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    if s > 0:
        return "low"
    word = str(value or "").strip().lower()
    word = WORDS.get(word, word)
    return word if word in RANK else "unknown"


def read_csv(path):
    if not os.path.exists(path):
        return None, []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return reader.fieldnames or [], list(reader)


def whitelist(entries_json):
    today = datetime.date.today().isoformat()
    with open(entries_json, encoding="utf-8") as f:
        entries = json.load(f)
    out = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)
    out.writerow(["vuln_id", "comment", "package", "version_local", "whitelist"])
    for e in entries:
        if e.get("until") and e["until"] <= today:
            continue
        out.writerow(
            [e["vulnId"], e["comment"], e.get("package") or "", e.get("version") or "", "True"]
        )


def lines(target, report_csv, triage_csv, stderr_path):
    fields, rows = read_csv(report_csv)
    _, triage = read_csv(triage_csv)
    head = 'scanner="vulnxscan"' + kv("target", target)

    # vulnxscan keeps going when vulnix fails (it logs the CalledProcessError
    # and drops the vulnix results): the report then has no vulnix column.
    if fields is not None:
        vulnix_ok = "vulnix" in fields
    else:
        try:
            with open(stderr_path, encoding="utf-8", errors="replace") as f:
                vulnix_ok = not re.search(r"\['vulnix'", f.read())
        except OSError:
            vulnix_ok = True

    active = [r for r in rows if r.get("whitelist", "False") not in ("True", "true", "1")]
    fixes = {}
    for t in triage:
        key = (t.get("vuln_id", ""), t.get("package", ""))
        fixes[key] = t

    packages = {}
    for r in active:
        packages.setdefault((r.get("package", "?"), r.get("version_local", "?")), []).append(r)

    for (pname, version), vulns in sorted(packages.items()):
        by_id = {}
        for r in vulns:
            by_id.setdefault(r["vuln_id"], r)
        ranked = sorted(by_id.values(), key=lambda r: (-score(r.get("severity")), r["vuln_id"]))
        sev = max((severity(r.get("severity")) for r in ranked), key=lambda s: RANK.get(s, 0))
        found_by = sorted({s for r in vulns for s in SCANNERS if r.get(s) == "1"})
        line = (
            "vulnerable " + head + kv("pname", pname) + kv("version", version)
            + kv("severity", sev) + kv("count", len(ranked))
            + kv("max_cvss", max(score(r.get("severity")) for r in ranked))
            + kv("top", ",".join(r["vuln_id"] for r in ranked[:3]))
            + kv("cves", ",".join(sorted(by_id)))
        )
        fixed = sorted(
            {
                t.get("version_nixpkgs", "")
                for r in ranked
                for t in [fixes.get((r["vuln_id"], pname), {})]
                if t.get("classify") == "fix_update_to_version_nixpkgs" and t.get("version_nixpkgs")
            }
        )
        if fixed:
            line += kv("fixed", fixed[-1])
        if found_by:
            line += kv("found_by", ",".join(found_by))
        print(line)

    print(
        "scan_done " + head + kv("vulnerable", len(packages))
        + kv("cves", len({r["vuln_id"] for r in active}))
        + kv("whitelisted", len(rows) - len(active))
    )
    if not vulnix_ok:
        print('scan_failed scanner="vulnix"' + kv("target", target) + kv("rc", "dropped by vulnxscan"))
        return 3
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "whitelist":
        whitelist(sys.argv[2])
    else:
        sys.exit(lines(*sys.argv[2:6]))
