# vulnix

`security.vulnix` scans the system closure periodically with
[vulnix](https://github.com/nix-community/vulnix) against the NVD CVE feeds,
keeps the report, writes one journal line per vulnerable package and, with
MiniSOC, turns them into alerts.

```nix
{
  imports = [ security-nix.nixosModules.vulnix ];   # or .security

  security.vulnix = {
    enable = true;
    interval = "daily";
    whitelist = {
      "openssl-3.0.13" = {
        cve = [ "CVE-2024-0727" ];
        until = "2027-01-01";
        comment = "PKCS12 parsing not reachable here";
      };
      libxml2.comment = "CPE mismatch";          # every CVE, every version
      "*".cve = [ "CVE-2023-12345" ];            # this CVE, any package
    };
  };
}
```

## What runs

- `vulnix.timer` (`interval`, `Persistent`, `randomizedDelay`) starts
  `vulnix.service`: a oneshot running as a dynamic user, with no capability,
  a read-only file system and a low priority. Store queries go through the
  nix daemon.
- By default it scans the **runtime** closure of the current system
  (`--system --closure`). `runtimeOnly = false` scans the build-time
  derivation closure instead (compilers, fetchers, test tools: noisy).
  `scanGcRoots` adds every live GC root (old generations), and `paths` adds
  extra links such as a user profile.
- The NVD cache is kept in `/var/cache/vulnix`. The first run downloads the
  feeds of the last six years (a few hundred MB, several minutes); later runs
  only fetch the `modified` feed, and nothing at all within two hours of the
  previous update. Persist `/var/cache/vulnix` on an ephemeral root, or every
  boot downloads everything again.
- The report (`--json --show-whitelisted`) is kept in
  `/var/lib/vulnix/report.json` (root only, `/var/lib/private`).

Read the result:

```bash
journalctl -u vulnix -o cat | grep -E '^(vulnerable|scan_)'
sudo jq '.[] | select(.affected_by != []) | {name, affected_by}' /var/lib/private/vulnix/report.json
sudo systemctl start vulnix   # scan now
```

## Journal lines

The three scanner modules (`security.vulnix`, [`security.sbomnix`](sbomnix.md),
[`security.containerScan`](container-scan.md)) write the same lines:

```text
vulnerable scanner="vulnix" target="system" pname="openssl" version="3.0.13" severity="critical" count="5" max_cvss="9.8" top="CVE-…,CVE-…,CVE-…" cves="CVE-…,…"
scan_done scanner="vulnix" target="system" vulnerable="12" cves="87" whitelisted="4"
scan_failed scanner="vulnix" target="system" rc="1"
```

`top` holds the three highest-scored CVEs, `cves` all of them. vulnix scans
all its roots at once, so `target` is `system` when only the system is
scanned, `nix-store` otherwise. The line holds no timestamp nor store hash,
so the same finding on the next scan is the same line.

## MiniSOC

`services.minisoc.integrations.vulnix.enable` follows `security.vulnix.enable`.
Each vulnerable package is one alert:

| event_type | example message | severity |
|---|---|---|
| `vuln_vulnerable` | `vulnix: openssl 3.0.13 is affected by 5 CVE (critical, max CVSS 9.8): CVE-…, … (+2)` | from the highest CVSS v3 score: ≥ 9 critical, ≥ 7 high, ≥ 4 medium, < 4 low; unscored (NVD backlog): medium |
| `vuln_scan_failed` | `vulnix scan failed (rc 1): vulnerability findings are no longer updated` | low |

The alert's id is a hash of the line. The next scan adds an occurrence to the
same alert, even after you closed it, so a finding you closed does not come
back every day. A new CVE for the package (or a new version that is still
vulnerable) changes the line and opens a new alert. The fields `scanner`,
`target`, `pname`, `version`, `cves` and `max_cvss` can be used in filter
rules.

Prefer the vulnix whitelist (with `until`) for an accepted risk, and MiniSOC
filters for noise you never want to see. Fixed packages do not close their
alerts: close them once the update is deployed.

## Limits

- **Derivers are required.** vulnix maps every store path to its `.drv`. A
  system built on the host has them. A system copied from another machine
  (`nixos-anywhere`, `nix copy`, `nixos-rebuild --target-host`) has no `.drv`
  on the target, and the scan fails (`scan_failed`). Copy the derivations as
  well (`nix copy --derivation`), or scan on the build machine:
  `vulnix ./result` after `nix build .#nixosConfigurations.<host>.config.system.build.toplevel`.
- **False positives**: names are matched against NVD CPE product names
  without the vendor, so homonyms and CVEs that only affect another platform
  show up.
- **False negatives**: a backported fix is only recognised when the patch
  file name contains the CVE id. Vendored dependencies (Go modules, Cargo,
  npm) and prebuilt binaries (`rustinel`, `elastic-agent` here) are seen only
  by their top-level name and version. A CVE without CPE data (NVD
  enrichment backlog) cannot match.
- Network access to `nvd.nist.gov` (or `mirror`) is needed at scan time.
- vulnix guesses from `nix --help` whether to pass
  `--experimental-features`, and gets it wrong with current Nix: the service
  enables `nix-command` itself (`NIX_CONFIG`). Running `vulnix` by hand on a
  host without flakes needs `NIX_CONFIG="extra-experimental-features = nix-command"`.

## Test

`checks/vulnix-test.nix` runs the real vulnix in a VM against a fictional NVD
mirror served on loopback. It checks that a CVE on a package built in the VM
is reported, that the whitelisted one is not, that two scans give the same
line, that the alert reaches the MiniSOC spool as `critical`, and that a
failed scan is reported. The VRL parser is unit-tested by `minisoc-vector`.
