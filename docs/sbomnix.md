# sbomnix

`security.sbomnix` uses [sbomnix](https://github.com/tiiuae/sbomnix) to keep
an SBOM of the system for every generation (CycloneDX, SPDX, CSV), and to scan
it with **vulnxscan**: grype and vulnix, plus OSV.dev on opt-in. CVEs that a
nixpkgs patch names are dropped, the whitelist is applied, and the findings
become journal lines and MiniSOC alerts.

```nix
{
  imports = [ security-nix.nixosModules.sbomnix ];   # or .security

  security.sbomnix = {
    enable = true;
    interval = "weekly";
    whitelist = [
      {
        vulnId = "CVE-2024-0727";
        package = "openssl";
        comment = "PKCS12 parsing not reachable here";
        until = "2027-01-01";
      }
    ];
  };
}
```

## vulnix or sbomnix?

| | `security.vulnix` | `security.sbomnix` |
|---|---|---|
| Scanners | vulnix (NVD) | grype (NVD, GitHub advisories, distributions) + vulnix, OSV.dev on opt-in |
| SBOM | no | CycloneDX, SPDX and CSV per generation |
| Nixpkgs patches | vulnix's patch-name check | vulnxscan drops a CVE when every component carries a patch naming it |
| Cost | light, daily | heavier (two scanners, grype database), weekly by default |
| What leaves the host | NVD feeds downloaded | NVD feeds, grype database, CPE dictionary downloaded; OSV / triage only with `allowRemote` |

vulnxscan already runs vulnix. If both modules scan the system with MiniSOC
on, every vulnix finding is reported twice, and the module warns about it.
Pick one, or use vulnix daily and sbomnix for the SBOM only
(`scan.enable = false`).

## What runs

`sbomnix.timer` starts `sbomnix.service`: a oneshot running as a dynamic user,
with no capability and a read-only file system. For each target:

1. **SBOM** (`sbom.enable`): `sbomnix <path>` writes
   `/var/lib/sbomnix/<target>/sbom/<store path name>/sbom.{cdx.json,spdx.json,csv}`.
   A generation that already has an SBOM is not done again. `current` links to
   the latest, and the `sbom.keep` newest (10) are kept. To diff two
   generations, compare their `sbom.csv`.
2. **Scan** (`scan.enable`): `vulnxscan <path> --skip-osv`. The report is kept
   in `/var/lib/sbomnix/<target>/vulns.csv` (and `vulns.triage.csv` with
   triage).

Targets: `system` (`/run/current-system`, `scanSystem = true`) plus `targets`.
A target can be a GC root that a CI keeps up to date with the closure of
another host, which covers a fleet from the build machine:

```nix
security.sbomnix.targets.laptop.path = "/nix/var/nix/gcroots/ci/laptop";
```

The caches (vulnix NVD data, the grype database, the sbomnix CPE dictionary)
are in `/var/cache/sbomnix`. Persist it on an ephemeral root, or every boot
downloads everything again.

## Privacy: `allowRemote`

By default only databases are downloaded: nothing about the host is sent. The
remote lookups are off:

| option | what is sent, and where |
|---|---|
| `allowRemote.osv` | name and version of **every** package of the target, to api.osv.dev (Google), at every scan |
| `allowRemote.triage` | names of the vulnerable packages, to repology.org; the fixed version available in nixpkgs is then reported (`fixed`) |
| `allowRemote.nixpkgsPrs` | with triage, every CVE id to api.github.com (search for nixpkgs pull requests; rate limited without a token) |

## Journal lines and MiniSOC

The same format as [vulnix](vulnix.md#journal-lines), with `scanner="vulnxscan"`,
`target` the target name, and:

- `found_by="grype,vulnix"`: the scanners that reported the package; a
  finding reported by several scanners is more credible;
- `fixed="…"`: with triage, the version nixpkgs already ships with a fix.

```text
vulnerable scanner="vulnxscan" target="system" pname="curl" version="8.1.0" severity="high" count="1" max_cvss="7.5" top="CVE-2023-38545" cves="CVE-2023-38545" found_by="grype,vulnix"
```

`services.minisoc.integrations.sbomnix.enable` follows `security.sbomnix.enable`
(source `sbomnix`, event types as for vulnix).

When vulnix fails inside vulnxscan (NVD unreachable, missing derivers),
vulnxscan **drops its results silently** and keeps going with grype alone. The
module detects it, writes
`scan_failed scanner="vulnix" target="…" rc="dropped by vulnxscan"` (a `low`
alert) and the unit fails.

## Package

`packages/sbomnix` is nixpkgs' sbomnix with fixes: at the locked nixos-unstable
revision it does not build.
- SimpleSQLite and sqliteschema pin `typepy < 2`. Relaxed: SimpleSQLite's own
  test suite passes with typepy 2.0.
- reuse's Sphinx `man` builder produces nothing with Sphinx 9.1. Only the
  HTML docs are kept.
- The wrapper's `makeWrapperArgs` is one string, which makeWrapper rejects.

`grype` and `vulnix` are package arguments: `nvdMirror` wraps vulnix with
`--mirror`, and the VM test replaces grype with a stub.

## Limits

- The `.drv` files of the target are required, as for [vulnix](vulnix.md#limits).
- Licences and other nixpkgs metadata are not in the SBOMs: sbomnix reads
  them only for flake references, and the module scans store paths.
- Vendored dependencies (Cargo, Go modules, npm) and prebuilt binaries are
  seen only by their top-level name and version.

## Test

`checks/sbomnix-test.nix` runs sbomnix and vulnxscan in a VM on a package
built there. vulnix runs for real against a fictional NVD mirror; grype is a
stub (its database cannot be fetched offline). The test checks:
- the merge of the scanners (`found_by`) and the whitelist, including an
  expired entry;
- the SBOMs, written once per generation;
- OSV skipped by default;
- the MiniSOC spool;
- the detection of vulnix results dropped by vulnxscan.

`checks/vulnscan-eval.nix` checks the privacy defaults and the wiring.
