# Container scan

`security.containerScan` scans the container images in use with
[Trivy](https://trivy.dev): Docker, root Podman and rootless Podman. It
reports known vulnerabilities (OS packages: apk, dpkg, rpm; language
dependencies: lockfiles, jars, Go and cargo-auditable Rust binaries) and
secrets left in the image layers. The findings become journal lines and
MiniSOC alerts.

```nix
{
  imports = [ security-nix.nixosModules.containerScan ];   # or .security

  security.containerScan = {
    enable = true;                 # follows virtualisation.docker / podman
    podman.rootlessUsers = [ "alice" ];
    minimumSeverity = "medium";
    whitelist = [
      { id = "CVE-2024-0727"; package = "openssl"; image = "^docker.io/library/nginx:"; comment = "not reachable"; }
      { kind = "secret"; id = "aws-access-key-id"; image = "^localhost/test-fixture"; comment = "fake key of a fixture"; }
    ];
  };
}
```

## What is covered

| source | how the images are found |
|---|---|
| running containers (`running`, default) | `docker ps` / `podman ps` for each runtime: `docker run`, compose, `podman run`, oci-containers |
| `virtualisation.oci-containers` (`fromOciContainers`, default) | the declared image of each container, even when it is stopped |
| Docker | `docker.enable`, follows `virtualisation.docker.enable` |
| root Podman | `podman.enable`, follows `virtualisation.podman.enable` |
| rootless Podman | `podman.rootlessUsers`, defaults to the non-root `podman.user` of oci-containers; add the users who run containers by hand. Give them `linger` |

Images built by Nix are not scanned by Trivy: they have no package database,
so Trivy would find nothing.
- `imageStream` (`dockerTools.streamLayeredImage`): its closure holds the image
  contents. It becomes a target of `security.sbomnix` (`image-<container>`)
  and a path of `security.vulnix`, when those modules are enabled. Otherwise
  the module warns.
- `imageFile` (`buildImage`, `buildLayeredImage`): the compressed tarball
  references nothing that vulnix or sbomnix could follow. It is not scanned,
  and the module warns. Use `imageStream` instead.

Not covered yet: containerd / k3s, images in a registry that are not pulled
on the host.

## How it works

An image id is immutable, so each image is exported and inventoried **once**:

1. `ExecStartPre=+` (root) lists the containers of each runtime and exports
   only the images that have no SBOM yet (`docker save`, `podman save`; for
   a rootless user, through `runuser` as that user).
2. The scanner, an unprivileged dynamic user without any container socket,
   turns each export into a CycloneDX SBOM (`trivy image --format cyclonedx`)
   and a secret report (`--scanners secret`), then deletes the export.
3. At every run, each SBOM in use is matched against the day's Trivy database
   (`trivy sbom`). This is fast and needs no daemon.

The code that parses untrusted image content therefore never holds the
Docker socket, which is root-equivalent. SBOMs of images no longer in use are
removed. The state is in `/var/lib/container-scan` (`sbom/<image id>.*`,
`export/images.tsv`: id, reference, container, runtime), the database in
`/var/cache/container-scan`.

## Privacy

Trivy downloads its database (default: mirror.gcr.io, then ghcr.io;
`dbRepository` to change it) and matches locally. Trivy also sends anonymous
usage data to Aqua and checks for updates by default: the module turns both
off (`--disable-telemetry --skip-version-check`). Nothing about the images
leaves the host.

## Journal lines and MiniSOC

Same format as [vulnix](vulnix.md#journal-lines), with `scanner="trivy"`, the
image as `target` (`reference@sha256:<12 hex of the id>`), and the fixed
version when Trivy knows one:

```text
vulnerable scanner="trivy" target="docker.io/library/nginx:1.27@sha256:0123456789ab" pname="openssl" version="3.0.13-r0" severity="high" count="2" max_cvss="9.8" top="CVE-…,CVE-…" cves="CVE-…,CVE-…" fixed="3.0.15-r0"
secret scanner="trivy" target="…" rule="aws-access-key-id" title="AWS Access Key ID" path="/app/.env"
scan_failed scanner="trivy" target="docker" rc="cannot list containers"
```

The severity is Trivy's (the highest of the package's vulnerabilities). A
pulled new image has a new id, so its findings are new alerts.
`services.minisoc.integrations.containerScan.enable` follows the module
(source `container_scan`):

| event_type | severity |
|---|---|
| `vuln_vulnerable` | Trivy's (`unknown` becomes `medium`) |
| `vuln_secret` | high |
| `vuln_scan_failed` | low: a runtime that cannot be listed, an image that cannot be exported or scanned |

Options: `minimumSeverity` (default `low`; unscored vulnerabilities are kept
unless it is `medium` or above), `ignoreUnfixed`, `whitelist` (regular
expressions on the id, optional package and image reference, `until`).

## Limits

- Export copies the image (`docker save`): large images need disk space in
  `/var/lib/container-scan` once, the first time they are seen.
- Rootless Podman without `linger` has no runtime directory outside a
  session: such a user's running containers are seen only while they are
  logged in.

## Test

`checks/container-scan-test.nix` runs Docker, root Podman and a rootless user
offline, with fictional Alpine images (an apk database, a fake AWS key), a
stopped declared container and a Nix-built one. It checks for real:
- the listing and the exports;
- the Trivy SBOMs and secret scan;
- one export per image;
- the whitelist;
- the garbage collection;
- the MiniSOC spool;
- a runtime that cannot be listed.

`trivy sbom` is a stub, because the vulnerability database cannot be fetched
offline. It still reads the stored SBOM and reports every `openssl` in it.
`checks/vulnscan-eval.nix` checks how oci-containers are split between Trivy
and sbomnix / vulnix.
