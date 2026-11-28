# security.containerScan with Docker, root Podman and rootless Podman, offline.
# Fictional Alpine images (an apk database, a fake AWS key in /app/.env) are
# loaded and run in each runtime; a declared oci-container is stopped, and a
# Nix-built one (imageStream) must be left out. Real: listing, export (as the
# rootless user too), Trivy SBOM and secret scan (no database needed), one
# export per image id, the whitelist, garbage collection, MiniSOC spool, a
# failing runtime. `trivy sbom` (matching against the vulnerability database,
# which cannot be fetched offline) is a stub reporting every openssl of the
# SBOM, so the matching code path still reads the stored SBOM.
{ pkgs, self }:

let
  trivy = pkgs.trivy;
  trivyStub = pkgs.writeShellScriptBin "trivy" ''
    for a in "$@"; do
      if [ "$a" = sbom ]; then
        for f; do :; done
        exec ${pkgs.jq}/bin/jq '{Results: [{Target: "sbom", Vulnerabilities: [.components[]
          | select(.name == "openssl")
          | {VulnerabilityID: "CVE-2099-1000", PkgName: .name, InstalledVersion: .version,
             FixedVersion: "9.9.9-r0", Severity: "HIGH", CVSS: {nvd: {V3Score: 7.5}}}]}]}' "$f"
      fi
    done
    exec ${trivy}/bin/trivy "$@"
  '';

  image =
    name: opensslVersion:
    pkgs.dockerTools.buildImage {
      inherit name;
      tag = "1";
      copyToRoot = [
        pkgs.pkgsStatic.busybox
        (pkgs.runCommand "${name}-root" { } ''
          mkdir -p $out/etc $out/lib/apk/db $out/app
          echo 3.19.1 > $out/etc/alpine-release
          printf 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.19.1\n' > $out/etc/os-release
          printf 'P:openssl\nV:${opensslVersion}\nA:x86_64\nL:Apache-2.0\no:openssl\n\n' > $out/lib/apk/db/installed
          echo 'AWS_ACCESS_KEY_ID=AKIAZ7Q2M4X9W3R8T6YV' > $out/app/.env
        '')
      ];
      config.Cmd = [
        "/bin/sleep"
        "3600"
      ];
    };
  dockerImg = image "app-docker" "3.0.13-r0";
  podmanImg = image "app-podman" "3.0.12-r0";
  rootlessImg = image "app-rootless" "3.0.11-r0";
  declaredImg = image "app-declared" "3.0.10-r0";
  nixImg = pkgs.dockerTools.streamLayeredImage {
    name = "nixy";
    tag = "1";
    contents = [ pkgs.pkgsStatic.busybox ];
    config.Cmd = [
      "/bin/sleep"
      "3600"
    ];
  };
in
pkgs.testers.runNixOSTest {
  name = "container-scan";

  nodes.machine = {
    imports = [ self.nixosModules.security ];
    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 4096;
    virtualisation.docker.enable = true;
    virtualisation.podman.enable = true;
    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      linger = true;
    };

    virtualisation.oci-containers = {
      backend = "podman";
      containers = {
        declared = {
          image = "localhost/app-declared:1";
          autoStart = false;
        };
        nixy = {
          image = "nixy:1";
          imageStream = nixImg;
          autoStart = false;
        };
      };
    };

    security.containerScan = {
      enable = true;
      package = trivyStub;
      podman.rootlessUsers = [ "alice" ];
      whitelist = [
        {
          kind = "secret";
          id = "aws-access-key-id";
          image = "app-podman";
          comment = "test: accepted for this image only";
        }
      ];
    };

    services.minisoc = {
      enable = true;
      package = pkgs.callPackage ../packages/minisoc { };
      collector.package = import ./vector-buildable.nix { inherit (pkgs) vector; };
      users = [ "alice" ];
    };
  };

  testScript = ''
    machine.wait_for_unit("minisoc-collector.service")
    machine.wait_for_unit("docker.service")
    machine.wait_for_unit("user@1000.service")
    alice = "sudo -u alice XDG_RUNTIME_DIR=/run/user/1000"

    machine.succeed("docker load -i ${dockerImg}")
    machine.succeed("docker run -d --name web --network none app-docker:1")
    machine.succeed("podman load -i ${podmanImg}")
    machine.succeed("podman run -d --name api --network none localhost/app-podman:1")
    machine.succeed("podman load -i ${declaredImg}")
    machine.succeed("${nixImg} | podman load")
    machine.succeed(f"cd /tmp && {alice} podman load -i ${rootlessImg}")
    machine.succeed(f"cd /tmp && {alice} podman run -d --name rl --network none localhost/app-rootless:1")

    state = "/var/lib/private/container-scan"

    def journal(prefix):
        return machine.succeed(f"journalctl -u container-scan.service -o cat | grep '^{prefix} ' || true").splitlines()

    with subtest("every runtime is listed, the Nix-built image is not"):
        machine.succeed("systemctl start container-scan.service")
        images = machine.succeed(f"cat {state}/export/images.tsv")
        print(images)
        for ref, label in [("app-docker:1", "docker"), ("localhost/app-podman:1", "podman"),
                           ("localhost/app-rootless:1", "podman:alice"), ("localhost/app-declared:1", "podman")]:
            assert any(l.split("\t")[1] == ref and l.split("\t")[3] == label for l in images.splitlines()), (ref, images)
        assert "nixy" not in images, images
        machine.fail(f"ls {state}/export/*.tar")

    with subtest("one line per vulnerable package and image, secrets, whitelist"):
        vulns = journal("vulnerable")
        print("\n".join(vulns))
        assert len(vulns) == 4, vulns
        for version in ["3.0.13-r0", "3.0.12-r0", "3.0.11-r0", "3.0.10-r0"]:
            line = [l for l in vulns if f'version="{version}"' in l]
            assert len(line) == 1 and 'severity="high"' in line[0] and 'fixed="9.9.9-r0"' in line[0], (version, vulns)
        assert any('target="localhost/app-rootless:1@sha256:' in l for l in vulns), vulns
        secrets = journal("secret")
        print("\n".join(secrets))
        assert len(secrets) == 3, secrets
        assert not any("app-podman" in l for l in secrets), secrets
        assert all('rule="aws-access-key-id"' in l and 'path="/app/.env"' in l for l in secrets), secrets

    with subtest("an image is exported once, lines are stable"):
        before = machine.succeed(f"stat -c %Y {state}/sbom/*.cdx.json")
        machine.succeed("systemctl start container-scan.service")
        assert machine.succeed(f"stat -c %Y {state}/sbom/*.cdx.json") == before
        again = journal("vulnerable")
        assert len(again) == 8 and sorted(again[:4]) == sorted(again[4:]), again

    with subtest("the findings reach the MiniSOC spool"):
        machine.wait_until_succeeds("cat /var/lib/minisoc-collector/spool/*.ndjson | grep vuln_vulnerable | grep -q container_scan")
        machine.wait_until_succeeds("cat /var/lib/minisoc-collector/spool/*.ndjson | grep -q vuln_secret")

    with subtest("images no longer in use are forgotten"):
        n = int(machine.succeed(f"ls {state}/sbom/*.cdx.json | wc -l"))
        assert n == 4, n
        machine.succeed("docker rm -f web && docker rmi app-docker:1")
        machine.succeed("systemctl start container-scan.service")
        assert int(machine.succeed(f"ls {state}/sbom/*.cdx.json | wc -l")) == 3

    with subtest("a runtime that cannot be listed is reported"):
        machine.succeed("systemctl stop docker.service docker.socket")
        machine.fail("systemctl start container-scan.service")
        machine.succeed("""journalctl -u container-scan.service -o cat | grep -q '^scan_failed scanner="trivy" target="docker" rc="cannot list containers"'""")
        machine.wait_until_succeeds("cat /var/lib/minisoc-collector/spool/*.ndjson | grep -q vuln_scan_failed")
  '';
}
