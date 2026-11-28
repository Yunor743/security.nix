# security.sbomnix: sbomnix and vulnxscan for real on a `hello` package built
# in the VM, vulnix against the fictional NVD mirror (fake-nvd.nix). grype is
# a stub returning fixed matches: its database cannot be fetched offline.
# Checks the SBOMs (written once per generation), the merge of the scanners
# (`found_by`), the vulnxscan whitelist, OSV skipped by default (no network:
# the scan would fail otherwise), the MiniSOC spool, and that vulnix results
# dropped by vulnxscan are reported.
{ pkgs, self }:

let
  nvd = import ./fake-nvd.nix { inherit pkgs; };
  match = id: score: {
    artifact = {
      name = "hello";
      version = nvd.helloVersion;
    };
    vulnerability = {
      inherit id;
      description = "Fictional grype match";
      cvss = [
        {
          version = "3.1";
          metrics.baseScore = score;
        }
      ];
      fix = {
        state = "fixed";
        versions = [ "2.12.2" ];
      };
    };
  };
  grypeStub = pkgs.writeShellScriptBin "grype" ''
    cat ${
      pkgs.writeText "grype.json" (
        builtins.toJSON {
          matches = [
            (match "CVE-2099-0001" 9.8)
            (match "CVE-2099-0003" 7.5)
          ];
        }
      )
    }
  '';
in
pkgs.testers.runNixOSTest {
  name = "sbomnix";

  nodes.machine = {
    imports = [
      self.nixosModules.security
      nvd.node
    ];
    virtualisation.memorySize = 2048;

    security.sbomnix = {
      enable = true;
      package = pkgs.callPackage ../packages/sbomnix { grype = grypeStub; };
      scanSystem = false;
      targets.hello.path = nvd.targetPath;
      nvdMirror = nvd.mirrorUrl;
      whitelist = [
        {
          vulnId = "CVE-2099-0002";
          package = "hello";
          comment = "test: accepted";
        }
        {
          vulnId = "CVE-2099-0003";
          comment = "expired, applies no more";
          until = "2020-01-01";
        }
      ];
    };

    users.users.alice.isNormalUser = true;
    services.minisoc = {
      enable = true;
      package = pkgs.callPackage ../packages/minisoc { };
      collector.package = import ./vector-buildable.nix { inherit (pkgs) vector; };
      users = [ "alice" ];
    };
  };

  testScript = ''
    import json

    machine.wait_for_unit("minisoc-collector.service")
    machine.wait_for_open_port(8000)
    machine.succeed("${nvd.buildTarget}")
    state = "/var/lib/private/sbomnix/hello"

    def lines():
        return machine.succeed("journalctl -u sbomnix.service -o cat | grep '^vulnerable ' || true").splitlines()

    with subtest("OSV and triage are off by default"):
        script = machine.succeed("systemctl cat sbomnix.service | grep ExecStart= | cut -d= -f2")
        body = machine.succeed(f"cat {script.strip()}")
        assert "--skip-osv" in body and "--triage" not in body, body

    with subtest("the scanners are merged, the whitelist applies"):
        machine.succeed("systemctl start sbomnix.service")
        out = lines()
        print("\n".join(out))
        assert len(out) == 1, out
        line = out[0]
        assert line.startswith('vulnerable scanner="vulnxscan" target="hello" pname="hello" version="${nvd.helloVersion}" severity="critical" count="2" max_cvss="9.8" top="CVE-2099-0001,CVE-2099-0003"'), line
        assert 'found_by="grype,vulnix"' in line, line
        assert "CVE-2099-0002" not in line, line
        machine.succeed("""journalctl -u sbomnix.service -o cat | grep -q 'scan_done scanner="vulnxscan" target="hello" vulnerable="1" cves="2" whitelisted="1"'""")
        machine.succeed(f"test -s {state}/vulns.csv")

    with subtest("SBOMs are written once per generation"):
        sbom = json.loads(machine.succeed(f"cat {state}/sbom/current/sbom.cdx.json"))
        # The test derivation has no pname: sbomnix keeps the full name.
        assert sbom["metadata"]["component"]["name"] == "hello-${nvd.helloVersion}", sbom
        machine.succeed(f"test -s {state}/sbom/current/sbom.spdx.json -a -s {state}/sbom/current/sbom.csv")
        before = machine.succeed(f"stat -c %Y {state}/sbom/current/sbom.cdx.json")
        machine.succeed("systemctl start sbomnix.service")
        assert machine.succeed(f"stat -c %Y {state}/sbom/current/sbom.cdx.json") == before
        again = lines()
        assert len(again) == 2 and again[0] == again[1], again

    with subtest("the finding reaches the MiniSOC spool"):
        machine.wait_until_succeeds(
            "cat /var/lib/minisoc-collector/spool/*.ndjson | grep vuln_vulnerable | grep found_by | grep -q '\"severity\":\"critical\"'"
        )

    with subtest("vulnix results dropped by vulnxscan are reported"):
        machine.succeed("systemctl stop fake-nvd.service")
        machine.succeed("rm -rf /var/cache/private/sbomnix/.cache/vulnix")
        machine.fail("systemctl start sbomnix.service")
        machine.succeed("""journalctl -u sbomnix.service -o cat | grep -q '^scan_failed scanner="vulnix" target="hello" rc="dropped by vulnxscan"'""")
        machine.wait_until_succeeds("cat /var/lib/minisoc-collector/spool/*.ndjson | grep -q vuln_scan_failed")
  '';
}
