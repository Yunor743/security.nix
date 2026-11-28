# security.vulnix with the real vulnix against a fictional NVD mirror served
# on loopback (fake-nvd.nix): a CVE on a `hello` package is reported as one
# deterministic journal line, a whitelisted one is not, the line reaches the
# MiniSOC spool as a critical alert, and a failed scan is reported too.
{ pkgs, self }:

let
  nvd = import ./fake-nvd.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "vulnix";

  nodes.machine = {
    imports = [
      self.nixosModules.security
      nvd.node
    ];
    virtualisation.memorySize = 2048;

    security.vulnix = {
      enable = true;
      scanSystem = false;
      paths = [ nvd.targetPath ];
      mirror = nvd.mirrorUrl;
      whitelist.hello = {
        cve = [ "CVE-2099-0002" ];
        comment = "test: accepted";
      };
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

    with subtest("the timer is installed"):
        machine.succeed("systemctl list-timers --all | grep -q vulnix.timer")

    def lines():
        return machine.succeed("journalctl -u vulnix.service -o cat | grep '^vulnerable ' || true").splitlines()

    with subtest("the CVE on hello is reported, the whitelisted one is not"):
        machine.succeed("systemctl start vulnix.service")
        out = lines()
        print("\n".join(out))
        hello = [l for l in out if 'pname="hello"' in l]
        assert len(hello) == 1, out
        assert 'version="${nvd.helloVersion}" severity="critical" count="1" max_cvss="9.8" top="CVE-2099-0001"' in hello[0], hello
        assert hello[0].startswith('vulnerable scanner="vulnix" target="nix-store" '), hello
        assert "CVE-2099-0002" not in hello[0], hello
        machine.succeed("""journalctl -u vulnix.service -o cat | grep -q 'scan_done scanner="vulnix" target="nix-store" vulnerable="1" cves="1" whitelisted="1"'""")
        report = json.loads(machine.succeed("cat /var/lib/private/vulnix/report.json"))
        entry = [e for e in report if e["pname"] == "hello"][0]
        assert entry["whitelisted"] == ["CVE-2099-0002"], entry
        assert machine.succeed("stat -c %a /var/lib/private").strip() == "700"

    with subtest("the finding reaches the MiniSOC spool as a critical alert"):
        machine.wait_until_succeeds(
            "cat /var/lib/minisoc-collector/spool/*.ndjson | grep vuln_vulnerable | grep -q '\"severity\":\"critical\"'"
        )

    with subtest("a second scan (cached NVD) gives the same line"):
        machine.succeed("systemctl start vulnix.service")
        again = lines()
        assert len(again) == 2 and again[0] == again[1], again

    with subtest("a failed scan is reported"):
        machine.succeed("systemctl stop fake-nvd.service")
        machine.succeed("rm -rf /var/cache/private/vulnix/*")
        machine.fail("systemctl start vulnix.service")
        machine.succeed("""journalctl -u vulnix.service -o cat | grep -q '^scan_failed scanner="vulnix"'""")
        machine.wait_until_succeeds("cat /var/lib/minisoc-collector/spool/*.ndjson | grep -q vuln_scan_failed")
  '';
}
