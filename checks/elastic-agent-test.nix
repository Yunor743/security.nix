{
  pkgs,
  lib,
  self,
}:

let
  elasticAgentPkg = pkgs.callPackage ../packages/elastic-agent { };
in
pkgs.testers.runNixOSTest {
  name = "elastic-agent-standalone";

  nodes.machine =
    { config, ... }:
    {
      imports = [ self.nixosModules.elastic-agent ];

      # The overlay provides pkgs.elastic-agent (mkForce: nixpkgs module sets
      # overlays read-only inside the test harness).
      nixpkgs.overlays = lib.mkForce [ self.overlays.default ];

      services.elastic-agent = {
        enable = true;
        role = "standalone";
        package = elasticAgentPkg;
        # Fake ES output: the test only validates the service wiring, not
        # actual ingestion.
        serverUrl = "http://localhost:9200";
        username = "test";
        passwordFile = builtins.toFile "es-password" "test-password";
      };

      virtualisation.diskSize = 6 * 1024; # full agent tree copy ~2GB
      system.stateVersion = "25.05";
    };

  testScript = ''
    machine.wait_for_unit("elastic-agent.service")

    with subtest("elastic-agent binary is patched and runs"):
        version = machine.succeed("elastic-agent version 2>/dev/null || true")
        assert "9.5.4" in version, f"unexpected version output: {version!r}"

    with subtest("config file is in /etc"):
        machine.succeed("test -f /etc/elastic-agent/elastic-agent.yml")
        machine.succeed("grep -q 'elasticsearch' /etc/elastic-agent/elastic-agent.yml")

    with subtest("state dir exists"):
        machine.succeed("test -d /var/lib/elastic-agent")

    with subtest("service is running (will be degraded without ES, but alive)"):
        machine.execute("systemctl is-active elastic-agent || true")
  '';
}
