{
  pkgs,
  lib,
  self,
}:

let
  jitHaterPkg = pkgs.callPackage ../packages/jit-hater { };
in
pkgs.testers.runNixOSTest {
  name = "jit-hater";

  nodes.machine =
    { config, ... }:
    {
      imports = [ self.nixosModules.jit-hater ];

      # The overlay provides pkgs.jit-hater (mkForce: nixpkgs module sets
      # overlays read-only inside the test harness).
      nixpkgs.overlays = lib.mkForce [ self.overlays.default ];

      services.jit-hater = {
        enable = true;
        package = jitHaterPkg;
      };

      # For the CLI check.
      environment.systemPackages = [ jitHaterPkg ];

      system.stateVersion = "25.05";
    };

  testScript = ''
    machine.wait_for_unit("jit-hater.service")

    with subtest("service stays active (a config schema mismatch makes it crash-loop)"):
        machine.execute("sleep 15")
        status = machine.succeed("systemctl is-active jit-hater").strip()
        assert status == "active", f"expected active, got: {status!r}"

    with subtest("binary accepts the generated config (nested schema)"):
        # The binary uses serde with deny_unknown_fields: flat keys such as
        # `dump.directory:` are rejected with "unknown field" and the service
        # crash-loops. The module must emit nested YAML sections.
        machine.fail("journalctl -u jit-hater | grep -q 'unknown field'")

    with subtest("dump directory on tmpfs is root-owned 0700"):
        machine.succeed("test -d /dev/shm/jit-hater")
        machine.succeed("test \"$(stat -c '%U %a' /dev/shm/jit-hater)\" = 'root 700'")

    with subtest("state directory exists"):
        machine.succeed("test -d /var/lib/jit-hater")

    with subtest("rules CLI lists the built-in rules"):
        machine.succeed("jit-hater rules | grep -q fluctuation")
  '';
}
