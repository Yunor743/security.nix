{
  pkgs,
  self,
}:

let
  fapolicydPkg = pkgs.callPackage ../packages/fapolicyd { };

  makeTest =
    name: extraConfig:
    pkgs.testers.runNixOSTest {
      inherit name;

      nodes.machine =
        { config, ... }:
        {
          imports = [ self.nixosModules.fapolicyd ];

          services.fapolicyd = {
            enable = true;
            package = fapolicydPkg;
          } // extraConfig;

          system.stateVersion = "25.05";
        };

      testScript = ''
        machine.wait_for_unit("fapolicyd")

        with subtest("fapolicyd daemon is running"):
            machine.succeed("systemctl is-active fapolicyd")

        with subtest("fapolicyd-cli is available"):
            machine.succeed("fapolicyd-cli --list")

        with subtest("config files are in /etc"):
            machine.succeed("test -f /etc/fapolicyd/fapolicyd.conf")
            machine.succeed("test -f /etc/fapolicyd/compiled.rules")
            machine.succeed("test -f /etc/fapolicyd/fapolicyd.trust")
            machine.succeed("test -d /etc/fapolicyd/rules.d")

        with subtest("fapolicyd user and group exist"):
            machine.succeed("id fapolicyd")
            machine.succeed("getent group fapolicyd")
      '';
    };
in
{
  permissive = makeTest "fapolicyd-permissive" {
    permissive = true;
    profile = "nixos";
  };

  enforcing-nixos = makeTest "fapolicyd-enforcing-nixos" {
    permissive = false;
    profile = "nixos";
  };

  known-libs = makeTest "fapolicyd-known-libs" {
    permissive = true;
    profile = "known-libs";
  };
}