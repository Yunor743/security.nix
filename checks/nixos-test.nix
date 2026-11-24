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
          }
          // extraConfig;

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

  # Enforcing: a Nix-built ELF copied outside the store cannot be read nor
  # executed, except read by a declared scanner (as Rustinel for YARA).
  fapolicyd-scanners =
    let
      # A distinct store path, so that `exe=` names only this program.
      scanner = pkgs.runCommandLocal "fapolicyd-test-scanner" { } ''
        install -D ${pkgs.gnugrep}/bin/grep $out/bin/test-scanner
      '';
    in
    pkgs.testers.runNixOSTest {
      name = "fapolicyd-scanners";
      nodes.machine = {
        imports = [ self.nixosModules.fapolicyd ];
        services.fapolicyd = {
          enable = true;
          package = fapolicydPkg;
          permissive = false;
          profile = "nixos";
          scanners = [ "${scanner}/bin/test-scanner" ];
        };
        environment.systemPackages = [ scanner ];
      };
      testScript = ''
        machine.wait_for_unit("fapolicyd")
        machine.succeed("install -m 755 ${pkgs.gnugrep}/bin/grep /tmp/nix-elf")
        machine.wait_until_succeeds("journalctl -u fapolicyd | grep -q 'Starting to listen'", timeout=60)

        with subtest("profile denies reading a Nix-built ELF outside the store"):
            machine.fail("cat /tmp/nix-elf > /dev/null")
            machine.wait_until_succeeds("journalctl -u fapolicyd | grep -q 'dec=deny_syslog perm=open.*path=/tmp/nix-elf'")

        with subtest("a declared scanner reads it"):
            machine.succeed("test-scanner -c . /tmp/nix-elf")

        with subtest("but cannot execute it"):
            machine.fail("/tmp/nix-elf --version")

        with subtest("a hardened service (own mount namespace) is mediated too"):
            machine.fail("systemd-run --wait -q -p ProtectSystem=strict /tmp/nix-elf --version")

        with subtest("store programs still run (enforcing)"):
            machine.succeed("ls / && id")
      '';
    };

  # watchMountNamespaces = false (containers): host sessions stay mediated,
  # mount namespaces (here a hardened service) are not.
  fapolicyd-no-namespaces = pkgs.testers.runNixOSTest {
    name = "fapolicyd-no-namespaces";
    nodes.machine = {
      imports = [ self.nixosModules.fapolicyd ];
      services.fapolicyd = {
        enable = true;
        package = fapolicydPkg;
        permissive = false;
        profile = "nixos";
        watchMountNamespaces = false;
      };
    };
    testScript = ''
      machine.wait_for_unit("fapolicyd")
      machine.wait_until_succeeds("journalctl -u fapolicyd | grep -q 'Starting to listen'", timeout=60)
      machine.succeed("grep -q '^allow_filesystem_mark = 0' /etc/fapolicyd/fapolicyd.conf")
      machine.succeed("install -m 755 ${pkgs.gnugrep}/bin/grep /tmp/nix-elf || true")
      machine.succeed("test -x /tmp/nix-elf || (systemctl stop fapolicyd && install -m 755 ${pkgs.gnugrep}/bin/grep /tmp/nix-elf && systemctl start fapolicyd && sleep 3)")

      with subtest("host shell: denied"):
          machine.fail("/tmp/nix-elf --version")

      with subtest("hardened service in its own mount namespace: not mediated"):
          machine.succeed("systemd-run --wait -q -p ProtectSystem=strict /tmp/nix-elf --version")
    '';
  };
}
