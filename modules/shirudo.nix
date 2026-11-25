{
  config,
  options,
  lib,
  pkgs,
  ...
}:

# shirudo (https://github.com/shirudo-dev/shirudo), a BPF security platform
# in pre-release: after boot, BPF program loads are restricted to signed
# loaders; operators ship signed micropatches ("upatches") and verify the
# TPM-measured state of their targets.
#
# Two roles:
# - operator: holds the signing keys, builds, signs and publishes; the
#   tooling runs on a stock NixOS kernel.
# - target: verifies and enforces. It needs the bpf-next kernel with the
#   signed-loader ABI and shirudo's patches (packages/shirudo/kernel.nix), a
#   TPM 2.0, and shirudo's boot chain (initrd, signed dm-verity runtime and
#   config images). This module prepares the kernel, the TPM, the command
#   line and the units; the boot chain itself (upstream: a dracut module) is
#   not ported to the NixOS initrd yet, so enforcement stays off until the
#   operator provisions the images (`enforce`).

let
  cfg = config.security.shirudo;
  target = cfg.role == "target";

  kernel = pkgs.callPackage ../packages/shirudo/kernel.nix { };
  defaultPackage = pkgs.callPackage ../packages/shirudo {
    inherit kernel;
    role = cfg.role;
  };

  # Programs that load unsigned BPF: refused once a target enforces.
  bpfLoaders = lib.filter (x: x.on) [
    {
      name = "services.rustinel";
      on = config.services.rustinel.enable or false;
    }
    {
      name = "services.jit-hater";
      on = config.services.jit-hater.enable or false;
    }
  ];
in
{
  options.security.shirudo = {
    enable = lib.mkEnableOption "shirudo, the BPF security platform (pre-release)";

    role = lib.mkOption {
      type = lib.types.enum [
        "operator"
        "target"
      ];
      default = "operator";
      description = ''
        `operator`: signing keys and the build / sign / publish tooling
        (`shirudo genkey`, `build`, `image`, `attest`). `target`: the kernel,
        TPM and units of a machine that verifies and enforces. One host has
        one role.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "pkgs.callPackage <security.nix>/packages/shirudo { }";
      description = "shirudo, built against the BTF of `kernel.package`.";
    };

    kernel = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = target;
        defaultText = lib.literalExpression ''role == "target"'';
        description = ''
          Boot the bpf-next kernel with the signed-loader ABI and shirudo's
          patches (a development base: for targets and test machines).
        '';
      };
      package = lib.mkOption {
        type = lib.types.package;
        default = kernel;
        defaultText = lib.literalExpression "pkgs.callPackage <security.nix>/packages/shirudo/kernel.nix { }";
      };
    };

    keysDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/shirudo/keys";
      description = "Operator signing keys (`SHIRUDO_KEYS_DIR`), root-only; shirudo's default, where `shirudo status` looks to recognise an operator. Back them up; persist `/var/lib/shirudo` on an ephemeral root.";
    };

    settings = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.oneOf [
          lib.types.str
          lib.types.int
          lib.types.bool
        ]
      );
      default = { };
      example = {
        "tpm.tcti" = "device:/dev/tpmrm0";
        "map_export.json_path" = "/var/log/shirudo/maps.jsonl";
      };
      description = ''
        `/etc/shirudo/shirudo.conf` (`key = value`): the host file of an
        operator (`tls.classical_hosts`…); on a target the authoritative copy
        lives in the signed images.
      '';
    };

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the target units (`shirudo.service`, map export, keepalive,
        bpm repository sync, XDP reconcile). Only once the operator has
        provisioned the signed runtime and config images under
        `/var/lib/shirudo/images`: from then on, unsigned BPF loaders (Rustinel,
        jit-hater...) are refused.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        environment.systemPackages = [ cfg.package ];
        environment.etc."shirudo/shirudo.conf" = lib.mkIf (cfg.settings != { }) {
          text = lib.concatStrings (
            lib.mapAttrsToList (
              k: v: "${k} = ${if lib.isBool v then lib.boolToString v else toString v}\n"
            ) cfg.settings
          );
          mode = "0600";
        };
      }

      (lib.mkIf (cfg.role == "operator") {
        environment.variables.SHIRUDO_KEYS_DIR = cfg.keysDir;
        # vmlinux.h and the example upatch, under /run/current-system/sw/share/shirudo.
        environment.pathsToLink = [ "/share/shirudo" ];
        systemd.tmpfiles.rules = [
          "d /var/lib/shirudo 0700 root root -"
          "d ${cfg.keysDir} 0700 root root -"
        ];
      })

      (lib.mkIf target {
        assertions = [
          {
            assertion = !cfg.enforce || bpfLoaders == [ ];
            message = "security.shirudo.enforce refuses unsigned BPF loaders: disable ${
              lib.concatMapStringsSep ", " (x: x.name) bpfLoaders
            } (or ship them as signed upatches).";
          }
        ];
        warnings = lib.optional (!cfg.enforce && bpfLoaders != [ ]) ''
          security.shirudo: ${
            lib.concatMapStringsSep ", " (x: x.name) bpfLoaders
          } load unsigned BPF programs; they will be refused once enforce is on.
        '';

        boot.kernelPackages = lib.mkIf cfg.kernel.enable (pkgs.linuxPackagesFor cfg.kernel.package);
        # Keyrings the signed loader and dm-verity check against.
        boot.kernelParams = [
          "bpf.keyring_unsealed=1"
          "dm_verity.keyring_unsealed=1"
        ];
        # The BPF LSM must be active.
        security.lsm = lib.mkIf (options.security ? lsm) (lib.mkAfter [ "bpf" ]);

        security.tpm2 = {
          enable = true;
          tctiEnvironment.enable = true;
        };

        systemd.packages = [ cfg.package ];
        # Shipped units are installed; enabled only with `enforce`.
        systemd.services = lib.mkIf cfg.enforce {
          shirudo.wantedBy = [ "multi-user.target" ];
          shirudo-map-export.wantedBy = [ "multi-user.target" ];
          shirudo-keepalive.wantedBy = [ "multi-user.target" ];
        };
        systemd.tmpfiles.rules = [
          "d /var/lib/shirudo 0700 root root -"
          "d /var/lib/shirudo/images 0700 root root -"
        ];
        security.pam.loginLimits = [
          {
            domain = "root";
            type = "-";
            item = "memlock";
            value = "unlimited";
          }
        ];
      })
    ]
  );
}
