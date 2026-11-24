# SELinux on NixOS.
#
# This module tree comes from nix-selinux by Alison Jenkins
# (https://github.com/alisonjenkins/nix-selinux, commit 4eb2952, MIT licence,
# see ./LICENSE): the store is labelled from outside Nix (privileged types only
# for exact store paths named by the configuration), the policy is a
# derivation loaded in the systemd initrd and switched and rolled back with
# the system generation. User documentation: ./selinux.md and
# docs/selinux.md.
#
# security.nix changes: the two packages not in nixpkgs (secilc,
# selinux-policy-minimal) are taken from packages/ when nixpkgs lacks them,
# so no overlay is needed.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.security.selinux;
  inherit (config.boot.kernelPackages) kernel;
  secilc = pkgs.secilc or (pkgs.callPackage ../../packages/secilc { });
in
{
  imports = [
    ./boot.nix
    ./policy.nix
    ./userland.nix
    ./services.nix
  ];

  options.security.selinux = {
    enable = lib.mkEnableOption "SELinux, a mandatory access control system";

    mode = lib.mkOption {
      type = lib.types.enum [
        "permissive"
        "enforcing"
      ];
      default = "permissive";
      description = ''
        `permissive` logs what the policy would block and blocks nothing.
        `enforcing` blocks it. Start permissive.

        If an enforcing system does not boot, choose the previous
        generation in the boot loader, or add `enforcing=0` to the kernel
        command line to boot permissive once.
      '';
    };

    type = lib.mkOption {
      type = lib.types.enum [
        "refpolicy"
        "minimal"
      ];
      default = "refpolicy";
      description = ''
        Which policy to run.

        `refpolicy` is the SELinux reference policy with a NixOS module:
        system services run in the domains it has for them, and
        {option}`security.selinux.services` confines more.

        `minimal` is a small policy written for NixOS in which everything
        is unconfined. It is for experiments and for writing a policy
        from nothing, in CIL. Most other options of this module do not
        apply to it.

        The name is also written to {file}`/etc/selinux/config` as
        `SELINUXTYPE`.
      '';
    };

    policyVersion = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      description = ''
        Kernel policy format version to build the policy for. When null,
        the highest version the policy tools support is used, which must
        not be newer than what the running kernel accepts.
      '';
    };

    loginContexts = lib.mkOption {
      type = lib.types.bool;
      default = cfg.type == "refpolicy";
      defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
      description = ''
        Build PAM and OpenSSH with SELinux support, so that login sessions
        start in the context the policy maps the user to. The policy must
        ship login mappings and default contexts; the minimal policy does
        not.
      '';
    };

    userContextServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = map (user: "home-manager-${user}") (lib.attrNames (config.home-manager.users or { }));
      defaultText = lib.literalExpression ''map (u: "home-manager-''${u}") (attrNames config.home-manager.users)'';
      description = ''
        System services that act for a user and run in the user context
        (`unconfined_u:unconfined_r:unconfined_t`) instead of the
        unconfined service domain: Home Manager activation starts a session
        bus (`dbus-run-session`) and writes the user's files, which the
        system bus domain must not do. [security.nix]
      '';
    };

    pamServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "login"
        "systemd-user"
      ]
      ++ lib.optionals config.services.displayManager.sddm.enable [
        "sddm"
        "sddm-greeter"
      ]
      ++ lib.optional config.services.displayManager.gdm.enable "gdm-password"
      ++ lib.optional config.services.xserver.displayManager.lightdm.enable "lightdm"
      ++ lib.optional config.services.greetd.enable "greetd";
      defaultText = lib.literalExpression ''[ "login" "systemd-user" ] ++ the enabled display manager'';
      description = ''
        PAM services that open user sessions with `pam_selinux`, so that
        the session (and the user's systemd manager) starts in the
        context {option}`security.selinux.loginMappings` gives the user
        instead of the context of the program that opened it. Applies when
        {option}`security.selinux.loginContexts` is on. [security.nix]
      '';
    };

    loginMappings = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            user = lib.mkOption {
              type = lib.types.str;
              description = "SELinux user.";
            };
            range = lib.mkOption {
              type = lib.types.str;
              default = "s0";
              description = "MLS or MCS range.";
            };
          };
        }
      );
      default = {
        root = {
          user = "unconfined_u";
          range = "s0-s0:c0.c1023";
        };
        __default__ = {
          user = "unconfined_u";
          range = "s0-s0:c0.c1023";
        };
      };
      description = ''
        Maps Linux login names to SELinux users, as in the `seusers` file.
        `__default__` applies to every name not listed. The default leaves
        all logins unconfined. Used by the `refpolicy` policy type.
      '';
    };

    dbusMediation = lib.mkOption {
      type = lib.types.bool;
      default = cfg.type == "refpolicy";
      defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
      description = ''
        Build the D-Bus message broker with SELinux support, so that it
        checks messages and name ownership against the policy. Applies
        to the `broker` implementation of {option}`services.dbus`.
      '';
    };

    relabelPaths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [
        "/etc"
        "/var"
        "/root"
        "/home"
        "/nix/var"
      ];
      description = ''
        Mutable paths whose labels are restored when the policy changes.
        The Nix store is labelled separately and must not be listed here.
      '';
    };

    developmentTools = lib.mkEnableOption "tools for analysing denials and writing policy";
  };

  config = lib.mkMerge [
    {
      _module.args.selinuxPkgs = {
        inherit secilc;
        selinux-policy-minimal =
          pkgs.selinux-policy-minimal or (pkgs.callPackage ../../packages/selinux-policy-minimal {
            inherit secilc;
          });
      };
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = !config.security.apparmor.enable;
          message = ''
            security.selinux.enable and security.apparmor.enable cannot both
            be set. Running both security modules together is not supported.
          '';
        }
        {
          # `kernel.config` holds only the options nixpkgs sets explicitly. The
          # stock kernel gets SELinux from the kernel's own defaults, so only an
          # explicit opt-out can be detected here.
          assertion =
            !(kernel ? config)
            || !(kernel.config.isSet "SECURITY_SELINUX")
            || kernel.config.isYes "SECURITY_SELINUX";
          message = ''
            security.selinux.enable requires a kernel built with
            CONFIG_SECURITY_SELINUX=y, but ${kernel.name or "the configured kernel"}
            sets it to something else.
          '';
        }
        {
          assertion = cfg.type == "refpolicy" || cfg.booleans == { };
          message = ''
            security.selinux.booleans has no effect with
            security.selinux.type = "minimal": that policy has no booleans.
            Remove the setting or use the refpolicy type.
          '';
        }
        {
          assertion = cfg.type == "refpolicy" || !cfg.logAllDenials;
          message = ''
            security.selinux.logAllDenials has no effect with
            security.selinux.type = "minimal": that policy hides no denials.
          '';
        }
        {
          assertion = cfg.type == "refpolicy" || !(cfg.loginContexts || cfg.dbusMediation);
          message = ''
            security.selinux.loginContexts and security.selinux.dbusMediation
            need security.selinux.type = "refpolicy": the minimal policy has
            no login mappings and no rules for the message bus.
          '';
        }
        {
          assertion = !(lib.any (lib.hasPrefix "/nix/store") cfg.relabelPaths);
          message = ''
            security.selinux.relabelPaths must not contain the Nix store,
            which is labelled separately.
          '';
        }
      ];

      # The stock kernel has SELinux built in. It is inactive only because it
      # is absent from the `lsm=` parameter that this option renders.
      security.lsm = [ "selinux" ];

      environment.etc."selinux/config".text = ''
        SELINUX=${cfg.mode}
        SELINUXTYPE=${cfg.type}
      '';
    })
  ];
}
