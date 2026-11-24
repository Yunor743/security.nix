# Loads the policy and labels the filesystem early in boot, and keeps the
# store labelled when the system is switched.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.security.selinux;

  setupTool = pkgs.callPackage ./setup { };

  # Identifies the exact-path rules, so the store paths they apply to are
  # relabelled when those rules change and not otherwise.
  exactRevision = builtins.substring 0 32 (
    builtins.hashString "sha256" (
      lib.concatMapStrings (e: "${toString e.path}=${e.type}\n") (lib.attrValues cfg.entrypoints)
      # Rules the policy derives itself change only when the policy does.
      + builtins.unsafeDiscardStringContext (toString cfg.policy)
    )
  );

  policyFile = "${cfg.policy}/policy/policy.${toString cfg.policy.policyVersion}";

  # The setup tool with this system's policy and rules filled in.
  setup = pkgs.writeShellScript "selinux-setup" ''
    exec ${lib.getExe setupTool} \
      --policy ${policyFile} \
      --spec ${cfg.policy}/contexts/files/file_contexts \
      --rev ${cfg.labelRevision} \
      --mutable-rev ${cfg.mutableLabelRevision} \
      --exact-rev ${exactRevision} \
      --exact-file ${cfg.policy}/nixos/exact-paths \
      ${lib.concatMapStringsSep " " (p: "--relabel ${lib.escapeShellArg p}") cfg.relabelPaths} \
      "$@"
  '';

  storeLabelsPath = pkgs.runCommand "selinux-store-labels-path" { } ''
    mkdir -p $out/lib/systemd/system
    {
      echo "[Unit]"
      echo "Description=Watch Nix Store Files That Have Specific SELinux Labels"
      echo "ConditionSecurity=selinux"
      echo "[Path]"
      sed 's/^/PathChanged=/' ${cfg.policy}/nixos/exact-paths
    } > $out/lib/systemd/system/selinux-store-labels.path
  '';
in
{
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !config.system.nixos-init.enable;
        message = ''
          security.selinux.enable does not support system.nixos-init.enable
          yet: the policy is loaded by a unit that runs before the NixOS
          activation unit in the initrd.
        '';
      }
    ];

    # Found by the initrd through the system closure it is about to boot.
    system.systemBuilderCommands = ''
      ln -s ${setup} $out/selinux-setup
    '';

    # Before activation, with the store still writable: load the policy and
    # label the new root. Activation then creates correctly labelled files,
    # and the real systemd enters its domain when the initrd hands over.
    boot.initrd.systemd.services.initrd-selinux-setup = {
      description = "Load SELinux Policy and Label the New Root";
      unitConfig = {
        DefaultDependencies = false;
        RequiresMountsFor = [ "/sysroot/nix/store" ];
      };
      after = [
        "initrd-find-nixos-closure.service"
        "initrd-fs.target"
      ];
      before = [ "initrd-nixos-activation.service" ];
      # Permissive systems still boot if this fails. Enforcing ones must not.
      ${if cfg.mode == "enforcing" then "requiredBy" else "wantedBy"} = [
        "initrd-nixos-activation.service"
      ];
      serviceConfig.Type = "oneshot";
      script = ''
        set -uo pipefail
        export PATH="/bin:${config.boot.initrd.systemd.package.util-linux}/bin"

        closure=$(readlink /nixos-closure)
        if [ ! -e "/sysroot$closure/selinux-setup" ] && [ ! -L "/sysroot$closure/selinux-setup" ]; then
          echo "$closure has no SELinux setup - skipping"
          exit 0
        fi

        if [ ! -d /sys/fs/selinux ]; then
          echo "SELinux is not active in this kernel - skipping"
          exit 0
        fi
        [ -e /sys/fs/selinux/load ] || mount -t selinuxfs selinuxfs /sys/fs/selinux

        # The setup tool lives in the new root and needs these there. They
        # are fresh mounts, not binds of the initrd's own: unmounting a bind
        # of /sys would propagate back and take the initrd's cgroup mounts
        # with it. They are removed again because stage 2 mounts its own.
        mkdir -p /sysroot/proc /sysroot/sys /sysroot/dev
        mount -t proc proc /sysroot/proc
        mount -t sysfs sysfs /sysroot/sys
        mount -t selinuxfs selinuxfs /sysroot/sys/fs/selinux
        mount -t devtmpfs devtmpfs /sysroot/dev
        cleanup() {
          umount /sysroot/dev /sysroot/sys/fs/selinux /sysroot/sys /sysroot/proc
        }
        trap cleanup EXIT

        chroot /sysroot "$closure/selinux-setup"
      '';
    };

    systemd = {
      # Watches every store file that has a specific label. Whatever
      # replaces one of them (any form of store optimisation, a repair)
      # starts selinux-store-labels.service, which puts the label back.
      # The list of files is known only once the policy is built, so the
      # unit is generated there.
      packages = [ storeLabelsPath ];
      paths.selinux-store-labels.wantedBy = [ "multi-user.target" ];

      services = {
        # After activation: restore labels on the mutable paths if the
        # rules changed. On first boot this covers what activation just
        # created.
        selinux-relabel = {
          description = "Restore SELinux Labels on Mutable Paths";
          unitConfig = {
            DefaultDependencies = false;
            ConditionSecurity = "selinux";
          };
          wantedBy = [ "sysinit.target" ];
          after = [ "local-fs.target" ];
          before = [
            "sysinit.target"
            "shutdown.target"
            # These create and adjust files under the paths being relabelled.
            "systemd-tmpfiles-setup.service"
            "systemd-journal-flush.service"
          ];
          conflicts = [ "shutdown.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${setup} --relabel-mutable";
          };
        };

        # Store optimisation replaces identical files with hard links to one
        # inode, and may keep the inode of a copy with a generic label.
        # Started by the path unit below whenever that happens.
        selinux-store-labels = {
          description = "Restore SELinux Labels in the Nix Store";
          unitConfig.ConditionSecurity = "selinux";
          serviceConfig = {
            Type = "oneshot";
            # Twice: the second run catches a file replaced during the first.
            ExecStart = [
              "${setup}"
              "${setup}"
            ];
            # A store path can be deleted while it is being labelled.
            Restart = "on-failure";
            RestartSec = 2;
          };
        };

        # The scheduled optimisation does not finish before labels are back.
        nix-optimise = lib.mkIf config.nix.optimise.automatic {
          serviceConfig.ExecStartPost = [ "${setup}" ];
        };

        # A boot without SELinux (the last resort in the manual) creates
        # files without labels. Make the next normal boot relabel.
        selinux-relabel-after-disabled = {
          description = "Schedule SELinux Relabelling After a Boot Without SELinux";
          unitConfig.ConditionSecurity = "!selinux";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${lib.getExe' pkgs.coreutils "rm"} -f /var/lib/selinux-nixos/relabelled";
          };
        };

        # The setuid wrappers are created at boot on their own tmpfs, where
        # new files get the filesystem's default type. Give them their
        # proper labels as soon as they exist.
        suid-sgid-wrappers.serviceConfig.ExecStartPost = [
          "-${lib.getExe' pkgs.policycoreutils "restorecon"} -RF ${dirOf config.security.wrapperDir}"
        ];
      };
    };

    # On switch: load the new generation's policy, apply its mode, and label
    # store paths that arrived with it, before any of its services start.
    system = {
      activationScripts.selinux = {
        deps = [ "etc" ];
        text = ''
          if [ "''${IN_NIXOS_SYSTEMD_STAGE1:-}" != true ] && [ -e /sys/fs/selinux/load ]; then
            # Load the new policy first: labels that use its new types are
            # only valid once the kernel knows them.
            # A policy the kernel refuses stops here: labelling with types the
            # kernel does not know would fail, and the old policy stays in
            # force. The pre-switch check below catches the usual cause first.
            if [ "$(tr -d '\0' < /proc/self/attr/current)" = kernel ]; then
              ${setup} --relabel-mutable
            elif ${lib.getExe' pkgs.policycoreutils "load_policy"}; then
              echo ${if cfg.mode == "enforcing" then "1" else "0"} > /sys/fs/selinux/enforce
              ${setup} --relabel-mutable
            else
              echo "security.selinux: the kernel rejected the new policy; the previous policy stays loaded and nothing was relabelled" >&2
              false
            fi
          fi
        '';
      };

      # Refuse to switch to a generation whose policy the running kernel
      # cannot load, before anything of the new generation is activated.
      preSwitchChecks.selinux = ''
        case "''${2:-}" in
          switch | test) ;;
          *) exit 0 ;;
        esac
        [ -r /sys/fs/selinux/policyvers ] || exit 0
        policy=${policyFile}
        od=${lib.getExe' pkgs.coreutils "od"}
        magic=$("$od" -An -tx4 -N4 "$policy" | tr -d ' ')
        version=$("$od" -An -tu4 -j16 -N4 "$policy" | tr -d ' ')
        supported=$(cat /sys/fs/selinux/policyvers)
        if [ "$magic" != f97cff8c ]; then
          echo "security.selinux: $policy is not a kernel policy" >&2
          exit 1
        fi
        if [ "$version" -gt "$supported" ]; then
          echo "security.selinux: the new policy has format version $version, but the running kernel accepts at most $supported." >&2
          echo "Set security.selinux.policyVersion = $supported, or activate this generation with 'boot' and reboot into its kernel." >&2
          exit 1
        fi
      '';
    };
  };
}
