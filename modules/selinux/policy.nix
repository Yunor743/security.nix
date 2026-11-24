# Composes the policy for this system and exposes it under /etc/selinux.
{
  config,
  lib,
  pkgs,
  selinuxPkgs,
  ...
}:
let
  cfg = config.security.selinux;

  # file_contexts.subs: alias paths labelled as their equivalent (libselinux
  # reads it next to file_contexts, for setfiles and restorecon alike).
  # [security.nix]
  substitutionsText = lib.concatStrings (
    lib.mapAttrsToList (alias: target: "${alias} ${target}\n") cfg.pathSubstitutions
  );
  withSubstitutions =
    policy:
    if cfg.pathSubstitutions == { } then
      policy
    else
      pkgs.runCommandLocal "${policy.name}-subs"
        {
          passthru = (policy.passthru or { }) // {
            inherit (policy) policyVersion;
          };
        }
        ''
          mkdir -p $out
          cp -rs ${policy}/. $out/
          chmod -R u+w $out
          rm -f $out/contexts/files/file_contexts.subs
          cp ${pkgs.writeText "file_contexts.subs" substitutionsText} $out/contexts/files/file_contexts.subs
        '';

  # Rules that name one exact store path. The hash in the path cannot be
  # chosen by whoever builds a package, so only content the system
  # configuration designates can receive these types.
  #
  # A label belongs to a file, not to a name. Where a configured path is
  # a symbolic link (the `nix` package's programs link into another store
  # path), the rule is written for the file the link leads to.
  exactRules =
    pkgs.runCommand "selinux-exact-rules"
      {
        entrypoints = lib.concatStrings (
          lib.unique (map (e: "${toString e.path}\t${e.type}\n") (lib.attrValues cfg.entrypoints))
        );
        passAsFile = [ "entrypoints" ];
      }
      ''
        mkdir $out
        : > rules
        : > paths
        while IFS=$'\t' read -r path type; do
          real=$(realpath -e "$path") || { echo "security.selinux.entrypoints: $path does not exist" >&2; exit 1; }
          case $real in
            /nix/store/*) ;;
            *) echo "security.selinux.entrypoints: $path is not in the Nix store" >&2; exit 1 ;;
          esac
          [ -f "$real" ] || { echo "security.selinux.entrypoints: $path is not a regular file" >&2; exit 1; }
          printf '%s\t--\tsystem_u:object_r:%s:s0\n' \
            "$(printf '%s' "$real" | sed 's/[][\.*+?(){}|^$]/\\&/g')" "$type" >> rules
          echo "$real" >> paths
        done < "$entrypointsPath"
        sort -u rules > $out/rules
        sort -u paths > $out/paths
        if [ "$(cut -f1 $out/rules | uniq -d | wc -l)" != 0 ]; then
          echo "security.selinux.entrypoints gives one file two types:" >&2
          cut -f1 $out/rules | uniq -d >&2
          exit 1
        fi
      '';

  genericFileContexts =
    (
      if cfg.type == "refpolicy" then
        pkgs.selinux-refpolicy.version + builtins.readFile ./refpolicy/nixos.fc
      else
        builtins.readFile selinuxPkgs.selinux-policy-minimal.fileContexts
    )
    + cfg.fileContexts;

  # Whether a file context rule can apply to a path in the Nix store. A
  # rule that begins with a literal directory other than /nix cannot, nor
  # one for /nix/var. Anything else, such as `/.*`, might.
  storeRule =
    line:
    let
      first = builtins.match "/([A-Za-z0-9_.-]+)([/[:space:](].*)?" line;
    in
    line != ""
    && !(lib.hasPrefix "#" line)
    && !(lib.hasPrefix "/nix/var" line)
    && (first == null || builtins.head first == "nix");
in
{
  options.security.selinux = {
    policy = lib.mkOption {
      type = lib.types.package;
      description = ''
        The built policy: a directory with the layout of
        {file}`/etc/selinux/<type>`. The default is the minimal policy
        extended with {option}`security.selinux.modules`,
        {option}`security.selinux.fileContexts` and
        {option}`security.selinux.entrypoints`.
      '';
      defaultText = lib.literalMD "the minimal policy built from this configuration";
    };

    modules = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            cil = lib.mkOption {
              type = lib.types.lines;
              default = "";
              description = "Policy rules in CIL, for the `minimal` policy type.";
            };
            te = lib.mkOption {
              type = lib.types.lines;
              default = "";
              description = ''
                Policy rules in the reference policy's language, for the
                `refpolicy` policy type: declarations, allow rules and
                calls of the reference policy's interfaces. The
                `policy_module` line is added.
              '';
            };
            "if" = lib.mkOption {
              type = lib.types.lines;
              default = "";
              description = "Interfaces this module offers to other modules, for the `refpolicy` policy type.";
            };
          };
        }
      );
      default = { };
      example = lib.literalExpression ''
        {
          myservice.te = '''
            type myservice_t;
            type myservice_exec_t;
            init_daemon_domain(myservice_t, myservice_exec_t)
          ''';
        }
      '';
      description = ''
        Policy fragments compiled into the system policy. A fragment that
        does not compile fails the system build, and the error names it.
        File context rules go in {option}`security.selinux.fileContexts`
        and {option}`security.selinux.entrypoints`.
      '';
    };

    pathSubstitutions = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        "/nix/persist/etc" = "/etc";
        "/nix/persist/var" = "/var";
        "/nix/persist/home" = "/home";
      };
      description = ''
        Paths labelled as if they were another path
        (`file_contexts.subs`). With an ephemeral root (impermanence),
        persistent storage such as `/nix/persist/etc` then gets the labels of
        `/etc`; add it to {option}`security.selinux.relabelPaths` too.
      '';
    };

    fileContexts = lib.mkOption {
      type = lib.types.lines;
      default = "";
      example = ''
        /srv/www(/.*)?	system_u:object_r:usr_t:s0
      '';
      description = ''
        Extra file context rules. Rules for the Nix store written here
        match on path patterns that any local user can imitate, so they
        must not hand out types that carry privilege. Use
        {option}`security.selinux.entrypoints` for that.
      '';
    };

    entrypoints = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            path = lib.mkOption {
              type = lib.types.path;
              description = "Exact path of a regular file in the Nix store.";
            };
            type = lib.mkOption {
              type = lib.types.str;
              description = "SELinux type to label that file with.";
            };
          };
        }
      );
      default = { };
      example = lib.literalExpression ''
        {
          nginx = {
            path = "''${pkgs.nginx}/bin/nginx";
            type = "nginx_exec_t";
          };
        }
      '';
      description = ''
        Files in the Nix store that get a specific type, named by their
        exact store path. This is the only way store content receives a
        type that carries privilege, such as the entry point of a domain.
      '';
    };

    fhsLabelledPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = lib.optionals (cfg.type == "refpolicy") (
        [ config.systemd.package ]
        ++ lib.optionals config.services.dbus.enable [
          config.services.dbus.dbusPackage
          config.services.dbus.brokerPackage
        ]
      );
      defaultText = lib.literalMD "systemd and D-Bus with the `refpolicy` policy type, otherwise empty";
      description = ''
        Packages whose programs get the types the reference policy gives
        the same programs at their usual locations under {file}`/usr`.
        Each one is named by its exact store path, so the service it
        belongs to enters the domain the policy has for it. Used by the
        `refpolicy` policy type.
      '';
    };

    logAllDenials = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Remove the policy's `dontaudit` rules, so that denials the policy
        normally hides are logged too. For policy development: a hidden
        denial still denies in enforcing mode. Used by the `refpolicy`
        policy type.
      '';
    };

    booleans = lib.mkOption {
      type = lib.types.attrsOf lib.types.bool;
      default = { };
      example = {
        ssh_sysadm_login = true;
      };
      description = ''
        Values of policy booleans and tunables, built into the policy. A
        name the policy does not have fails the build. Used by the
        `refpolicy` policy type.
      '';
    };

    labelRevision = lib.mkOption {
      type = lib.types.str;
      internal = true;
      description = ''
        Identifies the generic labelling rules that can apply to the Nix
        store. Store paths labelled under one revision are not visited
        again until it changes.
      '';
    };

    mutableLabelRevision = lib.mkOption {
      type = lib.types.str;
      internal = true;
      description = ''
        Identifies all generic labelling rules. The paths in
        {option}`security.selinux.relabelPaths` are relabelled when it
        changes.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    security.selinux = {
      # NixOS describes much of the filesystem layout as tmpfiles rules:
      # the dynamic loader stub in /lib64, root's channel list, state
      # directories of services. Let systemd-tmpfiles manage any file
      # that is not security-sensitive, as the policy offers.
      booleans = lib.mkIf (cfg.type == "refpolicy") {
        systemd_tmpfiles_manage_all = lib.mkDefault true;
      };

      policy = lib.mkDefault (
        withSubstitutions (
          if cfg.type == "refpolicy" then
            assert lib.assertMsg (lib.all (m: m.cil == "") (lib.attrValues cfg.modules)) ''
              security.selinux.modules.<name>.cil is for the minimal policy
              type. With refpolicy, write the module in
              security.selinux.modules.<name>.te.
            '';
            pkgs.callPackage ./refpolicy {
              name = cfg.type;
              policyVersion = if cfg.policyVersion != null then cfg.policyVersion else 33;
              extraFileContexts = cfg.fileContexts;
              inherit exactRules;
              fhsPackages = cfg.fhsLabelledPackages;
              localModules = lib.mapAttrs (_: m: { inherit (m) te "if"; }) cfg.modules;
              inherit (cfg) booleans;
              dontaudit = !cfg.logAllDenials;
              seusers = lib.concatStrings (
                lib.mapAttrsToList (login: m: "${login}:${m.user}:${m.range}\n") cfg.loginMappings
              );
            }
          else
            assert lib.assertMsg (lib.all (m: m.te == "" && m."if" == "") (lib.attrValues cfg.modules)) ''
              security.selinux.modules.<name>.te and .if are for the
              refpolicy policy type. With the minimal policy, write the
              module in security.selinux.modules.<name>.cil.
            '';
            selinuxPkgs.selinux-policy-minimal.override {
              name = cfg.type;
              policyVersion = if cfg.policyVersion != null then cfg.policyVersion else 33;
              extraCil = lib.mapAttrsToList (name: module: pkgs.writeText "${name}.cil" module.cil) cfg.modules;
              extraFileContexts = cfg.fileContexts;
              inherit exactRules;
            }
        )
      );

      labelRevision = builtins.substring 0 32 (
        builtins.hashString "sha256" (
          lib.concatStringsSep "\n" (lib.filter storeRule (lib.splitString "\n" genericFileContexts))
        )
      );
      mutableLabelRevision = builtins.substring 0 32 (
        # The list of paths too: adding one must trigger a pass. [security.nix]
        builtins.hashString "sha256" (
          genericFileContexts + substitutionsText + lib.concatStringsSep "\n" cfg.relabelPaths
        )
      );

      # PID 1 enters its domain only if the systemd binary carries this type.
      entrypoints = {
        systemd = {
          path = "${config.systemd.package}/lib/systemd/systemd";
          type = "init_exec_t";
        };
        systemd-initrd = {
          path = "${config.boot.initrd.systemd.package}/lib/systemd/systemd";
          type = "init_exec_t";
        };
      };
    };

    environment.etc."selinux/${cfg.type}".source = cfg.policy;
  };
}
