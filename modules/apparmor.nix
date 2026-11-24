{
  config,
  lib,
  pkgs,
  ...
}:

# AppArmor on NixOS with the apparmor.d profile collection.
#
# Builds on nixpkgs' security.apparmor (kernel parameter, LSM list, userland,
# apparmor.service) and adds:
# - the apparmor.d profiles, prebuilt and adapted to the Nix store
#   (packages/apparmor-d);
# - a global mode and per-profile modes, decided at load time (no rebuild of
#   the 1500+ profiles when a mode changes);
# - local overrides (`local/<profile>`) and extra tunables;
# - loading inside nixpkgs' apparmor.service, after its own steps, so
#   `aa-teardown` / `aa-remove-unknown` never leave apparmor.d unloaded;
# - a compiled-policy cache keyed by the profile tree, since store files all
#   share the same mtime and AppArmor's own cache check would accept stale
#   entries.

let
  cfg = config.security.apparmor-d;

  modeType = lib.types.enum [
    "disable"
    "complain"
    "enforce"
  ];

  modes = pkgs.writeText "apparmor-d-modes" (
    lib.concatStrings (lib.mapAttrsToList (name: mode: "${name} ${mode}\n") cfg.profiles)
  );

  # Profile tree loaded by the parser: the package, the modes, the local
  # overrides and the tunables of this configuration. Modes are written into
  # the profiles' flags here: `apparmor_parser --complain` would disable the
  # policy cache and recompile everything at every boot.
  tree =
    pkgs.runCommandLocal "apparmor-d-tree"
      {
        nativeBuildInputs = [ pkgs.perl ];
      }
      ''
        mkdir -p $out
        cp -rs ${cfg.package}/etc/apparmor.d/. $out/
        chmod -R u+w $out
        nixos=${cfg.package}/share/apparmor.d/nixos

        declare -A override upstream
        while read -r name mode; do override[$name]=$mode; done < ${modes}
        ${lib.optionalString cfg.followUpstreamComplain ''
          while read -r name; do upstream[$name]=1; done < "$nixos/upstream-complain"
        ''}

        enforce=0 complain=0 disabled=0
        while read -r file; do
          name=''${file##*/}
          mode=''${override[$name]:-}
          if [ -z "$mode" ]; then
            if [ -n "''${upstream[$name]:-}" ]; then mode=complain; else mode=${cfg.mode}; fi
          fi
          case $mode in
            disable)
              rm "$file"; disabled=$((disabled + 1)) ;;
            complain)
              cp --remove-destination "$(readlink "$file")" "$file"
              chmod u+w "$file"
              perl ${../packages/apparmor-d/set-mode.pl} "$file"
              complain=$((complain + 1)) ;;
            *)
              enforce=$((enforce + 1)) ;;
          esac
        done < <(sed "s|^|$out/|" $nixos/profile-paths)
        echo "$enforce profile(s) in enforce mode, $complain in complain mode, $disabled disabled" > $out/.nixos-modes

        mkdir -p $out/local
        ${lib.concatStrings (
          lib.mapAttrsToList (name: text: ''
            cp ${pkgs.writeText "apparmor-local-${name}" text} $out/local/${lib.escapeShellArg name}
          '') cfg.localOverrides
        )}
        ${lib.optionalString (cfg.extraTunables != "") ''
          cp ${pkgs.writeText "apparmor-tunables" cfg.extraTunables} $out/tunables/multiarch.d/zz-nixos-local
        ''}
      '';

  loader = pkgs.writeShellScript "apparmor-d-load" ''
    set -u
    export PATH=${
      lib.makeBinPath [
        pkgs.apparmor-parser
        pkgs.coreutils
        pkgs.findutils
        pkgs.gnused
      ]
    }
    tree=${tree}
    cache=/var/cache/apparmor-d/$(basename "$tree")

    # Keep only the cache of the current tree.
    mkdir -p "$cache"
    find /var/cache/apparmor-d -mindepth 1 -maxdepth 1 -not -path "$cache" -exec rm -rf {} +

    mapfile -t files < <(sed "s|^|$tree/|" ${cfg.package}/share/apparmor.d/nixos/profile-paths \
      | while read -r f; do [ -e "$f" ] && echo "$f"; done)

    if [ ''${#files[@]} -eq 0 ]; then
      echo "apparmor.d: no profile found in $tree" >&2
      exit 1
    fi

    rc=0
    apparmor_parser --replace --write-cache --cache-loc "$cache" --config-file /dev/null \
      -I "$tree" -b "$tree" ${lib.escapeShellArgs cfg.parserFlags} "''${files[@]}" || rc=$?
    echo "apparmor.d: $(cat "$tree/.nixos-modes")"
    # A profile the running kernel rejects must not stop the others nor the
    # boot; it is reported here and in the journal.
    [ "$rc" = 0 ] || echo "apparmor.d: some profiles failed to load (exit $rc)" >&2
    exit 0
  '';

  # Only the D-Bus implementation in use (a drop-in on the other one would
  # create an incomplete unit).
  dbusUnit = if config.services.dbus.implementation == "broker" then "dbus-broker" else "dbus";
in
{
  options.security.apparmor-d = {
    enable = lib.mkEnableOption ''
      AppArmor with the apparmor.d profile collection (more than 1500
      profiles confining system services, desktop environments and
      applications). Enables `security.apparmor`. Start in complain mode, read
      the denials (`aa-log`, `journalctl -k --grep apparmor`), then enforce'';

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/apparmor-d { };
      defaultText = lib.literalExpression "pkgs.callPackage ./packages/apparmor-d { }";
      description = "The apparmor.d profiles, prebuilt for NixOS.";
    };

    mode = lib.mkOption {
      type = lib.types.enum [
        "complain"
        "enforce"
      ];
      default = "complain";
      description = ''
        Mode of every profile not listed in `profiles`. `complain` only logs
        what a profile would deny: run it until the logs are clean before
        switching to `enforce`, which can break the boot or the session.
      '';
    };

    profiles = lib.mkOption {
      type = lib.types.attrsOf modeType;
      default = { };
      example = {
        firefox = "enforce";
        dbus-system = "complain";
        "hyprland" = "disable";
      };
      description = ''
        Per-profile mode (by profile file name, as listed by `aa-status` or
        in `share/apparmor.d/nixos/profiles` of the package). `disable` does
        not load the profile at all.
      '';
    };

    followUpstreamComplain = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Keep the profiles apparmor.d itself marks as work in progress in
        complain mode, even when `mode = "enforce"` (unless listed in
        `profiles`).
      '';
    };

    localOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.lines;
      default = { };
      example = lib.literalExpression ''
        {
          # Extra rules for the "pass" profile (Nix wrapper, keyboxd...)
          pass = '''
            /nix/store/*/libexec/keyboxd ix,
            owner /run/user/*/gnupg/S.keyboxd rw,
          ''';
        }
      '';
      description = ''
        Rules added to a profile through its `include if exists
        <local/NAME>` hook (every apparmor.d profile has one), without
        editing the profile itself.
      '';
    };

    extraTunables = lib.mkOption {
      type = lib.types.lines;
      default = "";
      example = ''
        @{bin}+=/opt/*/bin
        @{MOUNTDIRS}+=/data/
      '';
      description = "Variable definitions appended to apparmor.d's tunables.";
    };

    systemdDropins = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Start the D-Bus daemons in their apparmor.d profiles
        (`AppArmorProfile=`), as apparmor.d does on other distributions. The
        profile is optional: D-Bus still starts if it is not loaded.
      '';
    };

    parserFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "--warn=all" ];
      description = "Extra `apparmor_parser` arguments used when loading apparmor.d.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(config.security.selinux.enable or false);
        message = "security.apparmor-d and security.selinux are mutually exclusive (one major LSM at a time).";
      }
    ];

    security.apparmor.enable = true;

    environment.systemPackages = [ cfg.package ];

    systemd.tmpfiles.settings."10-apparmor-d"."/var/cache/apparmor-d".d = {
      mode = "0700";
      user = "root";
      group = "root";
    };

    systemd.services = lib.mkMerge [
      {
        # Load after nixpkgs' own steps: after aa-teardown on start, after
        # aa-remove-unknown on reload.
        apparmor = {
          serviceConfig = {
            ExecStartPost = lib.mkBefore [ "${loader}" ];
            ExecReload = lib.mkAfter [ "${loader}" ];
          };
          restartTriggers = [ loader ];
        };
      }
      (lib.mkIf cfg.systemdDropins {
        ${dbusUnit} = {
          serviceConfig.AppArmorProfile = "-dbus-system";
          after = [ "apparmor.service" ];
        };
      })
    ];
    systemd.user.services = lib.mkIf cfg.systemdDropins {
      ${dbusUnit}.serviceConfig.AppArmorProfile = "-dbus-session";
    };
  };
}
