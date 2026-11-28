{
  config,
  lib,
  pkgs,
  ...
}:

# SBOMs and multi-scanner vulnerability reports of Nix closures with sbomnix:
#
# - `sbomnix` writes a CycloneDX / SPDX / CSV SBOM per target and per
#   generation (a store path already covered is not done again), kept in
#   /var/lib/sbomnix/<target>/sbom/<store path name>, `current` -> latest.
# - `vulnxscan` scans the target with grype and vulnix (and OSV.dev on
#   opt-in), drops the CVEs that a nixpkgs patch names, applies the
#   whitelist, and the findings become journal lines (vulnscan-lib.nix).
# - Nothing that sends the package list to a third party (OSV.dev, the
#   Repology / GitHub triage) runs unless allowed in `allowRemote`.

let
  cfg = config.security.sbomnix;
  vlib = import ./vulnscan-lib.nix { inherit lib; };

  # vulnxscan runs vulnix without a mirror option: wrap it.
  package =
    if cfg.nvdMirror == null then
      cfg.package
    else
      cfg.package.override {
        vulnix = pkgs.writeShellScriptBin "vulnix" ''
          exec ${pkgs.vulnix}/bin/vulnix --mirror ${lib.escapeShellArg cfg.nvdMirror} "$@"
        '';
      };

  report = ./sbomnix-report.py;

  whitelistJson = pkgs.writeText "sbomnix-whitelist.json" (builtins.toJSON cfg.whitelist);

  scanArgs = lib.escapeShellArgs (
    lib.optional (!cfg.allowRemote.osv) "--skip-osv"
    ++ lib.optional cfg.allowRemote.triage "--triage"
    ++ lib.optional (cfg.allowRemote.triage && cfg.allowRemote.nixpkgsPrs) "--nixprs"
  );

  targetLine =
    name: t:
    "scan_target ${
      lib.escapeShellArgs [
        name
        t.path
        (if t.buildtime then "--buildtime" else "")
      ]
    }";

  scan = pkgs.writeShellScript "sbomnix-scan" ''
    set -u
    export PATH=${
      lib.makeBinPath [
        package
        pkgs.coreutils
        pkgs.findutils
        pkgs.gnugrep
        pkgs.python3
      ]
    }
    export HOME=/var/cache/sbomnix XDG_CACHE_HOME=/var/cache/sbomnix
    export GRYPE_DB_CACHE_DIR=/var/cache/sbomnix/grype NIX_REMOTE=daemon
    # See security.vulnix: vulnix misdetects the need for this with current Nix.
    export NIX_CONFIG="extra-experimental-features = nix-command"
    state=/var/lib/sbomnix
    failed=0
    work=$(mktemp -d)
    python3 ${report} whitelist ${whitelistJson} > "$work/whitelist.csv"
    wl=()
    if [ "$(wc -l < "$work/whitelist.csv")" -gt 1 ]; then wl=(--whitelist "$work/whitelist.csv"); fi

    fail() { # scanner target rc
      echo "scan_failed scanner=\"$1\" target=\"$2\" rc=\"$3\""
      failed=1
    }

    scan_target() { # name path [--buildtime]
      local name=$1 path=$2 bt=$3 real gen dir=$state/$1 rc
      if ! real=$(readlink -e "$path"); then
        fail sbomnix "$name" missing
        return
      fi
      mkdir -p "$dir/sbom"
      ${lib.optionalString cfg.sbom.enable ''
        gen=$dir/sbom/$(basename "$real")
        if [ ! -e "$gen/sbom.cdx.json" ]; then
          rm -rf "$gen.tmp" && mkdir "$gen.tmp"
          if (cd "$gen.tmp" && sbomnix "$real" $bt --cdx sbom.cdx.json --spdx sbom.spdx.json --csv sbom.csv); then
            mv "$gen.tmp" "$gen"
          else
            rc=$?
            rm -rf "$gen.tmp"
            fail sbomnix "$name" "$rc"
          fi
        fi
        if [ -e "$gen" ]; then
          ln -sfn "$(basename "$gen")" "$dir/sbom/current"
          # Keep the newest generations.
          ls -1t "$dir/sbom" | grep -vx current | tail -n +${toString (cfg.sbom.keep + 1)} \
            | while read -r old; do rm -rf "''${dir:?}/sbom/$old"; done
        fi
      ''}
      ${lib.optionalString cfg.scan.enable ''
        rm -rf "$work/scan" && mkdir "$work/scan"
        rc=0
        vulnxscan "$real" $bt ${scanArgs} "''${wl[@]}" --out "$work/scan/vulns.csv" 2> "$work/scan/stderr" || rc=$?
        cat "$work/scan/stderr" >&2
        if [ "$rc" -ne 0 ]; then
          fail vulnxscan "$name" "$rc"
          return
        fi
        python3 ${report} lines "$name" "$work/scan/vulns.csv" "$work/scan/vulns.triage.csv" "$work/scan/stderr" || failed=1
        rm -f "$dir/vulns.csv" "$dir/vulns.triage.csv"
        cp "$work/scan/"vulns*.csv "$dir/" 2> /dev/null || true
      ''}
    }

    ${lib.concatStringsSep "\n" (lib.mapAttrsToList targetLine cfg.targets)}
    rm -rf "$work"
    exit "$failed"
  '';
in
{
  options.security.sbomnix = {
    enable = lib.mkEnableOption ''
      SBOMs (CycloneDX, SPDX) and vulnerability scans of the system closure
      with sbomnix / vulnxscan (grype + vulnix, OSV.dev on opt-in), one
      journal line per vulnerable package (MiniSOC alerts)'';

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/sbomnix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./packages/sbomnix { }";
      description = "sbomnix, with the fixes of packages/sbomnix (nixpkgs' does not build at the locked revision).";
    };

    scanSystem = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Add the current system (`/run/current-system`) as the target `system`.";
    };

    targets = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            path = lib.mkOption {
              type = lib.types.str;
              example = "/nix/var/nix/gcroots/ci/laptop";
              description = ''
                Store path or link to it (e.g. a GC root a CI updates with the
                closure of another host). Its `.drv` files must be present.
              '';
            };
            buildtime = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Build-time dependencies instead of the runtime closure (noisy).";
            };
          };
        }
      );
      default = { };
      description = "Closures to cover; names must match `[A-Za-z0-9_-]+`.";
    };

    sbom = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Write the SBOMs (once per generation of each target).";
      };
      keep = lib.mkOption {
        type = lib.types.ints.positive;
        default = 10;
        description = "Generations kept per target.";
      };
    };

    scan.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Run vulnxscan on each target.";
    };

    allowRemote = {
      osv = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Also query OSV.dev (Google). This sends the name and version of
          every package of the target to api.osv.dev at each scan. Better
          coverage (GitHub advisories, CVEs the NVD has not enriched yet).
        '';
      };
      triage = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Triage the findings (`--triage`): look up, on repology.org, whether
          nixpkgs or upstream has a fixed version. Sends the vulnerable
          package names to repology.org. A fix available in nixpkgs is
          reported in the `fixed` field.
        '';
      };
      nixpkgsPrs = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "With `triage`, also search GitHub for nixpkgs pull requests naming each CVE (api.github.com, rate limited).";
      };
    };

    whitelist = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            vulnId = lib.mkOption {
              type = lib.types.str;
              example = "CVE-2024-0727";
              description = "Vulnerability id, a regular expression (`CVE-2023-.*`).";
            };
            comment = lib.mkOption {
              type = lib.types.str;
              description = "Why it is accepted (required by vulnxscan).";
            };
            package = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Only for this package name.";
            };
            version = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Only for this version of the package.";
            };
            until = lib.mkOption {
              type = lib.types.nullOr (lib.types.strMatching "[0-9]{4}-[0-9]{2}-[0-9]{2}");
              default = null;
              description = "The entry stops applying at this date (YYYY-MM-DD).";
            };
          };
        }
      );
      default = [ ];
      example = lib.literalExpression ''
        [ { vulnId = "CVE-2024-0727"; package = "openssl"; comment = "PKCS12 not used"; until = "2027-01-01"; } ]
      '';
      description = "Accepted findings (vulnxscan whitelist).";
    };

    nvdMirror = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching ".*/");
      default = null;
      description = "NVD feed mirror for vulnix (see security.vulnix.mirror).";
    };
  }
  // vlib.timerOptions "weekly";

  config = lib.mkIf cfg.enable {
    security.sbomnix.targets = lib.mkIf cfg.scanSystem {
      system.path = lib.mkDefault "/run/current-system";
    };

    assertions = [
      {
        assertion = cfg.targets != { };
        message = "security.sbomnix: no target (scanSystem or targets).";
      }
      {
        assertion = lib.all (n: builtins.match "[A-Za-z0-9_-]+" n != null) (lib.attrNames cfg.targets);
        message = "security.sbomnix.targets: names must match [A-Za-z0-9_-]+.";
      }
      {
        assertion = cfg.sbom.enable || cfg.scan.enable;
        message = "security.sbomnix: sbom.enable and scan.enable are both off.";
      }
    ];

    warnings =
      lib.optional
        (
          cfg.scan.enable
          && cfg.scanSystem
          && (config.security.vulnix.enable or false)
          && (config.security.vulnix.scanSystem or false)
          && (config.services.minisoc.enable or false)
        )
        "security.sbomnix and security.vulnix both scan the system: vulnxscan already runs vulnix, so MiniSOC gets every vulnix finding twice. Keep one (security.vulnix.enable = false, or security.sbomnix.scanSystem = false).";

    systemd.services.sbomnix = {
      description = "SBOMs and vulnerability scan of the system closure (sbomnix)";
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "nix-daemon.socket"
      ];
      serviceConfig = vlib.hardening // {
        ExecStart = scan;
        StateDirectory = "sbomnix";
        CacheDirectory = "sbomnix";
        # NVD feeds and the grype database on the first run.
        TimeoutStartSec = "3h";
      };
    };

    systemd.timers.sbomnix = vlib.mkTimer cfg;

    environment.systemPackages = [ package ];
  };
}
