{
  config,
  lib,
  options,
  pkgs,
  ...
}:

# Vulnerability and secret scans of the container images in use (Docker,
# Podman root and rootless) with Trivy.
#
# An image id is immutable, so each image is exported and inventoried once:
# 1. a privileged ExecStartPre (`+`) lists the images of the running and
#    declared (oci-containers) containers and exports only the new ones
#    (`docker save` / `podman save`, rootless through `runuser`);
# 2. the unprivileged scanner (dynamic user, no container socket) turns each
#    export into a CycloneDX SBOM and a secret report, then deletes it: the
#    code that parses untrusted image content never holds a root-equivalent
#    socket;
# 3. at every run, the stored SBOMs are matched against the current Trivy
#    database (`trivy sbom`), and the findings become journal lines
#    (vulnscan-lib.nix). SBOMs of images no longer in use are removed.
# Images built by Nix (oci-containers imageStream) are left to
# security.sbomnix / security.vulnix: Trivy finds no package database in them.

let
  cfg = config.security.containerScan;
  vlib = import ./vulnscan-lib.nix { inherit lib; };
  oci = config.virtualisation.oci-containers;
  declared = oci.containers;
  nixBuilt = lib.filterAttrs (_: c: c.imageFile != null || c.imageStream != null) declared;
  streamed = lib.filterAttrs (_: c: c.imageStream != null) declared;

  rank = {
    unknown = 0;
    low = 1;
    medium = 2;
    high = 3;
    critical = 4;
  };

  # Container runtimes: label, user (root or rootless), CLI, `inspect` format
  # of a container (image id | image reference | name), `save` arguments.
  docker = {
    bin = "${config.virtualisation.docker.package}/bin/docker";
    format = "{{.Image}}|{{.Config.Image}}|{{.Name}}";
    save = [ "save" ];
    # `docker save` takes no bare 64-hex id.
    idPrefix = "sha256:";
  };
  podman = {
    bin = "${config.virtualisation.podman.package}/bin/podman";
    format = "{{.Image}}|{{.ImageName}}|{{.Name}}";
    save = [
      "save"
      "--format"
      "docker-archive"
    ];
    idPrefix = "";
  };
  runtimes =
    lib.optional cfg.docker.enable (
      docker
      // {
        label = "docker";
        user = "root";
      }
    )
    ++ lib.optional cfg.podman.enable (
      podman
      // {
        label = "podman";
        user = "root";
      }
    )
    ++ map (
      u:
      podman
      // {
        label = "podman:${u}";
        user = u;
      }
    ) cfg.podman.rootlessUsers;

  # Declared registry images, per runtime label.
  declaredFor =
    label:
    lib.mapAttrsToList (name: c: "${name}\t${c.image}") (
      lib.filterAttrs (
        _: c:
        c.imageFile == null
        && c.imageStream == null
        && (
          if oci.backend == "docker" then
            label == "docker"
          else if (c.podman.user or "root") == "root" then
            label == "podman"
          else
            label == "podman:${c.podman.user}"
        )
      ) declared
    );

  nixImageRefs = pkgs.writeText "container-scan-nix-images" (
    lib.concatMapStrings (c: "${c.image}\n") (lib.attrValues nixBuilt)
  );

  state = "/var/lib/private/container-scan";

  # Privileged part: list and export. Output: export/images.tsv
  # (id, ref, container, runtime) and export/<id>.tar for new images.
  exportScript = pkgs.writeShellScript "container-scan-export" ''
    set -u
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.getent
        pkgs.util-linux
      ]
    }
    state=${state}
    owner=$(stat -c %u:%g "$state")
    mkdir -p "$state/export" "$state/sbom"
    rm -f "$state"/export/*
    list=$state/export/images.tsv
    errors=$state/export/errors
    : > "$list.tmp"
    : > "$errors"

    as() { # user cmd...
      local u=$1 uid
      shift
      if [ "$u" = root ]; then
        "$@"
        return
      fi
      uid=$(id -u "$u")
      runuser -u "$u" -- env HOME="$(getent passwd "$u" | cut -d: -f6)" XDG_RUNTIME_DIR="/run/user/$uid" "$@"
    }

    # Appends "id ref name label" lines for one runtime.
    collect() { # label user bin format declared-file
      local label=$1 user=$2 bin=$3 format=$4 declared=$5 ids c id ref name
      if ! ids=$(as "$user" "$bin" ps -q 2> /dev/null); then
        printf '%s\t%s\n' "$label" "cannot list containers" >> "$errors"
        return
      fi
      ${lib.optionalString cfg.running ''
        for c in $ids; do
          IFS='|' read -r id ref name < <(as "$user" "$bin" inspect --format "$format" "$c" 2> /dev/null) || continue
          printf '%s\t%s\t%s\t%s\n' "''${id#sha256:}" "$ref" "''${name#/}" "$label" >> "$list.tmp"
        done
      ''}
      ${lib.optionalString cfg.fromOciContainers ''
        while IFS=$'\t' read -r name ref; do
          [ -n "$ref" ] || continue
          id=$(as "$user" "$bin" image inspect --format '{{.Id}}' "$ref" 2> /dev/null) || continue
          printf '%s\t%s\t%s\t%s\n' "''${id#sha256:}" "$ref" "$name" "$label" >> "$list.tmp"
        done < "$declared"
      ''}
    }

    export_image() { # id label user bin id-prefix save-args...
      local id=$1 label=$2 user=$3 bin=$4 prefix=$5 out=$state/export/$1.tar
      shift 5
      if ! as "$user" "$bin" "$@" "$prefix$id" > "$out.tmp"; then
        rm -f "$out.tmp"
        printf '%s\t%s\n' "$label" "cannot export $id" >> "$errors"
        return
      fi
      chown "$owner" "$out.tmp"
      mv "$out.tmp" "$out"
    }

    ${lib.concatMapStrings (r: ''
      collect ${
        lib.escapeShellArgs [
          r.label
          r.user
          r.bin
          r.format
          (pkgs.writeText "declared" (lib.concatMapStrings (l: l + "\n") (declaredFor r.label)))
        ]
      }
    '') runtimes}

    # Nix-built images are left to sbomnix / vulnix.
    grep -vFf <(sed 's|^|\t|; s|$|\t|' ${nixImageRefs}) "$list.tmp" | sort -u > "$list" || true
    rm -f "$list.tmp"

    # Export the images not inventoried yet, once per id.
    declare -A seen
    while IFS=$'\t' read -r id ref name label; do
      [ -z "''${seen[$id]:-}" ] || continue
      seen[$id]=1
      [ ! -e "$state/sbom/$id.cdx.json" ] || continue
      case $label in
        ${lib.concatMapStrings (r: ''
          ${lib.escapeShellArg r.label}) export_image "$id" "$label" ${
            lib.escapeShellArgs (
              [
                r.user
                r.bin
                r.idPrefix
              ]
              ++ r.save
            )
          } ;;
        '') runtimes}
      esac
    done < "$list"
    chown -R "$owner" "$state/export" "$state/sbom"
  '';

  minRank = rank.${cfg.minimumSeverity};

  whitelistJson = pkgs.writeText "container-scan-whitelist.json" (builtins.toJSON cfg.whitelist);

  # Shared by both programs: $wl (whitelist), $ref (image reference).
  jqCommon = ''
    ${vlib.jqLib}
    def today: now | strftime("%Y-%m-%d");
    def accepted($kind; $id; $pkg):
      any($wl[] | select(.kind == $kind and (.until == null or .until > today));
        .id as $rx | (.image // "") as $im
        | ($id | test("^(" + $rx + ")$"))
          and (.package == null or .package == $pkg)
          and ($im == "" or ($ref | test($im))));
  '';

  linesJq = pkgs.writeText "container-scan-lines.jq" ''
    ${jqCommon}
    def hdr: "scanner=\"trivy\"" + kv("target"; $target);
    def score: [ .CVSS[]?.V3Score // empty ] | max // 0;
    def sev: (.Severity // "UNKNOWN") | ascii_downcase;
    def rank_of: {"critical": 4, "high": 3, "medium": 2, "low": 1}[.] // 0;
    # Unscored (unknown) vulnerabilities are kept unless the minimum is
    # medium or above.
    def kept_rank: (sev | rank_of) as $r | $r >= ${toString minRank} or ($r == 0 and ${toString minRank} <= 1);
    [ .Results[]? | .Vulnerabilities[]? ] as $all
    | [ $all[] | select(kept_rank)
        | select(${lib.boolToString (!cfg.ignoreUnfixed)} or ((.FixedVersion // "") != ""))
        | select(accepted("vulnerability"; .VulnerabilityID; .PkgName) | not) ] as $kept
    | ($kept | group_by([.PkgName, .InstalledVersion]) | .[]
        | . as $g
        | [ $g[] | { id: .VulnerabilityID, score: score, rank: (sev | rank_of), fixed: (.FixedVersion // "") } ]
        | unique_by(.id) | sort_by(-.rank, -.score, .id) as $v
        | "vulnerable " + hdr + kv("pname"; $g[0].PkgName) + kv("version"; $g[0].InstalledVersion)
          + kv("severity"; $g | map(sev) | max_by(rank_of))
          + kv("count"; $v | length) + kv("max_cvss"; [ $v[].score ] | max)
          + kv("top"; [ $v[:3][].id ] | join(","))
          + kv("cves"; [ $v[].id ] | sort | join(","))
          + ([ $v[].fixed | select(. != "") ] | unique | if length > 0 then kv("fixed"; last) else "" end)),
      ("scan_done " + hdr + kv("vulnerable"; $kept | map([.PkgName, .InstalledVersion]) | unique | length)
        + kv("cves"; $kept | map(.VulnerabilityID) | unique | length)
        + kv("whitelisted"; $all | map(select(accepted("vulnerability"; .VulnerabilityID; .PkgName))) | length))
  '';

  secretsJq = pkgs.writeText "container-scan-secrets.jq" ''
    ${jqCommon}
    .Results[]? | .Target as $path | .Secrets[]?
    | select(accepted("secret"; .RuleID // ""; null) | not)
    | "secret scanner=\"trivy\"" + kv("target"; $target) + kv("rule"; .RuleID)
      + kv("title"; .Title) + kv("path"; $path)
  '';

  dbArgs = lib.optionals (cfg.dbRepository != null) [
    "--db-repository"
    cfg.dbRepository
  ];

  scanScript = pkgs.writeShellScript "container-scan" ''
    set -u
    export PATH=${
      lib.makeBinPath [
        cfg.package
        pkgs.coreutils
        pkgs.jq
      ]
    }
    export HOME=/var/cache/container-scan
    state=/var/lib/container-scan
    # Trivy sends anonymous usage data to Aqua and checks for updates by
    # default: nothing but the database download leaves the host.
    trivy=(trivy --quiet --disable-telemetry --skip-version-check --cache-dir /var/cache/container-scan)
    failed=0
    fail() { echo "scan_failed scanner=\"trivy\" target=\"$1\" rc=\"$2\""; failed=1; }

    while IFS=$'\t' read -r label what; do
      fail "$label" "$what"
    done < "$state/export/errors"

    # Inventory of the new exports.
    for tar in "$state"/export/*.tar; do
      [ -e "$tar" ] || continue
      id=$(basename "$tar" .tar)
      rc=0
      "''${trivy[@]}" image --input "$tar" --format cyclonedx --output "$state/sbom/$id.cdx.json.tmp" || rc=$?
      ${lib.optionalString cfg.secrets.enable ''
        [ "$rc" -ne 0 ] || "''${trivy[@]}" image --input "$tar" --scanners secret --format json \
          --output "$state/sbom/$id.secrets.json" || rc=$?
      ''}
      rm -f "$tar"
      if [ "$rc" -eq 0 ]; then
        mv "$state/sbom/$id.cdx.json.tmp" "$state/sbom/$id.cdx.json"
      else
        rm -f "$state/sbom/$id.cdx.json.tmp"
        fail "$id" "$rc"
      fi
    done

    # Match every image in use against today's database.
    declare -A seen
    while IFS=$'\t' read -r id ref name label; do
      [ -z "''${seen[$id]:-}" ] || continue
      seen[$id]=1
      sbom=$state/sbom/$id.cdx.json
      [ -e "$sbom" ] || continue
      target="$ref@sha256:''${id:0:12}"
      rc=0
      "''${trivy[@]}" sbom ${lib.escapeShellArgs dbArgs} --scanners vuln --format json "$sbom" > "$state/report.json.tmp" || rc=$?
      if [ "$rc" -ne 0 ] || ! jq -e .Results "$state/report.json.tmp" > /dev/null 2>&1; then
        fail "$target" "$rc"
        continue
      fi
      mv "$state/report.json.tmp" "$state/sbom/$id.report.json"
      jq -r --arg target "$target" --arg ref "$ref" \
        --argjson wl "$(cat ${whitelistJson})" -f ${linesJq} "$state/sbom/$id.report.json"
      ${lib.optionalString cfg.secrets.enable ''
        if [ -e "$state/sbom/$id.secrets.json" ]; then
          jq -r --arg target "$target" --arg ref "$ref" --argjson wl "$(cat ${whitelistJson})" -f ${secretsJq} "$state/sbom/$id.secrets.json"
        fi
      ''}
    done < "$state/export/images.tsv"

    # Forget the images no longer in use.
    for f in "$state"/sbom/*; do
      [ -e "$f" ] || continue
      id=$(basename "$f"); id=''${id%%.*}
      [ -n "''${seen[$id]:-}" ] || rm -f "$f"
    done
    exit "$failed"
  '';
in
{
  options.security.containerScan = {
    enable = lib.mkEnableOption ''
      vulnerability and secret scans of the container images in use (Docker,
      Podman root and rootless) with Trivy, one journal line per vulnerable
      package and image (MiniSOC alerts)'';

    package = lib.mkPackageOption pkgs "trivy" { };

    running = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Scan the images of the running containers (`docker run`, compose, `podman run`…).";
    };

    fromOciContainers = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Scan the registry images of `virtualisation.oci-containers`, even when
        their container is stopped. Images built by Nix (`imageStream`) go
        to security.sbomnix / security.vulnix instead.
      '';
    };

    docker.enable = lib.mkOption {
      type = lib.types.bool;
      default = config.virtualisation.docker.enable;
      defaultText = lib.literalExpression "config.virtualisation.docker.enable";
      description = "Cover the containers of the Docker daemon.";
    };

    podman = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = config.virtualisation.podman.enable;
        defaultText = lib.literalExpression "config.virtualisation.podman.enable";
        description = "Cover the root Podman containers.";
      };
      rootlessUsers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = lib.unique (
          lib.filter (u: u != "root") (
            lib.mapAttrsToList (_: c: c.podman.user or "root") (
              lib.filterAttrs (_: _: oci.backend == "podman") declared
            )
          )
        );
        defaultText = lib.literalMD "the `podman.user` of the oci-containers that are not root";
        example = [ "alice" ];
        description = ''
          Users whose rootless Podman containers are covered. Their store is
          read as them (`runuser`); give them `linger` so that their
          containers and runtime directory exist without a session.
        '';
      };
    };

    secrets.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Look for secrets (keys, tokens) left in the image layers (`high` alerts).";
    };

    minimumSeverity = lib.mkOption {
      type = lib.types.enum (lib.attrNames rank);
      default = "low";
      description = "Ignore the vulnerabilities below this Trivy severity (`unknown`: keep all).";
    };

    ignoreUnfixed = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Ignore the vulnerabilities without a fixed version yet.";
    };

    whitelist = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            kind = lib.mkOption {
              type = lib.types.enum [
                "vulnerability"
                "secret"
              ];
              default = "vulnerability";
            };
            id = lib.mkOption {
              type = lib.types.str;
              example = "CVE-2024-0727";
              description = "CVE / advisory id, or secret rule id (`aws-access-key-id`); a regular expression.";
            };
            package = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Only for this package (vulnerabilities).";
            };
            image = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "^docker.io/library/nginx:";
              description = "Only for the image references matching this regular expression.";
            };
            comment = lib.mkOption {
              type = lib.types.str;
              default = "";
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
      description = "Accepted findings.";
    };

    dbRepository = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "ghcr.io/aquasecurity/trivy-db:2";
      description = ''
        Trivy database repository (Trivy's default: mirror.gcr.io, then
        ghcr.io). Trivy downloads the database and matches locally: no
        inventory leaves the host (telemetry and update checks are disabled).
      '';
    };
  }
  // vlib.timerOptions "daily";

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = runtimes != [ ];
            message = "security.containerScan: no container runtime (docker.enable, podman.enable or podman.rootlessUsers).";
          }
          {
            assertion = cfg.running || cfg.fromOciContainers;
            message = "security.containerScan: running and fromOciContainers are both off.";
          }
          {
            assertion = lib.all (u: config.users.users ? ${u}) cfg.podman.rootlessUsers;
            message = "security.containerScan.podman.rootlessUsers: unknown user.";
          }
          {
            assertion = cfg.podman.rootlessUsers == [ ] || config.virtualisation.podman.enable;
            message = "security.containerScan.podman.rootlessUsers needs virtualisation.podman.enable.";
          }
        ];

        warnings =
          lib.optional (lib.any (c: c.imageFile != null) (lib.attrValues declared))
            "security.containerScan: the oci-containers with `imageFile` (${
              lib.concatStringsSep ", " (lib.attrNames (lib.filterAttrs (_: c: c.imageFile != null) declared))
            }) are not scanned: Trivy finds no package database in Nix-built images, and their tarball references nothing vulnix/sbomnix could follow. Use `imageStream` (dockerTools.streamLayeredImage) to get them scanned by security.sbomnix / security.vulnix."
          ++
            lib.optional
              (
                streamed != { }
                && !(config.security.sbomnix.enable or false)
                && !(config.security.vulnix.enable or false)
              )
              "security.containerScan: the Nix-built oci-containers images (imageStream) are only scanned by security.sbomnix or security.vulnix; enable one of them.";

        systemd.services.container-scan = {
          description = "Vulnerability and secret scan of the container images in use (Trivy)";
          wants = [ "network-online.target" ];
          after = [
            "network-online.target"
          ]
          ++ lib.optional cfg.docker.enable "docker.service"
          ++ lib.optional cfg.podman.enable "podman.service";
          serviceConfig = vlib.hardening // {
            ExecStartPre = "+${exportScript}";
            ExecStart = scanScript;
            StateDirectory = "container-scan";
            CacheDirectory = "container-scan";
            # Exports of large images and the first database download.
            TimeoutStartSec = "3h";
          };
        };

        systemd.timers.container-scan = vlib.mkTimer cfg;

        environment.systemPackages = [ cfg.package ];
      }

      # Nix-built images (imageStream: its closure holds the image contents).
      (lib.optionalAttrs (options.security ? sbomnix) {
        security.sbomnix.targets = lib.mkIf config.security.sbomnix.enable (
          lib.mapAttrs' (name: c: lib.nameValuePair "image-${name}" { path = "${c.imageStream}"; }) streamed
        );
      })
      (lib.optionalAttrs (options.security ? vulnix) {
        security.vulnix.paths = lib.mkIf config.security.vulnix.enable (
          lib.mapAttrsToList (_: c: "${c.imageStream}") streamed
        );
      })
    ]
  );
}
