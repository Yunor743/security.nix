{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.elastic-agent;

  # ┌─────────────────────────────────────────────────────────────────────┐
  # │ NixOS limitations for the Elastic Agent (verified empirically)      │
  # └─────────────────────────────────────────────────────────────────────┘
  #
  # This module is self-sufficient for **standalone** and **fleet-agent**
  # roles: package (overlay), state-dir tree management, idempotent
  # enrollment, KEY=VALUE secret extraction, /bin/systemctl shim. A host
  # only needs `enable`, the role, and the URLs / secret files.
  #
  # Elastic Defend (endpoint-security integration) is a different story:
  #
  # 1. License: Defend CORE (detection engine, malware prevention) is free
  #    on the Basic license, but requires a Fleet-managed agent (role
  #    "fleet-agent"). Advanced features (ransomware prevention, host
  #    isolation, tamper protection, response console) require Enterprise.
  #
  # 2. The endpoint runtime installer makes TWO assumptions that break on
  #    stock NixOS:
  #    a. it hardcodes /bin/systemctl (NixOS only has /bin/sh) — solved
  #       here by the enableEndpointShim tmpfiles rule;
  #    b. it writes its own unit to /etc/systemd/system/ElasticEndpoint
  #       .service — on NixOS this directory is read-only (declarative
  #       units), so the install fails and the endpoint component stays
  #       stuck in "Starting: endpoint service runtime" forever.
  #
  # 3. Fix (the third assumption that upstream code makes): the endpoint
  #    installer writes the unit file ITSELF with a direct openat() to
  #    /etc/systemd/system/ElasticEndpoint.service (O_WRONLY|O_CREAT, 0600).
  #    On NixOS that path is a symlink into the read-only store, so the
  #    write fails with EACCES and the installer rolls back (exit 79) and
  #    the component loops forever in "Starting: endpoint service runtime".
  #    Note: systemctl writes (daemon-reload, enable) go through PID 1 and
  #    do NOT need a writable directory — only this direct openat does.
  #    Workaround: an activation script converts /etc/systemd/system from
  #    the NixOS symlink into a real, writable directory (0755) whose
  #    content is re-synced from /etc/static/systemd/system at every
  #    activation. Foreign files written by the endpoint installer are
  #    preserved. See `mutableUnitsDir` and the header of that snippet.
  #
  # 4. There is no override for the unit path upstream. Consequence: with
  #    the workarounds above, Elastic Defend DOES activate on NixOS (the
  #    agent installs the service itself and systemd manages it like any
  #    foreign unit). The agent stays HEALTHY for metrics/logs via Fleet.
  #
  # Everything else (stateDir tree, vault/proc-self-exe workaround,
  # token parsing) is handled by this module.

  # The elastic-agent.yml written to /etc (standalone role).
  # Password: Elastic Agent env-var substitution resolves
  # ${ELASTIC_AGENT_PASSWORD} from the service EnvironmentFile at runtime —
  # nothing sensitive lands in the (world-readable) /etc file.
  standaloneConfig =
    let
      # Indent the policy items under `inputs:` (2 spaces), dropping empty
      # lines so the generated YAML stays valid.
      indentedPolicy = lib.concatStringsSep "\n" (
        map (l: if lib.trim l == "" then "" else "  " + l) (lib.splitString "\n" cfg.policy)
      );
    in
    ''
        outputs:
          default:
            type: elasticsearch
            hosts: ['${cfg.serverUrl}']
            username: ${cfg.username}
            password: "__ELASTIC_AGENT_PASSWORD__"
            preset: ${cfg.preset}

        inputs:
      ${indentedPolicy}
    '';

  configText = if cfg.role == "standalone" then standaloneConfig else "";

  # Where the agent keeps its mutable state (enrollment, data, logs).
  stateDir = cfg.stateDir;

  runArgs = lib.optionals (cfg.role != "standalone") [
    # Fleet-managed agents get their policy from Fleet Server; the local
    # elastic-agent.yml is written by the enroll step.
  ];
in
{
  options.services.elastic-agent = {
    enable = lib.mkEnableOption "Elastic Agent — unified agent for logs, metrics and endpoint security (standalone or Fleet-managed)";

    package = lib.mkPackageOption pkgs "elastic-agent" { };

    role = lib.mkOption {
      type = lib.types.enum [
        "standalone"
        "fleet-agent"
      ];
      default = "standalone";
      description = ''
        - standalone: locally configured via `policy` writing directly to Elasticsearch.
        - fleet-agent: enrolled in Fleet Server (`fleet.*` options); the policy
          is managed from the Kibana Fleet UI.
      '';
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/elastic-agent";
      description = "Writable state directory (enrollment data, downloaded binaries, logs).";
    };

    extraCapabilities = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "CAP_DAC_READ_SEARCH"
        "CAP_SYS_PTRACE"
        "CAP_CHOWN"
        "CAP_SETGID"
        "CAP_SETUID"
      ];
      description = "Extra capabilities for the agent (monitoring inputs need read access to /proc, logs, etc).";
    };

    enableEndpointShim = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Install a /bin/systemctl symlink to the real systemctl. Required by
        the Elastic Defend endpoint installer, which hardcodes /bin/systemctl
        (absent on NixOS). Harmless on hosts that don't use /bin/systemctl
        otherwise.
      '';
    };

    mutableUnitsDir = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Make /etc/systemd/system a real, writable directory (0755) instead of
        the read-only NixOS symlink into the store.

        Required for Elastic Defend: the endpoint installer writes its own
        unit (/etc/systemd/system/ElasticEndpoint.service) with a direct
        openat() — which fails with EACCES through the read-only symlink.
        The declarative units are re-synced from /etc/static/systemd/system
        at every activation; files not managed by NixOS (e.g. the endpoint
        unit) are preserved.

        Set to false if you do not want /etc/systemd/system to become
        mutable on this host (Defend will not activate, metrics/logs still
        work).
      '';
    };

    extraEnv = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Extra environment variables for the service.";
    };

    # ---- standalone options ----

    serverUrl = lib.mkOption {
      type = lib.types.str;
      default = "http://localhost:9200";
      example = "https://siem.glx:9243";
      description = "Elasticsearch URL the agent sends data to (standalone role).";
    };

    username = lib.mkOption {
      type = lib.types.str;
      default = "elastic_agent";
      description = "Elasticsearch user (standalone role). Least-privilege: needs create_doc/create_index on the target data streams only.";
    };

    passwordFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/agenix/elastic-agent-es-password";
      description = ''
        File containing the Elasticsearch password. Its content is exported as
        ELASTIC_AGENT_PASSWORD for the service. The agent config references it
        through Elastic Agent's env var substitution ($\{ELASTIC_AGENT_PASSWORD\}).
      '';
    };

    preset = lib.mkOption {
      type = lib.types.enum [
        "balanced"
        "throughput"
        "scale"
      ];
      default = "balanced";
      description = "Elasticsearch output performance preset (standalone role).";
    };

    policy = lib.mkOption {
      type = lib.types.lines;
      default = ''
        - type: system/metrics
          id: system-metrics-default
          data_stream.namespace: default
          use_output: default
          streams:
            - metricsets:
                - cpu
              data_stream.dataset: system.cpu
            - metricsets:
                - memory
              data_stream.dataset: system.memory
            - metricsets:
                - network
              data_stream.dataset: system.network
            - metricsets:
                - filesystem
              data_stream.dataset: system.filesystem
      '';
      description = ''
        YAML list of inputs (standalone role). Each item is an input definition
        (see Elastic Agent standalone documentation). This module indents it
        under `inputs:`. Any input type is valid — `system/metrics`,
        `filestream` (list of files to ship), `journald`, etc. Example for
        shipping custom files (rustinel logs):

        ```
        - type: filestream
          id: rustinel-logs
          use_output: default
          data_stream.namespace: default
          streams:
            - id: rustinel-logs
              paths:
                - /var/log/rustinel/rustinel.log
                - /var/log/rustinel/alerts.json
              data_stream.dataset: rustinel
        ```

        File paths must be readable by the agent (it runs as root).
      '';
    };

    # ---- fleet-agent options ----

    fleet = {
      url = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "https://siem.glx:8220";
        description = "Fleet Server URL (fleet-agent role).";
      };

      enrollmentTokenFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "File containing the Fleet enrollment token (fleet-agent role).";
      };

      certificateAuthorities = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [ ];
        description = "PEM CA files to verify the Fleet Server certificate (fleet-agent role).";
      };

      insecure = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Skip TLS verification (fleet-agent role). Not recommended.";
      };

      tags = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Tags applied at enrollment (fleet-agent role).";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.role != "standalone" || cfg.passwordFile != null;
        message = "services.elastic-agent: standalone role requires passwordFile.";
      }
      {
        assertion =
          cfg.role != "fleet-agent" || (cfg.fleet.url != null && cfg.fleet.enrollmentTokenFile != null);
        message = "services.elastic-agent: fleet-agent role requires fleet.url and fleet.enrollmentTokenFile.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    environment.etc."elastic-agent/elastic-agent.yml" = lib.mkIf (cfg.role == "standalone") {
      source = pkgs.writeText "elastic-agent.yml" configText;
    };

    systemd.tmpfiles.settings."elastic-agent" = {
      "${stateDir}".d = {
        mode = "0700";
        user = "root";
        group = "root";
      };
      "/var/log/elastic-agent".d = {
        mode = "0755";
        user = "root";
        group = "root";
      };
    };

    # /bin/systemctl shim for the endpoint installer (see enableEndpointShim).
    systemd.tmpfiles.rules = lib.mkIf cfg.enableEndpointShim [
      "L+ /bin/systemctl - - - - /run/current-system/sw/bin/systemctl"
    ];

    # Elastic Defend's endpoint installer writes its unit file itself with a
    # direct openat() to /etc/systemd/system/ElasticEndpoint.service. On NixOS
    # that directory is a symlink into the read-only store (and even the
    # resolved store directory is mode 0555), so the open fails with EACCES
    # and the installer rolls back — the endpoint component then loops
    # forever in "Starting: endpoint service runtime".
    #
    # This activation snippet (runs after the `etc` snippet, which recreates
    # the symlink on every activation) converts the symlink into a real
    # writable directory and re-syncs the declarative units into it.
    # Foreign files (ElasticEndpoint.service, its wants symlink, ...) are
    # preserved. Without CAP_DAC_OVERRIDE the agent can still write here
    # because the directory is 0755 and the agent runs as root (uid 0 owns
    # it); the whole flow was verified empirically on NixOS 26.11.
    system.activationScripts.elasticAgentUnitsDir = lib.mkIf cfg.mutableUnitsDir (
      lib.stringAfter [ "etc" ] ''
        # Elastic Defend (services.elastic-agent): make /etc/systemd/system
        # writable. setup-etc.pl has just failed to (re)create its symlink
        # (rename(2) onto a directory fails with EISDIR) — a harmless
        # warning — so this runs after `etc` unconditionally.
        if [ -L /etc/systemd/system ]; then
          rm /etc/systemd/system
          mkdir -p /etc/systemd/system
        fi
        if [ -d /etc/systemd/system ]; then
          # Re-sync declarative units (dereference only the top level:
          # unit symlinks must stay symlinks pointing into /nix/store).
          cp -a /etc/static/systemd/system/. /etc/systemd/system/ || true
          # cp -a inherits the store dir mode (0555); restore owner-writable.
          chmod 0755 /etc/systemd/system
        else
          mkdir -p /etc/systemd/system
          chmod 0755 /etc/systemd/system
          cp -a /etc/static/systemd/system/. /etc/systemd/system/ || true
          chmod 0755 /etc/systemd/system
        fi
      ''
    );

    systemd.services.elastic-agent = {
      description = "Elastic Agent";
      documentation = [ "https://www.elastic.co/docs/reference/fleet" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      # The agent resolves its vault/secret dir relative to its own binary
      # (/proc/self/exe) — running the store copy directly would target the
      # read-only store. So we materialise a real copy of the package tree
      # inside the state dir (like the official container image layout) and
      # refresh it whenever the package changes.
      preStart = ''
        home=${stateDir}/Agent
        pkg=${cfg.package}/share/elastic-agent
        mkdir -p ${stateDir}/logs

        if [ "$(cat ${stateDir}/.package 2>/dev/null)" != "${cfg.package}" ]; then
          rm -rf "$home.tmp"
          cp -r "$pkg" "$home.tmp"
          chmod -R u+w "$home.tmp"
          rm -rf "$home.tmp/vault"
          rm -rf "$home.old"
          [ -d "$home" ] && mv "$home" "$home.old" || true
          mv "$home.tmp" "$home"
          rm -rf "$home.old"
          printf "%s" "${cfg.package}" > ${stateDir}/.package
        fi
      ''
      + lib.optionalString (cfg.role == "standalone" && cfg.passwordFile != null) ''

        # The passwordFile is a systemd EnvironmentFile (KEY=VALUE); extract
        # the bare value for the config render. The secret never lands in
        # /etc or the Nix store (the /etc template holds a placeholder token,
        # replaced here into the writable state dir).
        pw=$(sed -n 's/^ELASTIC_AGENT_PASSWORD=//p' ${cfg.passwordFile} | head -1)
        sed "s/__ELASTIC_AGENT_PASSWORD__/$pw/" \
          /etc/elastic-agent/elastic-agent.yml > ${stateDir}/elastic-agent.yml
        chmod 600 ${stateDir}/elastic-agent.yml
      ''
      + lib.optionalString (cfg.role == "fleet-agent") ''

        # Skip re-enrollment when the identity already exists (deploy upgrades,
        # service restarts): enroll --force would otherwise try to daemon-reload
        # an agent that isn't running during activation and fail the switch.
        if [ -f "$home/fleet.enc" ]; then
          echo "fleet.enrollmentTokenFile: agent already enrolled (fleet.enc present), skipping."
        else
          # The tokenFile is a systemd EnvironmentFile (KEY=VALUE); extract the
          # bare value.
          token=$(sed -n 's/^FLEET_ENROLLMENT_TOKEN=//p' ${cfg.fleet.enrollmentTokenFile} | head -1)
          # Non-fatal: if the daemon-reload step fails (no running agent during
          # activation), systemd restarts the service and the loop continues.
          "$home/elastic-agent" enroll \
            --url=${cfg.fleet.url} \
            --enrollment-token="$token" \
            --force \
            ${
              lib.optionalString (
                cfg.fleet.certificateAuthorities != [ ]
              ) "--certificate-authorities=${lib.concatStringsSep "," cfg.fleet.certificateAuthorities}"
            } \
            ${lib.optionalString cfg.fleet.insecure "--insecure"} \
            ${
              lib.optionalString (cfg.fleet.tags != [ ]) "--tag=${lib.concatStringsSep "," cfg.fleet.tags}"
            } \
            --path.home "$home" \
            --path.logs ${stateDir}/logs \
            2>&1 | grep -v "already enrolled" || \
            echo "WARN: enroll reported an error (see above); will retry on next restart."
        fi
      '';

      serviceConfig = {
        Type = "simple";
        ExecStart = "${stateDir}/Agent/elastic-agent run --path.home ${stateDir}/Agent --path.logs ${stateDir}/logs ${
          lib.optionalString (cfg.role == "standalone") "-c ${stateDir}/elastic-agent.yml"
        }";
        WorkingDirectory = stateDir;
        StateDirectory = builtins.baseNameOf stateDir;
        Environment = [
          "STATE_PATH=${stateDir}"
          # Keep the agent away from its read-only store home: logs and
          # runtime data must land in the state dir (journald captures
          # stdout/stderr anyway).
          "HOME=${stateDir}"
          "PATH=/run/current-system/sw/bin"
        ]
        ++ lib.mapAttrsToList (n: v: "${n}=${v}") cfg.extraEnv;
        EnvironmentFile = lib.mkIf (cfg.passwordFile != null) cfg.passwordFile;
        Restart = "always";
        RestartSec = 5;
        # Fleet enrollment (preStart) can take a while on first run.
        TimeoutStartSec = "10min";
        AmbientCapabilities = cfg.extraCapabilities;
        CapabilityBoundingSet = cfg.extraCapabilities;
        NoNewPrivileges = true;
        # The agent supervises child components; keep the cgroup.
        KillMode = "mixed";
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "elastic-agent";
      };
    };
  };
}
