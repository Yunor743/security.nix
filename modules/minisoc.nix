{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.minisoc;
  mlib = import ./minisoc-lib.nix { inherit lib; };
  inherit (mlib) severities;

  sevType = lib.types.enum severities;

  spoolDir = "${cfg.collector.stateDir}/spool";

  sourceModule = {
    options = {
      enable = lib.mkEnableOption "this source" // {
        default = true;
      };
      type = lib.mkOption {
        type = lib.types.enum [
          "file"
          "journald"
        ];
        default = "file";
        description = ''
          `file`: lines of the files in `paths`. `journald`: the `MESSAGE` of
          journal entries selected by `journald.matches` (the collector is
          then added to the `systemd-journal` group).
        '';
      };
      journald.matches = lib.mkOption {
        type = lib.types.attrsOf (lib.types.listOf lib.types.str);
        default = { };
        example = {
          _SYSTEMD_UNIT = [ "sshd.service" ];
        };
        description = "Journal fields and accepted values (`journalctl FIELD=value`); empty: whole journal.";
      };
      transform = lib.mkOption {
        type = lib.types.nullOr lib.types.lines;
        default = null;
        example = ''
          if !contains(.raw, "Failed password") { abort }
          .parsed.severity = "medium"
        '';
        description = ''
          VRL run after parsing (on `.raw` and `.parsed`): set fields the
          engine reads (`.parsed.message`, `.parsed.severity`,
          `.parsed.event_type`, `.parsed.timestamp`) or drop the event with
          `abort`.
        '';
      };
      paths = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "/var/log/rustinel/alerts.json*" ];
        description = ''
          Files to watch (glob patterns allowed). Files created later,
          rotated or truncated are followed by Vector, which also persists
          its read position across restarts.
        '';
      };
      parser = lib.mkOption {
        type = lib.types.enum [
          "json"
          "regex"
          "grok"
          "syslog"
          "raw"
        ];
        default = "json";
        description = ''
          How each line is parsed (in Vector/VRL): `json` (one object per
          line), `regex` (named captures, `pattern`), `grok` (`pattern`,
          standard grok patterns), `syslog` (RFC 3164/5424) or `raw` (the line
          becomes `message`). Lines that fail to parse are kept as
          `parse_error` events.
        '';
      };
      pattern = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
        description = "Regex (with named groups) or grok pattern, for the `regex` and `grok` parsers.";
      };
      normalizer = lib.mkOption {
        type = lib.types.enum [
          "generic"
          "rustinel"
        ];
        default = "generic";
        description = ''
          `generic`: fields located through `mapping` or common names
          (`@timestamp`/`timestamp`, `severity`/`level`, `message`/`msg`...).
          `rustinel`: Rustinel ECS alerts.
        '';
      };
      mapping = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = {
          severity = "alert.severity";
          message = "alert.signature";
          event_type = "event_type";
        };
        description = "Field paths (dotted) for `timestamp`, `severity`, `event_type` and `message`.";
      };
      severityMap = lib.mkOption {
        type = lib.types.attrsOf sevType;
        default = { };
        example = {
          "1" = "high";
          p1 = "critical";
        };
        description = "Source severity values (lower-case) mapped to MiniSOC severities.";
      };
      defaultSeverity = lib.mkOption {
        type = lib.types.nullOr sevType;
        default = null;
        description = "Severity when the event carries none (otherwise `unknown`).";
      };
      eventType = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Static event type for this source (otherwise read from the event).";
      };
      readFrom = lib.mkOption {
        type = lib.types.enum [
          "beginning"
          "end"
        ];
        default = "beginning";
        description = "Where to start in files seen for the first time.";
      };
      ignoreOlderThan = lib.mkOption {
        type = lib.types.int;
        default = 7 * 24 * 3600;
        description = "Skip files not modified for this many seconds.";
      };
    };
  };

  promptModule = {
    options = {
      text = lib.mkOption {
        type = lib.types.nullOr lib.types.lines;
        default = null;
        description = "Prompt embedded in the configuration.";
      };
      file = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Prompt file.";
      };
    };
  };

  promptNames = [
    "system"
    "analysis"
    "enrichment"
    "classification"
    "filter"
    "review"
  ];

  promptPath =
    name:
    let
      p = cfg.ai.prompts.${name};
      shortcut =
        if name == "analysis" && cfg.ai.prompt != null then
          pkgs.writeText "minisoc-prompt-analysis.md" cfg.ai.prompt
        else if name == "analysis" && cfg.ai.promptFile != null then
          cfg.ai.promptFile
        else
          null;
    in
    if p.text != null then
      pkgs.writeText "minisoc-prompt-${name}.md" p.text
    else if p.file != null then
      p.file
    else
      shortcut;

  remoteProviders = [
    "openai"
    "anthropic"
    "gemini"
    "openrouter"
  ];
  # Loopback check (the engine re-checks at runtime).
  endpointIsLocal =
    e:
    let
      authority = lib.head (lib.splitString "/" (lib.last (lib.splitString "://" e)));
    in
    lib.hasPrefix "[::1]" authority
    || builtins.match "(localhost|127\\.[0-9.]+)(:[0-9]+)?" authority != null;
  aiIsRemote =
    if cfg.ai.endpoint != null then
      !(endpointIsLocal cfg.ai.endpoint)
    else
      builtins.elem cfg.ai.provider remoteProviders;

  systemRulesFile =
    if cfg.filter.systemFile != null then
      cfg.filter.systemFile
    else if cfg.filter.systemRules != [ ] then
      (pkgs.formats.yaml { }).generate "alert_filter.yaml" {
        version = 1;
        filters = cfg.filter.systemRules;
      }
    else
      null;

  # Validated at build time with the engine's own parser.
  validatedSystemRules = pkgs.runCommandLocal "minisoc-system-rules" { } ''
    ${lib.getExe cfg.package} --config /dev/null filter validate ${systemRulesFile}
    cp ${systemRulesFile} $out
  '';

  engineConfig = {
    spool_dirs = lib.optional cfg.collector.enable spoolDir;
    poll_interval_ms = cfg.engine.pollIntervalMs;
    log_level = cfg.engine.logLevel;
    sources = lib.mapAttrs (_: s: {
      inherit (s) normalizer mapping;
      severity_map = s.severityMap;
      default_severity = s.defaultSeverity;
      event_type = s.eventType;
    }) cfg.sources;
    filter = {
      inherit (cfg.filter) file debug;
      system_files = lib.optional (systemRulesFile != null) "/etc/minisoc/alert_filter.yaml";
      seed = cfg.filter.seedUserFile;
      max_backups = cfg.filter.maxBackups;
    }
    // lib.optionalAttrs (cfg.filter.aiFile != null) { ai_file = cfg.filter.aiFile; };
    retention = {
      days = cfg.engine.retention.days;
      max_events = cfg.engine.retention.maxEvents;
    };
    ai = {
      enable = cfg.ai.enable;
      inherit (cfg.ai) provider model endpoint;
      api_key_file = cfg.ai.apiKeyFile;
      allow_remote = cfg.ai.allowRemote;
      analysis = {
        inherit (cfg.ai.analysis) enabled;
        auto_analyze = cfg.ai.analysis.autoAnalyze;
        min_severity = cfg.ai.analysis.minimumSeverity;
      };
      limits = with cfg.ai.limits; {
        max_concurrent = maxConcurrent;
        requests_per_minute = requestsPerMinute;
        daily_quota = dailyQuota;
        timeout_secs = timeout;
        max_retries = maxRetries;
        backoff_base_secs = backoffBase;
        max_queue = maxQueue;
        max_event_bytes = maxEventBytes;
        max_output_tokens = maxOutputTokens;
        cache_ttl_hours = cacheTtlHours;
      };
      privacy = with cfg.ai.privacy; {
        redact_private_ips = redactPrivateIps;
        redact_paths = redactPaths;
        redact_users = redactUsers;
        exclude_fields = excludeFields;
        send_raw = sendRaw;
      };
      auto_discard = with cfg.ai.analysis.autoDiscardPolicy; {
        mode = if cfg.ai.analysis.autoDiscard then mode else "off";
        maximum_severity = maximumSeverity;
        minimum_confidence = minimumConfidence;
        minimum_false_positive_likelihood = minimumFalsePositiveLikelihood;
        require_repeated_benign_pattern = requireRepeatedBenignPattern;
        minimum_occurrences = minimumOccurrences;
      };
      auto_filter = with cfg.ai.autoFilter; {
        mode = if enable then mode else "off";
        minimum_confidence = minimumConfidence;
        minimum_false_positive_likelihood = minimumFalsePositiveLikelihood;
        require_repeated_events = requireRepeatedEvents;
        minimum_occurrences = minimumOccurrences;
        protect_severity = protectSeverity;
        backup_before_write = backupBeforeWrite;
      };
      filter_review = with cfg.ai.filterReview; {
        mode = if enable then mode else "off";
        interval_hours = interval;
        lookback_days = lookbackDays;
        max_alerts = maxAlerts;
        minimum_false_positives = minimumFalsePositives;
        minimum_rule_age_hours = minimumRuleAge;
        low_hits_threshold = lowHitsThreshold;
        max_changes = maxChanges;
        minimum_confidence = minimumConfidence;
        backup_before_write = backupBeforeWrite;
      };
      prompts = lib.filterAttrs (_: v: v != null) (
        lib.genAttrs promptNames (n: if promptPath n == null then null else "${promptPath n}")
      );
    };
  };

  engineConfigFile = pkgs.writeText "minisoc-engine.json" (builtins.toJSON engineConfig);

  vectorConfigFile = pkgs.writeText "minisoc-vector.json" (
    builtins.toJSON (
      lib.recursiveUpdate (mlib.mkVectorConfig {
        inherit (cfg) sources;
        inherit spoolDir;
        dataDir = "${cfg.collector.stateDir}/data";
        journalctl = "${config.systemd.package}/bin/journalctl";
      }) cfg.collector.extraSettings
    )
  );

  enabledSources = lib.filterAttrs (_: s: s.enable) cfg.sources;
in
{
  options.services.minisoc = {
    enable = lib.mkEnableOption "MiniSOC, a personal local SOC (collector, filtering, triage UI, optional LLM analysis)";

    package = lib.mkPackageOption pkgs "minisoc" { };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Users running MiniSOC. They join the `minisoc` group (read access to
        the collector spool) and get the `minisoc-engine` user service.
        Alerts, pins and rules are per user (`~/.local/state/minisoc`,
        `~/.config/minisoc`).
      '';
    };

    collector = {
      enable = lib.mkEnableOption "the Vector collector (system service)" // {
        default = true;
      };
      package = lib.mkPackageOption pkgs "vector" { };
      readAnyFile = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Give the collector CAP_DAC_READ_SEARCH so it can read root-only logs
          (Rustinel writes 0600 files in a 0700 directory). Read access only:
          the service has no other capability, no network and a read-only
          view of the system. Disable when every source is world/group readable.
        '';
      };
      stateDir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/minisoc-collector";
        description = "Vector checkpoints (`data/`) and the normalized spool (`spool/`).";
      };
      spoolRetention = lib.mkOption {
        type = lib.types.str;
        default = "7d";
        description = "Age after which spool files are removed by systemd-tmpfiles (original logs are never touched).";
      };
      extraSettings = lib.mkOption {
        type = lib.types.attrs;
        default = { };
        description = "Merged into the generated Vector configuration.";
      };
    };

    integrations.rustinel.enable = lib.mkOption {
      type = lib.types.bool;
      default = config.services.rustinel.enable or false;
      defaultText = lib.literalExpression "config.services.rustinel.enable";
      description = "Collect Rustinel alerts (`/var/log/rustinel/alerts.json*`).";
    };

    integrations.apparmor = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = config.security.apparmor.enable;
        defaultText = lib.literalExpression "config.security.apparmor.enable";
        description = "Alert on AppArmor denials (kernel audit records in the journal).";
      };
      wouldBe = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Also alert (severity `low`) on what profiles in complain mode would
          deny. Noisy: apparmor.d in complain mode logs a lot.
        '';
      };
    };

    integrations.selinux = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = config.security.selinux.enable or false;
        defaultText = lib.literalExpression "config.security.selinux.enable";
        description = "Alert on SELinux AVC denials.";
      };
      wouldBe = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Also alert (severity `low`) on permissive denials (`permissive=1`), not enforced.";
      };
    };

    integrations.fapolicyd = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = config.services.fapolicyd.enable or false;
        defaultText = lib.literalExpression "config.services.fapolicyd.enable";
        description = "Alert on fapolicyd denials (`deny_syslog` rules).";
      };
      wouldBe = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          In permissive mode (`services.fapolicyd.permissive`), also alert
          (severity `low`) on what would be denied.
        '';
      };
    };

    sources = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule sourceModule);
      default = { };
      example = lib.literalExpression ''
        {
          applicationA = {
            paths = [ "/var/log/applicationA/log.txt" ];
            parser = "grok";
            pattern = "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
          };
        }
      '';
      description = "Log sources. Names must match `[A-Za-z0-9_-]+`.";
    };

    engine = {
      pollIntervalMs = lib.mkOption {
        type = lib.types.int;
        default = 1000;
        description = "Spool / rules polling interval.";
      };
      logLevel = lib.mkOption {
        type = lib.types.enum [
          "error"
          "warn"
          "info"
          "debug"
        ];
        default = "info";
      };
      retention = {
        days = lib.mkOption {
          type = lib.types.int;
          default = 30;
          description = "Events not seen for this many days are pruned (pinned ones are kept).";
        };
        maxEvents = lib.mkOption {
          type = lib.types.int;
          default = 20000;
          description = "Upper bound of stored events (pinned ones are kept).";
        };
      };
    };

    filter = {
      file = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "$XDG_CONFIG_HOME/security/minisoc-rules.yaml";
        description = ''
          Custom path of the per-user rules file (`~`, `$HOME` and `$XDG_*`
          are expanded per user). Takes priority over the default
          `~/.config/minisoc/alert_filter.yaml`. Must stay writable by the
          user for "Create filter" and AI auto-filter.
        '';
      };
      systemRules = lib.mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = [ ];
        example = lib.literalExpression ''
          [
            {
              id = "ignore_whoami_demo";
              description = "Rustinel demo rule";
              match = { source = "rustinel"; message = { contains = "Whoami"; }; };
              action = "exclude";
            }
          ]
        '';
        description = ''
          Rules administered by NixOS, installed read-only as
          `/etc/minisoc/alert_filter.yaml` (validated at build time) and
          evaluated before the user's rules. They end up in the world-readable
          Nix store: do not put sensitive values here.
        '';
      };
      systemFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Use this file instead of `systemRules`.";
      };
      aiFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "$XDG_STATE_HOME/minisoc/ai_filters.yaml";
        description = ''
          Per-user file of the rules owned by the AI (auto-filter and filter
          review); default `~/.config/minisoc/ai_filters.yaml`. MiniSOC
          rewrites it (validated, backed up first); the AI never writes the
          user rules file.
        '';
      };
      seedUserFile = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Create the user rules file (0600, directory 0700) when missing. Never overwrites.";
      };
      debug = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Log, for every event, which rule conditions matched (journalctl --user -u minisoc-engine).";
      };
      maxBackups = lib.mkOption {
        type = lib.types.int;
        default = 20;
        description = "Backups kept of the user rules file before each automated change.";
      };
    };

    ai = {
      enable = lib.mkEnableOption "LLM-based SOC N1 analysis (off by default; MiniSOC works fully without it)";

      provider = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.enum [
            "openai"
            "anthropic"
            "gemini"
            "ollama"
            "openrouter"
            "openai-compatible"
            "custom"
          ]
        );
        default = null;
        description = ''
          `ollama` (local by default), `openai`, `anthropic`, `gemini`,
          `openrouter` (any model routed by openrouter.ai, e.g.
          `anthropic/claude-haiku-5.5`),
          `openai-compatible` (any /chat/completions server: llama.cpp, vLLM,
          LM Studio...; needs `endpoint`) or `custom` (POST
          `{model, system, prompt}`, reply `{output}`; needs `endpoint`).
        '';
      };
      model = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "qwen3:8b";
        description = "Model name as the provider expects it.";
      };
      endpoint = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "http://127.0.0.1:11434";
        description = "Override the provider URL (required for openai-compatible and custom).";
      };
      apiKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/run/secrets/minisoc-api-key";
        description = ''
          File holding the API key, read at each request by the user's engine
          (so it must be readable by the MiniSOC users, e.g. a sops-nix/agenix
          secret owned by that user, mode 0400). Only the path is stored in
          the configuration; never put the key itself in Nix.
        '';
      };
      allowRemote = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Allow sending (redacted, size-limited) alert data to a non-local
          endpoint. Without it only loopback endpoints (e.g. Ollama) work.
        '';
      };
      prompt = lib.mkOption {
        type = lib.types.nullOr lib.types.lines;
        default = null;
        description = "Shortcut for `prompts.analysis.text`.";
      };
      promptFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Shortcut for `prompts.analysis.file`.";
      };
      prompts = lib.genAttrs promptNames (
        n:
        lib.mkOption {
          type = lib.types.submodule promptModule;
          default = { };
          description = ''
            `${n}` prompt (text or file). A user file
            `~/.config/minisoc/prompts/${n}.md` overrides it at runtime (edit
            with `minisoc prompts edit ${n}`, no rebuild needed).
          '';
        }
      );

      analysis = {
        enabled = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        autoAnalyze = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Analyze new admissible alerts automatically (otherwise only on request).";
        };
        minimumSeverity = lib.mkOption {
          type = sevType;
          default = "medium";
          description = "Only alerts at or above this severity are sent (unknown counts as medium).";
        };
        autoDiscard = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Let the AI propose (or perform, see autoDiscardPolicy.mode) closing benign alerts as false positive. The filter review never learns from these AI closures, only from the user's.";
        };
        autoDiscardPolicy = {
          mode = lib.mkOption {
            type = lib.types.enum [
              "suggest"
              "automatic"
            ];
            default = "suggest";
            description = "`suggest`: a proposal waits for your confirmation; `automatic`: closed as FP by the AI (re-openable).";
          };
          maximumSeverity = lib.mkOption {
            type = lib.types.enum [
              "info"
              "low"
              "medium"
              "high"
            ];
            default = "low";
            description = "Highest severity the AI may close as FP. critical: never (not configurable).";
          };
          minimumConfidence = lib.mkOption {
            type = lib.types.float;
            default = 0.75;
            description = "Minimum `benign_confidence` (confidence that the event is benign, not detection confidence).";
          };
          minimumFalsePositiveLikelihood = lib.mkOption {
            type = lib.types.enum [
              "low"
              "medium"
              "high"
            ];
            default = "high";
            description = "Minimum `false_positive_likelihood` given by the model. A suspicious/malicious/unknown verdict is always kept, whatever this says.";
          };
          requireRepeatedBenignPattern = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Require the same pattern to be seen `minimumOccurrences` times with >= 2 benign analyses.";
          };
          minimumOccurrences = lib.mkOption {
            type = lib.types.int;
            default = 2;
          };
          preservePinned = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Pinned alerts are never touched by the AI. Cannot be disabled.";
          };
        };
      };

      autoFilter = {
        enable = lib.mkEnableOption "AI proposals of exclusion rules for recurring benign alerts";
        mode = lib.mkOption {
          type = lib.types.enum [
            "suggest"
            "automatic"
          ];
          default = "suggest";
          description = "`suggest`: rules wait for validation in the UI; `automatic`: appended to the AI rules file (`filter.aiFile`, backup first).";
        };
        minimumConfidence = lib.mkOption {
          type = lib.types.float;
          default = 0.85;
        };
        minimumFalsePositiveLikelihood = lib.mkOption {
          type = lib.types.enum [
            "low"
            "medium"
            "high"
          ];
          default = "high";
          description = "Minimum `false_positive_likelihood` of the analysis that triggers a rule proposal.";
        };
        requireRepeatedEvents = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        minimumOccurrences = lib.mkOption {
          type = lib.types.int;
          default = 3;
        };
        protectSeverity = lib.mkOption {
          type = lib.types.listOf sevType;
          default = [
            "critical"
            "high"
          ];
          description = "Severities AI rules can never hide (critical and high are always included).";
        };
        backupBeforeWrite = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
      };

      filterReview = {
        enable = lib.mkEnableOption ''
          the scheduled AI review of the AI rules: from the alerts the user
          closed as false positive (TP closures as counter-examples) and each
          rule's counter, the model creates, updates or deletes the rules of
          the AI file. Code-enforced guardrails: see docs/minisoc.md'';
        mode = lib.mkOption {
          type = lib.types.enum [
            "suggest"
            "automatic"
          ];
          default = "suggest";
          description = "`suggest`: changes wait for validation in the UI; `automatic`: the AI rules file is rewritten (backup first).";
        };
        interval = lib.mkOption {
          type = lib.types.numbers.positive;
          default = 24;
          description = "Hours between two reviews (`minisoc review` runs one now).";
        };
        lookbackDays = lib.mkOption {
          type = lib.types.ints.positive;
          default = 30;
          description = "Closures taken into account.";
        };
        maxAlerts = lib.mkOption {
          type = lib.types.ints.positive;
          default = 200;
          description = "Closed alerts considered per verdict (most recent first).";
        };
        minimumFalsePositives = lib.mkOption {
          type = lib.types.ints.positive;
          default = 3;
          description = "A created or updated rule must cover at least this many alerts closed as FP by the user.";
        };
        minimumRuleAge = lib.mkOption {
          type = lib.types.numbers.nonnegative;
          default = 72;
          description = "Hours since its last change before a rule may be modified or deleted (its counter needs time).";
        };
        lowHitsThreshold = lib.mkOption {
          type = lib.types.ints.unsigned;
          default = 2;
          description = "A rule may be deleted when it excluded at most this many alerts since its last change (or when it would hide a TP).";
        };
        maxChanges = lib.mkOption {
          type = lib.types.ints.positive;
          default = 5;
        };
        minimumConfidence = lib.mkOption {
          type = lib.types.float;
          default = 0.7;
        };
        backupBeforeWrite = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
      };

      limits = {
        maxConcurrent = lib.mkOption {
          type = lib.types.ints.between 1 8;
          default = 1;
        };
        requestsPerMinute = lib.mkOption {
          type = lib.types.ints.positive;
          default = 6;
        };
        dailyQuota = lib.mkOption {
          type = lib.types.ints.positive;
          default = 200;
        };
        timeout = lib.mkOption {
          type = lib.types.ints.positive;
          default = 60;
          description = "Seconds per request.";
        };
        maxRetries = lib.mkOption {
          type = lib.types.ints.unsigned;
          default = 3;
        };
        backoffBase = lib.mkOption {
          type = lib.types.float;
          default = 2.0;
          description = "Exponential backoff base delay (seconds); Retry-After is honoured.";
        };
        maxQueue = lib.mkOption {
          type = lib.types.ints.positive;
          default = 100;
        };
        maxEventBytes = lib.mkOption {
          type = lib.types.ints.positive;
          default = 4000;
          description = "Upper bound of the event payload sent to the model.";
        };
        maxOutputTokens = lib.mkOption {
          type = lib.types.ints.positive;
          default = 4096;
        };
        cacheTtlHours = lib.mkOption {
          type = lib.types.ints.positive;
          default = 168;
          description = "Analyses are reused for similar alerts (same fingerprint, model and prompts).";
        };
      };

      privacy = {
        redactPrivateIps = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        redactPaths = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Replace file paths by a hash + basename.";
        };
        redactUsers = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Replace user names and /home/<user>.";
        };
        excludeFields = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [
            "process.command_line"
            "edr.process.cgroup_path"
          ];
          description = "Field paths never sent to the model.";
        };
        sendRaw = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Also send the raw log line (off: only normalized + parsed fields).";
        };
      };
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        services.minisoc.sources = lib.mkMerge [
          (lib.mkIf cfg.integrations.rustinel.enable {
            rustinel = {
              paths = lib.mkDefault [ "/var/log/rustinel/alerts.json*" ];
              parser = lib.mkDefault "json";
              normalizer = lib.mkDefault "rustinel";
            };
          })
          # Access denials of the security modules, from the journal.
          (lib.mkIf cfg.integrations.apparmor.enable {
            apparmor = {
              type = "journald";
              journald.matches._TRANSPORT = lib.mkDefault [ "audit" ];
              parser = "raw";
              readFrom = lib.mkDefault "end";
              transform = lib.mkDefault (
                mlib.macTransforms.apparmor { inherit (cfg.integrations.apparmor) wouldBe; }
              );
            };
          })
          (lib.mkIf cfg.integrations.selinux.enable {
            selinux = {
              type = "journald";
              journald.matches._TRANSPORT = lib.mkDefault [ "audit" ];
              parser = "raw";
              readFrom = lib.mkDefault "end";
              transform = lib.mkDefault (
                mlib.macTransforms.selinux { inherit (cfg.integrations.selinux) wouldBe; }
              );
            };
          })
          (lib.mkIf cfg.integrations.fapolicyd.enable {
            fapolicyd = {
              type = "journald";
              journald.matches._SYSTEMD_UNIT = lib.mkDefault [ "fapolicyd.service" ];
              parser = "raw";
              readFrom = lib.mkDefault "end";
              transform = lib.mkDefault (
                mlib.macTransforms.fapolicyd {
                  inherit (cfg.integrations.fapolicyd) wouldBe;
                  permissive = config.services.fapolicyd.permissive or false;
                }
              );
            };
          })
        ];

        assertions = [
          {
            assertion = lib.all (n: builtins.match "[A-Za-z0-9_-]+" n != null) (lib.attrNames cfg.sources);
            message = "services.minisoc.sources: names must match [A-Za-z0-9_-]+.";
          }
          {
            assertion = lib.all (
              s:
              !(lib.elem s.parser [
                "regex"
                "grok"
              ])
              || s.pattern != null
            ) (lib.attrValues cfg.sources);
            message = "services.minisoc.sources: the regex and grok parsers need a `pattern`.";
          }
          {
            assertion = lib.all (s: s.type != "file" || s.paths != [ ]) (lib.attrValues enabledSources);
            message = "services.minisoc.sources: file sources need `paths`.";
          }
          {
            assertion = lib.all (s: s.parser != "regex" || !(lib.hasInfix "'" s.pattern)) (
              lib.attrValues cfg.sources
            );
            message = "services.minisoc.sources: regex patterns cannot contain a single quote (use \\x27).";
          }
          {
            assertion = !cfg.ai.enable || (cfg.ai.provider != null && cfg.ai.model != null);
            message = "services.minisoc.ai: `provider` and `model` are required when AI is enabled.";
          }
          {
            assertion =
              !cfg.ai.enable
              || cfg.ai.endpoint != null
              || !(lib.elem cfg.ai.provider [
                "openai-compatible"
                "custom"
              ]);
            message = "services.minisoc.ai: provider ${toString cfg.ai.provider} needs `endpoint`.";
          }
          {
            assertion = !cfg.ai.enable || !aiIsRemote || cfg.ai.allowRemote;
            message = ''
              services.minisoc.ai: provider ${toString cfg.ai.provider} sends alert data off this machine.
              Set services.minisoc.ai.allowRemote = true to accept it (data is redacted and size-limited),
              or use a local provider (ollama, or a loopback endpoint).
            '';
          }
          {
            assertion =
              !cfg.ai.enable || cfg.ai.apiKeyFile != null || !(lib.elem cfg.ai.provider remoteProviders);
            message = "services.minisoc.ai: provider ${toString cfg.ai.provider} needs `apiKeyFile`.";
          }
          {
            assertion = cfg.ai.apiKeyFile == null || !(lib.hasPrefix builtins.storeDir cfg.ai.apiKeyFile);
            message = "services.minisoc.ai.apiKeyFile must not be in the Nix store (world-readable); use sops-nix/agenix.";
          }
          {
            assertion = cfg.ai.analysis.autoDiscardPolicy.preservePinned;
            message = "services.minisoc.ai.analysis.autoDiscardPolicy.preservePinned cannot be disabled.";
          }
          {
            assertion = !cfg.collector.enable || enabledSources != { };
            message = "services.minisoc: the collector has no source (enable Rustinel or define services.minisoc.sources).";
          }
        ];

        warnings =
          lib.optional (
            cfg.users == [ ]
          ) "services.minisoc: no user in services.minisoc.users, nobody will run the engine."
          ++
            lib.optional (cfg.ai.enable && aiIsRemote)
              "services.minisoc.ai: redacted alert data will be sent to a remote provider (${toString cfg.ai.provider}).";

        users.groups.minisoc = { };
        users.users = lib.genAttrs cfg.users (_: {
          extraGroups = [ "minisoc" ];
        });

        environment.systemPackages = [ cfg.package ];

        environment.etc = {
          "minisoc/engine.json".source = engineConfigFile;
        }
        // lib.optionalAttrs (systemRulesFile != null) {
          "minisoc/alert_filter.yaml".source = validatedSystemRules;
        };

        # Per-user engine: reads the spool (group minisoc) and the user's own
        # rules / state. Runs unprivileged, only for members of `minisoc`.
        systemd.user.services.minisoc-engine = {
          description = "MiniSOC engine";
          documentation = [ "https://github.com/Yunor743/security.nix" ];
          wantedBy = [ "default.target" ];
          unitConfig.ConditionGroup = "minisoc";
          restartTriggers = [ engineConfigFile ];
          environment.MINISOC_CONFIG = "/etc/minisoc/engine.json";
          serviceConfig = {
            ExecStart = "${lib.getExe cfg.package} engine";
            Restart = "on-failure";
            RestartSec = 5;
            UMask = "0077";
            NoNewPrivileges = true;
            LockPersonality = true;
            RestrictRealtime = true;
            MemoryDenyWriteExecute = true;
            SystemCallArchitectures = "native";
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
          };
        };
      }

      (lib.mkIf cfg.collector.enable {
        users.users.minisoc-collector = {
          isSystemUser = true;
          group = "minisoc";
          description = "MiniSOC log collector";
        };

        systemd.tmpfiles.settings."10-minisoc" = {
          ${cfg.collector.stateDir}.d = {
            user = "minisoc-collector";
            group = "minisoc";
            mode = "0750";
          };
          "${cfg.collector.stateDir}/data".d = {
            user = "minisoc-collector";
            group = "minisoc";
            mode = "0700";
          };
          ${spoolDir}.d = {
            user = "minisoc-collector";
            group = "minisoc";
            mode = "0750";
            age = cfg.collector.spoolRetention;
          };
        };

        systemd.services.minisoc-collector = {
          description = "MiniSOC log collector (Vector)";
          wantedBy = [ "multi-user.target" ];
          after = [ "local-fs.target" ];
          restartTriggers = [ vectorConfigFile ];
          serviceConfig = {
            ExecStartPre = [
              # As root ("+"): the directories may be hidden by a bind mount
              # set up after tmpfiles ran (impermanence on switch).
              "+${pkgs.coreutils}/bin/install -d -o minisoc-collector -g minisoc -m 0750 ${cfg.collector.stateDir} ${spoolDir}"
              "+${pkgs.coreutils}/bin/install -d -o minisoc-collector -g minisoc -m 0700 ${cfg.collector.stateDir}/data"
              "${lib.getExe cfg.collector.package} validate --no-environment ${vectorConfigFile}"
            ];
            ExecStart = "${lib.getExe cfg.collector.package} --config ${vectorConfigFile}";
            User = "minisoc-collector";
            Group = "minisoc";
            UMask = "0027";
            Restart = "on-failure";
            RestartSec = 5;

            # Read-only access to logs, nothing else.
            # Journal sources (security module denials...).
            SupplementaryGroups = lib.optional (lib.any (s: s.type == "journald") (
              lib.attrValues enabledSources
            )) "systemd-journal";
            AmbientCapabilities = lib.optional cfg.collector.readAnyFile "CAP_DAC_READ_SEARCH";
            CapabilityBoundingSet = lib.optional cfg.collector.readAnyFile "CAP_DAC_READ_SEARCH";
            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = "read-only";
            ReadWritePaths = [ cfg.collector.stateDir ];
            PrivateTmp = true;
            PrivateDevices = true;
            PrivateNetwork = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectKernelLogs = true;
            ProtectControlGroups = true;
            ProtectClock = true;
            ProtectHostname = true;
            RestrictAddressFamilies = [ "AF_UNIX" ];
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            SystemCallArchitectures = "native";
            SystemCallFilter = [ "@system-service" ];
          };
        };
      })
    ]
  );
}
