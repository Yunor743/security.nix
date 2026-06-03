{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.rustinel;

  yara-forge-strip-console =
    pkg:
    pkgs.runCommand "yara-forge-stripped" { } ''
      mkdir -p $out/share/yara-forge
      ${pkgs.perl}/bin/perl -0777 -pe 's/\s*and\s+console\.log\s*\([^)]*\)\s*//g; s/console\.log\s*\([^)]*\)\s*and\s*//g; s/^import "console"\n//gm' \
        ${pkg}/share/yara-forge/full/yara-rules-full.yar \
        > $out/share/yara-forge/yara-rules-full.yar
    '';
in
{
  options.services.rustinel = {
    enable = lib.mkEnableOption "rustinel, an open-source endpoint detection engine using eBPF, Sigma, YARA, and IOC matching";

    package = lib.mkPackageOption pkgs "rustinel" { };

    settings = lib.mkOption {
      type =
        with lib.types;
        attrsOf (
          attrsOf (oneOf [
            bool
            int
            str
            (listOf str)
          ])
        );
      default = { };
      description = ''
        Configuration for rustinel's config.toml.
        Top-level sections become TOML tables. Boolean values
        are converted to true/false automatically.
      '';
    };

    yaraRulesPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = ''
        Package containing YARA rules to install.
        Set to pkgs.yara-forge-rules to use the full YARA Forge rule set.
      '';
    };

    sigmaRulesPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = ''
        Package containing Sigma rules to install.
        Set to pkgs.sigma-rules to use the full SigmaHQ rule set.
      '';
    };

    rules = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Additional YARA rules appended to the default rules.
        Each rule should be a complete YARA rule block.
      '';
    };

    sigmaRules = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Additional Sigma rules appended to the default rules.
        Each rule should be a complete YAML document.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc =
      let
        yaraPkg =
          if cfg.yaraRulesPackage != null then yara-forge-strip-console cfg.yaraRulesPackage else null;

        sigmaPkg = cfg.sigmaRulesPackage;

        yaraRulesPath =
          if yaraPkg != null then "${yaraPkg}/share/yara-forge" else "/etc/rustinel/rules/yara";

        sigmaRulesPath =
          if sigmaPkg != null then "${sigmaPkg}/share/sigma" else "/etc/rustinel/rules/sigma";

        defaultConfig = {
          scanner = {
            sigma_enabled = true;
            sigma_rules_path = sigmaRulesPath;
            yara_enabled = true;
            yara_rules_path = yaraRulesPath;
          };
          reload = {
            enabled = true;
            debounce_ms = 2000;
          };
          allowlist = {
            paths = [
              "/nix/store/"
              "/run/wrappers/"
              "/usr/bin/"
              "/usr/sbin/"
              "/usr/lib/"
              "/usr/lib64/"
              "/usr/libexec/"
              "/bin/"
              "/sbin/"
              "/lib/"
              "/lib64/"
            ];
          };
          logging = {
            level = "info";
            directory = "/var/log/rustinel";
            filename = "rustinel.log";
            console_output = false;
          };
          alerts = {
            directory = "/var/log/rustinel";
            filename = "alerts.json";
            match_debug = "off";
          };
          response = {
            enabled = false;
            prevention_enabled = false;
            min_severity = "critical";
            channel_capacity = 128;
          };
          ioc = {
            enabled = true;
            hashes_path = "/etc/rustinel/rules/ioc/hashes.txt";
            ips_path = "/etc/rustinel/rules/ioc/ips.txt";
            domains_path = "/etc/rustinel/rules/ioc/domains.txt";
            paths_regex_path = "/etc/rustinel/rules/ioc/paths_regex.txt";
            default_severity = "high";
            max_file_size_mb = 50;
          };
        };

        mergedConfig = lib.recursiveUpdate defaultConfig cfg.settings;

        toTOMLValue =
          v:
          if builtins.isBool v then
            if v then "true" else "false"
          else if builtins.isInt v then
            toString v
          else if builtins.isList v then
            "[" + lib.concatStringsSep ", " (map (x: "\"${x}\"") v) + "]"
          else
            "\"${v}\"";

        toTOMLSection =
          name: attrs:
          let
            lines = lib.mapAttrsToList (k: v: "${k} = ${toTOMLValue v}") attrs;
          in
          "[${name}]\n" + lib.concatStringsSep "\n" lines;

        configText = lib.concatStringsSep "\n\n" (lib.mapAttrsToList toTOMLSection mergedConfig);

        defaultYARARules = ''
          rule ExampleMarkerString {
              strings:
                  $a = "RUSTINEL_TEST_MARKER" ascii wide
              condition:
                  $a
          }
        ''

        + cfg.rules;

        defaultSigmaRules = ''
          title: Example - Whoami Execution (Linux)
          id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
          status: experimental
          description: Detects execution of whoami (demo rule).
          author: Rustinel
          logsource:
              category: process_creation
              product: linux
          detection:
              selection:
                  Image|endswith:
                      - /whoami
                      - /coreutils
                  CommandLine|contains: whoami
              condition: selection
          level: low
        ''

        + cfg.sigmaRules;
      in
      let
        etcFiles = {
          "rustinel/config.toml".source = pkgs.writeText "config.toml" configText;
          "rustinel/rules/ioc/hashes.txt".source = pkgs.writeText "hashes.txt" "";
          "rustinel/rules/ioc/ips.txt".source = pkgs.writeText "ips.txt" "";
          "rustinel/rules/ioc/domains.txt".source = pkgs.writeText "domains.txt" "";
          "rustinel/rules/ioc/paths_regex.txt".source = pkgs.writeText "paths_regex.txt" "";
        }
        // (
          if yaraPkg != null then
            {
              "rustinel/rules/yara/yara-forge-rules.yar".source =
                "${yaraPkg}/share/yara-forge/yara-rules-full.yar";
            }
          else
            {
              "rustinel/rules/yara/example_test_string.yar".source =
                pkgs.writeText "example_test_string.yar" defaultYARARules;
            }
        )
        // (
          if sigmaPkg != null then
            { "rustinel/rules/sigma/.keep".source = pkgs.writeText ".keep" ""; }
          else
            {
              "rustinel/rules/sigma/linux_whoami.yml".source =
                pkgs.writeText "linux_whoami.yml" defaultSigmaRules;
            }
        );
      in
      etcFiles;

    environment.systemPackages = [
      cfg.package
    ]
    ++ lib.optional (cfg.yaraRulesPackage != null) cfg.yaraRulesPackage
    ++ lib.optional (cfg.sigmaRulesPackage != null) cfg.sigmaRulesPackage;

    systemd.services.rustinel = {
      description = "Rustinel eBPF Endpoint Detection";
      documentation = [ "https://github.com/Karib0u/rustinel" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      preStart = ''
        ln -sf /etc/rustinel/config.toml /var/lib/rustinel/config.toml
        ln -sfn /etc/rustinel/rules /var/lib/rustinel/rules
      '';

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} run";
        WorkingDirectory = "/var/lib/rustinel";
        Restart = "on-failure";
        RestartSec = 5;
        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_SYS_RESOURCE"
          "CAP_SYS_ADMIN"
        ];
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_SYS_RESOURCE"
          "CAP_SYS_ADMIN"
        ];
        NoNewPrivileges = true;
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "rustinel";
      };
    };

    systemd.tmpfiles.settings."rustinel" = {
      "/var/log/rustinel".d = {
        mode = "0755";
        user = "root";
        group = "root";
      };
      "/var/lib/rustinel".d = {
        mode = "0755";
        user = "root";
        group = "root";
      };
    };
  };
}
