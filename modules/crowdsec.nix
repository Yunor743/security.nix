{
  config,
  options,
  lib,
  pkgs,
  ...
}:

# CrowdSec for a NixOS host in a few options, on top of nixpkgs'
# services.crowdsec and services.crowdsec-firewall-bouncer:
#
# - a standalone engine with its local API, the machine registered, the
#   firewall bouncer registered and wired to nftables/iptables;
# - log sources derived from the enabled services (sshd, nginx, caddy...),
#   with their hub collections;
# - `mode = "simulation"` first: decisions are computed and logged but the
#   bouncer ignores them; `enforce` bans;
# - progressive ban duration, an allow-list of addresses that are never
#   banned, the community blocklist / central API off by default (it shares
#   the attacking IPs with CrowdSec) — opt in.

let
  cfg = config.security.crowdsec;

  stateDir = "/var/lib/crowdsec";

  # Sources for the services this host runs: name -> acquisition, collection.
  autoSources = lib.filter (s: s.when) [
    {
      when = config.services.openssh.enable;
      collections = [
        "crowdsecurity/linux"
        "crowdsecurity/sshd"
      ];
      acquisition = {
        source = "journalctl";
        journalctl_filter = [ "_SYSTEMD_UNIT=sshd.service" ];
        labels.type = "syslog";
      };
    }
    {
      when = config.services.nginx.enable or false;
      collections = [ "crowdsecurity/nginx" ];
      acquisition = {
        source = "file";
        filenames = [ "/var/log/nginx/*.log" ];
        labels.type = "nginx";
      };
    }
    {
      when = config.services.caddy.enable or false;
      collections = [ "crowdsecurity/caddy" ];
      acquisition = {
        source = "journalctl";
        journalctl_filter = [ "_SYSTEMD_UNIT=caddy.service" ];
        labels.type = "caddy";
      };
    }
  ];

  sources = lib.optionals cfg.sources.auto autoSources;

  # nixpkgs reorganised its module (26.05): everything under `settings`.
  newApi = (options.services.crowdsec.settings.type.getSubOptions [ ]) ? config;

  acquisitions = map (s: s.acquisition) sources ++ cfg.sources.extra;

  allowParsers = lib.optional (cfg.allowList != [ ]) {
    name = "nixos/allow-list";
    description = "Addresses never banned (security.crowdsec.allowList)";
    whitelist = {
      reason = "security.crowdsec.allowList";
      ip = lib.filter (a: !lib.hasInfix "/" a) cfg.allowList;
      cidr = lib.filter (lib.hasInfix "/") cfg.allowList;
    };
  };

  ban = {
    type = "ban";
    duration = cfg.banDuration;
  };

  profiles = [
    (
      {
        name = "nixos_ip_remediation";
        filters = [ "Alert.Remediation == true && Alert.GetScope() == 'Ip'" ];
        decisions = [ ban ];
        on_success = "break";
      }
      // lib.optionalAttrs cfg.progressiveBans {
        # 1st ban: banDuration; then multiplied by the number of past bans.
        # No `%` here: nixpkgs writes profiles through systemd-tmpfiles,
        # which reads `%` as a specifier.
        duration_expr = "string((GetDecisionsCount(Alert.GetValue()) + 1) * ${toString cfg.banMinutes}) + \"m\"";
      }
    )
    {
      name = "nixos_range_remediation";
      filters = [ "Alert.Remediation == true && Alert.GetScope() == 'Range'" ];
      decisions = [
        {
          type = "ban";
          duration = cfg.banDuration;
        }
      ];
      on_success = "break";
    }
  ];
in
{
  options.security.crowdsec = {
    enable = lib.mkEnableOption ''
      CrowdSec (behaviour-based intrusion prevention): local engine and API,
      sources derived from the enabled services, firewall bouncer'';

    mode = lib.mkOption {
      type = lib.types.enum [
        "simulation"
        "enforce"
      ];
      default = "simulation";
      description = ''
        `simulation`: scenarios fire and decisions are recorded (`cscli
        decisions list`, `cscli alerts list`, the journal) but flagged as
        simulated: the bouncer bans nobody. `enforce`: decisions are applied
        by the firewall bouncer. Start in simulation and look at what would
        have been banned.
      '';
    };

    sources = {
      auto = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Watch the logs of the services this host runs, with their hub
          collections: sshd (journal), nginx (files), caddy (journal).
        '';
      };
      extra = lib.mkOption {
        type = lib.types.listOf (pkgs.formats.yaml { }).type;
        default = [ ];
        example = lib.literalExpression ''
          [ { source = "file"; filenames = [ "/var/log/myapp/*.log" ]; labels.type = "myapp"; } ]
        '';
        description = "Additional acquisitions (CrowdSec data source specifications).";
      };
    };

    collections = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "crowdsecurity/http-cve" ];
      description = "Hub collections installed in addition to those of the detected sources.";
    };

    allowList = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "192.0.2.10"
        "100.64.0.0/10"
      ];
      description = ''
        Addresses or CIDR ranges that never trigger a decision (your VPN,
        monitoring, admin hosts). Private ranges are already allow-listed by
        the `crowdsecurity/whitelists` parser of the linux collection.
      '';
    };

    banDuration = lib.mkOption {
      type = lib.types.str;
      default = "4h";
      description = "Duration of a ban (first one when `progressiveBans`).";
    };

    progressiveBans = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Repeat offenders get longer bans: the duration is multiplied by the number of past decisions on the address.";
    };

    banMinutes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 240;
      internal = true;
      description = "Base of the progressive duration, in minutes (follows `banDuration` by default).";
    };

    bouncer = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Apply the decisions with the firewall bouncer (nftables when `networking.nftables.enable`, iptables otherwise).";
      };
    };

    communityBlocklist = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Register to the CrowdSec central API: receive the community blocklist
        and share the alerts of this host (attacking IPs, scenarios). Off by
        default: nothing leaves the host.
      '';
    };

    consoleEnrollTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Enroll this engine in the CrowdSec console with this token (file, not in the Nix store). Requires `communityBlocklist`.";
    };

    lapiListen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      example = "127.0.0.1:8081";
      description = "Address of the local API (bouncers and cscli). Change the port when 8080 is taken.";
    };

    metrics = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Prometheus metrics on 127.0.0.1:6060 (used by `cscli metrics`).";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.consoleEnrollTokenFile == null || cfg.communityBlocklist;
        message = "security.crowdsec.consoleEnrollTokenFile requires security.crowdsec.communityBlocklist.";
      }
    ];

    security.crowdsec.banMinutes = lib.mkDefault (
      let
        m = builtins.match "([0-9]+)(h|m)" cfg.banDuration;
      in
      if m == null then
        240
      else if builtins.elemAt m 1 == "h" then
        lib.toInt (builtins.head m) * 60
      else
        lib.toInt (builtins.head m)
    );

    services.crowdsec = lib.mkMerge [
      {
        enable = true;
        autoUpdateService = lib.mkDefault true;
        hub.collections = lib.unique (lib.concatMap (s: s.collections) sources ++ cfg.collections);
      }
      # nixpkgs >= 26.05: everything under `settings`.
      (lib.optionalAttrs newApi {
        settings = {
          inherit acquisitions profiles;
          parsers.s02Enrich = allowParsers;
          simulation.simulation = cfg.mode == "simulation";
          console.enrollKeyFile = lib.mkIf (cfg.consoleEnrollTokenFile != null) cfg.consoleEnrollTokenFile;
          config = {
            api.server = {
              listen_uri = cfg.lapiListen;
              online_client.credentials_path =
                if cfg.communityBlocklist then "${stateDir}/online_api_credentials.yaml" else null;
            };
            prometheus.enabled = cfg.metrics;
          };
        };
      })
      # Earlier nixpkgs: `localConfig` + `settings.general`.
      (lib.optionalAttrs (!newApi) {
        localConfig = {
          inherit acquisitions profiles;
          parsers.s02Enrich = allowParsers;
        };
        settings = {
          simulation.simulation = cfg.mode == "simulation";
          lapi.credentialsFile = "${stateDir}/local_api_credentials.yaml";
          capi.credentialsFile = lib.mkIf cfg.communityBlocklist "${stateDir}/online_api_credentials.yaml";
          console.tokenFile = lib.mkIf (cfg.consoleEnrollTokenFile != null) cfg.consoleEnrollTokenFile;
          general = {
            api.server = {
              enable = true;
              listen_uri = cfg.lapiListen;
              online_client = lib.mkIf (!cfg.communityBlocklist) (lib.mkForce null);
            };
            prometheus.enabled = cfg.metrics;
          };
        };
      })
    ];

    # nixpkgs writes these files with tmpfiles: the engine does not notice a
    # change (simulation -> enforce, new source...) without a restart.
    systemd.services.crowdsec.restartTriggers = [
      (builtins.hashString "sha256" (
        builtins.toJSON {
          inherit acquisitions profiles allowParsers;
          inherit (cfg) mode collections;
        }
      ))
    ];

    services.crowdsec-firewall-bouncer = lib.mkIf cfg.bouncer.enable {
      enable = true;
      registerBouncer.enable = true;
    };
  };
}
