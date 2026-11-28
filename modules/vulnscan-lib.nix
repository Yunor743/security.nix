# Pure helpers shared by the vulnerability scanner modules (security.vulnix,
# security.sbomnix, security.containerScan).
#
# Every scanner writes the same journal lines, parsed by MiniSOC's
# `vulnTransform` (minisoc-lib.nix). They hold no timestamp nor store hash:
# MiniSOC ids are a hash of the line, so the same finding on the next scan is
# an occurrence of the existing alert, and a new CVE or version a new one.
#
#   vulnerable scanner="trivy" target="nginx:1.27@sha256:0123456789ab" pname="openssl" version="3.0.13"
#     severity="critical" count="3" max_cvss="9.8" top="CVE-…" cves="CVE-…" fixed="3.0.15" [found_by="grype,vulnix"] [containers="web"]
#   secret scanner="trivy" target="…" rule="aws-access-key-id" title="AWS Access Key ID" path="/app/.env"
#   scan_done scanner="trivy" target="…" vulnerable="12" cves="40" whitelisted="2"
#   scan_failed scanner="trivy" target="…" rc="1"
{ lib }:

{
  # Unprivileged oneshot scanner: dynamic user, read-only system, no
  # capability; network for the vulnerability databases.
  hardening = {
    Type = "oneshot";
    DynamicUser = true;
    UMask = "0077";
    Nice = 19;
    IOSchedulingClass = "idle";
    ProtectSystem = "strict";
    ProtectHome = "read-only";
    PrivateTmp = true;
    PrivateDevices = true;
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
    ];
    RestrictNamespaces = true;
    LockPersonality = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictRealtime = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [ "@system-service" ];
  };

  timerOptions = defaultInterval: {
    interval = lib.mkOption {
      type = lib.types.str;
      default = defaultInterval;
      example = "Mon *-*-* 08:00:00";
      description = "When to scan (systemd `OnCalendar`). Missed scans run at boot (`Persistent`).";
    };
    randomizedDelay = lib.mkOption {
      type = lib.types.str;
      default = "1h";
      description = "`RandomizedDelaySec` of the timer.";
    };
  };

  mkTimer = cfg: {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = cfg.interval;
      Persistent = true;
      RandomizedDelaySec = cfg.randomizedDelay;
    };
  };

  # jq definitions for the line format. `kv(k; v)`: ` k="v"` (JSON-quoted,
  # parse_key_value reads it back); `sev_of_cvss`: the vulnix scale.
  jqLib = ''
    def kv(k; v): " " + k + "=" + (v | tostring | @json);
    def sev_of_cvss:
      if . >= 9 then "critical" elif . >= 7 then "high"
      elif . >= 4 then "medium" elif . > 0 then "low" else "unknown" end;
    def sev_rank:
      {"critical": 4, "high": 3, "medium": 2, "low": 1}[ascii_downcase] // 0;
  '';
}
