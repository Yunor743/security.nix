{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.jit-hater;

  settingsFormat = pkgs.formats.yaml { };
  configFile = settingsFormat.generate "jit-hater.yaml" cfg.settings;
in
{
  options.services.jit-hater = {
    enable = lib.mkEnableOption "JIT-Hater, the behavioral memory threat detector";

    package = lib.mkPackageOption pkgs "jit-hater" { };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = settingsFormat.type;
        options = {
          "dump.directory" = lib.mkOption {
            type = lib.types.str;
            default = "/dev/shm/jit-hater";
            description = ''
              Directory where suspicious memory pages are dumped.
              Must live on a tmpfs: dumps may contain secrets held by
              legitimate processes (browsers, keyrings...).
            '';
          };
          "dump.granularity" = lib.mkOption {
            type = lib.types.enum [
              "page"
              "vma"
            ];
            default = "page";
            description = "Dump the 4KiB page or the whole VMA (capped).";
          };
          "monitor.fluctuation_threshold" = lib.mkOption {
            type = lib.types.int;
            default = 5;
            description = "Executable-state transitions on one page before a fluctuation dump.";
          };
          "monitor.poll_interval_secs" = lib.mkOption {
            type = lib.types.int;
            default = 5;
            description = "/proc polling interval (fallback mode).";
          };
          "scanner.interval_secs" = lib.mkOption {
            type = lib.types.int;
            default = 300;
            description = "Structural /proc scan period in service mode.";
          };
          "rules.jit_allowlist" = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Process names tolerated by the fluctuation rule.";
          };
          "log.format" = lib.mkOption {
            type = lib.types.enum [
              "json"
              "human"
            ];
            default = "json";
          };
          "log.filter" = lib.mkOption {
            type = lib.types.str;
            default = "info";
          };
        };
      };
      default = { };
      description = "JIT-Hater configuration (see config/jit-hater.example.yaml upstream).";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra CLI arguments passed to `jit-hater monitor`.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.tmpfiles.settings."10-jit-hater"."/dev/shm/jit-hater".d =
      lib.mkIf (cfg.settings."dump.directory" == "/dev/shm/jit-hater")
        {
          user = "root";
          group = "root";
          mode = "0700";
        };

    systemd.services.jit-hater = {
      description = "JIT-Hater — behavioral memory threat detector";
      documentation = [ "https://github.com/Yunor743/JIT-Hater" ];
      after = [ "local-fs.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} monitor --config ${configFile} ${lib.escapeShellArgs cfg.extraArgs}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Root agent with the minimum needed: read anything
        # (dumps/procfs), trace processes, eBPF.
        NoNewPrivileges = true;
        CapabilityBoundingSet = [
          "CAP_DAC_READ_SEARCH"
          "CAP_SYS_PTRACE"
          "CAP_BPF"
          "CAP_PERFMON"
        ];
        AmbientCapabilities = [
          "CAP_DAC_READ_SEARCH"
          "CAP_SYS_PTRACE"
          "CAP_BPF"
          "CAP_PERFMON"
        ];
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        StateDirectory = "jit-hater";
      };
    };
  };
}
