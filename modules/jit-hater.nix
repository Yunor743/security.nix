{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.jit-hater;
in
{
  options.services.jit-hater = {
    enable = lib.mkEnableOption "JIT-Hater, the behavioral memory threat detector";

    package = lib.mkPackageOption pkgs "jit-hater" { };

    configFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      description = "Generated JIT-Hater configuration file (useful for debugging or manual runs).";
    };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = (pkgs.formats.yaml { }).type;
        options = {
          dump = {
            directory = lib.mkOption {
              type = lib.types.str;
              default = "/dev/shm/jit-hater";
              description = ''
                Directory where suspicious memory pages are dumped.
                Must live on a tmpfs: dumps may contain secrets held by
                legitimate processes (browsers, keyrings...).
              '';
            };
            granularity = lib.mkOption {
              type = lib.types.enum [
                "page"
                "vma"
              ];
              default = "page";
              description = "Dump the 4KiB page or the whole VMA (capped).";
            };
          };
          monitor = {
            prefer_ebpf = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Use eBPF probes when the kernel supports them (LSM hooks need
                CONFIG_BPF_LSM and `bpf` in the lsm= boot parameter), otherwise
                fall back to /proc polling.
              '';
            };
            fluctuation_threshold = lib.mkOption {
              type = lib.types.int;
              default = 5;
              description = "Executable-state transitions on one page before a fluctuation dump.";
            };
            poll_interval_secs = lib.mkOption {
              type = lib.types.int;
              default = 5;
              description = "/proc polling interval (fallback mode).";
            };
          };
          scanner = {
            interval_secs = lib.mkOption {
              type = lib.types.int;
              default = 300;
              description = "Structural /proc scan period in service mode (0 = off).";
            };
          };
          rules = {
            disabled = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Rule slugs to disable (see `jit-hater rules` for the full list).";
            };
            jit_allowlist = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = ''
                Process names tolerated by the fluctuation rule. On NixOS,
                wrapped binaries have a `.name-wrapped` comm, not the package
                name — allowlist both when needed.
              '';
            };
            process_allowlist = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Process name (comm) prefixes whose findings are fully ignored.";
            };
          };
          log = {
            format = lib.mkOption {
              type = lib.types.enum [
                "json"
                "human"
              ];
              default = "json";
            };
            filter = lib.mkOption {
              type = lib.types.str;
              default = "info";
              description = "tracing filter, e.g. \"info\", \"debug\", \"jit_hater=trace\".";
            };
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
    services.jit-hater.configFile =
      (pkgs.formats.yaml { }).generate "jit-hater.yaml" cfg.settings;

    systemd.tmpfiles.settings."10-jit-hater"."/dev/shm/jit-hater".d =
      lib.mkIf (cfg.settings.dump.directory == "/dev/shm/jit-hater")
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
        ExecStart = "${lib.getExe cfg.package} monitor --config ${cfg.configFile} ${lib.escapeShellArgs cfg.extraArgs}";
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
