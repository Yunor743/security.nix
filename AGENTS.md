# AGENTS.md

## Project Overview

**security.nix** is a Nix flake providing NixOS packages and modules for endpoint security and detection. It packages fapolicyd, rustinel, YARA Forge rules, and SigmaHQ rules for declarative deployment on NixOS.

## Repository Structure

```
.
├── flake.nix                  # Flake entry point: packages, modules, overlays, checks, formatter
├── flake.lock                 # Locked dependency versions (nixpkgs only)
├── shell.nix                  # Development shell (nixfmt-rfc-style, nil)
├── packages/
│   ├── fapolicyd/
│   │   ├── default.nix        # fapolicyd derivation with NixOS patches
│   │   └── patches/
│   │       ├── nixos-symlinks.patch  # Removes O_NOFOLLOW for /etc symlink compat
│   │       └── dyn-linker.patch      # Replaces m4 dynamic linker discovery with placeholder
│   ├── rustinel/
│   │   └── default.nix        # Binary package from GitHub releases
│   ├── yara-forge-rules/
│   │   └── default.nix        # YARA Forge curated rules (zip)
│   └── sigma-rules/
│       └── default.nix        # SigmaHQ detection rules (zip)
├── modules/
│   ├── fapolicyd.nix          # NixOS module: services.fapolicyd options & config
│   ├── rustinel.nix           # NixOS module: services.rustinel options & config
│   ├── elastic-agent.nix      # NixOS module: services.elastic-agent options & config
│   ├── jit-hater.nix          # NixOS module: services.jit-hater options & config
│   └── security.nix           # Aggregation module: imports all of the above
├── checks/
│   ├── nixos-test.nix         # VM integration tests (permissive, enforcing, known-libs profiles)
│   ├── elastic-agent-test.nix # VM integration test (standalone agent wiring)
│   └── jit-hater-test.nix     # VM integration test (service stays active, nested config accepted)
├── example/
│   ├── flake.nix              # Standalone example flake (from-local / from-github sources)
│   ├── fortress.nix           # Example NixOS host config (fapolicyd + rustinel + disko + impermanence)
│   ├── disko.nix              # Disk layout (btrfs + ESP via disko)
│   ├── impermanence.nix       # Btrfs root rollback + persistence via impermanence
│   └── README.md              # Deployment instructions (nixos-anywhere, nixos-rebuild)
└── README.md                  # Full documentation
```

## Key Concepts

- **fapolicyd** — File access policy daemon for application whitelisting. On NixOS, `/etc` is a symlink forest to `/nix/store`, so upstream's `O_NOFOLLOW` breaks. The package patches this out. The module provides three profiles: `nixos` (trust `/nix/store` + `/run/wrappers`), `known-libs` (trust db + shared libs), `custom` (no defaults). All deny rules use `deny_syslog` (not `deny_audit`) because NixOS has no auditd — `deny_audit` events go to the audit subsystem which is unconfigured, making denials invisible in the journal. Always start with `permissive = true` to avoid deadlocks.
- **rustinel** — eBPF-based EDR (Sigma/YARA/IOC). Distributed as prebuilt musl binaries. The module generates TOML config, manages YARA/Sigma/IOC rule files, and sets `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN` capabilities automatically. Requires Linux 5.8+ with BTF. When `yaraRulesPackage` or `sigmaRulesPackage` are set, the module deploys the packaged rules instead of the demo defaults. The default Sigma rule matches `whoami` execution, including NixOS multi-call `coreutils` binaries via `CommandLine|contains: whoami`. Known limitation: YARA scanning does not trigger on process-start events with relative paths (`./binary`) — only absolute paths are scanned. After a rustinel crash-loop (e.g. from invalid config), the eBPF tracepoints may become orphaned and YARA stops receiving events — a full VM reboot is required to restore eBPF functionality. Valid `match_debug` values since v1.8.0 are `"off"`, `"summary"`, and `"full"` (earlier versions crashed on anything but `"off"`).
- **YARA Forge rules** — Curated YARA rule sets. The rustinel module strips `console.log` calls from YARA rules (JavaScript `console` is not available in YARA's native engine).
- **SigmaHQ rules** — Complete Sigma detection rules for use with rustinel.
- **elastic-agent** — Official Elastic Agent (standalone or Fleet-managed). The package is the upstream tarball with the ELF interpreter patched for NixOS. The module materialises a writable copy of the package tree under `stateDir` (the binary resolves its vault relative to `/proc/self/exe`, which would target the read-only store otherwise). For Elastic Defend, two NixOS workarounds are required and shipped: `enableEndpointShim` (`/bin/systemctl` symlink — the endpoint installer hardcodes it) and `mutableUnitsDir` (converts `/etc/systemd/system` from the NixOS store symlink into a real 0755 directory, re-synced from `/etc/static/systemd/system` at every activation, preserving foreign files). Verified empirically on 9.5.4: the endpoint installer writes its unit with a direct `openat()` (fails EACCES through the store symlink → rollback exit 79 → infinite `Starting: endpoint service runtime` loop), while `systemctl enable/start` go through PID 1 and never need a writable directory. Beware: `cp -a` from the store dir copies its 0555 mode — the activation script `chmod 0755`s the top-level directory (the agent has `NoNewPrivileges` and no `CAP_DAC_OVERRIDE`, so an owner-unwritable dir blocks it). Never dereference the sync (`cp -aL`): the `.wants/` entries MUST remain symlinks — systemd ignores regular files in wants dirs, which silently kills udevd/networkd at boot.
- **jit-hater** — Behavioral memory-threat detector (dumps suspicious pages for offline YARA/AV scanning). The binary parses its YAML config with serde `deny_unknown_fields` and expects a **nested** schema (top-level sections `dump`/`monitor`/`scanner`/`rules`/`log`) — the module's `settings` options are declared as nested suboptions so the generated YAML matches; flat dotted keys (`dump.directory:`) make the service crash-loop with `unknown field` (this was the initial module bug, caught by the VM test). `settings` is a freeform YAML type: extra upstream keys pass through. `services.jit-hater.configFile` (read-only) exposes the generated file for debugging/manual runs. On JIT-dense desktops, `rwx_region`, `unbacked_rx` and the `mprotect_*`/`mmap_*` eBPF rules fire on every JIT compilation (browsers, bun, node, NixOS wrapped binaries — whose comm is `.name-wrapped`, not the package name) — disable them via `settings.rules.disabled` and keep the behavioral rules (`fluctuation`, `memfd_exec`, `ptrace_*`, `deleted_file_exec`); tune `rules.jit_allowlist` (fluctuation) and `rules.process_allowlist` (full ignore, comm prefix).

## Build & Development Commands

```bash
# Build a package
nix build .#fapolicyd
nix build .#rustinel
nix build .#yara-forge-rules
nix build .#sigma-rules

# Run VM integration tests
nix flake check

# Format Nix files
nix fmt

# Build the fortress example VM (from example/ directory)
nix build example#nixosConfigurations.from-local.config.system.build.vm
```

## Formatting & Linting

- **Formatter**: `nixfmt-tree` (nixfmt-rfc-style)
- Format before committing: `nix fmt`

## Coding Conventions

- Nix files use `nixfmt-rfc-style` formatting (2-space indent, no trailing whitespace)
- Module options use `lib.mkOption` with explicit types and descriptions
- Default values use `lib.mkDefault` / `lib.mkOptionDefault` where appropriate
- Config sections use `lib.mkIf cfg.enable` pattern
- Package calls use `pkgs.callPackage` pattern
- TOML config generation for rustinel is done manually (no TOML library in nixpkgs lib)
- Patches are stored in `packages/<pkg>/patches/` and described with a header comment
- The `rustinel` module strips `console.log` from YARA rules using a Perl one-liner — YARA Forge rules sometimes include JavaScript `console.log` debugging statements that conflict with native YARA
- When `yaraRulesPackage` is set, a symlink to the YARA Forge rules file is placed in `/etc/rustinel/rules/yara/` instead of the demo rule; likewise for `sigmaRulesPackage` with a `.keep` placeholder

## Architecture Decisions

- fapolicyd module inlines rule generation: rule files are `attrsOf lines` sorted by natural sort order, compiled into a single `compiled.rules` via `pkgs.runCommandLocal`
- fapolicyd uses `deny_syslog` instead of `deny_audit` — on NixOS, auditd is not configured by default, so `deny_audit` events are invisible; `deny_syslog` sends denials to the journal where they appear as `rule=N dec=deny_syslog perm=execute ... path=/path/to/binary`
- fapolicyd has a known LMDB bug: `open_dbi:Permission denied` spam in logs — the daemon still functions correctly (rules are evaluated, access decisions are made), but the trust database is uninitialized. This is cosmetic and does not affect policy enforcement.
- Macro substitution (`%python3_path%`, `%ld_so_path%`) happens in `environment.etc` using `lib.replaceStrings`
- fapolicyd assertions prevent dangerous configs (e.g., enforcing mode without any trusted paths)
- rustinel's `yaraRulesPackage` and `sigmaRulesPackage` are nullable so the module works with or without external rule packages
- When a rule package is provided, the TOML config paths point to the nix store (`/nix/store/.../share/yara-forge` or `/nix/store/.../share/sigma`), and symlinks are placed in `/etc/rustinel/rules/` for discoverability
- rustinel default Sigma rule uses `Image|endswith: [/whoami, /coreutils]` + `CommandLine|contains: whoami` to handle NixOS multi-call binaries where `whoami` is a symlink to `coreutils`
- The example uses `disko` for declarative disk partitioning (btrfs + ESP) and `impermanence` for btrfs root rollback on boot
- The overlay exposes all four packages so `nixpkgs.overlays = [ self.overlays.default ]` makes them available as `pkgs.fapolicyd`, `pkgs.rustinel`, etc.

## Testing

- Tests are NixOS VM tests in `checks/` (fapolicyd ×3 profiles, elastic-agent standalone, jit-hater)
- fapolicyd tests verify: daemon is active, `fapolicyd-cli --list` works, config files exist in `/etc`, user/group exist
- The jit-hater test asserts the service stays `active` after 15s (a config schema mismatch makes it crash-loop with `Restart=on-failure`), the binary accepts the generated config (no `unknown field` in the journal), the tmpfs dump dir is root 0700, and the `rules` CLI works
- No automated tests for rustinel yet
- Run all tests: `nix flake check`

## Warnings

- **Never** ptrace or strace the fapolicyd daemon — it will deadlock the system
- Always start with `permissive = true` and verify policy before switching to enforcing mode
- fapolicyd's LMDB trust database produces `open_dbi:Permission denied` log spam — this is a known cosmetic issue and does not affect functionality
- rustinel YARA scanning does not trigger on process-start events with relative paths (`./binary`) — only absolute paths are scanned. Use absolute paths in detection testing.
- After a rustinel crash-loop (e.g. from invalid `match_debug` config), the eBPF tracepoints may become orphaned and YARA stops receiving events — a full VM reboot is required to restore eBPF functionality. A `sudo systemctl stop rustinel && sudo systemctl start rustinel` can also restore functionality if a full reboot is not possible.
- `match_debug` valid values since v1.8.0 are `"off"`, `"summary"`, and `"full"` (up to v1.0.2 only `"off"` existed — other values crashed with `enum MatchDebugLevel does not have variant constructor`)
- **YARA detection bug: rustinel v1.0.2 eBPF does not capture process-start events for executables in `/home/` (and possibly other user-writable paths outside standard system directories). YARA detection works for `/tmp/`, `/var/`, and `/nix/store/` but NOT for `/home/`. Sigma detection works correctly for all paths. This is an upstream bug — the YARA worker never receives the executable path for binaries under `/home/`. Workaround: for testing YARA detection, place test binaries in `/tmp/` instead of `/home/`.