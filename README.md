# Security.nix

NixOS packages and modules for endpoint security and detection

## Packages

| Package | Description |
|---------|-------------|
| `fapolicyd` | File access policy daemon for application whitelisting |
| `rustinel` | Open-source EDR using eBPF, Sigma, YARA, and IOC detection |
| `yara-forge-rules` | Curated YARA rule sets from YARA Forge |
| `sigma-rules` | SigmaHQ detection rules (complete set) |

## NixOS Modules

| Module | Description |
|--------|-------------|
| `services.fapolicyd` | File access policy daemon with profiles for NixOS |
| `services.rustinel` | eBPF-based endpoint detection with Sigma, YARA, and IOC |

## Quick Start

Add the flake to your inputs:

```nix
{
  inputs = {
    security-nix.url = "github:Yunor743/security.nix";
  };
}
```

### fapolicyd

```nix
{
  imports = [ nix-security.nixosModules.fapolicyd ];

  nixpkgs.overlays = [ nix-security.overlays.default ];

  services.fapolicyd = {
    enable = true;
    profile = "nixos";   # trusts /nix/store and /run/wrappers, denies everything else
    permissive = false;   # enforce policy (start with true to test first!)
  };
}
```

To add custom rules on top of a profile:

```nix
services.fapolicyd = {
  enable = true;
  profile = "nixos";
  extraRules = {
    "15-authorized.rules" = ''
      allow perm=any all : dir=/home/user/authorized/
    '';
  };
};
```

## Policy Profiles

### `nixos` (default)

Trusts everything under `/nix/store/` and `/run/wrappers/`, denies all other execution. Ideal for NixOS where the store is immutable and content-addressed.

```
1. allow perm=any all : dir=/nix/store/
2. allow perm=any all : dir=/run/wrappers/
3. deny_audit perm=any pattern=ld_so : all
4. deny_audit perm=any all : ftype=application/x-bad-elf
5. deny_audit perm=execute all : all
6. allow perm=open all : all
```

### `known-libs`

Upstream known-libs policy adapted from Fedora. Trusts files in the trust database and shared libraries from trusted paths. Requires populating `services.fapolicyd.trust`.

### `custom`

No default rules — you must set `services.fapolicyd.rules` yourself.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `services.fapolicyd.enable` | bool | `false` | Enable the daemon |
| `services.fapolicyd.package` | package | `pkgs.fapolicyd` | Package to use |
| `services.fapolicyd.permissive` | bool | `true` | Log denials without enforcing |
| `services.fapolicyd.profile` | enum | `"nixos"` | Policy profile: `nixos`, `known-libs`, or `custom` |
| `services.fapolicyd.rules` | attrsOf lines | from profile | Rule files for `/etc/fapolicyd/rules.d/` |
| `services.fapolicyd.extraRules` | attrsOf lines | `{}` | Extra rules merged on top of the profile |
| `services.fapolicyd.settings` | attrsOf (bool\|int\|str) | sensible defaults | fapolicyd.conf key-value pairs |
| `services.fapolicyd.trust` | lines | `""` | Content of `fapolicyd.trust` |
| `services.fapolicyd.extraFilterRules` | listOf str | `[]` | Extra filter rules |
| `services.fapolicyd.python3Path` | str | `${pkgs.python3.interpreter}` | Path to python3 for `%python3_path%` |
| `services.fapolicyd.ldSoPath` | str | dynamic linker | Path to ld.so for `%ld_so_path%` |

## NixOS Patches

fapolicyd uses `O_NOFOLLOW` when opening its config and rules files, which breaks on NixOS because `/etc/fapolicyd/*` are symlinks to the Nix store. We patch this out so the daemon follows symlinks.

The dynamic linker discovery macro (`m4/dyn_linker.m4`) is patched because it relies on `rev` and `realpath` which are not available in the Nix sandbox.

Static linking (`-static` in LDFLAGS) is removed because it is incompatible with NixOS's glibc NSS.

## Warning

fapolicyd can **deadlock your system** if the policy blocks access to critical libraries. Always test with `permissive = true` first, then switch to `permissive = false` once you have verified the policy works.

**Never** try to ptrace or strace the fapolicyd daemon — it will deadlock the system.

The default `subj_cache_size` is set to `8191` (instead of the upstream default of `4099`) to prevent cache evictions that can cause false denials on busy NixOS systems.

### Known limitation: subject cache and file moves

fapolicyd caches subject entries by device and inode number. When a file is moved within the same filesystem (`mv`), the inode is preserved and the cache entry remains valid. This means a binary that was approved in an authorized directory (e.g. `/home/user/authorized/`) can still execute after being moved to an unauthorized location (e.g. `/home/user/`) until the cache entry expires or fapolicyd is restarted.

This is an inherent limitation of fapolicyd's caching design. To mitigate it:

- `allow_filesystem_mark` is set to `true` by default in this module, which enables fanotify filesystem marks so fapolicyd is notified of file modifications.
- In practice, this only matters for files that were previously in an authorized directory and then moved out — new files in unauthorized directories are always blocked.

## Rustinel

[Rustinel](https://github.com/Karib0u/rustinel) is an open-source endpoint detection engine using eBPF on Linux, with Sigma, YARA, and IOC matching.

```nix
services.rustinel = {
  enable = true;

  # Add custom allowlist paths (NixOS paths are included by default)
  settings.allowlist.paths = [
    "/nix/store/"
    "/run/wrappers/"
  ];

  # Add custom Sigma rules
  sigmaRules = ''
    title: My Custom Detection
    id: 00000000-0000-0000-0000-000000000001
    status: experimental
    logsource:
      category: process_creation
      product: linux
    detection:
      selection:
        Image|endswith: '/whoami'
      condition: selection
    level: low
  '';
};
```

### Rustinel Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `services.rustinel.enable` | bool | `false` | Enable the daemon |
| `services.rustinel.package` | package | `pkgs.rustinel` | Package to use |
| `services.rustinel.settings` | attrsOf (attrsOf ...) | sensible defaults | TOML config sections |
| `services.rustinel.rules` | lines | `""` | Additional YARA rules |
| `services.rustinel.sigmaRules` | lines | `""` | Additional Sigma rules |

---

## TODO

- [x] fapolicyd.nix
- [x] rustinel.nix
- [ ] vulnix
- [ ] hardened kernel
- [ ] mineral.nix
- [ ] lkrg
- [ ] apparmor
- [ ] falco
- [ ] auditd
- [ ] antivirus
- [ ] usbguard
- [ ] snort / suricata
- [ ] canaries ?
- [ ] sandboxes ?

