# Security.nix

NixOS packages and modules for endpoint security and detection

> **SOLVED** — Elastic Defend on NixOS
>
> The `endpoint` component of the official elastic-agent now installs and
> runs on NixOS (verified against 9.5.4 on NixOS 26.11). The module ships
> the two required workarounds (both on by default):
>
> 1. `/bin/systemctl` shim (`enableEndpointShim`) — the endpoint installer
>    hardcodes `/bin/systemctl`, which does not exist on NixOS.
> 2. writable `/etc/systemd/system` (`mutableUnitsDir`) — the endpoint
>    installer writes its own unit file with a direct `openat()` to
>    `/etc/systemd/system/ElasticEndpoint.service`; through the NixOS
>    read-only symlink that open fails with EACCES and the installer rolls
>    back (exit 79). An activation script converts the symlink into a real
>    0755 directory, re-synced from the declarative units at every
>    activation (foreign files are preserved). See
>    `modules/elastic-agent.nix` for details.
>
> Note: systemctl-side writes (`daemon-reload`, `enable`, `start`) go
> through PID 1 and never needed a writable directory — only the direct
> `openat()` does. See the "Elastic Defend on NixOS" section below.


## Packages

| Package | Description |
|---------|-------------|
| `fapolicyd` | File access policy daemon for application whitelisting |
| `rustinel` | Open-source EDR using eBPF, Sigma, YARA, and IOC detection |
| `elastic-agent` | Official Elastic Agent (log/metrics shipper, Elastic Defend runtime) |
| `yara-forge-rules` | Curated YARA rule sets from YARA Forge |
| `sigma-rules` | SigmaHQ detection rules (complete set) |

## NixOS Modules

| Module | Description |
|--------|-------------|
| `services.fapolicyd` | File access policy daemon with profiles for NixOS |
| `services.rustinel` | eBPF-based endpoint detection with Sigma, YARA, and IOC |
| `services.elastic-agent` | Official Elastic Agent — standalone (direct Elasticsearch) or Fleet-managed |

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

### elastic-agent

Official Elastic Agent, supporting two roles:

- `standalone` — locally configured (declarative `policy`), writes directly to
  Elasticsearch. Requires an ES user with write privileges on the target
  data streams (e.g. `logs-*`, `metrics-*`).
- `fleet-agent` — enrolled in a [Fleet Server](https://www.elastic.co/docs/reference/fleet/fleet-server);
  the agent policy is then managed from the Kibana Fleet UI (required for
  integrations such as Elastic Defend).

```nix
{
  imports = [ security-nix.nixosModules.elastic-agent ];
  nixpkgs.overlays = [ security-nix.overlays.default ];

  services.elastic-agent = {
    enable = true;
    role = "standalone"; # or "fleet-agent"
    serverUrl = "https://siem.example.com:9243";
    username = "elastic_agent";
    passwordFile = "/run/agenix/elastic-agent-es-password";
    policy = ''
      - type: system/metrics
        id: system-metrics-default
        data_stream.namespace: default
        use_output: default
        streams:
          - metricsets: [cpu, memory, network, filesystem]
            data_stream.dataset: system.cpu
    '';
  };
}
```

Fleet-managed variant:

```nix
services.elastic-agent = {
  enable = true;
  role = "fleet-agent";
  fleet = {
    url = "https://fleet.example.com:8220";
    enrollmentTokenFile = "/run/agenix/fleet-enrollment-token";
    # Optional: pin the CA to verify the Fleet Server certificate. By
    # default the system trust store is used.
    certificateAuthorities = [ "/etc/ssl/certs/internal-ca.crt" ];
    tags = [ "workstation" ];
  };
};
```

Notes:
- The agent runs from a symlink tree in the writable `stateDir`
  (`/var/lib/elastic-agent`): the immutable package stays in the Nix store,
  state (enrollment, data, logs) lands in the state dir. `STATE_PATH` is set
  accordingly.
- The package is the official binary with its ELF interpreter patched for
  NixOS (the upstream tarball ships a generic glibc interpreter path).
- `enableEndpointShim` (default `true`): creates `/bin/systemctl` for the
  Elastic Defend endpoint installer (which hardcodes it).
- `mutableUnitsDir` (default `true`): makes `/etc/systemd/system` a real
  writable directory so the Elastic Defend endpoint installer can write its
  unit — required for Defend; see "Elastic Defend on NixOS — solved".
- **Elastic Defend licensing**: the detection engine and malware prevention
  are included in the free Basic license, but Defend requires a Fleet-managed
  agent. Advanced features (ransomware prevention, host isolation, tamper
  protection…) require Enterprise.

#### Elastic Defend on NixOS — solved

The module is **self-sufficient** for both roles: it handles the package
(overlay), the writable state-dir tree, idempotent enrollment, KEY=VALUE
secret extraction, and the two endpoint workarounds below. No other host
modification is required.

Elastic Defend's endpoint runtime **does activate on NixOS** with this
module (verified against agent 9.5.4 on NixOS 26.11). Two NixOS-specific
assumptions needed workarounds:

1. `/bin/systemctl` does not exist on NixOS. The endpoint installer invokes
   it literally (`systemctl list-unit-files`, `daemon-reload`, `enable`,
   `start`). Workaround: `enableEndpointShim` installs a tmpfiles symlink
   `/bin/systemctl` → `/run/current-system/sw/bin/systemctl`.

2. The endpoint installer writes its own unit file **directly** with
   `openat("/etc/systemd/system/ElasticEndpoint.service", O_WRONLY|O_CREAT)`
   — not via systemctl. On NixOS that path is a symlink into the read-only
   store, so the open fails with `EACCES` and the installer rolls back the
   whole install (exit status 79); the `endpoint` component then loops
   forever in `Starting: endpoint service runtime`. There is no upstream
   override for the unit path (verified against 9.5.x).
   Workaround: `mutableUnitsDir` (default `true`) installs an activation
   script that converts `/etc/systemd/system` into a real, owner-writable
   directory (0755) and re-syncs the declarative units from
   `/etc/static/systemd/system` at every activation. Foreign files written
   at runtime (the endpoint unit, its enable symlink) are preserved, and
   the state survives reboots (no impermanence on /etc).

   Side notes from the debugging session:
   - `systemctl enable` works on read-only directories because it is
     executed by PID 1 (over D-Bus), which has full capabilities — only
     the installer's direct `openat()` needs the writable directory.
   - The agent runs with a restricted capability bounding set
     (`NoNewPrivileges`), so a directory owned by root but mode 0555 (as a
     `cp -a` from the store produces) is still not writable: the sync
     `chmod 0755`s the top-level directory.

Licensing reminder: Defend CORE (detection engine, malware prevention) is
free on the Basic license but requires a Fleet-managed agent (role
`fleet-agent`). Advanced features (ransomware prevention, host isolation,
tamper protection, response console) require Enterprise regardless of the
OS. The endpoint writes its telemetry directly to Elasticsearch — make
sure your firewall allows the agent host to reach the ES HTTPS endpoint
(e.g. `:9243`), otherwise the component reports `DEGRADED: Unable to
connect to output server` while the runtime itself stays healthy.

### Rustinel Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `services.rustinel.enable` | bool | `false` | Enable the daemon |
| `services.rustinel.package` | package | `pkgs.rustinel` | Package to use |
| `services.rustinel.settings` | attrsOf (attrsOf ...) | sensible defaults | TOML config sections |
| `services.rustinel.rules` | lines | `""` | Additional YARA rules |
| `services.rustinel.sigmaRules` | lines | `""` | Additional Sigma rules |

### Capabilities

The rustinel service runs with the following ambient capabilities:

- `CAP_BPF` — load and attach eBPF programs
- `CAP_NET_ADMIN` — network telemetry capture
- `CAP_SYS_RESOURCE` — raise resource limits for eBPF maps
- `CAP_SYS_ADMIN` — required for certain eBPF operations
- `CAP_DAC_READ_SEARCH` — bypass file read permission checks for YARA scanning

`CAP_DAC_READ_SEARCH` is essential: without it, the YARA scanner cannot read files that lack "other" read permissions (e.g. `0700`, `0600`), causing silent scan failures that return "no matches" instead of an error. This capability allows the EDR to scan all files regardless of ownership and permissions, as expected from an endpoint detection agent.

The service also sets `NoNewPrivileges = true` to prevent privilege escalation through setuid binaries.

---

## TODO

- [ ] move the fortress example in microvm.nix
- [x] fapolicyd.nix
- [x] rustinel.nix
- [x] elastic-agent
- [ ] kunai
- [ ] vulnix
- [ ] hardened kernel
- [ ] mineral.nix
- [ ] lkrg / kspp
- [ ] selinux
- [ ] IMA/EVM
- [ ] apparmor
- [ ] falco / tracee / cilium
- [ ] auditd
- [ ] antivirus
- [ ] usbguard
- [ ] snort / suricata
- [ ] canaries ?
- [ ] sandboxes ?
- [ ] ptrace hardening
- [ ] procfs hardening (hidepid)

## Future projects

### SANDBOX : Wrap kunai-sandbox in Nix
- https://why.kunai.rocks/blog/2024/10/02/kunai-malware-sandboxing
- https://github.com/kunai-project/sandbox

### Offensive machine
- inspired by exegol

### Check Sécurix
- https://github.com/cloud-gouv/securix/

### Check ANSSI hardening guide
- https://blog.stephane-robert.info/docs/securiser/durcissement/anssi-bp-28/

