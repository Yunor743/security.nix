# AppArmor and apparmor.d on NixOS

`security.apparmor-d` turns on AppArmor with the
[apparmor.d](https://github.com/roddhjav/apparmor.d) collection: more than
1500 profiles confining system services, desktop environments and
applications, adapted to the Nix store.

It builds on nixpkgs' `security.apparmor` (kernel parameter, `lsm=`, tools,
`apparmor.service`), which keeps working for your own profiles
(`security.apparmor.policies`).

```nix
{
  imports = [ security-nix.nixosModules.apparmor ];   # or .security

  security.apparmor-d = {
    enable = true;
    mode = "complain";            # log only (default)
    profiles = {
      firefox = "enforce";        # per profile: enforce | complain | disable
      hyprland = "disable";
    };
  };
}
```

Reboot after the first switch (AppArmor must be in the kernel's `lsm=`).

## Why apparmor.d does not work on NixOS as-is, and what is done

nixpkgs has `roddhjav-apparmor-rules`, a raw copy of the repository. Those
files do not load on NixOS. `packages/apparmor-d` builds them properly:

| Problem | Fix |
|---|---|
| Programs apparmor.d expects from the stock AppArmor package (`runc`, `crun`, `podman`: unconfined stubs) are absent; a `px` to them is denied once enforced | The stock unconfined profiles apparmor.d does not define are added, attached in the store too (`stock/`). |
| The profiles need apparmor.d's preprocessor (ABI conversion, directives, attachments), and NixOS is not one of its distributions | `prebuild` is built from source and run for a `nixos` distribution added by a small patch (same exclusions as Arch, plus pacman). |
| Programs are not in `/usr/bin`: AppArmor matches the **resolved** path, `/nix/store/<hash>-pkg/bin/foo` | `@{bin}`, `@{sbin}` and `@{lib}` also cover `/nix/store/*/…` and the setuid wrappers `/run/wrappers/wrappers.*`, both in the tunables and in the values the preprocessor uses to write profile attachments (`profile ls /{{,usr/}bin/ls,nix/store/*/bin/ls,…}`). |
| Files are read through `/etc → /etc/static → /nix/store` and `/run/current-system/sw` | Every profile may read the store and map its programs and libraries (`abstractions/base{,-strict}.d/nixos`). The store is world-readable anyway. |
| `@{bin}/foo Px` and `@{bin}/* ix` were exact path vs glob; with the store both are globs: *"conflicting x modifiers"* | Exec rules get AppArmor 4.1 rule priorities: upstream priorities are kept in order (×10), then a rule on one program wins over a wildcard rule, profiles over abstractions (`exec-priority.pl`). |
| Nix wrappers: `bin/foo` is a script that runs `bin/.foo-wrapped`, or a wrapper package runs the same name in another store path | `.*-wrapped*` programs and the profile's own `@{exec_path}` inherit the wrapper's profile. |
| Layout: helpers FHS distributions put in `lib/<pkg>/` are in `libexec/` (`sshd-session`, `sshd-auth`…), session scripts in the package's `share/`, coreutils is one multi-call binary, `unix_chkpwd` is a setuid wrapper | Exec rules and attachments get the NixOS path too (`nix-libexec.pl`, `nix-coreutils.pl`, and `nix-fhs.pl` for literal FHS paths: `/usr/bin/foo` → `/nix/store/*/{bin,sbin}/foo`, `/usr/share/…` → `/nix/store/*/share/…`, `/usr/lib…/foo` → `/nix/store/*/lib{,exec}/**/foo`); a few per-profile fixes (dockerd's `libexec/docker/dockerd`, sddm's weston greeter). |
| A profile that does not compile would break the whole load | Every profile is compiled at build time; a failing one is set aside in `share/apparmor.d/nixos/incompatible.tsv` with the error. Currently none: all 1595 compile. |

## Modes

- `mode` applies to every profile not listed in `profiles`.
- Profiles apparmor.d marks as work in progress stay in complain mode
  unless listed (`followUpstreamComplain`).
- The mode is applied when the profiles are loaded: changing it does not
  rebuild the profiles, a switch reloads them.

**Start in `complain`, read the logs for some time, then enforce
profile by profile.** An enforced profile on a system component can break
the boot or the session.

## Local overrides and tunables

Every apparmor.d profile ends with `include if exists <local/NAME>`:

```nix
security.apparmor-d.localOverrides.pass = ''
  /nix/store/*/libexec/keyboxd ix,
  owner /run/user/*/gnupg/S.keyboxd rw,
'';

security.apparmor-d.extraTunables = ''
  @{bin}+=/opt/*/bin
'';
```

## Ephemeral root (impermanence)

With impermanence, programs reach persistent files through symlinks or bind
mounts, and AppArmor matches the resolved path
(`/nix/persist/etc/ssh/ssh_host_ed25519_key`), which no profile allows:
sshd would not start once enforced. `persistentStoragePaths` (default: the
enabled `environment.persistence` entries) adds `alias` rules so that every
rule on `/etc/`, `/var/`, `/home/`… also applies under the storage path
(`persistentDirectories`). Nothing to configure when impermanence is used.

## Reading denials

```sh
aa-status                         # loaded profiles and their mode
journalctl --grep apparmor        # denials (complain: ALLOWED, enforce: DENIED)
aa-log                            # apparmor.d's log viewer
```

## How it is loaded

The profiles are loaded inside nixpkgs' `apparmor.service`, after its own
steps (`aa-teardown` on start, `aa-remove-unknown` on reload), so a
`nixos-rebuild switch` never leaves them unloaded. The compiled policy is
cached in `/var/cache/apparmor-d/<tree>`: store files all have the same
modification time, so the cache is keyed by the profile tree instead of
AppArmor's own time check. Persist `/var/cache/apparmor-d` on an ephemeral
root, otherwise the profiles are compiled at every boot.

D-Bus is started in apparmor.d's `dbus-system` / `dbus-session` profiles
(`systemdDropins`), optionally: it still starts if the profile is absent.

## Tested

- VM test `apparmor-d`: 1982 profiles loaded (sub-profiles included), `top`
  runs as `top (enforce)` from the store, an enforced local override denies,
  a reload keeps everything, the cache is used.
- `owned` in **enforce** mode (Hyprland, SDDM, Home Manager, Docker,
  impermanence, with fapolicyd enforcing): boots, graphical login, apps
  (kitty, Nautilus with gvfs FUSE), Docker containers, Nix builds, scp; the
  remaining denials are tty inheritance by `pkill`/`hyprctl`. Getting there
  needed NixOS fixes in the package (logind varlink socket of systemd ≥ 258,
  the greeter's DRM/input devices passed by logind, session tty/log of
  `start-hyprland`, `runc`/`crun` stubs from stock AppArmor so `px` to
  container runtimes resolves, Docker CLI wrapper, fusermount setuid
  wrapper, qemu-ga/spice-vdagentd/cups/tmpfiles/resolvconf paths,
  `tailscaled` switching to the `resolvconf` profile instead of running the
  openresolv wrapper script under its own…) and three
  local overrides specific to that host (Ambxst config, `/.swapvol`, Docker
  storage under `/nix/persist` seen through ``).
- `owned` (Hyprland desktop, impermanence): boots in complain mode with all
  1595 profiles loaded; sshd/sshd-session, sddm and its helpers, dockerd,
  NetworkManager, sudo… run in their profiles, and a full boot plus desktop
  login produces a single unmatched transition (`//null-` child), down from
  about 10 000. First boot 2 min 15 s (compilation), then 14 s in total with
  the profiles loaded from the cache.

## Known limits

- apparmor.d's `sftp-server` may only write to `~/Downloads` and sync
  directories: `scp` elsewhere fails once enforced (widen it with
  `localOverrides.sftp-server` if wanted).
- Complain mode does not log everything enforce mode denies (repeated
  events are not re-audited, `file_inherit`…): before enforcing a desktop,
  keep a recovery path (previous generation) and test the login.

- A package laid out differently than the cases above leaves its parent
  profile without a transition: in complain mode the activity is logged
  under `…//null-…` children. Add the store path with a local override
  (`localOverrides.<parent> = "/nix/store/*/libexec/foo Px,";`).
- Paths left as is: reads (the whole store is readable), `/etc` scripts of
  other distributions (cron, if-up.d, init.d, motd), programs in `/opt` and
  in home directories (Tor Browser, VS Code extensions).
- The first load compiles every profile (minutes on small machines); keep
  `/var/cache/apparmor-d` on persistent storage.

## Updating apparmor.d

The package is pinned to one apparmor.d commit. To update it:

```sh
nix run nixpkgs#nix-update -- --flake --version=branch apparmor-d
nix build .#apparmor-d                      # compiles every profile
nix build .#checks.x86_64-linux.apparmor-d  # VM test
```

The workflow `.github/workflows/update-apparmor-d.yml` does this weekly and
opens a pull request listing the profiles set aside.

## Recovery

- Boot the previous generation, or add `apparmor=0` to the kernel command
  line.
- A specialisation without AppArmor is a convenient escape hatch:

```nix
specialisation.no-apparmor.configuration.security.apparmor-d.enable = lib.mkForce false;
```

## Options

| Option | Default | |
|---|---|---|
| `enable` | `false` | |
| `package` | `packages/apparmor-d` | |
| `mode` | `"complain"` | `complain` / `enforce` |
| `profiles.<name>` | `{}` | `enforce` / `complain` / `disable` |
| `followUpstreamComplain` | `true` | keep upstream WIP profiles in complain |
| `localOverrides.<name>` | `{}` | rules added to a profile |
| `extraTunables` | `""` | variable definitions |
| `persistentStoragePaths` | from `environment.persistence` | ephemeral root storage, aliased |
| `persistentDirectories` | `etc var home root srv opt usr` | directories aliased under it |
| `systemdDropins` | `true` | D-Bus in its profiles |
| `parserFlags` | `[]` | extra `apparmor_parser` arguments |

`security.apparmor-d` and `security.selinux` are mutually exclusive.

## Credits

apparmor.d by Alexandre Pujol and contributors (GPL-2.0). The NixOS
approach follows Grimmauld's work on AppArmor and apparmor.d for NixOS.
