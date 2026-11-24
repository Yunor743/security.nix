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
| The profiles need apparmor.d's preprocessor (ABI conversion, directives, attachments), and NixOS is not one of its distributions | `prebuild` is built from source and run for a `nixos` distribution added by a small patch (same exclusions as Arch, plus pacman). |
| Programs are not in `/usr/bin`: AppArmor matches the **resolved** path, `/nix/store/<hash>-pkg/bin/foo` | `@{bin}`, `@{sbin}` and `@{lib}` also cover `/nix/store/*/…` and the setuid wrappers `/run/wrappers/wrappers.*`, both in the tunables and in the values the preprocessor uses to write profile attachments (`profile ls /{{,usr/}bin/ls,nix/store/*/bin/ls,…}`). |
| Files are read through `/etc → /etc/static → /nix/store` and `/run/current-system/sw` | Every profile may read the store and map its programs and libraries (`abstractions/base{,-strict}.d/nixos`). The store is world-readable anyway. |
| `@{bin}/foo Px` and `@{bin}/* ix` were exact path vs glob; with the store both are globs: *"conflicting x modifiers"* | Exec rules on one program get an AppArmor 4.1 rule priority over wildcard rules, and profiles over abstractions (`exec-priority.pl`). Conflicts drop from 66 to 18. |
| Nix wrappers: `bin/foo` is a script that runs `bin/.foo-wrapped` | `.*-wrapped*` programs inherit the wrapper's profile. |
| Profiles that still do not compile would break the whole load | Every profile is compiled at build time; the 18 failing ones (desktop launchers of KDE, XFCE, LXQt, Hyprland, waybar…) are set aside in `share/apparmor.d/nixos/incompatible.tsv` with the error. |

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

## Reading denials

```sh
aa-status                         # loaded profiles and their mode
journalctl -k --grep apparmor     # denials (complain: ALLOWED, enforce: DENIED)
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
- `owned` (Hyprland desktop, impermanence): boots in complain mode with
  every profile loaded; sshd, sddm, dockerd, NetworkManager, sudo… run in
  their profiles. First boot 2 min 15 s (compilation), then 14 s in total
  with the profiles loaded from the cache in 1.7 s.

## Known limits

- Some packages lay out their programs differently than FHS distributions:
  `libexec/sshd-session` where apparmor.d expects `lib/ssh/sshd-session`,
  `libexec/sddm-helper` for `lib/sddm/sddm-helper`. The parent profile then
  does not find the transition to the child profile: in complain mode the
  activity is logged under `…//null-…` children. Map them with an alias in
  `extraTunables` (e.g. `alias /usr/lib/ssh/sshd-session -> ${pkgs.openssh}/libexec/sshd-session,`)
  or a local override.
- 18 profiles do not compile with store paths (see `incompatible.tsv`).
- The first load compiles every profile (minutes on small machines); keep
  `/var/cache/apparmor-d` on persistent storage.

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
| `systemdDropins` | `true` | D-Bus in its profiles |
| `parserFlags` | `[]` | extra `apparmor_parser` arguments |

`security.apparmor-d` and `security.selinux` are mutually exclusive.

## Credits

apparmor.d by Alexandre Pujol and contributors (GPL-2.0). The NixOS
approach follows Grimmauld's work on AppArmor and apparmor.d for NixOS.
