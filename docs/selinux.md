# SELinux on NixOS

`security.selinux` runs NixOS under SELinux: the reference policy with a
NixOS module, a labelled Nix store, logins in their mapped contexts, D-Bus
mediation, confinement of system services and, optionally, of Nix builds.

The module comes from [nix-selinux](https://github.com/alisonjenkins/nix-selinux)
by Alison Jenkins (MIT, commit `4eb2952`), the most complete port of SELinux
to NixOS, developed with upstream nixpkgs in mind. Its manual chapter is
[`modules/selinux/selinux.md`](../modules/selinux/selinux.md); this page is
a summary.

```nix
{
  imports = [ security-nix.nixosModules.selinux ];   # or .security

  # Required: the policy is loaded by a unit of the systemd initrd.
  boot.initrd.systemd.enable = true;

  security.selinux = {
    enable = true;
    mode = "permissive";      # log only; then "enforcing"
  };
}
```

Reboot, then `nixos-selinux status`.

## How it works

- **No change to Nix.** Labels are extended attributes set by NixOS on the
  store, at boot and at switch. Paths already labelled under the current
  rules are skipped (marker attribute), so an unchanged boot does not write.
- **Generic types for the store, privileged types only for exact paths.**
  A rule that gives `init_exec_t` names the full hashed path; nobody can
  obtain it by building a package with a similar name.
- **The policy is a derivation** in the system closure (refpolicy compiled
  with `nixos.te`/`nixos.fc`), loaded in the initrd before activation,
  switched and rolled back with the generation.
- systemd, coreutils, PAM, OpenSSH and dbus-broker are rebuilt with SELinux
  support through their package options (a first build takes a while).

## Main options

| Option | Default | |
|---|---|---|
| `enable` | `false` | |
| `mode` | `"permissive"` | `permissive` logs, `enforcing` blocks |
| `type` | `"refpolicy"` | or `minimal` (a CIL policy to experiment with) |
| `booleans.<name>` | `{}` | refpolicy booleans and tunables |
| `modules.<name>` | `{}` | your own policy modules (`.te`, `.fc`, `.if`) |
| `services.<unit>` | `{}` | confine a systemd service in its own domain (`rules`, `permissive`) |
| `confine.*` | | sshd, nscd, Nix daemon, `nixBuilds` (builds in `nix_build_t`) |
| `entrypoints.<name>` | `{}` | exact-path labels (`path`, `type`) |
| `loginMappings` | `unconfined_u` | the `seusers` file |
| `loginContexts`, `dbusMediation` | `true` with refpolicy | PAM/OpenSSH and broker with SELinux |
| `relabelPaths` | `/etc /var /root /home /nix/var` | mutable paths relabelled when rules change |
| `logAllDenials` | `false` | disable `dontaudit` rules (debugging) |
| `developmentTools` | `false` | `audit2allow`, `sesearch`… |

## Additions in security.nix

On top of nix-selinux (all marked `[security.nix]` in the sources):

- `pathSubstitutions` writes `file_contexts.subs`, so that a path is
  labelled as another one. For an ephemeral root (impermanence), the
  persistent storage gets the labels of the paths it feeds:

  ```nix
  security.selinux = {
    pathSubstitutions = {
      "/nix/persist/etc" = "/etc";
      "/nix/persist/var" = "/var";
      "/nix/persist/home" = "/home";
      "/nix/persist/root" = "/root";
    };
    relabelPaths = [ "/etc" "/var" "/root" "/home" "/nix/var" "/nix/persist" ];
    fileContexts = "/nix/persist\t-d\tsystem_u:object_r:root_t:s0\n";
  };
  ```

- `userContextServices`: systemd services run in the user context
  (default: Home Manager activations), whose D-Bus sessions must not run in
  the system bus domain.
- `pamServices`: PAM services that open sessions with `pam_selinux`
  (default: `login`, `systemd-user` and the enabled display manager with its
  greeter), so a
  graphical session and the user's systemd manager start in the user's
  mapped context, not in the context of the program that opened them.
- Policy rules found on a real desktop (the `owned` host: Hyprland, SDDM,
  Home Manager, impermanence on btrfs, rustinel): recent systemd relabelling
  its symlinks, users' Nix profiles in `XDG_DATA_DIRS`, timesyncd/nscd
  sysctls, memory-pressure files, tmpfiles on a fresh root subvolume,
  udev helpers in `lib/`, dbus-broker's configuration watch, and `perf_event`
  for unconfined services (eBPF security tools).

## Tested

- VM test `selinux-refpolicy` (enforcing): boot, SSH (key and password),
  console login in the mapped context, sudo/su, confined services, Nix
  daemon and confined builds, reboot, zero denials.
- `owned` (Hyprland desktop, SDDM, Home Manager, impermanence on btrfs,
  rustinel, Docker): boots **enforcing**, no failed unit, graphical login
  to Hyprland with the shell and widgets, Home Manager activation, a handful
  of harmless denials (capability `net_admin` probes, `unix_chkpwd`
  inheritance flags). In permissive the would-be denials went from 276 to
  that.

Session buses: the greeter and user sessions open through `pam_selinux`
(`pamServices`) and services started outside a login (`userContextServices`)
get the user context, so `dbus-daemon` session buses no longer run in
`system_dbusd_t`.

## Recovery

- In the boot loader, pick the previous generation, or add `enforcing=0`
  to the kernel command line (boots permissive once).
- Removing `selinux` from `lsm=` boots without SELinux.

## Limits

- Requires the systemd initrd; `system.nixos-init.enable` is not supported.
- Services that are not confined run unconfined (`initrc_t`), as with a
  targeted policy elsewhere. Confinement is opt-in per service.
- The first boot labels the whole store (seconds to tens of seconds).
- `security.selinux` and `security.apparmor-d` are mutually exclusive.

See the upstream design notes for the threat model and open questions:
<https://github.com/alisonjenkins/nix-selinux/blob/main/docs/design.md>.
