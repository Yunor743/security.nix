# SELinux {#module-security-selinux}

SELinux limits what each service may do, even when it runs as root. This module loads a policy at boot and keeps every file labelled, including the Nix store. Nix itself is not changed.

The module is experimental.

## Quick start {#module-security-selinux-enabling}

```nix
{
  security.selinux.enable = true;
}
```

Rebuild and reboot. The first boot labels the whole store once, which adds a few seconds.

The system starts in *permissive* mode: nothing is blocked, and what would be blocked is logged. Check it:

```ShellSession
$ nixos-selinux status
# nixos-selinux denials
```

When normal use logs no denials, turn enforcement on:

```nix
{
  security.selinux.mode = "enforcing";
}
```

## If it goes wrong {#module-security-selinux-recovery}

Read this before enforcing. If an enforcing system does not boot, or you cannot log in, pick one from the boot loader menu:

| Try | How | Effect |
|---|---|---|
| 1. Previous generation | Select it in the menu. | The system as it was before the change. |
| 2. Permissive, once | Edit the entry and add `enforcing=0` to the kernel command line. | Policy loaded, nothing blocked, denials logged. |
| 3. SELinux off, once | Edit the entry and remove `selinux` from `lsm=`. | No SELinux at all. The next normal boot relabels by itself. |

Then fix the configuration (`nixos-selinux denials` shows what was blocked) or set `mode = "permissive"`, and switch.

An enforcing system refuses to boot if its policy cannot be loaded, instead of running unprotected. A switch to a policy the running kernel cannot load is refused before anything changes.

## Words you need {#module-security-selinux-glossary}

- **Label**: every file and process has one. Rules are written in terms of labels, not paths or users.
- **Type**: the part of a label that rules use, such as `sshd_exec_t`. By convention it ends in `_t`.
- **Domain**: the type of a running process, such as `sshd_t`. A service is *confined* when it runs in a domain of its own.
- **Denial**: a log entry saying that a domain tried something its rules do not allow.
- **Unconfined**: allowed everything SELinux could restrict. Ordinary Unix permissions still apply.

## What is confined {#module-security-selinux-confined}

Out of the box: systemd's daemons (journald, udev, logind), D-Bus, and the services below. `nixos-selinux status` lists them and checks each one.

| Option | Default | Service |
|---|---|---|
| `confine.sshd` | on | OpenSSH daemon |
| `confine.nscd` | on | Name service cache |
| `confine.getty` | on | Console login |
| `confine.dhcpcd` | on | DHCP client |
| `confine.nix` | on | Nix daemon (own domain, not restricted) |
| `confine.nixBuilds` | off | Nix builds; see [](#module-security-selinux-confined-builds) |

Everything else, including your login session, is unconfined until you confine it.

## Confining a service {#module-security-selinux-adding-policy}

Name the systemd service and say what it may do:

```nix
{
  security.selinux.services.myservice = {
    permissive = true; # log only, while you find out what it needs
    rules = ''
      logging_send_syslog_msg(myservice_t)
    '';
  };
}
```

The module finds the program the service starts, creates the domain `myservice_t`, and makes systemd start the service in it. A new domain may do almost nothing, so:

1. Switch, and use the service normally.
2. Run `nixos-selinux denials --rules`. It prints a rule for each thing that was denied.
3. Read the rules, paste the ones you agree with into `rules`, and repeat until nothing is logged.
4. Remove `permissive = true`.

Rules are written in the [reference policy's language](https://github.com/SELinuxProject/refpolicy/wiki): plain `allow` rules, or its interfaces such as `logging_send_syslog_msg`, which bundle the rules for a common task.

If the policy already has a domain for the service, use it instead of creating one:

```nix
{
  security.selinux.services.nginx = {
    domain = "httpd_t";
    createDomain = false;
  };
}
```

## When something is denied {#module-security-selinux-denials}

```ShellSession
# nixos-selinux denials
```

Each line is one kind of denial: which domain, on what, how often.

- **A service you confined**: add a rule (`nixos-selinux denials --rules`).
- **A file with the wrong label**: fix the label, not the rule. `nixos-selinux relabel` restores labels; `security.selinux.fileContexts` adds a rule for a path outside the store.
- **"Permission denied" but nothing logged**: the policy hides some expected denials. Build once with `security.selinux.logAllDenials = true`.

`security.selinux.developmentTools = true` installs `sesearch`, `audit2allow` and friends.

## How it fits NixOS {#module-security-selinux-store-labels}

- **The policy is part of the system.** It is built with the configuration and switches and rolls back with the generation. `semodule` and `setsebool -P` have nothing to write to; use `security.selinux.booleans` and the options above.
- **Store files get harmless labels by pattern**: programs `bin_t`, libraries `lib_t`. Anyone can build a store path, so a pattern never grants privilege.
- **Privileged labels go to exact store paths** that the configuration names. `security.selinux.services` does this for you; `security.selinux.entrypoints` does it for a single file.
- **Labels look after themselves.** They are set at boot and at switch, and restored when anything replaces a labelled file. `nixos-selinux relabel` redoes everything by hand if you ever want to.

### Confined builds {#module-security-selinux-confined-builds}

`confine.nixBuilds = true` runs builds in a domain that may write only the build's outputs and build directory, on top of the Nix sandbox. It cannot be combined with remote builders or a `post-build-hook`; the build says so.

### Store optimisation {#module-security-selinux-store-optimisation}

Safe in every form: `nix-store --optimise`, `nix.optimise.automatic` and `nix.settings.auto-optimise-store`. Optimisation links identical files together and can drop a label; the module notices and puts it back by itself.

## Limits {#module-security-selinux-limits}

- Not compatible with `security.apparmor.enable` or `system.nixos-init.enable`.
- Users are unconfined; `security.selinux.loginMappings` can change that for experiments.
- Not yet tried on a real machine.
