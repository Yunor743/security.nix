# USBGuard

`security.usbguard` authorizes USB devices with a policy that suits a
workstation, on top of nixpkgs' `services.usbguard` (daemon and its systemd
hardening): learn first, the devices present at first start allowed, a
declarative allow-list, interface classes rejected whatever the mode, one
journal line per decision, desktop notifications and MiniSOC alerts.

```nix
{
  imports = [ security-nix.nixosModules.usbguard ];   # or .security

  security.usbguard = {
    enable = true;
    mode = "learn";                 # then "enforce"
    rejectInterfaces = [ "08:*:*" ];  # no USB storage, in both modes
    allowedDevices = [
      { id = "046d:c52b"; name = "USB Receiver"; comment = "Logitech mouse"; }
    ];
  };
}
```

## Modes

- `learn`: every device is authorized, but USBGuard still evaluates the rules
  and records which devices only got in through the permissive default:
  they would be blocked once enforced (`decision=allow by=default` in the
  journal, `low` alerts in MiniSOC). Rejected interface classes are rejected
  in learn mode too.
- `enforce`: a device that no rule allows is blocked (`blockTarget = "block"`:
  visible, unusable, allowable later) or rejected (`"reject"`: logically
  removed).

Start in `learn`, plug what you use, read the log, then enforce.

## The rules file

`/var/lib/usbguard/rules.conf` stays writable so that USBGuard's own tools
work:

1. A **NixOS-managed block** is rewritten at the top of the file on every
   start: `rejectInterfaces` first (the first matching rule wins, so they
   beat any allow rule), hubs (`allowHubs`), boot keyboards/mice
   (`allowHid`, off by default: a "BadUSB" device is a keyboard), the
   `allowedDevices`, `extraRules`.
2. Below it, **learned rules are kept**: the policy generated once for the
   devices present at the first start (`allowPresentDevices`, so enforcing
   never locks out the keyboard of a desktop), and every
   `usbguard allow-device -p <id>`.

```sh
usbguard list-devices                # id, allow/block, name, port
usbguard allow-device -p 12          # allow now and forever (persisted)
usbguard block-device 12
journalctl -u usbguard-events        # one line per decision
```

On an ephemeral root, persist `/var/lib/usbguard`.

## Journal and MiniSOC

USBGuard's audit records do not say whether a rule or the default target
decided. `usbguard-events.service` follows the daemon's event stream and
writes one line per decision:

```
decision=reject by=rule rule_id=1 mode=learn id=46f4:0001 name="QEMU USB HARDDRIVE" serial="…" port="2-4" interfaces="08:06:50"
decision=allow by=default rule_id=4294967294 mode=learn id=0627:0001 name="QEMU USB Keyboard" serial="…" port="1-5" interfaces="03:01:01"
```

With MiniSOC, `services.minisoc.integrations.usbguard` (on by default with
this module) turns them into alerts: blocked / rejected devices (`medium`),
and in learn mode the devices that would be blocked (`low`).

## Options

| Option | Default | |
|---|---|---|
| `enable` | `false` | |
| `mode` | `"learn"` | `learn` / `enforce` |
| `blockTarget` | `"block"` | `block` / `reject` for devices no rule allows (enforce) |
| `allowPresentDevices` | `true` | allow the devices present at the first start (once) |
| `presentDevicePolicy` | `"apply-policy"` | devices connected when the daemon starts |
| `allowHubs` | `true` | hubs (class 09) |
| `allowHid` | `false` | any boot keyboard / mouse |
| `rejectInterfaces` | `[]` | e.g. `08:*:*` storage, `e0:*:*` wireless, `02:*:*` network |
| `allowedDevices` | `[]` | `{ id; serial; name; hash; viaPort; comment; }` |
| `extraRules` | `""` | raw `usbguard-rules.conf(5)` rules |
| `ipcGroups` | `[ "wheel" ]` | who may list / allow / block |
| `notifier.enable` | desktop present | usbguard-notifier user service |

## Tested

- VM test `usbguard`: devices present at first start learned, a hot-plugged
  keyboard blocked in enforce mode, a USB stick rejected by the managed rule
  (no block device appears), `allow-device -p` surviving a daemon restart,
  the managed block written once.
- `owned` (desktop, AppArmor enforced): learn then enforce; a virtual USB
  stick is rejected in both modes, an unknown keyboard is allowed (learn,
  `low` alert "would be blocked") then blocked (enforce), allowed for good
  with `allow-device -p`; decisions show up in MiniSOC. The apparmor.d
  profile of `usbguard-daemon` needed the NixOS location of its rules
  (`/var/lib/usbguard`): fixed in `packages/apparmor-d`.
