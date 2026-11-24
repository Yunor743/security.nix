# CrowdSec

`security.crowdsec` sets up CrowdSec (behaviour-based detection of attacks
from the network: SSH brute force, web scans…) on a NixOS host in a few
options, on top of nixpkgs' `services.crowdsec` and
`services.crowdsec-firewall-bouncer`:

- a standalone engine with its local API, the machine and the firewall
  bouncer registered automatically;
- log sources derived from the services the host runs, with their hub
  collections;
- `simulation` first, then `enforce`;
- progressive ban durations, an allow-list, the central API **off by
  default** (nothing leaves the host);
- decisions as MiniSOC alerts.

```nix
{
  imports = [ security-nix.nixosModules.crowdsec ];   # or .security

  security.crowdsec = {
    enable = true;
    mode = "simulation";                 # then "enforce"
    allowList = [ "100.64.0.0/10" ];      # e.g. your Tailscale network
  };
}
```

Works with both shapes of the nixpkgs module (`localConfig` /
`settings.general` up to 25.11, everything under `settings` since 26.05):
the module detects which one it has.

## Sources

`sources.auto` (default) watches what the host runs:

| Enabled service | Acquisition | Collections |
|---|---|---|
| `services.openssh` | journal, `_SYSTEMD_UNIT=sshd.service` | `crowdsecurity/linux`, `crowdsecurity/sshd` |
| `services.nginx` | `/var/log/nginx/*.log` | `crowdsecurity/nginx` |
| `services.caddy` | journal, `caddy.service` | `crowdsecurity/caddy` |

`sources.extra` adds raw acquisitions, `collections` more hub collections
(e.g. `crowdsecurity/http-cve`). The hub is downloaded at start
(`crowdsec-setup`) and refreshed daily.

## Modes and bans

- `simulation`: scenarios fire, alerts and decisions are recorded
  (`cscli alerts list`, `cscli decisions list`, the journal) but flagged as
  simulated: the bouncer bans nobody.
- `enforce`: the firewall bouncer applies the decisions (nftables when
  `networking.nftables.enable`, iptables + ipset otherwise).

Bans last `banDuration` (4 h); with `progressiveBans` (default) a repeat
offender gets `banDuration × (past decisions + 1)`. Private ranges are
never banned (the `crowdsecurity/whitelists` parser of the linux
collection); `allowList` adds your own addresses / ranges.

Changing the mode, sources or profiles restarts the engine (nixpkgs writes
them with tmpfiles, which the engine does not watch).

```sh
cscli alerts list ; cscli decisions list
cscli decisions add --ip 198.51.100.4 --duration 1h   # manual ban
cscli decisions delete --ip 198.51.100.4
cscli metrics                                          # with `metrics = true`
```

On an ephemeral root, persist `/var/lib/crowdsec` (database, hub,
credentials).

## Central API, console

`communityBlocklist = true` registers the engine to the CrowdSec central
API: it receives the community blocklist and **shares the alerts of this
host** (attacking addresses, scenarios). `consoleEnrollTokenFile` enrolls
it in the CrowdSec console (requires `communityBlocklist`; the token file
must not be in the Nix store).

## MiniSOC

`services.minisoc.integrations.crowdsec` (on with CrowdSec) turns decisions
into alerts: `high` for a ban, `medium` for a simulated one, e.g. *CrowdSec:
203.0.113.7 (/0) triggered crowdsecurity/ssh-bf and gets a 240m ban*.

## Options

| Option | Default | |
|---|---|---|
| `enable` | `false` | |
| `mode` | `"simulation"` | `simulation` / `enforce` |
| `sources.auto` | `true` | sources of the enabled services |
| `sources.extra` | `[]` | raw acquisitions |
| `collections` | `[]` | extra hub collections |
| `allowList` | `[]` | addresses / CIDR never banned |
| `banDuration` | `"4h"` | |
| `progressiveBans` | `true` | longer bans for repeat offenders |
| `bouncer.enable` | `true` | firewall bouncer |
| `communityBlocklist` | `false` | central API (shares alerts) |
| `consoleEnrollTokenFile` | `null` | console enrollment |
| `lapiListen` | `"127.0.0.1:8080"` | local API address |
| `metrics` | `false` | Prometheus on 127.0.0.1:6060 |

## Tested

- Check `crowdsec-eval`: collections and acquisitions follow sshd, the
  simulation flag, the allow-list parser, progressive bans, the central API
  off unless enabled, the bouncer registered. A VM test cannot start
  CrowdSec: its setup downloads the hub, and NixOS tests have no network.
- `owned` (nixpkgs 26.05 module): an SSH brute force from a fake public
  address (203.0.113.7, network namespace) is detected
  (`crowdsecurity/ssh-bf`, `ssh-slow-bf`); in simulation the decision is
  simulated and nothing is blocked, in enforce the address is banned and its
  connections dropped, the ban grows with each offence (4 h, 8 h, …), and
  every decision shows up in MiniSOC.
- Found on the way: a `%` in a profile breaks nixpkgs 26.05 (profiles are
  written through systemd-tmpfiles, which reads `%` as a specifier): the
  progressive expression avoids it.
