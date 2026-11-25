# MiniSOC

A personal, local Security Operations Center for a NixOS workstation. MiniSOC
collects the alerts of the security tools installed on the machine (Rustinel
today, any log file you declare), normalizes them into one format, filters
the noise with an external rules file, keeps a lifecycle per alert (pin,
close as true positive / false positive, re-open, filter) and shows them in
a Quickshell desktop widget. An LLM can optionally add a SOC level 1
analysis, propose (or, within strict limits, apply) FP closures and
exclusion rules, and periodically **review its own rules from the alerts you
closed as FP**: the noise shrinks as you use the machine, relevant alerts
keep coming.

MiniSOC works entirely without an LLM and without any remote service.

- [Architecture](#architecture)
- [Installation (NixOS)](#installation-nixos)
- [Installation (Home Manager)](#installation-home-manager)
- [Sources and parsers](#sources-and-parsers)
- [Normalized event format](#normalized-event-format)
- [alert_filter.yaml](#alert_filteryaml)
- [Permissions and data locations](#permissions-and-data-locations)
- [The widget: pin / details / TP / FP](#the-widget)
- [Command line](#command-line)
- [AI analysis](#ai-analysis) — [providers](#providers), [secrets](#secrets), [prompts](#prompts), [auto-close as FP](#auto-close-as-fp), [auto-filter](#auto-filter), [filter review](#filter-review), [privacy](#privacy)
- [Complete example](#complete-example)
- [Troubleshooting](#troubleshooting)
- [Status and limits](#status-and-limits)

## Architecture

```
 Rustinel / app logs (root-only files allowed)
        │  tail, glob, rotation, truncation, checkpoints
        ▼
 ┌──────────────────────────┐   system service, user minisoc-collector
 │ Collector: Vector + VRL  │   CAP_DAC_READ_SEARCH only, no network,
 │ parse json/regex/grok/   │   read-only filesystem view
 │ syslog/raw               │
 └────────────┬─────────────┘
              ▼ /var/lib/minisoc-collector/spool/events-YYYY-MM-DD.ndjson
              │ (0640, group minisoc, aged out by tmpfiles)
 ┌────────────┴─────────────┐   systemd *user* service, one per user in
 │ Engine (`minisoc engine`)│   services.minisoc.users (Rust, no root)
 │  normalize → dedup →     │
 │  filter (alert_filter)   │──── ~/.config/minisoc/alert_filter.yaml (0600)
 │  → SQLite lifecycle      │──── ~/.local/state/minisoc/minisoc.sqlite3
 │  → AI queue (optional)   │──── LLM provider (opt-in, local by default)
 └────────────┬─────────────┘
              ▼ $XDG_RUNTIME_DIR/minisoc/state.json (atomic, 0600)
 ┌──────────────────────────┐ ┌──────────────────────────┐
 │ Quickshell widget        │ │ Web UI (`minisoc web`)   │  both read the state and run
 └──────────────────────────┘ └──────────────────────────┘  `minisoc <action>` as the user
                                loopback + token             (never root)
```

- **Collector** (`services.minisoc.collector`): [Vector](https://vector.dev)
  0.55 file sources and one VRL `remap` per source. Vector persists read
  positions, follows globs, new files, rotation and truncation. Each line
  becomes a spool record `{minisoc: {source, parser, file, parse_error},
  raw, parsed}`; lines that fail to parse are kept (`parse_error`).
- **Engine** (`packages/minisoc`, Rust): tails the spool (offset per file
  and inode, resumes after restart, partial lines wait), normalizes,
  de-duplicates (stable id = hash of source + raw line, repeats increment
  `occurrences`), applies the rules, stores, feeds the AI queue, prunes and
  publishes `state.json`.
- **Store**: SQLite (WAL) holding metadata and lifecycle only. Original logs
  and the spool are never modified.
- **AI analyzer**: in-process worker threads behind a bounded queue. The
  ingestion loop never waits for the model.
- **UI** (`packages/minisoc-ui`): Quickshell 0.3 layer-shell widget.
- **Web UI** (`minisoc web`, optional): the same view and actions in a
  browser tab, served by a user service on a loopback port.

The collector and the UI are independent: the engine also reads a per-user
inbox (`minisoc ingest`), so MiniSOC keeps working with Vector stopped, and
the UI only depends on `state.json` + the CLI.

## Installation (NixOS)

```nix
{
  inputs.security-nix.url = "github:Yunor743/security.nix";

  outputs = { nixpkgs, security-nix, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        security-nix.nixosModules.security   # or .minisoc alone
        {
          nixpkgs.overlays = [ security-nix.overlays.default ];
          services.rustinel.enable = true;
          services.minisoc = {
            enable = true;
            users = [ "alice" ];
          };
        }
      ];
    };
  };
}
```

With `services.rustinel.enable`, the Rustinel source
(`/var/log/rustinel/alerts.json*`, Rustinel normalizer) is added
automatically (`services.minisoc.integrations.rustinel.enable`).

The engine starts with the user's systemd instance (`default.target`) for
members of the `minisoc` group: log out and in once after the first switch
(group membership). Check with `systemctl --user status minisoc-engine`.

## Installation (Home Manager)

Home Manager is optional: it only installs and configures the widget, seeds
the user rules and manages prompt overrides.

```nix
home-manager.users.alice = {
  imports = [ security-nix.homeManagerModules.minisoc ];
  programs.minisoc = {
    enable = true;
    ui = {
      profile = "desktop";           # compact | desktop | analyst
      position = "top-right";
      layer = "bottom";              # under windows, like a desktop widget
      opacity = 0.9;
      monoFont = "JetBrains Mono";
      colors.accent = "#4d9fff";
    };
    filter.initialRules = [ ];       # written once, never overwritten
  };
};
```

The widget runs as `minisoc-ui.service` bound to `graphical-session.target`.
If your compositor does not start that target (Hyprland without UWSM, for
example), set `ui.autostart = false` and add `exec-once = minisoc-ui` to the
compositor configuration. Without Home Manager, run `minisoc-ui` yourself.

## Sources and parsers

```nix
services.minisoc.sources = {
  # One JSON object per line
  clamav = {
    paths = [ "/var/log/clamav/*.json" ];
    parser = "json";
    mapping = { message = "signature"; severity = "level"; };
    eventType = "malware_detected";
    defaultSeverity = "high";
  };

  # Grok (standard patterns: TIMESTAMP_ISO8601, IP, WORD, GREEDYDATA...)
  applicationA = {
    paths = [ "/var/log/applicationA/log.txt" ];
    parser = "grok";
    pattern = "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
  };

  # Regex with named groups (Rust regex syntax; no single quote)
  backup = {
    paths = [ "/var/log/backup.log" ];
    parser = "regex";
    pattern = "^(?P<level>[A-Z]+) (?P<message>.+)$";
  };

  # RFC 3164 / 5424 syslog lines
  sshd = { paths = [ "/var/log/sshd.log" ]; parser = "syslog"; };

  # Raw text: the line becomes `message`
  notes = { paths = [ "/var/log/notes.log" ]; parser = "raw"; defaultSeverity = "info"; };
};
```

| option | meaning |
|---|---|
| `type` | `file` (default) or `journald` |
| `paths` | files or globs; files created later are picked up |
| `journald.matches` | journal fields and values (`{ _SYSTEMD_UNIT = [ "sshd.service" ]; }`) |
| `transform` | VRL run after parsing: set `.parsed.message`/`severity`/`event_type`, or `abort` to drop |
| `parser` | `json`, `regex`, `grok`, `syslog`, `raw` |
| `pattern` | regex / grok pattern |
| `normalizer` | `generic` (default) or `rustinel` |
| `mapping` | dotted paths for `timestamp`, `severity`, `event_type`, `message` |
| `severityMap` | source value (lower-case) → MiniSOC severity |
| `defaultSeverity`, `eventType` | fallbacks |
| `readFrom` | `beginning` (default) or `end` for files seen the first time |
| `ignoreOlderThan` | skip files untouched for N seconds (default 7 days) |

Without `mapping`, the generic normalizer looks for `@timestamp`,
`timestamp`, `time`…, `severity`, `level`, `log.level`, `priority`…,
`message`, `msg`, `rule.name`…, `event_type`, `event.action`, `type`….
Flat dotted keys (ECS: `{"process.name": …}`) and nested objects both work.
Numeric severities: 0–7 are syslog levels, larger numbers use the ECS 0–100
scale.

### Journal sources

With `type = "journald"`, each journal entry selected by `journald.matches`
is one line (`MESSAGE`); the collector joins the `systemd-journal` group.
A `transform` turns it into an alert and drops what is not one:

```nix
services.minisoc.sources.sshd-failures = {
  type = "journald";
  journald.matches._SYSTEMD_UNIT = [ "sshd.service" ];
  parser = "raw";
  readFrom = "end";
  transform = ''
    if !contains(.raw, "Failed password") { abort }
    .parsed.severity = "medium"
    .parsed.event_type = "ssh_failed_password"
  '';
};
```

### Access denials of AppArmor, SELinux and fapolicyd

Enabled automatically with the module they watch
(`services.minisoc.integrations.{apparmor,selinux,fapolicyd}.enable`). A
denial becomes an alert:

| source | example message | severity |
|---|---|---|
| `apparmor` | `AppArmor denied open /root/secret — aa-probe (profile x)` | medium |
| `selinux` | `SELinux denied read on file shadow — cat (user_t → shadow_t)` | medium |
| `fapolicyd` | `fapolicyd denied execute /tmp/x — …/bin/bash (rule 4)` | high |

The parsed fields (`profile`, `operation`, `comm`, `scontext`, `exe`,
`path`…) can be used in filter rules (`fields:`).

Only enforced denials are alerts. Complain/permissive modes log what they
would deny without denying it; `integrations.<name>.wouldBe = true` adds
those as `low` alerts (`… would deny …`). For fapolicyd, permissive mode is
taken from `services.fapolicyd.permissive`, since it logs the same line.
apparmor.d in complain mode logs a lot: keep `wouldBe` off for AppArmor.

Planned sources (ClamAV, Snort, Suricata, auditd, Elastic Agent, CrowdSec)
need no code: declare them as above once the tool writes its log.

## Normalized event format

```json
{
  "id": "evt-3f0c9a1d2b7e4c5a6f80",
  "timestamp": "2026-11-23T18:30:00.000Z",
  "source": "rustinel",
  "severity": "high",
  "event_type": "yara_match",
  "message": "Example.Malware — /tmp/suspicious.bin",
  "fields": { "...": "every original parsed field, untouched" }
}
```

- `severity` ∈ `critical`, `high`, `medium`, `low`, `info`, `unknown`.
- `id` is stable (hash of source + original line): the same line always maps
  to the same alert, repeats increase `occurrences`.
- The details view and `minisoc show <id> --json` also give `raw` (the
  original line), `meta` (file, parser, parse error), `fingerprint`
  (similarity key: same source/type/message once numbers and hex ids are
  stripped), lifecycle flags, AI analysis and history.
- Rustinel mapping: severity from `edr.rule.severity`, type
  `<engine>_match` (`sigma_match`, `yara_match`, `ioc_match`), message
  `rule.name — process.executable`.

## alert_filter.yaml

Loaded at start and **hot-reloaded** whenever it changes.

```yaml
version: 1

filters:
  - id: ignore_known_test_alert
    enabled: true
    description: Ignore known test events
    match:
      source: snort
      event_type: test_alert
    action: exclude

  - id: ignore_localhost_noise
    enabled: true
    description: Ignore localhost informational events
    match:
      severity: [info]
      source_ip: {cidr: 127.0.0.0/8}
    action: exclude

  - id: ignore_nightly_backup
    match:
      source: backup
      any:
        - message: {regex: "^backup (started|done)$"}
        - fields:
            job.name: {in: [nightly, weekly]}
      not:
        severity: [high, critical]
    action: exclude
```

**Conditions.** The keys of a `match` mapping are ANDed:

| key | tested value |
|---|---|
| `source`, `severity`, `event_type`, `message` | normalized fields |
| `source_ip` | first of `source.ip`, `src_ip`, `source_ip`, `src`, `client.ip`, `srcip`, `ip` |
| `dest_ip` | first of `destination.ip`, `dst_ip`, `dest_ip`, `destination_ip`, `dst`, `server.ip`, `dstip` |
| `fields: {path: matcher}` | any original field (dotted path) |
| `all: [..]` / `any: [..]` / `not: {..}` | AND / OR / NOT of sub-conditions |

**Matchers.** A scalar means equality, a list means membership, a mapping
combines operators (all must hold): `equals`, `not_equals`, `in`,
`contains`, `prefix`, `suffix`, `regex` (Rust syntax, ≤ 512 chars), `cidr`
(one network or a list), `exists` (true/false). A list-valued field matches
when any element matches.

**Behaviour.**
- A matching alert leaves the main feed, keeps `filtered_by: <rule id>`,
  counts in the rule's hit statistics and stays visible in
  *Manage ▸ Filtered*. Logs are never touched.
- Rules apply retroactively: a new rule hides matching stored alerts, a
  removed or disabled rule brings them back.
- **Pinned alerts are never hidden by any rule.**
- First matching rule wins; system rules (NixOS) come before user rules.
- Rules are extensible: `action` only accepts `exclude` today, the parser
  rejects anything else rather than ignoring it.

**Strict validation.** Unknown keys (`sevrity:`), invalid severities, bad
regexes or networks, empty conditions or empty `contains`, duplicate ids and
unsupported actions are errors. An invalid file is rejected *as a whole* and
**the last valid version of that file stays in force** (also across
restarts, from a copy in `~/.local/state/minisoc/filters-last-good/`): a
broken edit can never make all alerts disappear, nor bring back hidden noise.
The widget shows a warning, `minisoc status` and `minisoc filter validate`
give the error.

**Debug.** `minisoc explain <id>` shows, rule by rule, which conditions
matched. `services.minisoc.filter.debug = true` logs this for every event
(`journalctl --user -u minisoc-engine`).

**Files.**
- User file: `~/.config/minisoc/alert_filter.yaml`, or
  `services.minisoc.filter.file` (custom path, takes priority; `~` and
  `$XDG_*` are expanded per user). Created 0600 in a 0700 directory if
  missing, never overwritten.
- System file: `services.minisoc.filter.systemRules` (or `systemFile`) is
  installed read-only as `/etc/minisoc/alert_filter.yaml` and **validated at
  build time** by the engine's own parser. It lives in the world-readable
  Nix store: keep sensitive values in the user file.
- Home Manager: `programs.minisoc.filter.initialRules` seeds the user file
  once.
- AI file: `~/.config/minisoc/ai_filters.yaml` (`services.minisoc.filter.aiFile`),
  the rules **owned by the AI** (auto-filter, accepted AI proposals, filter
  review). The AI never writes your file; you may edit this one, the next
  review starts from what is there. It is rewritten by MiniSOC (comments
  are not kept).
- Every automated write is atomic (temp file + fsync + rename, mode 0600)
  and validated first; a write is refused if the current file is invalid.
  Writes to your file (Create filter, rollback) only append: your other
  rules and comments are preserved; backups in
  `~/.local/state/minisoc/filter-backups/` (last 20), `minisoc filter
  rollback` restores the latest. The AI file is backed up in
  `filter-backups/ai/` before each rewrite.

**Counters.** Every rule shows how many alerts it excluded **since it was
created or last modified** (`hits`, `since`), how many **over the last
`filter.recentDays` days** (default 14, `recent_hits`), and the stored alerts
it hides now (`hidden`): in *Manage ▸ Rules* (`12 since 24/11 14:22 · 3 in
14 d`), `minisoc filter list` and `state.json`.

- There is no periodic reset of the total. It restarts at 0 only when the
  rule's definition changes (any key: match, enabled, description,
  metadata…), so a rule that stops catching anything after a change is
  visible at once; a removed rule's counters are forgotten.
- The recent counter is kept per day and slides: a rule that was busy
  months ago and catches nothing now shows a high total but `0 in 14 d`.
  The filter review retires AI rules on this window. Day buckets older than
  the retention (at least 90 days) are pruned.

## Permissions and data locations

| path | owner / mode | content |
|---|---|---|
| `/etc/minisoc/engine.json` | store, 0444 | engine config (no secret, only the key file path) |
| `/etc/minisoc/alert_filter.yaml` | store, 0444 | system rules |
| `/var/lib/minisoc-collector/data` | minisoc-collector, 0700 | Vector checkpoints |
| `/var/lib/minisoc-collector/spool` | minisoc-collector:minisoc, 0750 | parsed events, 0640, aged out after `spoolRetention` |
| `~/.config/minisoc/alert_filter.yaml` | user, 0600 (dir 0700) | user rules |
| `~/.config/minisoc/ai_filters.yaml` | user, 0600 | rules owned by the AI |
| `~/.config/minisoc/prompts/*.md` | user | runtime prompt overrides |
| `~/.local/state/minisoc/` | user, 0700 | SQLite store, backups, last-good rules, inbox |
| `$XDG_RUNTIME_DIR/minisoc/state.json` | user, 0600 | snapshot for the UI |
| `$XDG_RUNTIME_DIR/minisoc/web.token`, `web.url` | user, 0600 | web UI access token (stable for the session) |

- The collector runs as `minisoc-collector` with only `CAP_DAC_READ_SEARCH`
  (`collector.readAnyFile`, needed for Rustinel's root-only logs),
  `PrivateNetwork`, `ProtectSystem=strict`, a syscall filter and write
  access to its state directory only.
- The engine, the widget and the web UI run as the user. Nothing in the UI
  runs as root.
- Spool readers are the members of `minisoc` (`services.minisoc.users`).
  The engine warns when the user rules file is group/world readable.

## The widget

Compact view: `MINISOC`, engine status (pulsing dot; red when a critical
alert is active, grey when the engine is offline), AI state and provider
(`LOCAL` / `REMOTE`), counters per severity, **Pinned** zone, latest alerts,
and the management panel (▼).

Each alert: **PIN/UNPIN**, **DETAILS**, **TP** / **FP** (close with a
verdict), **FILTER** (create a rule from this alert), **AI** (analyze /
re-analyze). Above the feed, **close all as FP** (two clicks) closes every
active alert as false positive; pinned alerts are kept.

- **Pin**: the alert moves to the Pinned zone at the top, gets an accent
  frame, survives restarts, is never hidden by a rule and never touched by
  the AI. Several alerts can be pinned.
- **Details**: the window grows sideways (towards the screen centre) to show
  the full alert while the feed stays usable: source, file, time, severity,
  type, message, occurrences, similar alerts, state, filtering rule, the
  original fields as an indented tree, the raw line, the AI analysis in a
  separate violet frame labelled with provider/model and a confidence bar,
  AI proposals, and the decision history. Close (or click the alert again)
  to go back to the compact view.
- **TP (true positive)**: the alert was real (relevant activity, handled).
  It leaves the feed; the AI will **never** write a rule hiding it or its
  pattern.
- **FP (false positive)**: the alert was noise. It leaves the feed and
  becomes evidence for the [filter review](#filter-review): several FP
  closures with the same cause (same executable, file, profile…) lead the AI
  to a rule. One FP closure alone never does.
- Closing never modifies logs and **never creates a rule by itself**.
  Closed alerts are listed in *Manage ▸ Closed* with their verdict and who
  closed them; they can be re-qualified (**MARK TP** / **MARK FP**) or
  re-opened (**REOPEN**). Alerts closed before verdicts existed count as FP.
- **Create filter**: shows the rule that would be added (source +
  event_type + exact message), then appends it after confirmation. From the
  CLI you can add fields: `minisoc filter create <id> --field
  process.executable --no-message`.

Management panel: closed alerts (TP / FP counts, re-qualify, re-open),
filtered alerts, rules with their owner (system / user / AI) and their
counter since their last change, file status (open your file or the AI
file, roll back the last change), pending AI proposals (accept / reject,
filter review changes included), AI status and statistics (with the last and
next filter review and its summary), and prompt editing.

Profiles: `compact` (360 px, 5 alerts), `desktop` (440 px, 10 alerts +
statistics), `analyst` (520 px, 20 alerts, management panel open, wide
details). Everything can be overridden: `width`, `detailsWidth`,
`maxHeight`, `visibleEvents`, `position`, `layer`, `margin`, `opacity`,
`screen`, `font`, `monoFont`, `fontSize`, `radius`, `colors.*`.

Desktop notifications: the widget sends a `notify-send` for every new
visible alert (icon and urgency follow the severity, `critical` stays
until dismissed). Alerts that are already closed or filtered never
notify, and nothing fires on widget startup for pre-existing alerts.
`ui.notify.enable` (default `true`) turns it off;
`ui.notify.minimumSeverity` (default `low`) raises the floor (`medium`,
`high`, `critical`).

IPC (keybindings, scripts): `minisoc-ui-ipc call minisoc toggleManage`,
`details <id>`, `close`, `tp <id>`, `fp <id>`, `closeAllFp`,
`setProfile analyst`.

## The web UI

The widget's view and actions in a browser tab, for a bigger screen, a
session without Quickshell, or longer triage: active (pinned + feed),
closed, filtered, rules with their counters, AI proposals and AI status, a
details pane (fields, raw line, AI analysis, history), "Create filter" with
the YAML preview, explain, search and severity filters, keyboard shortcuts
(`j`/`k` move, `t`/`f` close as TP/FP, `p` pin, `/` search, `Esc` close)
and optional browser notifications.

```nix
services.minisoc.web.enable = true;   # user service minisoc-web, 127.0.0.1:8743
```

Then `minisoc web --open` (or the "MiniSOC" application entry the Home
Manager module adds, `programs.minisoc.web.desktopEntry`). Links:
`#alert=<id>` opens an alert, `#tab=rules` a tab.

It follows the widget's design: it only reads `state.json` and runs
`minisoc <action>` as the user, through a whitelist (pin, unpin, tp, fp,
fp --all, reopen, analyze, filter create, filter rollback, proposal
accept/reject, review); no shell, no free argument. Colors and fonts come
from `~/.config/minisoc/ui.json` (`programs.minisoc.ui`).

**Access.** Other local users can connect to a loopback port, so:

- the server only binds a loopback address (refused otherwise);
- every API call needs the user's token, 64 hex characters from
  `/dev/urandom` in `$XDG_RUNTIME_DIR/minisoc/web.token` (0600, kept across
  restarts of the service, gone at logout). `minisoc web --url` prints the
  address with the token in the fragment, which the browser never sends; the
  page stores it in its local storage and removes it from the address bar.
  `--open` hands the browser a 0600 redirect page instead of the URL: a
  process' arguments are readable by every local user;
- the `Host` header must name the loopback address (DNS rebinding), a POST
  from another origin is refused, and the page runs under a strict CSP
  (`script-src 'self'`, no inline script or style, no framing);
- data is inserted as text, never as HTML.

One UI per user: on a host with several users in `services.minisoc.users`,
give the others their own port with `MINISOC_WEB_LISTEN=127.0.0.1:8744`
(`systemctl --user edit minisoc-web`).

Through an SSH tunnel, forward the same port (`ssh -L 8743:127.0.0.1:8743`):
the Host check refuses any other address (HTTP 421).

## Command line

```
minisoc status                      engine, rules files, AI status
minisoc list [--state active|pinned|closed|tp|fp|filtered|analyzed|all] [--json]
minisoc show <id> [--json]          everything about one alert
minisoc pin|unpin <id>
minisoc tp <id> | fp <id> | fp --all   close as true / false positive (all: every active alert)
minisoc reopen <id>                 re-open a closed alert (`restore`; `discard` = `fp`)
minisoc review [--dry-run] [--show-input] [--json]   AI filter review now (dry run: change nothing;
                                    show-input: the redacted data sent, no request)
minisoc explain <id>                why rules keep / exclude it
minisoc analyze <id>                request an AI analysis
minisoc filter validate [FILE] | list | draft <id> | create <id> | backups | rollback [--to FILE]
minisoc proposals [--status pending] ; minisoc proposal accept|reject <n>
minisoc ingest --source NAME [--parser json|raw] [FILE|-]
minisoc prompts list | show NAME | edit NAME | path NAME | reset NAME
minisoc web [--url | --open]           serve the browser UI (user service) / print its address / open it
```

## AI analysis

Disabled by default. When enabled, every new alert that is not filtered and
is at least `analysis.minimumSeverity` (`unknown` counts as medium) is
queued; the model returns a structured SOC N1 analysis that is stored with
the alert and displayed separately from the original data.

```json
{
  "summary": "Possible port scanning activity",
  "classification": "reconnaissance",
  "severity_assessment": "medium",
  "confidence": 0.87,
  "benign_confidence": 0.10,
  "context": "The source attempted connections to multiple ports.",
  "facts": ["..."], "hypotheses": ["Possible network reconnaissance"],
  "missing_information": ["..."], "indicators": ["Multiple destination ports"],
  "impact": "...",
  "recommended_investigations": ["Check connection history"],
  "false_positive_likelihood": "medium",
  "suggested_action": "investigate"
}
```

Replies are validated: unknown keys are dropped, values are type- and
range-checked, a reply without `summary` and `confidence` is rejected,
doubtful enums fall back to `unknown` / `investigate`. `confidence` (quality
of the analysis) and `benign_confidence` (the event is harmless) are
distinct: a sure detection is never read as a sure benign verdict.

Performance and robustness: minimum severity, similarity de-duplication (a
pattern already queued or in flight shares its result), cache (same
fingerprint + provider + model + prompts, `cacheTtlHours`), rate limit
(`requestsPerMinute`), daily quota, bounded queue (least severe dropped
first), concurrency (`maxConcurrent`), timeout, retries with exponential
backoff honouring `Retry-After`, bounded payload (`maxEventBytes`). Pending
alerts are re-queued after a restart. Provider errors show in the widget and
in the alert history; they never block ingestion or the UI.

### Providers

| provider | endpoint (default) | key |
|---|---|---|
| `ollama` | `http://127.0.0.1:11434` (`/api/chat`, JSON mode) | none |
| `openai` | `https://api.openai.com/v1` (`/chat/completions`, JSON mode) | `apiKeyFile` |
| `anthropic` | `https://api.anthropic.com/v1/messages` | `apiKeyFile` |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta` (`generateContent`, JSON) | `apiKeyFile` |
| `openrouter` | `https://openrouter.ai/api/v1` (OpenAI chat format; model ids such as `anthropic/claude-haiku-5.5`) | `apiKeyFile` |
| `openai-compatible` | required (llama.cpp, vLLM, LM Studio, LocalAI…) | optional |
| `custom` | required: `POST {model, system, prompt, max_tokens}` → `{"output": "<json>"}` | optional (Bearer) |

`model` is mandatory (MiniSOC does not guess model names). Adding a provider
means one request shape and one reply extractor in
`packages/minisoc/src/ai/providers.rs`.

**Remote endpoints must be opted in**: any non-loopback endpoint (including
openai/anthropic/gemini) requires `ai.allowRemote = true`, checked at
evaluation time and again by the engine. The widget shows `REMOTE` and the
management panel warns that redacted alerts leave the machine.

### Secrets

```nix
sops.secrets.minisoc-api-key = { owner = "alice"; mode = "0400"; };
services.minisoc.ai.apiKeyFile = config.sops.secrets.minisoc-api-key.path;
```

Only the path is in the configuration; the engine reads the file at each
request and never logs it. Paths inside `/nix/store` are rejected. Since the
engine is a user service, the file must be readable by that user (agenix:
`owner = "alice"`).

### Prompts

Five prompts are assembled for each request: `system`, `analysis`,
`enrichment`, `classification` (analysis call) and `filter` (rule
proposals). Defaults live in `packages/minisoc/prompts/`. Precedence:

1. `~/.config/minisoc/prompts/<name>.md` — edit with `minisoc prompts edit
   <name>` or *Manage ▸ AI ▸ Edit*; read at every request, no rebuild;
2. Nix: `services.minisoc.ai.prompts.<name>.text` / `.file` (or the
   `ai.prompt` / `ai.promptFile` shortcuts for `analysis`);
3. built-in default.

Whatever the prompts say, the engine appends fixed rules to the system
prompt and wraps the alert in `<alert_data>…</alert_data>` (a closing tag
inside the data is escaped): alert content is untrusted data, never
instructions. The model cannot change its guardrails: every automatic
decision is enforced in code from the Nix configuration, which it never sees.

### Auto-close as FP

The options keep their former name (`autoDiscard`): the AI closes benign
alerts as **false positive**, never as TP. These AI closures are never used
as evidence by the filter review (the AI does not learn from itself).

```nix
services.minisoc.ai.analysis = {
  autoDiscard = true;
  autoDiscardPolicy = {
    mode = "suggest";              # or "automatic"
    maximumSeverity = "low";       # info | low | medium | high
    minimumConfidence = 0.75;      # on benign_confidence
    requireRepeatedBenignPattern = true;
    minimumOccurrences = 2;
  };
};
```

An alert is closed as FP (automatic) or proposed (suggest) only if **all** of:
not critical (hard rule), not `unknown`, severity ≤ `maximumSeverity`
(default `low`, so high is never closed by the AI unless configured), not
pinned (hard rule), suggested action `discard`, classification not
malicious/suspicious/reconnaissance/unknown, false-positive likelihood
`high`, `benign_confidence` ≥ threshold, and (by default) the pattern seen
≥ `minimumOccurrences` times with at least two benign analyses. Every AI
closure is recorded with its justification, visible in *Closed* as
`closed as FALSE POSITIVE by ai`, and re-openable.

### Auto-filter

```nix
services.minisoc.ai.autoFilter = {
  enable = true;
  mode = "suggest";                # or "automatic"
  minimumConfidence = 0.85;
  requireRepeatedEvents = true;
  minimumOccurrences = 3;
  protectSeverity = [ "critical" "high" ];
  backupBeforeWrite = true;
};
```

When a pattern recurs (`minimumOccurrences`) and its analysis is confidently
benign, the model receives up to five redacted samples and proposes one
rule. MiniSOC accepts it only if: `source` and `event_type` are exact, at
least one `message`/`fields` condition pins the pattern (strings ≥ 6 chars,
regexes with ≥ 8 literal characters and not matching the empty string), no
`severity`/`all`/`any`/`not`/IP keys, confidence ≥ threshold, it matches the
triggering alert, and among recent stored alerts it matches no other
pattern, no pinned alert and nothing high/critical. MiniSOC then **injects
`severity: {in: [...]}` itself** with only the non-protected levels
(critical and high are always protected), so the rule can never hide them.

`suggest`: the rule waits in *Manage ▸ AI proposals*. `automatic`: it is
appended to the AI rules file `ai_filters.yaml` (backup, atomic write,
existing rules never changed or widened); your own file is never written by
the AI. AI rules carry their provenance:

```yaml
metadata:
  generated_by: minisoc-ai
  provider: ollama
  model: qwen3:8b
  confidence: 0.99
  created_at: "2026-11-23T18:30:00.000Z"
  reason: Repeated benign informational events
  fingerprint: 3a9c…
  source_event: evt-…
```

Rejected proposals are kept (status `invalid`) with the reason.

### Filter review

A scheduled pass where the AI re-examines **its whole rule list** against
what you did with the alerts, so the feed improves empirically as you use
the workstation.

```nix
services.minisoc.ai.filterReview = {
  enable = true;
  mode = "suggest";           # or "automatic" (rewrites ai_filters.yaml)
  interval = 6;               # hours; `minisoc review` runs one now
  lookbackDays = 30;          # closures taken into account
  minimumFalsePositives = 3;  # FP closures a rule must cover
  minimumRuleAge = 72;        # hours before a rule may be changed / deleted
  lowHitsThreshold = 2;       # a rule excluding <= this over filter.recentDays may go
  maxChanges = 5;             # per review
  minimumConfidence = 0.7;
  maxOutputTokens = 16384;    # the reply of a review is long; reasoning counts
  reasoningEffort = null;     # "low" for reasoning models that truncate
};
```

**What the model receives** (redacted like any AI request): the alerts you
closed as FP in the look-back window, grouped by similar pattern with their
count; the alerts you closed as TP (counter-examples); the AI rules with
their counters (since their last change, and over the recent window) and
how many FP/TP closures each
matches; your rules and the system rules as read-only context. Only *your*
closures count: AI closures are never evidence.

**What it answers**: a summary and a list of changes on the AI file:
`create` (e.g. several fapolicyd or AppArmor denials closed as FP on the same
executable or profile → one rule on that executable), `update` (widen a rule
to new FP closures of the same cause, or narrow it), `delete` (a rule that
excludes almost nothing since its last change: the noise it targeted is
gone). The prompt is `review` (`minisoc prompts edit review`).

**Guardrails, enforced in code before anything is written:**

- Only rules of the AI file are created, modified or deleted. Your rules and
  the system rules are never touched.
- A created/updated rule names an exact `source` and `event_type` plus a
  specific `message`/`fields` condition (same matcher limits as auto-filter);
  MiniSOC injects the severity protection (critical/high never hidden; a
  severity in the model's answer is ignored).
- It must cover at least `minimumFalsePositives` alerts **you** closed as FP,
  and among recent alerts it may hide nothing else: no pinned alert, no alert
  closed as TP, no high/critical alert, no alert of a pattern you never
  closed as FP (too broad), no duplicate of an existing rule.
- A partial `message` match (`prefix`, `contains`, `regex`: typically a
  detection title) needs a `fields` condition pinning the object
  (executable, file, profile…): without it the rule would silence a whole
  detection for every program. Every (redacted) alert message is sent in full
  so that exact rules are possible.
- A rule changed less than `minimumRuleAge` hours ago is left alone (its
  counter needs time). A rule is deleted only when it excluded at most
  `lowHitsThreshold` alerts over the last `filter.recentDays` days (since
  its last change), or — at once — when it
  would hide an alert closed as TP or breaks a guardrail added since it was
  written. This clean-up is done by the code itself at every review,
  before asking the model (and even when the model cannot be reached).
- At most `maxChanges` changes per review, each with `confidence` ≥
  `minimumConfidence`. Rejected changes are listed with the reason.
- `suggest`: changes wait in *Manage ▸ AI proposals* (re-checked against the
  current state when you accept; a refused change is never proposed again).
  `automatic`: one validated, backed-up rewrite of `ai_filters.yaml`; the
  engine hot-reloads it and the new rules' counters start at 0.
- No request when nothing changed since the last review (same closures, same
  rules and counters, same prompt), and none at all while there is neither an FP closure
  nor an AI rule. Reviews count in the daily quota.

Check it with `minisoc review --dry-run` (shows what the model would change
and what the guardrails refuse, writes nothing), `minisoc review --show-input`
(the redacted data a review sends, no request), the history
(`filter_review_create|update|delete`), and *Manage ▸ AI* (last/next run,
summary, applied/proposed/rejected counts, last error). Undo an applied
change by editing `ai_filters.yaml` or restoring a backup from
`~/.local/state/minisoc/filter-backups/ai/`.

### Privacy

Sent to the model: source, timestamp, severity, type, message and the parsed
fields — **not** the raw line (`privacy.sendRaw`). By default private /
loopback / link-local IPs are replaced by `<private-ip-hash>` and user names
(and `/home/<user>`) by `<user>`. `privacy.redactPaths` replaces paths by a
hash + basename, `privacy.excludeFields` drops fields, `maxEventBytes`
bounds the payload. Use `provider = "ollama"` to keep everything local.

## Complete example

`example/minisoc.nix` (Rustinel + a grok source + system rules + local
Ollama analysis in suggest mode + Home Manager widget):

```nix
{ config, security-nix, ... }:
{
  imports = [ security-nix.nixosModules.security ];
  nixpkgs.overlays = [ security-nix.overlays.default ];

  services.rustinel.enable = true;
  services.ollama.enable = true;

  services.minisoc = {
    enable = true;
    users = [ "alice" ];
    sources.applicationA = {
      paths = [ "/var/log/applicationA/*.log" ];
      parser = "grok";
      pattern = "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
    };
    filter.systemRules = [
      {
        id = "rustinel_whoami_demo";
        description = "Demo Sigma rule shipped with the Rustinel module";
        match = { source = "rustinel"; message.contains = "Whoami Execution"; };
        action = "exclude";
      }
    ];
    ai = {
      enable = true;
      provider = "ollama";
      model = "qwen3:8b";
      analysis = {
        minimumSeverity = "medium";
        autoDiscard = true;                     # suggest mode by default
      };
      autoFilter.enable = true;                 # suggest mode by default
      filterReview.enable = true;               # every 6 h, suggest mode by default
    };
  };

  home-manager.users.alice = {
    imports = [ security-nix.homeManagerModules.minisoc ];
    programs.minisoc = {
      enable = true;
      ui.profile = "desktop";
    };
  };
}
```

## Troubleshooting

- **Widget says ENGINE OFFLINE**: `systemctl --user status minisoc-engine`.
  Not started? The user must be in `services.minisoc.users`, then log out
  and back in (the unit has `ConditionGroup=minisoc`).
- **No events**: `systemctl status minisoc-collector`,
  `ls -l /var/lib/minisoc-collector/spool`, `journalctl -u
  minisoc-collector`. Vector only reads files matching `paths` and modified
  within `ignoreOlderThan`. Test the engine alone with
  `echo '{"severity":"high","message":"test"}' | minisoc ingest --source test`.
- **An alert disappeared**: `minisoc list --state all`, then `minisoc
  explain <id>` (rule, and whether it is an AI rule) or `minisoc show <id>`
  (history: who closed it, with which verdict).
- **The AI review hides something it should not**: close one of those
  alerts as TP — the next review must then delete or narrow the rule (a rule
  hiding a TP may be removed at once), and no new rule may hide it. Or remove
  the rule from `ai_filters.yaml` yourself.
- **Rules not applied**: `minisoc filter validate` — an invalid file keeps
  its previous version in force; `minisoc status` shows the error.
- **AI**: *Manage ▸ AI* or `minisoc status` (`last_error`, quota);
  `journalctl --user -u minisoc-engine`. `refusing to send data to a remote
  endpoint` means `ai.allowRemote` is off.
- **`reply truncated at N tokens`**: reasoning models ("thinking", e.g. GLM,
  o-series) spend part of the output budget on reasoning. Raise
  `ai.limits.maxOutputTokens` (or `ai.filterReview.maxOutputTokens` for
  reviews) or set `ai.reasoningEffort` / `ai.filterReview.reasoningEffort`
  to `"low"`.
- **Widget does not start with Hyprland**: no `graphical-session.target`;
  use `exec-once = minisoc-ui` and `ui.autostart = false`.
- **Reset everything** (alerts, pins, history; logs untouched): stop the
  engine and remove `~/.local/state/minisoc/`.

## Status and limits

Implemented and covered by tests: everything above. Notable limits of this
first version:

- Only the `exclude` rule action exists (the format is versioned and rejects
  unknown actions, so new ones can be added safely).
- No rule editor in the widget: *Open rules file* opens your editor; the
  widget validates nothing itself, the engine does.
- One engine per user: alerts, pins and rules are per user, the spool is
  shared.
- Sources beyond Rustinel are declared generically (no dedicated
  normalizer yet for ClamAV, Suricata EVE, auditd, CrowdSec…).
