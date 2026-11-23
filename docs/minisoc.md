# MiniSOC

A personal, local Security Operations Center for a NixOS workstation. MiniSOC
collects the alerts of the security tools installed on the machine (Rustinel
today, any log file you declare), normalizes them into one format, filters
the noise with an external rules file, keeps a lifecycle per alert (pin,
discard, restore, filter) and shows them in a Quickshell desktop widget.
An LLM can optionally add a SOC level 1 analysis and propose (or, within
strict limits, apply) discards and exclusion rules.

MiniSOC works entirely without an LLM and without any remote service.

- [Architecture](#architecture)
- [Installation (NixOS)](#installation-nixos)
- [Installation (Home Manager)](#installation-home-manager)
- [Sources and parsers](#sources-and-parsers)
- [Normalized event format](#normalized-event-format)
- [alert_filter.yaml](#alert_filteryaml)
- [Permissions and data locations](#permissions-and-data-locations)
- [The widget: pin / details / discard](#the-widget)
- [Command line](#command-line)
- [AI analysis](#ai-analysis) — [providers](#providers), [secrets](#secrets), [prompts](#prompts), [auto-discard](#auto-discard), [auto-filter](#auto-filter), [privacy](#privacy)
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
 ┌──────────────────────────┐
 │ Quickshell widget        │  reads the state, runs `minisoc <action>`
 └──────────────────────────┘  as the user (never root)
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
| `paths` | files or globs; files created later are picked up |
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
- Every automated write (Create filter, AI rule, accepted proposal,
  rollback) is atomic (temp file + fsync + rename, mode 0600), preceded by a
  backup in `~/.local/state/minisoc/filter-backups/` (last 20), and only
  appends: other rules and comments are preserved. A write is refused if the
  current file is invalid. `minisoc filter rollback` restores the latest
  backup.

## Permissions and data locations

| path | owner / mode | content |
|---|---|---|
| `/etc/minisoc/engine.json` | store, 0444 | engine config (no secret, only the key file path) |
| `/etc/minisoc/alert_filter.yaml` | store, 0444 | system rules |
| `/var/lib/minisoc-collector/data` | minisoc-collector, 0700 | Vector checkpoints |
| `/var/lib/minisoc-collector/spool` | minisoc-collector:minisoc, 0750 | parsed events, 0640, aged out after `spoolRetention` |
| `~/.config/minisoc/alert_filter.yaml` | user, 0600 (dir 0700) | user rules |
| `~/.config/minisoc/prompts/*.md` | user | runtime prompt overrides |
| `~/.local/state/minisoc/` | user, 0700 | SQLite store, backups, last-good rules, inbox |
| `$XDG_RUNTIME_DIR/minisoc/state.json` | user, 0600 | snapshot for the UI |

- The collector runs as `minisoc-collector` with only `CAP_DAC_READ_SEARCH`
  (`collector.readAnyFile`, needed for Rustinel's root-only logs),
  `PrivateNetwork`, `ProtectSystem=strict`, a syscall filter and write
  access to its state directory only.
- The engine and the widget run as the user. Nothing in the UI runs as root.
- Spool readers are the members of `minisoc` (`services.minisoc.users`).
  The engine warns when the user rules file is group/world readable.

## The widget

Compact view: `MINISOC`, engine status (pulsing dot; red when a critical
alert is active, grey when the engine is offline), AI state and provider
(`LOCAL` / `REMOTE`), counters per severity, **Pinned** zone, latest alerts,
and the management panel (▼).

Each alert: **PIN/UNPIN**, **DETAILS**, **DISCARD** (or **RESTORE**),
**FILTER** (create a rule from this alert), **AI** (analyze / re-analyze).

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
- **Discard**: removes the alert from the active feed and records who did it
  and why. It never modifies logs and **never creates a rule**: discarded
  alerts are listed in *Manage ▸ Discarded* and can be restored.
- **Create filter**: shows the rule that would be added (source +
  event_type + exact message), then appends it after confirmation. From the
  CLI you can add fields: `minisoc filter create <id> --field
  process.executable --no-message`.

Management panel: discarded alerts (restore), filtered alerts, rules with
hit counters and file status (open the file, roll back the last change),
pending AI proposals (accept / reject), AI status and statistics, and prompt
editing.

Profiles: `compact` (360 px, 5 alerts), `desktop` (440 px, 10 alerts +
statistics), `analyst` (520 px, 20 alerts, management panel open, wide
details). Everything can be overridden: `width`, `detailsWidth`,
`maxHeight`, `visibleEvents`, `position`, `layer`, `margin`, `opacity`,
`screen`, `font`, `monoFont`, `fontSize`, `radius`, `colors.*`.

IPC (keybindings, scripts): `minisoc-ui-ipc call minisoc toggleManage`,
`details <id>`, `close`, `setProfile analyst`.

## Command line

```
minisoc status                      engine, rules files, AI status
minisoc list [--state active|pinned|discarded|filtered|analyzed|all] [--json]
minisoc show <id> [--json]          everything about one alert
minisoc pin|unpin|discard|restore <id>
minisoc explain <id>                why rules keep / exclude it
minisoc analyze <id>                request an AI analysis
minisoc filter validate [FILE] | list | draft <id> | create <id> | backups | rollback [--to FILE]
minisoc proposals [--status pending] ; minisoc proposal accept|reject <n>
minisoc ingest --source NAME [--parser json|raw] [FILE|-]
minisoc prompts list | show NAME | edit NAME | path NAME | reset NAME
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

### Auto-discard

```nix
services.minisoc.ai.analysis = {
  autoDiscard = true;
  autoDiscardPolicy = {
    mode = "suggest";              # or "automatic"
    maximumSeverity = "low";       # info | low | medium | high
    minimumConfidence = 0.95;      # on benign_confidence
    requireRepeatedBenignPattern = true;
    minimumOccurrences = 3;
  };
};
```

An alert is discarded (automatic) or proposed (suggest) only if **all** of:
not critical (hard rule), not `unknown`, severity ≤ `maximumSeverity`
(default `low`, so high is never auto-discarded unless configured), not
pinned (hard rule), suggested action `discard`, classification not
malicious/suspicious/reconnaissance/unknown, false-positive likelihood
`high`, `benign_confidence` ≥ threshold, and (by default) the pattern seen
≥ `minimumOccurrences` times with at least two benign analyses. Every AI
discard is recorded with its justification, visible in *Discarded* with
`discarded by ai`, and restorable.

### Auto-filter

```nix
services.minisoc.ai.autoFilter = {
  enable = true;
  mode = "suggest";                # or "automatic"
  minimumConfidence = 0.98;
  requireRepeatedEvents = true;
  minimumOccurrences = 5;
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
appended to the user rules file (backup, atomic write, existing rules never
changed or widened). AI rules carry their provenance:

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

Rejected proposals are kept (status `invalid`) with the reason. Roll back
with `minisoc filter rollback`.

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
  explain <id>` (rule) or `minisoc show <id>` (history: who discarded it).
- **Rules not applied**: `minisoc filter validate` — an invalid file keeps
  its previous version in force; `minisoc status` shows the error.
- **AI**: *Manage ▸ AI* or `minisoc status` (`last_error`, quota);
  `journalctl --user -u minisoc-engine`. `refusing to send data to a remote
  endpoint` means `ai.allowRemote` is off.
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
