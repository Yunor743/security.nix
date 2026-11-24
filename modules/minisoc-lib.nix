# Pure helpers shared by the MiniSOC module and its checks.
{ lib }:

rec {
  severities = [
    "unknown"
    "info"
    "low"
    "medium"
    "high"
    "critical"
  ];

  # VRL program for one source: keep the original line in `.raw`, parse it
  # into `.parsed`, record parse errors instead of dropping the event.
  # `$` is doubled because Vector interpolates environment variables in its
  # configuration files.
  vrl =
    name: src:
    let
      parse =
        {
          json = ''
            parsed, err = parse_json(.raw)
          '';
          regex = ''
            parsed, err = parse_regex(.raw, r'${src.pattern}')
          '';
          grok = ''
            parsed, err = parse_grok(.raw, ${builtins.toJSON src.pattern})
          '';
          syslog = ''
            parsed, err = parse_syslog(.raw)
          '';
        }
        .${src.parser} or null;
      body = ''
        .minisoc = {"source": ${builtins.toJSON name}, "parser": ${builtins.toJSON src.parser}, "file": .file}
        .raw = string!(.message)
      ''
      + (
        if parse == null then
          ''
            .parsed = {"message": .raw}
          ''
        else
          parse
          + ''
            if err != null {
              .minisoc.parse_error = err
            } else {
              .parsed = parsed
            }
          ''
      )
      + lib.optionalString ((src.transform or null) != null) src.transform
      + (
        if (src.type or "file") == "journald" then
          # Only what the engine reads: journald adds dozens of fields.
          ''
            if exists(.timestamp) && is_object(.parsed) && !exists(.parsed.timestamp) {
              .parsed.timestamp = .timestamp
            }
            . = {"minisoc": .minisoc, "raw": .raw, "parsed": .parsed}
          ''
        else
          ''
            del(.message)
            del(.source_type)
            del(.host)
            del(.file)
          ''
      );
    in
    lib.replaceStrings [ "$" ] [ "$$" ] body;

  # VRL turning access denials of the Linux security modules (read from the
  # journal, parser "raw") into MiniSOC events; other lines are dropped.
  # `wouldBe`: also keep the decisions of complain/permissive modes, which
  # are logged but not enforced.
  macTransforms = {
    # Kernel audit records, e.g.
    #   apparmor="DENIED" operation="open" class="file" profile="top"
    #   name="/etc/shadow" pid=42 comm="top" requested_mask="r" ...
    # D-Bus mediation wraps them in msg='...'.
    apparmor =
      { wouldBe }:
      ''
        if !contains(.raw, "apparmor=") { abort }
        kv = parse_key_value(.raw) ?? {}
        if is_string(kv.msg) { kv = merge(kv, parse_key_value(string!(kv.msg)) ?? {}) }
        decision = string(kv.apparmor) ?? ""
        if decision != "DENIED" && !(${lib.boolToString wouldBe} && decision == "ALLOWED") { abort }
        denied = decision == "DENIED"
        what = string(kv.name) ?? string(kv.capname) ?? string(kv.member) ?? string(kv.peer) ?? ""
        verb = "would deny"
        .parsed = {"event_type": "apparmor_would_deny", "severity": "low"}
        if denied {
          verb = "denied"
          .parsed = {"event_type": "apparmor_denied", "severity": "medium"}
        }
        profile = string(kv.profile) ?? string(kv.label) ?? "?"
        .parsed.message = join!(["AppArmor", verb, string(kv.operation) ?? "access", what, "—", string(kv.comm) ?? "?", "(profile " + profile + ")"], " ")
        .parsed.profile = profile
        .parsed.operation = kv.operation
        .parsed.name = what
        .parsed.comm = kv.comm
        .parsed.pid = kv.pid
        .parsed.denied_mask = kv.denied_mask
      '';

    # avc:  denied  { read } for  pid=42 comm="cat" name="shadow" dev="vda"
    # ino=12 scontext=user_u:user_r:user_t:s0 tcontext=system_u:object_r:shadow_t:s0
    # tclass=file permissive=0
    selinux =
      { wouldBe }:
      ''
        m = parse_regex(.raw, r'avc:\s+denied\s+\{\s*(?P<perms>[^}]*?)\s*\}') ?? {}
        if !exists(m.perms) { abort }
        kv = parse_key_value(.raw) ?? {}
        permissive = (string(kv.permissive) ?? "0") == "1"
        if permissive && !${lib.boolToString wouldBe} { abort }
        stype = string(split(string(kv.scontext) ?? "", ":")[2]) ?? "?"
        ttype = string(split(string(kv.tcontext) ?? "", ":")[2]) ?? "?"
        what = string(kv.name) ?? string(kv.path) ?? string(kv.capability) ?? string(kv.dest) ?? ""
        verb = "denied"
        .parsed = {"event_type": "selinux_denied", "severity": "medium"}
        if permissive {
          verb = "would deny"
          .parsed = {"event_type": "selinux_would_deny", "severity": "low"}
        }
        .parsed.message = join!(["SELinux", verb, string!(m.perms), "on", string(kv.tclass) ?? "?", what, "—", string(kv.comm) ?? "?", "(" + stype + " → " + ttype + ")"], " ")
        .parsed.perms = m.perms
        .parsed.tclass = kv.tclass
        .parsed.name = what
        .parsed.comm = kv.comm
        .parsed.pid = kv.pid
        .parsed.scontext = kv.scontext
        .parsed.tcontext = kv.tcontext
      '';

    # syslog_format of the fapolicyd module:
    # rule=9 dec=deny_syslog perm=execute auid=1000 pid=42 exe=/bin/bash : path=/tmp/x ftype=... trust=0
    # In permissive mode the same line is logged and access is granted.
    fapolicyd =
      { wouldBe, permissive }:
      ''
        kv = parse_key_value(.raw) ?? {}
        dec = string(kv.dec) ?? ""
        if !starts_with(dec, "deny") { abort }
        if ${lib.boolToString permissive} && !${lib.boolToString wouldBe} { abort }
        perm = string(kv.perm) ?? "access"
        verb = "denied"
        .parsed = {"event_type": "fapolicyd_denied", "severity": "high"}
        if ${lib.boolToString permissive} {
          verb = "would deny"
          .parsed = {"event_type": "fapolicyd_would_deny", "severity": "low"}
        }
        .parsed.message = join!(["fapolicyd", verb, perm, string(kv.path) ?? "?", "—", string(kv.exe) ?? "?", "(rule " + (string(kv.rule) ?? "?") + ")"], " ")
        .parsed.rule = kv.rule
        .parsed.perm = kv.perm
        .parsed.path = kv.path
        .parsed.exe = kv.exe
        .parsed.pid = kv.pid
        .parsed.auid = kv.auid
        .parsed.ftype = kv.ftype
      '';
  };

  mkVectorConfig =
    {
      sources,
      spoolDir,
      dataDir,
      journalctl ? "journalctl",
    }:
    let
      enabled = lib.filterAttrs (_: s: s.enable) sources;
    in
    {
      data_dir = dataDir;
      api.enabled = false;
      sources = lib.mapAttrs' (
        n: s:
        lib.nameValuePair "src_${n}" (
          if (s.type or "file") == "journald" then
            {
              type = "journald";
              include_matches = s.journald.matches;
              since_now = s.readFrom == "end";
              journalctl_path = journalctl;
            }
          else
            {
              type = "file";
              include = s.paths;
              read_from = s.readFrom;
              ignore_older_secs = s.ignoreOlderThan;
              max_line_bytes = 1048576;
              glob_minimum_cooldown_ms = 1000;
            }
        )
      ) enabled;
      transforms = lib.mapAttrs' (
        n: s:
        lib.nameValuePair "parse_${n}" {
          type = "remap";
          inputs = [ "src_${n}" ];
          source = vrl n s;
        }
      ) enabled;
      sinks.spool = {
        type = "file";
        inputs = map (n: "parse_${n}") (lib.attrNames enabled);
        # Daily files; the engine tracks offsets per file (inode), and
        # systemd-tmpfiles ages old ones out.
        path = "${spoolDir}/events-%Y-%m-%d.ndjson";
        encoding.codec = "json";
      };
    };
}
