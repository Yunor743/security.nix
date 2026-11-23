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
      + ''
        del(.message)
        del(.source_type)
        del(.host)
        del(.file)
      '';
    in
    lib.replaceStrings [ "$" ] [ "$$" ] body;

  mkVectorConfig =
    {
      sources,
      spoolDir,
      dataDir,
    }:
    let
      enabled = lib.filterAttrs (_: s: s.enable) sources;
    in
    {
      data_dir = dataDir;
      api.enabled = false;
      sources = lib.mapAttrs' (
        n: s:
        lib.nameValuePair "src_${n}" {
          type = "file";
          include = s.paths;
          read_from = s.readFrom;
          ignore_older_secs = s.ignoreOlderThan;
          max_line_bytes = 1048576;
          glob_minimum_cooldown_ms = 1000;
        }
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
