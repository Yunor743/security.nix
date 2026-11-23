# Validates the generated Vector configuration and unit-tests the VRL parsers
# (json, regex, grok, syslog, raw) with `vector test`, on fictional lines.
{
  lib,
  runCommandLocal,
  vector,
  writeText,
}:

let
  mlib = import ../modules/minisoc-lib.nix { inherit lib; };
  src = parser: pattern: {
    enable = true;
    paths = [ "/var/log/${parser}/*.log" ];
    inherit parser pattern;
    readFrom = "beginning";
    ignoreOlderThan = 86400;
  };
  base = mlib.mkVectorConfig {
    sources = {
      app_json = src "json" null;
      app_regex = src "regex" "^(?P<level>[A-Z]+) (?P<message>.+)$";
      app_grok = src "grok" "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
      app_syslog = src "syslog" null;
      app_raw = src "raw" null;
    };
    spoolDir = "/tmp/spool";
    dataDir = "/tmp/data";
  };
  case = name: transform: line: assertions: {
    inherit name;
    inputs = [
      {
        insert_at = transform;
        type = "log";
        log_fields = {
          message = line;
          file = "/var/log/test.log";
        };
      }
    ];
    outputs = [
      {
        extract_from = transform;
        conditions = [
          {
            type = "vrl";
            source = lib.replaceStrings [ "$" ] [ "$$" ] assertions;
          }
        ];
      }
    ];
  };
  config = base // {
    tests = [
      (case "json" "parse_app_json" ''{"severity":"high","message":"x","n":1}'' ''
        assert_eq!(.minisoc.source, "app_json")
        assert_eq!(.parsed.severity, "high")
        assert_eq!(.parsed.n, 1)
        assert_eq!(.raw, "{\"severity\":\"high\",\"message\":\"x\",\"n\":1}")
        assert!(!exists(.message))
      '')
      (case "json-error-kept" "parse_app_json" "{broken" ''
        assert!(exists(.minisoc.parse_error))
        assert_eq!(.raw, "{broken")
        assert!(!exists(.parsed))
      '')
      (case "regex" "parse_app_regex" "ERROR disk full" ''
        assert_eq!(.parsed.level, "ERROR")
        assert_eq!(.parsed.message, "disk full")
      '')
      (case "grok" "parse_app_grok" "2026-11-23T18:30:00Z 10.0.0.5 WARN port scan detected" ''
        assert_eq!(.parsed.ip, "10.0.0.5")
        assert_eq!(.parsed.level, "WARN")
        assert_eq!(.parsed.message, "port scan detected")
        assert_eq!(.minisoc.parser, "grok")
      '')
      (case "syslog" "parse_app_syslog"
        "<34>1 2026-11-23T18:30:00.000Z host sshd 1234 - - Failed password for root"
        ''
          assert_eq!(.parsed.appname, "sshd")
          assert_eq!(.parsed.severity, "crit")
          assert_eq!(.parsed.message, "Failed password for root")
        ''
      )
      (case "raw" "parse_app_raw" "plain text line" ''
        assert_eq!(.parsed.message, "plain text line")
      '')
    ];
  };
  file = writeText "minisoc-vector-test.json" (builtins.toJSON config);
in
runCommandLocal "minisoc-vector-test" { nativeBuildInputs = [ vector ]; } ''
  export HOME=$TMPDIR
  vector validate --no-environment ${file}
  vector test ${file}
  touch $out
''
