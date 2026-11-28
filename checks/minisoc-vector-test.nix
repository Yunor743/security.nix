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
  vectorBuildable = import ./vector-buildable.nix { inherit vector; };
  src = parser: pattern: {
    enable = true;
    paths = [ "/var/log/${parser}/*.log" ];
    inherit parser pattern;
    readFrom = "beginning";
    ignoreOlderThan = 86400;
  };
  mac = transform: {
    enable = true;
    type = "journald";
    journald.matches._TRANSPORT = [ "audit" ];
    parser = "raw";
    pattern = null;
    readFrom = "end";
    ignoreOlderThan = 86400;
    inherit transform;
  };
  base = mlib.mkVectorConfig {
    sources = {
      app_json = src "json" null;
      app_regex = src "regex" "^(?P<level>[A-Z]+) (?P<message>.+)$";
      app_grok = src "grok" "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
      app_syslog = src "syslog" null;
      app_raw = src "raw" null;
      # Security module denials, as the integrations configure them.
      mac_apparmor = mac (mlib.macTransforms.apparmor { wouldBe = false; });
      mac_selinux = mac (mlib.macTransforms.selinux { wouldBe = false; });
      mac_selinux_wb = mac (mlib.macTransforms.selinux { wouldBe = true; });
      mac_fapolicyd = mac (
        mlib.macTransforms.fapolicyd {
          wouldBe = false;
          permissive = false;
        }
      );
      mac_usbguard = mac mlib.usbguardTransform;
      mac_crowdsec = mac mlib.crowdsecTransform;
      mac_fapolicyd_perm = mac (
        mlib.macTransforms.fapolicyd {
          wouldBe = false;
          permissive = true;
        }
      );
    };
    spoolDir = "/tmp/spool";
    rateLimit = {
      threshold = 100;
      window = 60;
    };
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
  none = name: transform: line: {
    inherit name;
    no_outputs_from = [ transform ];
    inputs = [
      {
        insert_at = transform;
        type = "log";
        log_fields.message = line;
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
      (case "rate-key-ignores-numbers" "parse_app_raw" "denied pid=4242 serial 17" ''
        assert_eq!(.minisoc.rate_key, md5("app_raw|\"denied pid=# serial #\""))
      '')
      (case "apparmor-denied" "parse_mac_apparmor"
        ''apparmor="DENIED" operation="open" class="file" profile="top" name="/etc/shadow" pid=42 comm="top" requested_mask="r" denied_mask="r" fsuid=0 ouid=0''
        ''
          assert_eq!(.parsed.severity, "medium")
          assert_eq!(.parsed.event_type, "apparmor_denied")
          assert_eq!(.parsed.message, "AppArmor denied open /etc/shadow — top (profile top)")
          assert!(!exists(.file))
        ''
      )
      (case "apparmor-dbus" "parse_mac_apparmor"
        ''USER_AVC pid=1 uid=101 auid=4294967295 msg='apparmor="DENIED" operation="dbus_method_call" bus="system" path="/org/freedesktop/login1" interface="org.freedesktop.login1.Manager" member="PowerOff" mask="send" name="org.freedesktop.login1" pid=7 label="foo" peer_label="unconfined" exe="/x" sauid=101 hostname=? addr=? terminal=?' ''
        ''
          assert_eq!(.parsed.event_type, "apparmor_denied")
          assert!(contains(string!(.parsed.message), "dbus_method_call"))
        ''
      )
      (none "apparmor-complain-dropped" "parse_mac_apparmor"
        ''apparmor="ALLOWED" operation="open" class="file" profile="sddm" name="/sys/x" pid=1 comm="sddm" requested_mask="r" denied_mask="r"''
      )
      (none "audit-other-dropped" "parse_mac_apparmor"
        ''SERVICE_START pid=1 uid=0 msg='unit=sshd comm="systemd"' ''
      )
      (case "selinux-denied" "parse_mac_selinux"
        ''avc:  denied  { read } for  pid=42 comm="cat" name="shadow" dev="vda" ino=12 scontext=user_u:user_r:user_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0''
        ''
          assert_eq!(.parsed.event_type, "selinux_denied")
          assert_eq!(.parsed.message, "SELinux denied read on file shadow — cat (user_t → shadow_t)")
        ''
      )
      (none "selinux-permissive-dropped" "parse_mac_selinux"
        ''avc:  denied  { read } for  pid=42 comm="cat" name="x" scontext=a:b:c_t:s0 tcontext=a:b:d_t:s0 tclass=file permissive=1''
      )
      (case "selinux-permissive-would-be" "parse_mac_selinux_wb"
        ''avc:  denied  { read write } for  pid=42 comm="cat" path="/x" scontext=a:b:c_t:s0 tcontext=a:b:d_t:s0 tclass=file permissive=1''
        ''
          assert_eq!(.parsed.severity, "low")
          assert_eq!(.parsed.message, "SELinux would deny read write on file /x — cat (c_t → d_t)")
        ''
      )
      (case "fapolicyd-denied" "parse_mac_fapolicyd"
        "rule=9 dec=deny_syslog perm=execute auid=1000 pid=42 exe=/run/current-system/sw/bin/bash : path=/tmp/evil ftype=application/x-executable trust=0"
        ''
          assert_eq!(.parsed.severity, "high")
          assert_eq!(.parsed.message, "fapolicyd denied execute /tmp/evil — /run/current-system/sw/bin/bash (rule 9)")
        ''
      )
      (case "usbguard-reject" "parse_mac_usbguard"
        ''decision=reject by=rule rule_id=1 mode=learn id=46f4:0001 name="QEMU USB HARDDRIVE" serial="1-0000:00:02.1:00.0-4" port="2-4" interfaces="08:06:50 "''
        ''
          assert_eq!(.parsed.severity, "medium")
          assert_eq!(.parsed.event_type, "usbguard_reject")
          assert_eq!(.parsed.message, "USBGuard rejected USB device QEMU USB HARDDRIVE (46f4:0001) on port 2-4")
        ''
      )
      (case "usbguard-learn-would-block" "parse_mac_usbguard"
        ''decision=allow by=default rule_id=4294967294 mode=learn id=0627:0001 name="QEMU USB Keyboard" serial="x" port="1-5" interfaces="03:01:01 "''
        ''
          assert_eq!(.parsed.severity, "low")
          assert_eq!(.parsed.event_type, "usbguard_would_block")
        ''
      )
      (none "usbguard-allowed-by-rule-dropped" "parse_mac_usbguard"
        ''decision=allow by=rule rule_id=8 mode=enforce id=0627:0001 name="QEMU USB Tablet" serial="x" port="1-1" interfaces="03:00:00 "''
      )
      (case "crowdsec-simulated" "parse_mac_crowdsec"
        ''time="2026-11-24T16:44:08+01:00" level=info msg="(owned/crowdsec) crowdsecurity/ssh-bf by ip 203.0.113.7 (/0) : (simulated alert)240m ban on Ip 203.0.113.7" module=db''
        ''
          assert_eq!(.parsed.severity, "medium")
          assert_eq!(.parsed.message, "CrowdSec: 203.0.113.7 (/0) triggered crowdsecurity/ssh-bf and would get a 240m ban (simulation)")
        ''
      )
      (case "crowdsec-ban" "parse_mac_crowdsec"
        ''time="2026-11-24T16:44:08+01:00" level=info msg="(owned/crowdsec) crowdsecurity/ssh-bf by ip 198.51.100.4 (FR/1234) : 4h ban on Ip 198.51.100.4" module=db''
        ''
          assert_eq!(.parsed.severity, "high")
          assert_eq!(.parsed.event_type, "crowdsec_decision")
          assert_eq!(.parsed.ip, "198.51.100.4")
        ''
      )
      (none "crowdsec-other-dropped" "parse_mac_crowdsec"
        ''time="2026-11-24T16:44:07+01:00" level=info msg="Ip 203.0.113.7 performed 'crowdsecurity/ssh-bf' (6 events over 283ms) at 2026"''
      )
      (none "fapolicyd-allow-dropped" "parse_mac_fapolicyd"
        "rule=1 dec=allow perm=open auid=0 pid=1 exe=/x : path=/y ftype=text/plain trust=1"
      )
      (none "fapolicyd-permissive-dropped" "parse_mac_fapolicyd_perm"
        "rule=9 dec=deny_syslog perm=execute auid=1000 pid=42 exe=/bin/sh : path=/tmp/x ftype=application/x-executable trust=0"
      )
    ];
  };
  file = writeText "minisoc-vector-test.json" (builtins.toJSON config);
in
runCommandLocal "minisoc-vector-test" { nativeBuildInputs = [ vectorBuildable ]; } ''
  export HOME=$TMPDIR
  vector validate --no-environment ${file}
  vector test ${file}
  touch $out
''
