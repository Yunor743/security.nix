# End-to-end MiniSOC test with fictional alerts only: Vector collector ->
# per-user engine -> filters / lifecycle / AI guardrails -> Quickshell widget,
# plus the Home Manager module.
{
  pkgs,
  lib,
  self,
  home-manager,
}:

let
  # Mock LLM endpoint (`custom` provider): a busybox CGI that always answers
  # "benign, discard, 99%" — the guardrails must still protect critical,
  # medium (above maximumSeverity) and pinned alerts.
  mockLlm = pkgs.writeTextDir "cgi-bin/llm" ''
    #!/bin/sh
    cat > /dev/null
    printf 'Content-Type: application/json\r\n\r\n'
    printf '%s' '{"output": "{\"summary\": \"Benign test activity\", \"classification\": \"benign\", \"severity_assessment\": \"info\", \"confidence\": 0.99, \"benign_confidence\": 0.99, \"false_positive_likelihood\": \"high\", \"suggested_action\": \"discard\", \"facts\": [\"fictional test event\"]}"}'
  '';

  # Fictional Rustinel 1.8-style alerts (flat ECS keys).
  alert =
    {
      seq,
      sev,
      engine,
      rule,
      exe,
    }:
    builtins.toJSON {
      "@timestamp" = "2026-11-23T18:2${toString seq}:00.000000000Z";
      "event.sequence" = seq;
      "event.kind" = "alert";
      "event.action" = "process-start";
      "edr.rule.severity" = sev;
      "edr.rule.engine" = engine;
      "rule.name" = rule;
      "process.executable" = exe;
      "process.pid" = 4000 + seq;
      "user.name" = "alice";
    };
  alerts = pkgs.writeText "alerts.json" (
    lib.concatMapStrings (a: alert a + "\n") [
      {
        seq = 1;
        sev = "Low";
        engine = "Sigma";
        rule = "Example - Whoami Execution (Linux)";
        exe = "/run/current-system/sw/bin/whoami";
      }
      {
        seq = 2;
        sev = "Medium";
        engine = "Sigma";
        rule = "Execution Of Script Located In Potentially Suspicious Directory";
        exe = "/tmp/fictional.sh";
      }
      {
        seq = 3;
        sev = "Critical";
        engine = "Yara";
        rule = "FICTIONAL_Test_Marker";
        exe = "/tmp/fictional.bin";
      }
      {
        seq = 4;
        sev = "Low";
        engine = "Sigma";
        rule = "Fictional Admin Tool Usage";
        exe = "/run/current-system/sw/bin/ss";
      }
    ]
  );

  aaProbe = pkgs.runCommandLocal "aa-probe" { } ''
    install -D ${pkgs.gnugrep}/bin/grep $out/bin/aa-probe
  '';
  minisocPkg = pkgs.callPackage ../packages/minisoc { };
  minisocUi = pkgs.callPackage ../packages/minisoc-ui { minisoc = minisocPkg; };

  swayConfig = pkgs.writeText "sway-test.conf" ''
    output HEADLESS-1 resolution 1920x1080
    exec systemctl --user import-environment WAYLAND_DISPLAY
  '';
in
pkgs.testers.runNixOSTest {
  name = "minisoc";

  nodes.machine =
    { config, ... }:
    {
      imports = [
        self.nixosModules.security
        home-manager.nixosModules.home-manager
      ];
      # Packages are passed explicitly: the test harness pkgs ignore overlays.

      virtualisation.memorySize = 3072;

      # A real AppArmor denial for the security module integration: a probe
      # program (a copy of grep) confined to the store, reading a root file.
      security.apparmor.enable = true;
      security.apparmor.policies.minisoc-probe.profile = ''
        include <tunables/global>
        profile minisoc-probe ${aaProbe}/bin/aa-probe {
          include <abstractions/base>
          /nix/store/** mr,
        }
      '';
      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        linger = true;
      };

      services.minisoc = {
        enable = true;
        package = minisocPkg;
        users = [ "alice" ];
        integrations.rustinel.enable = true;
        # Home Manager seeds the user rules in this test.
        filter.seedUserFile = false;
        filter.systemRules = [
          {
            id = "system_ignore_whoami_demo";
            description = "Rustinel demo rule";
            match = {
              source = "rustinel";
              message.contains = "Whoami Execution";
            };
            action = "exclude";
          }
        ];
        ai = {
          enable = true;
          provider = "custom";
          endpoint = "http://127.0.0.1:8080/cgi-bin/llm";
          model = "mock";
          analysis = {
            minimumSeverity = "low";
            autoDiscard = true;
            autoDiscardPolicy = {
              mode = "automatic";
              requireRepeatedBenignPattern = false;
            };
          };
          limits.requestsPerMinute = 600;
        };
      };

      systemd.services.mock-llm = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.busybox}/bin/httpd -f -p 127.0.0.1:8080 -h ${
            pkgs.runCommand "mock-llm-root" { } ''
              mkdir -p $out/cgi-bin
              install -m755 ${mockLlm}/cgi-bin/llm $out/cgi-bin/llm
            ''
          }";
          DynamicUser = true;
        };
      };

      home-manager.useGlobalPkgs = true;
      home-manager.users.alice = {
        imports = [ self.homeManagerModules.minisoc ];
        home.stateVersion = "25.05";
        programs.minisoc = {
          enable = true;
          package = minisocUi;
          cliPackage = minisocPkg;
          ui.autostart = false;
          ui.profile = "desktop";
          filter.initialRules = [
            {
              id = "user_initial_rule";
              match = {
                source = "nonexistent";
                event_type = "never";
              };
            }
          ];
        };
      };

      programs.sway.enable = true;
      environment.systemPackages = [
        pkgs.grim
        aaProbe
        pkgs.jq
      ];
      fonts.packages = [ pkgs.dejavu_fonts ];
    };

  testScript = ''
    import json, time

    def sh(cmd):
        return machine.succeed(cmd)

    def ctl(args):
        return sh(f"su - alice -c 'minisoc {args}'")

    def events(state="all"):
        return json.loads(ctl(f"list --state {state} --limit 100 --json"))

    def find(substr, state="all"):
        for e in events(state):
            if substr in e["message"]:
                return e
        return None

    def wait_for(pred, what, timeout=90):
        for _ in range(timeout):
            v = pred()
            if v:
                return v
            time.sleep(1)
        raise Exception(f"timeout waiting for {what}")

    def user_systemctl(args):
        return sh(f"su - alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user {args}'")

    machine.wait_for_unit("minisoc-collector.service")
    machine.wait_for_unit("mock-llm.service")
    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("minisoc-engine.service", "alice")

    with subtest("collector is confined: read-only capability, no network"):
        props = sh("systemctl show minisoc-collector -p User -p CapabilityBoundingSet -p PrivateNetwork -p ProtectSystem")
        assert "User=minisoc-collector" in props, props
        assert "CapabilityBoundingSet=cap_dac_read_search" in props, props
        assert "PrivateNetwork=yes" in props, props

    with subtest("security module denial becomes an alert (AppArmor)"):
        sh("echo secret > /root/minisoc-probe-secret")
        machine.fail("aa-probe secret /root/minisoc-probe-secret")
        aa = wait_for(lambda: find("AppArmor denied"), "AppArmor denial alert")
        assert aa["source"] == "apparmor" and aa["severity"] == "medium", aa
        assert "/root/minisoc-probe-secret" in aa["message"] and "minisoc-probe" in aa["message"], aa

    with subtest("Home Manager seeded the user rules 0600 in a 0700 dir"):
        assert sh("stat -c '%a %U' /home/alice/.config/minisoc/alert_filter.yaml").strip() == "600 alice"
        assert sh("stat -c '%a' /home/alice/.config/minisoc").strip() == "700"
        sh("grep -q user_initial_rule /home/alice/.config/minisoc/alert_filter.yaml")
        assert json.loads(sh("cat /home/alice/.config/minisoc/ui.json"))["profile"] == "desktop"

    with subtest("root-only log created after start is collected (0600 file in 0700 dir)"):
        sh("install -d -m 0700 /var/log/rustinel")
        sh("install -m 0600 ${alerts} /var/log/rustinel/alerts.json.2026-11-23")
        wait_for(lambda: len(events()) >= 5, "4 Rustinel events + the AppArmor one in the store")
        spool = sh("stat -c '%a %G' /var/lib/minisoc-collector/spool/*.ndjson").split()
        assert spool[0] in ("640", "600") and spool[1] == "minisoc", spool

    with subtest("normalization and system filter"):
        whoami = find("Whoami Execution")
        assert whoami["filtered_by"] == "system_ignore_whoami_demo", whoami
        crit = find("FICTIONAL_Test_Marker")
        assert crit["severity"] == "critical" and crit["event_type"] == "yara_match", crit
        assert find("Suspicious Directory")["severity"] == "medium"
        out = ctl(f"explain {whoami['id']}")
        assert "EXCLUDED by rule 'system_ignore_whoami_demo'" in out, out

    with subtest("AI analysis + auto-discard guardrails"):
        wait_for(lambda: all(e["analyzed"] for e in events() if not e["filtered_by"]), "AI analyses")
        low = find("Fictional Admin Tool Usage")
        assert low["discarded"] and low["discarded_by"] == "ai", low
        crit = find("FICTIONAL_Test_Marker")
        assert not crit["discarded"], "critical must never be auto-discarded"
        med = find("Suspicious Directory")
        assert not med["discarded"], "medium is above maximumSeverity=low"
        assert not find("Whoami Execution")["analyzed"], "filtered events are not sent to the AI"
        hist = json.loads(ctl(f"show {low['id']} --json"))["history"]
        assert any(h["actor"] == "ai" and h["action"] == "discard" for h in hist), hist

    with subtest("restore, pin persistence across engine restart, discard"):
        low = find("Fictional Admin Tool Usage")
        ctl(f"restore {low['id']}")
        assert not find("Fictional Admin Tool Usage")["discarded"]
        med = find("Suspicious Directory")
        ctl(f"pin {med['id']}")
        user_systemctl("restart minisoc-engine")
        machine.wait_for_unit("minisoc-engine.service", "alice")
        assert any(e["id"] == med["id"] for e in events("pinned")), "pin survives a restart"
        ctl(f"discard {low['id']} --reason seen")
        assert any(e["id"] == low["id"] for e in events("discarded"))
        sh("test -e /var/log/rustinel/alerts.json.2026-11-23")  # logs untouched
        assert sh("wc -l < /var/log/rustinel/alerts.json.2026-11-23").strip() == "4"

    with subtest("create filter from an alert: hot reload, backup, pinned stays visible"):
        crit = find("FICTIONAL_Test_Marker")
        ctl(f"filter create {crit['id']} --rule-id hide_fictional_marker")
        wait_for(lambda: find("FICTIONAL_Test_Marker")["filtered_by"] == "hide_fictional_marker", "hot reload")
        assert sh("stat -c '%a' /home/alice/.config/minisoc/alert_filter.yaml").strip() == "600"
        sh("ls /home/alice/.local/state/minisoc/filter-backups/alert_filter.*.yaml")
        sh("grep -q user_initial_rule /home/alice/.config/minisoc/alert_filter.yaml")  # existing rule kept
        med = find("Suspicious Directory")
        ctl(f"filter create {med['id']} --rule-id hide_pinned")
        time.sleep(3)
        assert find("Suspicious Directory")["filtered_by"] is None, "pinned alert never hidden"

    with subtest("an invalid rules file cannot neutralize filtering"):
        sh("su - alice -c 'echo \"version: 1\nfilters: [ {id: broken, match: {} } ]\" > ~/.config/minisoc/alert_filter.yaml'")
        time.sleep(3)
        assert find("FICTIONAL_Test_Marker")["filtered_by"] == "hide_fictional_marker", "last valid version in force"
        assert find("Whoami Execution")["filtered_by"] == "system_ignore_whoami_demo"
        st = json.loads(ctl("status --json"))
        assert st["filter"]["ok"] is False, st["filter"]
        ctl("filter rollback")
        wait_for(lambda: json.loads(ctl("status --json"))["filter"]["ok"], "rollback restores a valid file")

    with subtest("Home Manager never overwrites the user rules file"):
        before = sh("sha256sum /home/alice/.config/minisoc/alert_filter.yaml")
        sh("systemctl restart home-manager-alice.service")
        assert sh("sha256sum /home/alice/.config/minisoc/alert_filter.yaml") == before

    with subtest("state file and engine run unprivileged"):
        assert sh("stat -c '%a %U' /run/user/1000/minisoc/state.json").strip() == "600 alice"
        assert sh("stat -c '%a' /home/alice/.local/state/minisoc").strip() == "700"
        owners = set(sh("ps -o user= -C minisoc").split())
        assert owners == {"alice"}, owners

    with subtest("works without the collector (direct ingest)"):
        sh("systemctl stop minisoc-collector")
        sh("su - alice -c 'echo \"{\\\"severity\\\":\\\"high\\\",\\\"message\\\":\\\"fictional manual event\\\"}\" | minisoc ingest --source manual'")
        wait_for(lambda: find("fictional manual event"), "ingested event")
        assert find("fictional manual event")["severity"] == "high"

    with subtest("Quickshell widget: renders, details view expands the window"):
        sh("su - alice -c 'XDG_RUNTIME_DIR=/run/user/1000 WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1 sway -c ${swayConfig} >/tmp/sway.log 2>&1 &'")
        machine.wait_until_succeeds("test -S /run/user/1000/wayland-1")
        env = "XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-1 QT_QPA_PLATFORM=wayland QT_QUICK_BACKEND=software"
        sh(f"su - alice -c '{env} minisoc-ui >/tmp/ui.log 2>&1 &'")
        ipc = lambda c: sh(f"su - alice -c '{env} minisoc-ui-ipc call minisoc {c}'").strip()
        machine.wait_until_succeeds(f"su - alice -c '{env} minisoc-ui-ipc call minisoc activeCount' | grep -qv '^0$'", timeout=60)
        base = int(ipc("windowWidth"))
        assert ipc("pinnedCount") == "1"
        med = find("Suspicious Directory")
        ipc(f"details {med['id']}")
        machine.wait_until_succeeds(f"su - alice -c '{env} minisoc-ui-ipc call minisoc detailsLoaded' | grep -q true", timeout=30)
        time.sleep(1)
        assert ipc("expanded") == "true"
        wide = int(ipc("windowWidth"))
        assert wide > base, (base, wide)
        sh(f"su - alice -c '{env} grim /tmp/minisoc-details.png'")
        machine.copy_from_vm("/tmp/minisoc-details.png", "")
        ipc("close")
        time.sleep(1)
        assert int(ipc("windowWidth")) == base
        sh(f"su - alice -c '{env} grim /tmp/minisoc-minimal.png'")
        machine.copy_from_vm("/tmp/minisoc-minimal.png", "")

    with subtest("discard from the widget hides the alert at once and closes its details"):
        manual = find("fictional manual event")
        before = int(ipc("shownCount"))
        ipc(f"details {manual['id']}")
        ipc(f"discard {manual['id']}")
        assert int(ipc("shownCount")) == before - 1, "hidden immediately"
        assert ipc("expanded") == "false", "details closed"
        wait_for(lambda: find("fictional manual event")["discarded"], "engine records the discard")
        time.sleep(2)
        assert int(ipc("shownCount")) == before - 1, "still hidden after the engine republished"

    with subtest("discard all: every active alert hidden, pinned kept, restorable"):
        sh("su - alice -c 'echo \"{\\\"severity\\\":\\\"medium\\\",\\\"message\\\":\\\"fictional bulk event\\\"}\" | minisoc ingest --source manual'")
        wait_for(lambda: find("fictional bulk event"), "bulk event")
        time.sleep(2)
        ipc("discardAll")
        assert ipc("shownCount") == ipc("pinnedCount") == "1", "only the pinned alert remains"
        wait_for(lambda: not events("active"), "engine discarded every active alert")
        assert len(events("pinned")) == 1
        bulk = find("fictional bulk event")
        assert bulk["discarded"] and bulk["discarded_by"] == "user", bulk
        ctl(f"restore {bulk['id']}")
        assert not find("fictional bulk event")["discarded"]
        ipc("toggleManage")
        time.sleep(1)
        sh(f"su - alice -c '{env} grim /tmp/minisoc-compact.png'")
        machine.copy_from_vm("/tmp/minisoc-compact.png", "")
        log = sh("cat /tmp/ui.log")
        assert "ReferenceError" not in log and "TypeError" not in log, log
  '';
}
