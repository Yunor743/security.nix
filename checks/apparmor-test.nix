# apparmor.d on NixOS: profiles load, attach to programs in the Nix store,
# enforce per-profile modes and local overrides, and survive a reload of
# apparmor.service (aa-remove-unknown).
{
  pkgs,
  self,
}:

pkgs.testers.runNixOSTest {
  name = "apparmor-d";

  nodes.machine = {
    imports = [ self.nixosModules.apparmor ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 4;

    security.apparmor-d = {
      enable = true;
      # Package passed explicitly: the test harness pkgs ignore overlays.
      package = pkgs.callPackage ../packages/apparmor-d { };
      mode = "complain";
      profiles = {
        lsblk = "enforce";
        top = "enforce";
        findmnt = "disable";
      };
      # Fictional restriction to observe an enforced denial.
      localOverrides.lsblk = ''
        audit deny @{sys}/** r,
      '';
    };
    environment.systemPackages = [ pkgs.procps ];
  };

  testScript = ''
    import json

    machine.wait_for_unit("apparmor.service")

    def status():
        return json.loads(machine.succeed("aa-status --json"))

    with subtest("apparmor.d profiles are loaded"):
        st = status()
        profiles = st["profiles"]
        print(f"{len(profiles)} profiles loaded")
        assert len(profiles) > 1000, len(profiles)
        assert profiles["lsblk"] == "enforce", profiles.get("lsblk")
        assert profiles["top"] == "enforce"
        assert profiles["free"] == "complain", "global mode"
        assert "findmnt" not in profiles, "disabled profile not loaded"

    with subtest("a profile attaches to a program in the Nix store"):
        exe = machine.succeed("readlink -f $(command -v top)").strip()
        assert exe.startswith("/nix/store/"), exe
        machine.succeed("top -b -d 60 -n 2 >/dev/null 2>&1 & echo $! > /tmp/top.pid")
        machine.wait_until_succeeds("test -s /tmp/top.pid && kill -0 $(cat /tmp/top.pid)")
        label = machine.succeed("cat /proc/$(cat /tmp/top.pid)/attr/apparmor/current").strip()
        print("top runs as:", label)
        assert label == "top (enforce)", label
        machine.succeed("kill $(cat /tmp/top.pid)")

    with subtest("enforce mode and local overrides apply"):
        # lsblk needs /sys, denied by the local override.
        machine.fail("lsblk 2>&1 | grep -q vda")
        machine.wait_until_succeeds("journalctl --grep 'apparmor=\"DENIED\".*profile=\"lsblk\"' >/dev/null")

    with subtest("reloading apparmor.service keeps apparmor.d loaded"):
        # Profiles the kernel creates at run time for complain-mode children
        # ("//null-...") are dropped by aa-remove-unknown, as intended.
        def static():
            return {p for p in status()["profiles"] if "//null-" not in p}
        before = static()
        machine.succeed("systemctl reload apparmor.service")
        after = static()
        print("removed by reload:", sorted(before - after), "added:", sorted(after - before))
        assert after == before

    with subtest("compiled policy cache is used and keyed by the profile tree"):
        machine.succeed("test -n \"$(ls -A /var/cache/apparmor-d/*/)\"")
        assert machine.succeed("ls /var/cache/apparmor-d | wc -l").strip() == "1"
  '';
}
