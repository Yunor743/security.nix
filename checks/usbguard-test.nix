# security.usbguard: devices present at first start are learned, a new
# keyboard is blocked in enforce mode, mass storage is rejected whatever
# the mode, `usbguard allow-device -p` survives a daemon restart and the
# NixOS-managed block of the rules file is not duplicated; every decision is
# a journal line (usbguard-events).
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "usbguard";

  nodes.machine = {
    imports = [ self.nixosModules.usbguard ];
    security.usbguard = {
      enable = true;
      mode = "enforce";
      rejectInterfaces = [ "08:*:*" ];
    };
    virtualisation.qemu.options = [
      "-device qemu-xhci,id=xhci"
      "-device usb-tablet,bus=xhci.0"
    ];
  };

  testScript = ''
    import os, subprocess
    machine.wait_for_unit("usbguard.service")
    machine.wait_for_unit("usbguard-events.service")

    def devices():
        return machine.succeed("usbguard list-devices")

    with subtest("devices present at first start are learned"):
        rules = machine.succeed("cat /var/lib/usbguard/rules.conf")
        print(rules)
        assert "Devices present at first start" in rules
        assert "QEMU USB Tablet" in rules
        assert "allow" in devices().split("QEMU USB Tablet")[0].splitlines()[-1]

    with subtest("a new keyboard is blocked (enforce)"):
        machine.send_monitor_command("device_add usb-kbd,bus=xhci.0,id=kbd1")
        machine.wait_until_succeeds("usbguard list-devices --blocked | grep -q 'QEMU USB Keyboard'")
        machine.wait_until_succeeds(
            "journalctl -u usbguard-events -o cat | grep 'decision=block by=default' | grep -q 'QEMU USB Keyboard'"
        )

    with subtest("mass storage is rejected by the managed rule"):
        img = os.path.join(os.environ.get("TMPDIR", "/tmp"), "stick.img")
        subprocess.run(["truncate", "-s", "8M", img], check=True)
        machine.send_monitor_command(f"drive_add 0 if=none,id=stick,file={img},format=raw")
        machine.send_monitor_command("device_add usb-storage,bus=xhci.0,drive=stick,id=stick1")
        machine.wait_until_succeeds(
            "journalctl -u usbguard-events -o cat | grep 'decision=reject by=rule' | grep -q 'HARDDRIVE'"
        )
        machine.fail("lsblk -o TRAN | grep -q usb")

    with subtest("allow-device -p persists across a restart, managed block kept once"):
        dev = devices().split("QEMU USB Keyboard")[0].splitlines()[-1].split(":")[0]
        machine.succeed(f"usbguard allow-device -p {dev}")
        machine.succeed("systemctl restart usbguard.service")
        machine.wait_for_unit("usbguard.service")
        machine.wait_until_succeeds("usbguard list-devices --blocked | grep -vq 'QEMU USB Keyboard' || true")
        line = [l for l in devices().splitlines() if "QEMU USB Keyboard" in l][0]
        assert ": allow " in line, line
        assert machine.succeed("grep -c 'managed by NixOS' /var/lib/usbguard/rules.conf").strip() == "1"
  '';
}
