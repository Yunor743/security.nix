# Enforcing mode with the minimal policy: the system boots and behaves
# normally, and a service placed in a confined domain is really blocked.
{
  name = "selinux-enforcing";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [
        ./ext4-nix.nix
      ];

      security.selinux = {
        enable = true;
        type = "minimal";
        mode = "enforcing";

        modules.demo.cil = ''
          (type demo_t)
          (call confined_domain (demo_t))
        '';
      };

      # Reads one file it is allowed to and one it is not, and reports.
      systemd.services.demo = {
        serviceConfig = {
          Type = "oneshot";
          SELinuxContext = "system_u:system_r:demo_t:s0";
        };
        script = ''
          echo "context=$(tr -d '\0' < /proc/self/attr/current)"
          if cat /etc/hostname > /dev/null; then
            echo "hostname=readable"
          fi
          if cat /var/lib/demo-secret > /dev/null 2>&1; then
            echo "secret=readable"
          else
            echo "secret=denied"
          fi
        '';
      };

      services.openssh.enable = true;

      environment.systemPackages = [ pkgs.attr ];
      virtualisation.memorySize = 2048;
    };

  testScript = ''
    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")

    with subtest("SELinux is enforcing"):
        assert machine.succeed("getenforce").strip() == "Enforcing"
        print(machine.succeed("sestatus"))

    with subtest("PID 1 runs in the init domain"):
        pid1 = machine.succeed("cat /proc/1/attr/current").strip("\x00\n ")
        assert pid1 == "system_u:system_r:init_t:s0", pid1

    with subtest("nothing failed during boot"):
        failed = machine.succeed("systemctl --failed --no-legend").strip()
        assert failed == "", failed

    with subtest("nothing was denied during boot"):
        denials = machine.succeed("journalctl -b -k --no-pager | grep 'avc:  denied' || true").strip()
        assert denials == "", denials

    with subtest("SSH login works"):
        machine.wait_for_unit("sshd.service")
        machine.succeed(
            "mkdir -p -m 700 /root/.ssh",
            "ssh-keygen -q -t ed25519 -N ''' -f /root/.ssh/id_ed25519",
            "cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys",
        )
        session = machine.succeed(
            "ssh -n -o StrictHostKeyChecking=no -o BatchMode=yes root@localhost id -Z"
        ).strip()
        assert session == "system_u:system_r:unconfined_t:s0", session

    with subtest("the Nix daemon builds a derivation"):
        machine.succeed(
            "nix-build --no-substitute -E '"
            "derivation { name = \"selinux-test\"; system = builtins.currentSystem;"
            " builder = \"/bin/sh\"; args = [ \"-c\" \"echo built > $out\" ]; }'"
            " -o /tmp/result"
        )
        assert machine.succeed("cat /tmp/result").strip() == "built"

    with subtest("a confined service is blocked from what its policy lacks"):
        machine.succeed("echo secret > /var/lib/demo-secret")
        # Unconfined processes can read it.
        machine.succeed("cat /var/lib/demo-secret")

        machine.succeed("systemctl start demo.service")
        output = machine.succeed("journalctl -b -u demo.service --no-pager -o cat")
        print(output)
        assert "context=system_u:system_r:demo_t:s0" in output, output
        assert "hostname=readable" in output, output
        assert "secret=denied" in output, output
        assert "secret=readable" not in output, output

        denials = machine.succeed(
            "journalctl -b -k --no-pager | grep 'avc:  denied' | grep demo_t"
        )
        print(denials)
        assert "permissive=0" in denials, denials

    with subtest("a store path imitating systemd gets no privileged label"):
        # Answers the forged-path objection: an unprivileged user adds a
        # store path laid out like systemd. Only the exact store path named
        # by the system configuration may carry the init entrypoint type.
        machine.succeed(
            "mkdir -p /tmp/forged/lib/systemd /tmp/nobody-home",
            "cp -L /run/current-system/systemd/lib/systemd/systemd /tmp/forged/lib/systemd/systemd",
            "chmod -R a+rX /tmp/forged && chown nobody /tmp/nobody-home",
        )
        forged = machine.succeed(
            "runuser -u nobody -- env HOME=/tmp/nobody-home nix-store --add /tmp/forged"
        ).strip()
        assert forged.startswith("/nix/store/"), forged
        real = machine.succeed(
            "stat -L -c %C /run/current-system/systemd/lib/systemd/systemd"
        ).strip()
        assert real == "system_u:object_r:init_exec_t:s0", real
        label = machine.succeed(f"stat -c %C {forged}/lib/systemd/systemd").strip()
        print(label)
        assert "init_exec_t" not in label, label

    with subtest("the system reboots cleanly into enforcing mode"):
        machine.reboot()
        machine.wait_for_unit("multi-user.target")
        assert machine.succeed("getenforce").strip() == "Enforcing"
        failed = machine.succeed("systemctl --failed --no-legend").strip()
        assert failed == "", failed
        # The labeller has now processed the imitating path with the
        # generic rules; it still must not carry the entrypoint type.
        label = machine.succeed(f"stat -c %C {forged}/lib/systemd/systemd").strip()
        assert label == "system_u:object_r:lib_t:s0", label
  '';
}
