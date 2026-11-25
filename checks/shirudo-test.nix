# security.shirudo: a target boots the bpf-next kernel with shirudo's
# patches (BPF LSM active, BTF, TPM 2.0 from swtpm) and shirudo reports its
# state there (init pending: the signed boot chain is not provisioned); an
# operator generates its ML-DSA-87 signing material on a stock kernel.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "shirudo";

  nodes = {
    target = {
      imports = [ self.nixosModules.shirudo ];
      security.shirudo = {
        enable = true;
        role = "target";
      };
      virtualisation.tpm.enable = true;
      virtualisation.memorySize = 2048;
    };
    operator = {
      imports = [ self.nixosModules.shirudo ];
      security.shirudo.enable = true;
      environment.systemPackages = [
        pkgs.util-linux
        pkgs.openssl
      ];
    };
  };

  testScript = ''
    import json
    import re
    # shirudo locks its memory (mlockall): root needs an unlimited memlock.
    run = "prlimit --memlock=unlimited:unlimited shirudo"

    start_all()

    with subtest("target: patched kernel, BPF LSM, BTF, TPM"):
        target.wait_for_unit("multi-user.target")
        release = target.succeed("uname -r").strip()
        print("kernel:", release)
        assert release == "7.4-shirudo", release
        lsm = target.succeed("cat /sys/kernel/security/lsm").strip()
        print("lsm:", lsm)
        assert "bpf" in lsm.split(","), lsm
        target.succeed("test -s /sys/kernel/btf/vmlinux")
        target.succeed("test -c /dev/tpmrm0")
        target.succeed("grep -q bpf.keyring_unsealed=1 /proc/cmdline")

    with subtest("target: shirudo reports the state of the host"):
        out = target.succeed(f"{run} version")
        print(out)
        report = json.loads(target.succeed(f"{run} status --json"))
        print(json.dumps(report, indent=1)[:1500])
        verdict = report["status"]
        conditions = {c["type"]: c["status"] for c in report["conditions"]}
        print("conditions:", conditions)
        assert {"LsmAttached", "KeyringSealed", "TpmMeasured"} <= set(conditions), conditions
        print("verdict:", verdict)
        # Not initialised: no signed boot chain on this test machine.
        assert verdict in ("init-pending", "lsm-off", "degraded"), verdict
        # The target units are installed, not enabled (enforce = false).
        target.succeed("systemctl cat shirudo.service >/dev/null")
        target.fail("systemctl is-enabled shirudo.service")

    with subtest("operator: ML-DSA-87 signing material"):
        operator.wait_for_unit("multi-user.target")
        keys = "/var/lib/shirudo/keys"
        operator.succeed(f"stat -c %a {keys} | grep -qx 700")
        operator.succeed(f"{run} genkey --keys-dir {keys}")
        operator.succeed(f"stat -c %a {keys}/signing_key.pem | grep -qx 600")
        operator.succeed(f"openssl x509 -inform der -in {keys}/cert.der -noout -subject | grep -q 'CN *= *shirudo'")
        operator.fail(f"{run} genkey --keys-dir {keys}")  # refuses to overwrite
        # The default keys directory: status recognises the operator.
        assert json.loads(operator.succeed(f"{run} status --json"))["is_operator"] is True

    with subtest("operator: compile and sign a upatch"):
        example = operator.succeed("readlink -f /run/current-system/sw/share/shirudo/examples/basic.bpf.c").strip()
        operator.succeed(f"{run} build {example} -o /tmp/basic.upatch")
        info = operator.succeed(f"{run} upatch info /tmp/basic.upatch")
        print(info)
        assert re.search(r"Payload type:\s+bpf", info), info
        assert re.search(r"Signature:\s+Offset:\s+\d+\s+Length:\s+[1-9]\d* bytes", info), info
  '';
}
