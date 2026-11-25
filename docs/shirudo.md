# shirudo

[shirudo](https://github.com/shirudo-dev/shirudo) is a BPF-based security
platform, in **pre-release**: after boot, a target only accepts BPF programs
from signed loaders; operators ship signed micropatches ("upatches": BPF
programs that observe or shield the kernel and user space, e.g. block a
vulnerable code path until the kernel is updated) and verify the
TPM-measured state of their targets.

`security.shirudo` packages it for NixOS and prepares both roles. It cannot
yet enforce on NixOS: shirudo's boot chain (a dracut initrd module, signed
dm-verity runtime and config images) is not ported to the NixOS initrd.

```nix
{
  imports = [ security-nix.nixosModules.shirudo ];   # or .security

  # A workstation that signs and publishes upatches:
  security.shirudo = {
    enable = true;
    role = "operator";
  };

  # A machine that will verify and enforce (kernel, TPM, units):
  # security.shirudo = { enable = true; role = "target"; };
}
```

## What is packaged

| Package | |
|---|---|
| `shirudo-kernel` | bpf-next at the commit shirudo pins, with its 7 carried patches (task cgroup attach and `tpm_command` LSM hooks, `security.bpf` xattrs, sleepable inode hooks, trusted `d_parent`, read-only remote mm access, release naming), on **NixOS' regular kernel configuration** plus what shirudo needs: BPF LSM, BTF, `BPF_FMODRET_SCAN` (built with LLVM), ML-DSA / X.509 / PKCS#7 signature verification, TPM built in, signed dm-verity root hashes. Release `7.4-shirudo`. |
| `shirudo` | The CLI (built against that kernel's BTF), the operator helpers (`libexec/shirudo/shirudo-build` with clang 23, image generators, the BPF headers and `vmlinux.h` under `share/shirudo`, an example upatch); with `role = "target"` the target units and `shirudo-gen-initrd`. Upstream links the target binary as a static PIE against its own static OpenSSL/curl/TPM2-TSS; here it links the Nix store libraries. |

## Roles

**operator** (stock kernel): `shirudo genkey`, `build`, `image`, `attest`.
`keysDir` (`/var/lib/shirudo/keys`, shirudo's default, 0700, `SHIRUDO_KEYS_DIR`) holds
the ML-DSA-87 signing key: back it up, persist it on an ephemeral root.
`shirudo status` on an operator lists the roles `target, operator`: the
certificate `genkey` writes, `/var/lib/shirudo/keys/cert.der`, is also the
path where a target keeps its certificate (upstream behaviour); `Status:
lsm-off` is expected there.

**target**:

- boots `shirudo-kernel` (`kernel.enable`), adds the BPF LSM to the active
  LSMs and `bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1` to the
  command line;
- enables the TPM 2.0 stack (`security.tpm2`);
- installs the units (`shirudo.service` runs `shirudo init`, map export,
  keepalive, bpm repository sync, XDP reconcile) **without enabling them**:
  `enforce = true` enables them once the operator has provisioned the signed
  images under `/var/lib/shirudo/images`;
- refuses `enforce` while unsigned BPF loaders run on the host
  (`services.rustinel`, `services.jit-hater`): they would be denied. A
  warning says so before.

`shirudo` locks its memory (`mlockall`): root gets an unlimited memlock
limit; from a shell, `prlimit --memlock=unlimited:unlimited shirudo …`.

## Options

| Option | Default | |
|---|---|---|
| `enable` | `false` | |
| `role` | `"operator"` | `operator` / `target` |
| `package` | built for `role` | |
| `kernel.enable` | `role == "target"` | boot the bpf-next kernel |
| `kernel.package` | `shirudo-kernel` | |
| `keysDir` | `/var/lib/shirudo/keys` | operator signing material |
| `settings` | `{}` | `/etc/shirudo/shirudo.conf` (`key = value`) |
| `enforce` | `false` | enable the target units (needs the signed images) |

## Tested

- VM test `shirudo`: a target boots `7.4-shirudo` with the BPF LSM active,
  BTF, a TPM 2.0 (swtpm) and the keyring parameters; `shirudo status` runs
  and reports the host as not initialised (no signed boot chain); the units
  are installed and not enabled. An operator generates its ML-DSA-87 key and
  self-signed certificate (`genkey` refuses to overwrite them, `status`
  recognises the operator), then compiles and signs the shipped example
  upatch (`share/shirudo/examples/basic.bpf.c`) with `shirudo build`.
- `owned` (Hyprland desktop, AppArmor enforce, fapolicyd enforcing, Rustinel):
  operator role, key generated under the persisted `/var/lib/shirudo`, the
  example upatch built and signed without any AppArmor or fapolicyd denial,
  every other security service still active.

## Not done yet

- The boot chain: shirudo's dracut module (`90shirudo`) measures and mounts
  the signed runtime image in the initrd; NixOS uses its own systemd initrd.
  Porting it is what enforcement on NixOS needs.
- Upstream's hardened static target binary (static OpenSSL 3.5+, curl,
  TPM2-TSS built from source by its Makefile, which a Nix build cannot
  download).
