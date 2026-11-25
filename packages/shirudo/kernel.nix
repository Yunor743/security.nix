# The kernel shirudo targets: bpf-next at the commit shirudo pins
# (testing/kernel/bpf-next.commit), with shirudo's carried patches
# (testing/kernel/patches: signed-loader ABI users, tpm_command LSM hook,
# sleepable inode hooks...), on top of the regular NixOS kernel
# configuration plus the options shirudo requires (BPF LSM, BTF, fmod_ret
# scan, ML-DSA signature verification, built-in TPM, signed dm-verity).
#
# A development base (bpf-next 7.4-rc): for shirudo targets and tests, not
# a general-purpose kernel.
{
  lib,
  buildLinux,
  fetchzip,
  callPackage,
  llvmPackages_22,
  libxml2,
  zlib,
  zstd,
  ncurses,
  ...
}@args:

let
  shirudo = callPackage ./source.nix { };
  commit = "2bf3351c5f894697e8443eeef5333d4c4ce90cab";
  patchNames = [
    "0001-cgroup-security-add-task_cgroup_attach-LSM-hook.patch"
    "0002-kbuild-drop-a-.0-sublevel-and-the-rc-suffix-from-the.patch"
    "0020-tpm-Let-LSMs-inspect-userspace-commands.patch"
    "0021-bpf-Read-security.bpf-xattrs-for-LSM-programs-without-the-callers-permission.patch"
    "0022-bpf-Let-sleepable-LSM-programs-attach-to-the-remaining-inode-hooks.patch"
    "0023-bpf-Treat-dentry-d_parent-as-a-trusted-pointer.patch"
    "0024-mm-Let-LSMs-check-read-only-remote-mm-access-under-CAP_PERFMON.patch"
  ];

  kernel =
    (buildLinux (
      removeAttrs args [
        "fetchzip"
        "callPackage"
        "llvmPackages_22"
        "libxml2"
        "zlib"
        "zstd"
        "ncurses"
      ]
      // {
        # Release 7.4 (0002 drops the .0 sublevel and the -rc suffix).
        version = "7.4.0-rc3-shirudo";
        modDirVersion = "7.4-shirudo";
        src = fetchzip {
          name = "bpf-next-${commit}";
          url = "https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/snapshot/bpf-next-${commit}.tar.gz";
          hash = "sha256-ZEMUjJmYDz4ukNBpg4/I/l6GAMa/I/fooWu713aAmDo=";
        };
        kernelPatches = map (name: {
          inherit name;
          patch = "${shirudo.src}/testing/kernel/patches/${name}";
        }) patchNames;

        structuredExtraConfig = with lib.kernel; {
          LOCALVERSION = freeform "-shirudo";
          # BPF LSM and the attach mechanisms of signed upatches.
          BPF_SYSCALL = yes;
          BPF_JIT = yes;
          BPF_LSM = yes;
          BPF_EVENTS = yes;
          BPF_FMODRET_SCAN = yes;
          FTRACE = yes;
          FUNCTION_TRACER = yes;
          DYNAMIC_FTRACE = yes;
          DYNAMIC_FTRACE_WITH_DIRECT_CALLS = yes;
          FPROBE = yes;
          DEBUG_INFO_BTF = yes;
          SECURITY = yes;
          SECURITYFS = yes;
          # Signature verification of loaders and dm-verity root hashes.
          KEYS = yes;
          ASYMMETRIC_KEY_TYPE = yes;
          ASYMMETRIC_PUBLIC_KEY_SUBTYPE = yes;
          X509_CERTIFICATE_PARSER = yes;
          PKCS7_MESSAGE_PARSER = yes;
          SYSTEM_DATA_VERIFICATION = yes;
          CRYPTO_MLDSA = yes;
          CRYPTO_SHA256 = yes;
          CRYPTO_SHA512 = yes;
          # TPM built in (measured state, tpm_command hook).
          TCG_TPM = yes;
          TCG_TIS_CORE = yes;
          TCG_TIS = yes;
          TCG_CRB = yes;
          # dm-verity (a module in NixOS' configuration) checks the root
          # hash signature of the runtime and config images.
          DM_VERITY_VERIFY_ROOTHASH_SIG = yes;
          TMPFS_XATTR = yes;
        };
        # NixOS' common configuration names options of released kernels;
        # a few do not exist (or moved) on this development base.
        ignoreConfigErrors = true;
        # BPF_FMODRET_SCAN: Kconfig and resolve_btfids look for LLVM (headers,
        # MC libraries) through llvm-config, at configuration and build time.
        extraMakeFlags = [ "LLVM_CONFIG=${llvmPackages_22.llvm.dev}/bin/llvm-config" ];
        extraMeta = {
          branch = "bpf-next";
          description = "bpf-next with shirudo's patches (signed-loader ABI targets)";
        };
      }
    )).overrideAttrs
      (old: {
        # BPF_FMODRET_SCAN: resolve_btfids reads the machine code with LLVM.
        nativeBuildInputs = old.nativeBuildInputs ++ [ llvmPackages_22.llvm.dev ];
        # LLVM's system libraries, for that host tool.
        depsBuildBuild = (old.depsBuildBuild or [ ]) ++ [
          libxml2
          zlib
          zstd
          ncurses
        ];
        passthru = old.passthru // {
          inherit commit;
        };
      });
in
kernel
