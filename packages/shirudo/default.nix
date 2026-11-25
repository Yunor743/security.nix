# shirudo, built against the BTF of the bpf-next kernel it targets
# (vmlinux.h for the BPF programs and the upatch build helper).
#
# `role = "operator"`: the shirudo CLI with the operator helpers (build,
# image generators, quote-check), BPF headers and vmlinux.h.
# `role = "target"`: the same CLI plus the target units and initrd tools;
# upstream links the target binary as a static PIE against its own static
# OpenSSL / curl / TPM2-TSS, here it is linked against the Nix store ones.
{
  lib,
  stdenv,
  callPackage,
  pkg-config,
  llvmPackages_23,
  openssl,
  curl,
  tpm2-tss,
  elfutils,
  zlib,
  zstd,
  luajit,
  which,
  python3,
  bash,
  kernel ? callPackage ./kernel.nix { },
  role ? "operator",
}:

let
  source = callPackage ./source.nix { };
  clang = llvmPackages_23.clang-unwrapped;
in
stdenv.mkDerivation {
  pname = "shirudo";
  inherit (source) version src;

  nativeBuildInputs = [
    pkg-config
    clang
    llvmPackages_23.llvm
    which
    python3
  ];
  buildInputs = [
    openssl
    curl
    tpm2-tss
    elfutils
    zlib
    zstd
    luajit
  ];

  postPatch = ''
    patchShebangs .
  '';

  makeFlags = [
    "prefix=${placeholder "out"}"
    "systemdunitdir=${placeholder "out"}/lib/systemd/system"
    "udevrulesdir=${placeholder "out"}/lib/udev/rules.d"
    "dracutmodulesdir=${placeholder "out"}/lib/dracut/modules.d"
    "BPF_VMLINUX_BTF=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build/vmlinux"
    "CLANG=clang"
  ]
  # The operator compiles upatches at run time (`shirudo build`): clang is a
  # runtime dependency there, not on a target.
  ++ lib.optionals (role == "operator") [
    "SHIRUDO_CLANG_PATH=${clang}/bin/clang"
  ];

  buildFlags = [ "all" ];
  enableParallelBuilding = true;

  installTargets = [ "install" ];

  postInstall = ''
    # Operator helpers, vmlinux.h and the BPF headers `shirudo build` compiles
    # against: upstream's install-operator, without the quote-check tool, which
    # upstream links against a static OpenSSL (a placeholder stands in).
    mkdir -p tools/quote-check
    touch tools/quote-check/shirudo-quote-check
    make -f Makefile.shirudo $makeFlags -o quote-check \
      bindir=$out/bin libexecdir=$out/libexec sharedir=$out/share \
      completionsdir=$out/share/bash-completion/completions install-operator
    rm $out/bin/shirudo-quote-check
    # A minimal upatch to check the operator chain (fentry on do_nanosleep).
    install -Dm644 testing/fixtures/basic.bpf.c $out/share/shirudo/examples/basic.bpf.c
  ''
  + lib.optionalString (role == "target") ''
    install -Dm755 tools/gen-initrd/shirudo-gen-initrd $out/bin/shirudo-gen-initrd
    # Units from their templates (@bindir@ -> the store).
    units="shirudo shirudo-initrd shirudo-map-export shirudo-keepalive shirudo-xdp-reconcile shirudo-bpm-repo-update shirudo-bpm-tree-sync"
    make -f Makefile.shirudo $makeFlags bindir=$out/bin $(for u in $units; do echo systemd/$u.service; done)
    install -d $out/lib/systemd/system
    for u in $units; do install -m644 systemd/$u.service $out/lib/systemd/system/; done
    install -m644 systemd/*.timer $out/lib/systemd/system/
  '';

  passthru = {
    inherit kernel role;
  };

  meta = {
    description = "BPF-based security platform: signed BPF loaders, signed upatches, TPM attestation";
    homepage = "https://github.com/shirudo-dev/shirudo";
    license = lib.licenses.bsd2;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    mainProgram = "shirudo";
  };
}
