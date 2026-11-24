{
  lib,
  stdenv,
  fetchurl,
  libsepol,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "secilc";
  inherit (libsepol) version;

  src = fetchurl {
    url = "https://github.com/SELinuxProject/selinux/releases/download/${finalAttrs.version}/secilc-${finalAttrs.version}.tar.gz";
    # The version follows libsepol, which differs between NixOS releases.
    hash =
      {
        "3.10" = "sha256-ZlgHHW8QRBhNOXMGKnmBh1N64cPdtMMa/UF98zMxbBA=";
        "3.11" = "sha256-H7feAF01rgrG/4+PyVXQihW1waZ+lhuX75h1dq8NsRo=";
      }
      .${finalAttrs.version} or (throw "secilc: no source hash for version ${finalAttrs.version}");
  };

  buildInputs = [ libsepol ];

  # The default target also builds man pages, which needs xmlto and DocBook.
  buildFlags = [
    "secilc"
    "secil2conf"
    "secil2tree"
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 -t $out/bin secilc secil2conf secil2tree
    install -Dm644 -t $out/share/doc/secilc docs/*.md
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    $out/bin/secilc -o policy.test -f file_contexts.test test/minimum.cil
    test -s policy.test
    runHook postInstallCheck
  '';

  meta = {
    description = "SELinux Common Intermediate Language (CIL) compiler";
    homepage = "https://github.com/SELinuxProject/selinux/tree/main/secilc";
    license = lib.licenses.bsd2;
    platforms = lib.platforms.linux;
    mainProgram = "secilc";
  };
})
