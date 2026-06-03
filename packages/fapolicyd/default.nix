{
  lib,
  stdenv,
  fetchFromGitHub,
  autoreconfHook,
  pkg-config,
  file,
  openssl,
  libcap_ng,
  libseccomp,
  lmdb,
  uthash,
  systemd,
  audit,
  linuxHeaders,
  withAudit ? true,
}:

let
  ldSoPath = stdenv.cc.bintools.dynamicLinker;
in

stdenv.mkDerivation (finalAttrs: {
  pname = "fapolicyd";
  version = "1.5";

  src = fetchFromGitHub {
    owner = "linux-application-whitelisting";
    repo = "fapolicyd";
    rev = "v${finalAttrs.version}";
    hash = "sha256-pEiSt7BD/jyRrKBQlHZtNwKrZsiUeJq+Bl4Wamc5nOg=";
  };

  patches = [
    ./patches/nixos-symlinks.patch
    ./patches/dyn-linker.patch
  ];

  postPatch =
    let
      esc = lib.escapeShellArg;
    in
    ''
      substituteInPlace src/library/paths.h \
        --replace-fail '/usr/share/fapolicyd/fapolicyd-magic.mgc' ${esc "${placeholder "out"}/share/fapolicyd/fapolicyd-magic.mgc"}

      substituteInPlace init/fagenrules \
        --replace-fail 'fapolicyd-cli --check-rules' ${esc "${placeholder "out"}/bin/fapolicyd-cli --check-rules"}

      substituteInPlace init/fapolicyd.service \
        --replace-fail '/usr/sbin/fagenrules' ${esc "${placeholder "out"}/bin/fagenrules"} \
        --replace-fail '/usr/sbin/fapolicyd' ${esc "${placeholder "out"}/bin/fapolicyd"}

      substituteInPlace m4/dyn_linker.m4 \
        --replace-fail '@LD_SO_PATH@' ${esc ldSoPath}

      sed -i src/Makefile.am -e 's/[[:space:]]-static$/ /'
    '';

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    file
  ];

  buildInputs = [
    openssl
    libcap_ng
    libseccomp
    lmdb
    uthash
    systemd
    linuxHeaders
  ]
  ++ lib.optional withAudit audit;

  configureFlags = [
    "--without-rpm"
    "--without-deb"
    "--disable-shared"
  ]
  ++ lib.optional withAudit "--with-audit";

  makeFlags = [
    "sbindir=$(out)/bin"
  ];

  postInstall = ''
    mkdir -p $out/share/fapolicyd/sample-rules
    cp -v rules.d/*.rules $out/share/fapolicyd/sample-rules/
  '';

  enableParallelBuilding = true;

  doCheck = true;

  meta = {
    description = "File access policy daemon for application whitelisting on Linux";
    homepage = "https://github.com/linux-application-whitelisting/fapolicyd";
    license = lib.licenses.gpl3Plus;
    maintainers = with lib.maintainers; [ ];
    platforms = lib.platforms.linux;
    mainProgram = "fapolicyd";
  };
})
