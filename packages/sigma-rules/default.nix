{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

stdenv.mkDerivation {
  pname = "sigma-rules";
  version = "2026-07-01";

  src = fetchurl {
    url = "https://github.com/SigmaHQ/sigma/releases/download/r2026-07-01/sigma_all_rules.zip";
    hash = "sha256-VyXJG1gTWHrWpLC44CM/pENIsVlfgY2Lf9OdYDM4UIU=";
  };

  sourceRoot = ".";

  nativeBuildInputs = [ unzip ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/sigma
    cp -r rules/. $out/share/sigma/
    runHook postInstall
  '';

  meta = {
    description = "SigmaHQ detection rules (complete set)";
    homepage = "https://github.com/SigmaHQ/sigma";
    license = lib.licenses.cc0;
    platforms = lib.platforms.all;
  };
}
