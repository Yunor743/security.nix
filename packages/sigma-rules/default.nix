{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

stdenv.mkDerivation {
  pname = "sigma-rules";
  version = "2026-04-01";

  src = fetchurl {
    url = "https://github.com/SigmaHQ/sigma/releases/download/r2026-04-01/sigma_all_rules.zip";
    hash = "sha256-10iEIEd9ZULvu6IrkBu7c7arjpXOQR35LZXCfcXXN8I=";
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