{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

stdenv.mkDerivation {
  pname = "yara-forge-rules";
  version = "2026-03-29";

  src = fetchurl {
    url = "https://github.com/YARAHQ/yara-forge/releases/download/20260329/yara-forge-rules-full.zip";
    hash = "sha256-z7NMbv8B5YkSAg10iGiS1MNqtayVkJrtzD/SVQRZrNc=";
  };

  nativeBuildInputs = [ unzip ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/yara-forge
    cp -r . $out/share/yara-forge/
    runHook postInstall
  '';

  meta = {
    description = "Curated YARA rules from YARA Forge (full set)";
    homepage = "https://github.com/YARAHQ/yara-forge";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.all;
  };
}
