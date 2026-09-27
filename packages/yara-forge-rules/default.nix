{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

stdenv.mkDerivation {
  pname = "yara-forge-rules";
  version = "2026-09-20";

  src = fetchurl {
    url = "https://github.com/YARAHQ/yara-forge/releases/download/20260920/yara-forge-rules-full.zip";
    hash = "sha256-JGcxElKKqT4T1TdTEnMswhE79O/bjNhfM6rq662jWVE=";
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
