{
  lib,
  stdenv,
  fetchurl,
}:

let
  version = "1.8.0";
  hashes = {
    x86_64-linux = "sha256-kWQEqZnBGT4HTAIzHhFWIQGC+5AYkHqUzMFJ3epYrTY=";
    aarch64-linux = "sha256-QDxi0FJ61y0HVDfvb3pYcDr9wK8oAmH7AvT3eOzM+GU=";
  };
  archMap = {
    x86_64-linux = "x86_64-unknown-linux-musl";
    aarch64-linux = "aarch64-unknown-linux-musl";
  };
in
stdenv.mkDerivation {
  pname = "rustinel";
  inherit version;

  src = fetchurl {
    url = "https://github.com/Karib0u/rustinel/releases/download/v${version}/rustinel-${version}-${
      archMap.${stdenv.hostPlatform.system} or (throw "Unsupported system: ${stdenv.hostPlatform.system}")
    }.tar.gz";
    hash =
      hashes.${stdenv.hostPlatform.system} or (throw "Unsupported system: ${stdenv.hostPlatform.system}");
  };

  sourceRoot = "rustinel-${version}-${archMap.${stdenv.hostPlatform.system}}";

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/etc/rustinel $out/share/rustinel/rules/{sigma,yara,ioc}

    install -Dm755 rustinel $out/bin/rustinel
    install -Dm644 config.toml $out/etc/rustinel/config.toml

    cp -r rules/sigma/* $out/share/rustinel/rules/sigma/
    cp -r rules/yara/* $out/share/rustinel/rules/yara/
    cp -r rules/ioc/* $out/share/rustinel/rules/ioc/

    runHook postInstall
  '';

  meta = {
    description = "Open-source endpoint detection engine using eBPF, Sigma, YARA, and IOC matching";
    homepage = "https://github.com/Karib0u/rustinel";
    license = lib.licenses.asl20;
    maintainers = with lib.maintainers; [ ];
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    mainProgram = "rustinel";
  };
}
