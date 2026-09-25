{
  lib,
  stdenv,
  fetchurl,
  patchelf,
  ...
}:

let
  version = "9.5.4";
  hashes = {
    x86_64-linux = "sha256-ynZRwn/NVY+IZ9A8RMdKCXmudLsuXPCPDbGUxVIQm3A=";
    # NOTE: the aarch64 tarball is published as linux-arm64 (not -aarch64).
    # aarch64 builds are untested (no hardware) — report issues if the
    # patchelf pass or the components differ on that platform.
    aarch64-linux = "sha512-/0hbge3w0WUq1x0p63O+3oDi0YMiWZeZhvBZAdiAKoj3EqfEncRxEyPv+9xacyGvOcG1kC7aEbHgdF+pgIrfBA==";
  };
  archMap = {
    x86_64-linux = "x86_64";
    aarch64-linux = "arm64";
  };
in
stdenv.mkDerivation {
  pname = "elastic-agent";
  inherit version;

  src = fetchurl {
    url = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${version}-linux-${archMap.${stdenv.hostPlatform.system}}.tar.gz";
    hash = hashes.${stdenv.hostPlatform.system};
  };

  sourceRoot = "elastic-agent-${version}-linux-${archMap.${stdenv.hostPlatform.system}}";

  nativeBuildInputs = [ patchelf ];

  # Elastic Agent is a Go binary dynamically linked against glibc but only
  # requesting the system interpreter (/lib64/ld-linux-x86-64.so.2). On NixOS
  # that path is the stub-ld, so we patch the interpreter of the agent binary
  # and every component to the real glibc loader.
  installPhase = ''
    runHook preInstall

    mkdir -p $out/share/elastic-agent

    # The tarball root becomes the agent home (components/ layout preserved).
    cp -r . $out/share/elastic-agent/

    agentBin=$out/share/elastic-agent/data/elastic-agent-*/elastic-agent
    agentBin=$(echo $agentBin)

    interpreter=$(cat ${stdenv.cc}/nix-support/dynamic-linker)

    for elf in "$agentBin" $out/share/elastic-agent/data/elastic-agent-*/components/*; do
      # Skip non-ELF files (specs, zips, notices) and true static binaries
      # (some Go components have no .interp section).
      if head -c 4 "$elf" | grep -q $'\x7fELF'; then
        patchelf --set-interpreter "$interpreter" "$elf" 2>/dev/null || true
      fi
    done

    # Components also need a writable working dir at runtime; the tarball
    # layout expects everything relative to the agent home.
    mkdir -p $out/bin
    ln -s "$agentBin" $out/bin/elastic-agent

    # The binary resolves version files relative to its own location.
    ln -s $out/share/elastic-agent/data/elastic-agent-*/*.version $out/bin/ 2>/dev/null || true

    runHook postInstall
  '';

  # Keep the prebuilt directory structure: do not strip (breaks Go binaries
  # that verify their own checksums) and do not patch shebangs inside data/.
  dontStrip = true;
  dontPatchShebangs = true;
  dontAutoPatchelf = true;

  passthru = {
    inherit version;
    updateScript = null; # TODO
  };

  meta = with lib; {
    description = "Elastic Agent - single, unified way to add monitoring for logs, metrics, and other types of data to a host";
    homepage = "https://www.elastic.co/elastic-agent";
    license = licenses.elastic20;
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
    platforms = builtins.attrNames hashes;
    mainProgram = "elastic-agent";
  };
}
