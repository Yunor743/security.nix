{
  lib,
  stdenvNoCC,
  makeWrapper,
  quickshell,
  minisoc,
  libnotify,
  xdg-utils,
}:

# Quickshell desktop widget for MiniSOC. `minisoc-ui` starts it; it reads the
# engine state and runs `minisoc` for every action (as the current user).
stdenvNoCC.mkDerivation {
  pname = "minisoc-ui";
  inherit (minisoc) version;

  src = ../minisoc/ui;

  nativeBuildInputs = [ makeWrapper ];

  installPhase = ''
    runHook preInstall
    install -Dm644 -t $out/share/minisoc/ui *.qml
    makeWrapper ${lib.getExe quickshell} $out/bin/minisoc-ui \
      --add-flags "-p $out/share/minisoc/ui" \
      --set-default MINISOC_BIN ${lib.getExe minisoc} \
      --suffix PATH : ${
        lib.makeBinPath [
          libnotify
          xdg-utils
        ]
      }
    # IPC helper: `minisoc-ui-ipc call minisoc toggleManage`
    makeWrapper ${lib.getExe quickshell} $out/bin/minisoc-ui-ipc \
      --add-flags "ipc -p $out/share/minisoc/ui"
    runHook postInstall
  '';

  meta = {
    description = "MiniSOC desktop widget (Quickshell)";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "minisoc-ui";
  };
}
