{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "minisoc";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./prompts
      ./web
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  # Unit tests (parsing, filters, store, AI guardrails, mock providers) run
  # in the build; they only use temp dirs and loopback sockets.
  doCheck = true;

  postInstall = ''
    install -Dm644 -t $out/share/minisoc/prompts prompts/*.md
  '';

  meta = {
    description = "MiniSOC engine and CLI: normalize, filter, triage and optionally LLM-enrich local security alerts";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "minisoc";
  };
}
