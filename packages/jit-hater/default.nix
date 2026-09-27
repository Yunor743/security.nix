{
  lib,
  rustPlatform,
  pkg-config,
  fetchFromGitHub,
}:

rustPlatform.buildRustPackage {
  pname = "jit-hater";
  version = "0.1.0-unstable-2026-09-27";

  src = fetchFromGitHub {
    owner = "Yunor743";
    repo = "JIT-Hater";
    rev = "2a998a65133ac8d3d4715a7498a09d81049768e3";
    hash = "sha256-4FOBsPx5XLTnzB6d7tPUuD1v9hHagdIdDdPaXzGn5Ps=";
  };

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];

  meta = {
    description = "Behavioral memory threat detector for Linux (watch, dump, analyze)";
    homepage = "https://github.com/Yunor743/JIT-Hater";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "jit-hater";
  };
}
