{
  description = "Security.nix - Extended endpoint security and detection for nixos";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      eachSystem = nixpkgs.lib.genAttrs supportedSystems;

      forSystem =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
        in
        {
        packages.fapolicyd = pkgs.callPackage ./packages/fapolicyd { };
        packages.rustinel = pkgs.callPackage ./packages/rustinel { };
        packages.elastic-agent = pkgs.callPackage ./packages/elastic-agent { };
        packages.yara-forge-rules = pkgs.callPackage ./packages/yara-forge-rules { };
        packages.sigma-rules = pkgs.callPackage ./packages/sigma-rules { };

          checks =
            let
              tests = pkgs.callPackage ./checks/nixos-test.nix { self = self; };
              agentTest = {
                elastic-agent-standalone =
                  pkgs.callPackage ./checks/elastic-agent-test.nix { inherit self; };
              };
            in
            builtins.removeAttrs (tests // agentTest) [
              "overrideDerivation"
              "override"
            ];

          formatter = pkgs.nixfmt-tree;
        };
    in
    {
      overlays.default = final: prev: {
        fapolicyd = prev.callPackage ./packages/fapolicyd { };
        rustinel = prev.callPackage ./packages/rustinel { };
        elastic-agent = prev.callPackage ./packages/elastic-agent { };
        yara-forge-rules = prev.callPackage ./packages/yara-forge-rules { };
        sigma-rules = prev.callPackage ./packages/sigma-rules { };
      };

      nixosModules = {
        fapolicyd = import ./modules/fapolicyd.nix;
        rustinel = import ./modules/rustinel.nix;
        elastic-agent = import ./modules/elastic-agent.nix;
        security = import ./modules/security.nix;
        default = import ./modules/security.nix;
      };

      security = import ./modules/security.nix;

      packages = eachSystem (system: (forSystem system).packages);

      checks = eachSystem (system: (forSystem system).checks);

      formatter = eachSystem (system: (forSystem system).formatter);
    };
}
