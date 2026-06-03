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
          packages.yara-forge-rules = pkgs.callPackage ./packages/yara-forge-rules { };
          packages.sigma-rules = pkgs.callPackage ./packages/sigma-rules { };

          checks =
            let
              tests = pkgs.callPackage ./checks/nixos-test.nix { self = self; };
            in
            builtins.removeAttrs tests [
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
        yara-forge-rules = prev.callPackage ./packages/yara-forge-rules { };
        sigma-rules = prev.callPackage ./packages/sigma-rules { };
      };

      nixosModules = {
        fapolicyd = import ./modules/fapolicyd.nix;
        rustinel = import ./modules/rustinel.nix;
        # default = self.nixosModules.fapolicyd;
      };

      packages = eachSystem (system: (forSystem system).packages);

      checks = eachSystem (system: (forSystem system).checks);

      formatter = eachSystem (system: (forSystem system).formatter);
    };
}
