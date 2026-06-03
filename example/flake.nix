{
  description = "Fortress host : a security.nix example";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    security-from-github = {
      url = "github:Yunor743/security.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    security-from-local = {
      url = "path:..";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    impermanence = {
      url = "github:nix-community/impermanence";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, ... }@inputs:
    {
      nixosConfigurations = {
        from-local = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = { inherit self; };
          modules = [
            # { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.security-from-local.security
            inputs.disko.nixosModules.disko
            inputs.impermanence.nixosModules.impermanence
            ./fortress.nix
          ];
        };
        from-github = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = { inherit self; };
          modules = [
            # { nixpkgs.overlays = [ self.overlays.default ]; }
            inputs.security-from-github.security
            inputs.disko.nixosModules.disko
            inputs.impermanence.nixosModules.impermanence
            ./fortress.nix
          ];
        };
      };
    };
}
