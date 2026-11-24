{
  description = "Security.nix - Extended endpoint security and detection for nixos";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    # Only used by the MiniSOC VM test (Home Manager module).
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
      ...
    }:
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
          packages.jit-hater = pkgs.callPackage ./packages/jit-hater { };
          packages.yara-forge-rules = pkgs.callPackage ./packages/yara-forge-rules { };
          packages.sigma-rules = pkgs.callPackage ./packages/sigma-rules { };
          packages.apparmor-d = pkgs.callPackage ./packages/apparmor-d { };
          packages.secilc = pkgs.callPackage ./packages/secilc { };
          packages.selinux-policy-minimal = pkgs.callPackage ./packages/selinux-policy-minimal {
            secilc = pkgs.callPackage ./packages/secilc { };
          };
          packages.minisoc = pkgs.callPackage ./packages/minisoc { };
          packages.minisoc-ui = pkgs.callPackage ./packages/minisoc-ui {
            minisoc = pkgs.callPackage ./packages/minisoc { };
          };

          checks =
            let
              tests = pkgs.callPackage ./checks/nixos-test.nix { self = self; };
              agentTest = {
                elastic-agent-standalone = pkgs.callPackage ./checks/elastic-agent-test.nix { inherit self; };
              };
              jitHaterTest = {
                jit-hater = pkgs.callPackage ./checks/jit-hater-test.nix { inherit self; };
              };
              minisocTests = {
                minisoc-vector = pkgs.callPackage ./checks/minisoc-vector-test.nix { };
                apparmor-d = pkgs.callPackage ./checks/apparmor-test.nix { inherit self; };
                usbguard = pkgs.callPackage ./checks/usbguard-test.nix { inherit self; };
                crowdsec-eval = pkgs.callPackage ./checks/crowdsec-eval.nix { inherit self nixpkgs; };
                # SELinux VM tests from nix-selinux (enforcing boots, zero denials).
                selinux-enforcing = pkgs.testers.runNixOSTest {
                  imports = [ ./checks/selinux/enforcing.nix ];
                  defaults.imports = [ self.nixosModules.selinux ];
                };
                selinux-refpolicy = pkgs.testers.runNixOSTest {
                  imports = [ (import ./checks/selinux/refpolicy.nix { }) ];
                  defaults.imports = [ self.nixosModules.selinux ];
                };
                minisoc = pkgs.callPackage ./checks/minisoc-test.nix { inherit self home-manager; };
              };
            in
            builtins.removeAttrs (tests // agentTest // jitHaterTest // minisocTests) [
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
        jit-hater = prev.callPackage ./packages/jit-hater { };
        yara-forge-rules = prev.callPackage ./packages/yara-forge-rules { };
        sigma-rules = prev.callPackage ./packages/sigma-rules { };
        apparmor-d = final.callPackage ./packages/apparmor-d { };
        secilc = final.callPackage ./packages/secilc { };
        selinux-policy-minimal = final.callPackage ./packages/selinux-policy-minimal { };
        minisoc = final.callPackage ./packages/minisoc { };
        minisoc-ui = final.callPackage ./packages/minisoc-ui { };
      };

      nixosModules = {
        fapolicyd = import ./modules/fapolicyd.nix;
        rustinel = import ./modules/rustinel.nix;
        elastic-agent = import ./modules/elastic-agent.nix;
        jit-hater = import ./modules/jit-hater.nix;
        minisoc = import ./modules/minisoc.nix;
        apparmor = import ./modules/apparmor.nix;
        selinux = import ./modules/selinux;
        usbguard = import ./modules/usbguard.nix;
        crowdsec = import ./modules/crowdsec.nix;
        security = import ./modules/security.nix;
        default = import ./modules/security.nix;
      };

      homeManagerModules = {
        minisoc = import ./modules/minisoc-home.nix;
        default = import ./modules/minisoc-home.nix;
      };

      security = import ./modules/security.nix;

      packages = eachSystem (system: (forSystem system).packages);

      checks = eachSystem (system: (forSystem system).checks);

      formatter = eachSystem (system: (forSystem system).formatter);
    };
}
