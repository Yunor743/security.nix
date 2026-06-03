{
  modulesPath,
  pkgs,
  ...
}:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
    (modulesPath + "/profiles/qemu-guest.nix")
    ./disko.nix
    ./impermanence.nix
  ];

  console = {
    earlySetup = true;
    keyMap = "fr";
  };

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  networking.hostName = "fortress";

  users.mutableUsers = false;

  users.users.root = {
    initialPassword = "passwd";
  };

  users.users.user = {
    isNormalUser = true;
    description = "user";
    extraGroups = [
      "networkmanager"
      "wheel"
    ];
    initialPassword = "passwd";
  };

  security.sudo.extraConfig = ''
    user ALL=(ALL) NOPASSWD: ALL
  '';

  environment.systemPackages = with pkgs; [
    file
    htop
  ];

  services = {
    openssh = {
      enable = true;
      settings = {
        PasswordAuthentication = true;
        PermitRootLogin = "yes";
      };
    };

    fapolicyd = {
      enable = true;
      permissive = false;
      profile = "nixos";
      extraRules = {
        "15-authorized.rules" = ''
          allow perm=any all : dir=/home/user/authorized/
        '';
      };
    };

    rustinel = {
      enable = true;
      yaraRulesPackage = pkgs.yara-forge-rules;
      sigmaRulesPackage = pkgs.sigma-rules;
    };
  };

  system.stateVersion = "25.05";
}
