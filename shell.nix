{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  name = "nix-fapolicyd";

  packages = with pkgs; [
    nixfmt-rfc-style
    nil
  ];
}
