{
  lib,
  writeShellApplication,
  coreutils,
  findutils,
  gawk,
  gnugrep,
  gnused,
  attr,
  util-linux,
  libselinux,
  policycoreutils,
}:

writeShellApplication {
  name = "nixos-selinux-setup";

  runtimeInputs = [
    coreutils
    findutils
    gawk
    gnugrep
    gnused
    attr
    util-linux
    libselinux
    policycoreutils
  ];

  text = builtins.readFile ./setup.sh;

  meta = {
    description = "Load the SELinux policy and label the filesystem on NixOS";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "nixos-selinux-setup";
  };
}
