# Gives a test VM a real ext4 filesystem at /nix, holding the system closure.
#
# NixOS test VMs normally see the host's store over 9p behind an overlay.
# Neither can hold SELinux labels the way a real installation does, so the
# tests would not exercise store labelling at all.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  closure = pkgs.closureInfo { rootPaths = [ config.system.build.toplevel ]; };

  # An ext4 image with the closure under /store and its registration next to
  # it, with room to spare for labels and the Nix database.
  nixImage =
    pkgs.runCommand "selinux-test-nix.img"
      {
        nativeBuildInputs = [
          pkgs.e2fsprogs
          pkgs.fakeroot
          pkgs.libfaketime
        ];
      }
      ''
        mkdir -p root/store root/var/nix/db
        xargs -I % cp -a --reflink=auto % -t root/store/ < ${closure}/store-paths
        cp ${closure}/registration root/registration

        blocks=$(du -s -B 4096 --apparent-size root | awk '{ print int($1 * 1.3) }')
        inodes=$(find root | wc -l)
        truncate -s $(( blocks * 4096 + inodes * 512 + 512 * 1024 * 1024 )) $out

        faketime -f "1970-01-01 00:00:01" fakeroot \
          mkfs.ext4 -q -L nix -N $(( inodes * 2 )) -d root $out
      '';
in
{
  virtualisation = {
    mountHostNixStore = false;
    useNixStoreImage = false;
    writableStore = false;

    # qemu keeps writes to this drive in a temporary overlay, so the image in
    # the host's store is never modified. Reboots within one run keep them.
    qemu.drives = [
      {
        name = "nix";
        file = "${nixImage}";
        driveExtraOpts = {
          format = "raw";
          snapshot = "on";
        };
        deviceExtraOpts.serial = "nix";
      }
    ];

    fileSystems."/nix" = {
      device = "/dev/disk/by-label/nix";
      fsType = "ext4";
      neededForBoot = true;
    };
  };

  # Tests in nixpkgs run without Nix unless they ask for it. These build
  # with it and query its database.
  nix.enable = true;

  # NixOS 26.05's VM module registers store paths from a file on the
  # host's store, which this image does not contain. The command below
  # does the same from the image's own list.
  systemd.services.register-nix-paths.enable = false;

  # Tell Nix about the store paths in the image, as an installer would have.
  boot.postBootCommands = lib.mkBefore ''
    if [ -f /nix/registration ]; then
      ${lib.getExe' config.nix.package.out "nix-store"} --load-db < /nix/registration
      rm /nix/registration
    fi
  '';
}
