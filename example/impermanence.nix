{
  ...
}: {
  boot.initrd.systemd.services."rootfs-cleanup" = {
    description = "Rollback BTRFS @ subvolume to a pristine state";
    wantedBy = [ "initrd.target" ];
    # requires = [ "dev-disk-by\\x2did-ata\\x2dPhison_SATA_SSD_2143332432454365.device" ];
    # after = [ "dev-disk-by\\x2did-ata\\x2dPhison_SATA_SSD_2143332432454365.device" ];
    after = [ "initrd-root-device.target" ];
    before = [ "sysroot.mount" ];
    unitConfig.DefaultDependencies = "no";
    serviceConfig.Type = "oneshot";
    script = ''
    mkdir /btrfs_tmp
    mount /dev/disk/by-partlabel/disk-main-root /btrfs_tmp # CONFIRM THIS IS CORRECT FROM findmnt
    if [[ -e /btrfs_tmp/root ]]; then
        mkdir -p /btrfs_tmp/old_roots
        timestamp=$(date --date="@$(stat -c %Y /btrfs_tmp/root)" "+%Y-%m-%-d_%H:%M:%S")
        mv /btrfs_tmp/root "/btrfs_tmp/old_roots/$timestamp"
    fi

    delete_subvolume_recursively() {
        IFS=$'\n'
        for i in $(btrfs subvolume list -o "$1" | cut -f 9- -d ' '); do
            delete_subvolume_recursively "/btrfs_tmp/$i"
        done
        btrfs subvolume delete "$1"
    }

    for i in $(find /btrfs_tmp/old_roots/ -maxdepth 1 -mtime +30); do
        delete_subvolume_recursively "$i"
    done

    btrfs subvolume create /btrfs_tmp/root
    umount /btrfs_tmp
    '';
  };

  systemd.tmpfiles.rules = [
    "d /storage 0700 root root -"
  ];

  # Use /nix/persist as the persistence root, matching Disko's mountpoint
  environment.persistence."/nix/persist" = {
    hideMounts = true;
    directories = [
      "/storage"
      "/etc"
      # "/var/spool" # Mail queues, cron jobs
      # "/srv" # Web server data, etc.
      # "/root"
    ];
    files = [
      # "/nix/persist/swapfile" # Persist swapfile (impermanence manages this file)
    ];
  };

}

