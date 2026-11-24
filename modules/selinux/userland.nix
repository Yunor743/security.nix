# Core userland built with SELinux support.
#
# nixpkgs builds these without it by default, so enabling SELinux rebuilds
# them. Only the packages needed to load a policy and inspect labels are
# switched by default. PAM and OpenSSH are switched when
# `security.selinux.loginContexts` is on.
{
  config,
  lib,
  pkgs,
  selinuxPkgs,
  ...
}:
let
  cfg = config.security.selinux;

  # `pkgs.coreutils` comes from a bootstrap stage, so its default libselinux
  # would be evaluated in that stage's package set, which cannot build it.
  # Pass the final ones explicitly.
  selinuxCoreutils = pkgs.coreutils.override {
    selinuxSupport = true;
    inherit (pkgs) libselinux libsepol;
  };

  # nixpkgs disables SELinux in PAM outright, so flip the build flag.
  selinuxPam = pkgs.linux-pam.overrideAttrs (old: {
    mesonFlags = map (
      flag: if flag == "-Dselinux=disabled" then "-Dselinux=enabled" else flag
    ) old.mesonFlags;
    buildInputs = old.buildInputs ++ [ pkgs.libselinux ];
    # pam_sepermit wants to create its lock directory under /var at
    # install time. Point that at the output instead.
    postPatch = (old.postPatch or "") + ''
      sed -i "s|^    sepermit_lockdir,|    get_option('prefix') / 'share/empty-sepermit',|" \
        modules/module-meson.build
    '';
  });

  # The command people use day to day; see the manual chapter.
  nixosSelinux = pkgs.writeShellApplication {
    name = "nixos-selinux";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.gnugrep
      config.systemd.package
    ];
    text =
      lib.replaceStrings
        [ "@type@" "@mode@" "@units@" "@setup@" ]
        [
          cfg.type
          cfg.mode
          "${pkgs.writeText "selinux-confined-units" (
            lib.concatStrings (lib.mapAttrsToList (unit: domain: "${unit} ${domain}\n") cfg.confinedUnits)
          )}"
          "/run/current-system/selinux-setup"
        ]
        (builtins.readFile ./nixos-selinux.sh);
  };
in
{
  config = lib.mkIf cfg.enable {
    systemd.services = lib.genAttrs cfg.userContextServices (_: {
      serviceConfig.SELinuxContext = "unconfined_u:unconfined_r:unconfined_t:s0";
    });

    # PID 1 loads the policy, labels /dev and /run, and applies
    # SELinuxContext= only when systemd is built with SELinux support.
    systemd.package = pkgs.systemd.override { withSelinux = true; };

    environment.systemPackages = [
      nixosSelinux
      # `ls -Z`, `id -Z`, `cp --preserve=context` and friends.
      (lib.hiPrio selinuxCoreutils)
      pkgs.libselinux # getenforce, selinuxenabled, getfilecon, ...
      pkgs.policycoreutils # load_policy, setfiles, restorecon, sestatus, ...
    ]
    ++ lib.optionals cfg.developmentTools [
      pkgs.setools
      pkgs.selinux-python # audit2allow, audit2why
      pkgs.checkpolicy
      selinuxPkgs.secilc
    ];

    # Sessions start in the context the policy maps the user to, instead
    # of inheriting the context of the login program. OpenSSH does this
    # itself when built with SELinux support; console logins use
    # pam_selinux.
    # The message bus asks the policy whether a sender may talk to a
    # receiver and whether a service may own a name, when it is built to.
    services.dbus.brokerPackage = lib.mkIf cfg.dbusMediation (
      lib.mkDefault (
        pkgs.dbus-broker.overrideAttrs (old: {
          mesonFlags = old.mesonFlags ++ [
            "-D=selinux=true"
            "-D=audit=true"
          ];
          buildInputs = old.buildInputs ++ [
            pkgs.libselinux
            pkgs.audit
            pkgs.libcap_ng
          ];
        })
      )
    );

    programs.ssh.package = lib.mkIf cfg.loginContexts (
      lib.mkDefault (
        # Older nixpkgs has no build flag for it.
        if (lib.functionArgs pkgs.openssh.override) ? withSelinux then
          pkgs.openssh.override { withSelinux = true; }
        else
          pkgs.openssh.overrideAttrs (old: {
            buildInputs = old.buildInputs ++ [ pkgs.libselinux ];
            configureFlags = old.configureFlags ++ [ "--with-selinux" ];
          })
      )
    );

    security = {
      auditd.enable = lib.mkIf cfg.developmentTools (lib.mkDefault true);

      pam = lib.mkIf cfg.loginContexts {
        package = lib.mkDefault selinuxPam;
        services = lib.genAttrs cfg.pamServices (_: {
          rules.session.selinux = {
            # After every other session module: it sets the context of the
            # next program the session executes (the user's shell, the user
            # manager, the graphical session).
            order = 100000;
            control = "required";
            modulePath = "${config.security.pam.package}/lib/security/pam_selinux.so";
          };
        });
      };
    };
  };
}
