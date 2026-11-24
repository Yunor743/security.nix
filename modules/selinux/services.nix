# Puts well-known services into the domains the reference policy has for
# them. The reference policy finds a service's programs by their FHS
# paths, which do not exist on NixOS, so the programs are named here by
# exact store path instead.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.security.selinux;
  refpolicy = cfg.type == "refpolicy";

  # The program a systemd service starts: the first word of its
  # ExecStart, without systemd's prefixes. Null when it cannot be told.
  programOf =
    unitName:
    let
      unit = config.systemd.services.${unitName} or null;
      start = unit.serviceConfig.ExecStart or null;
      first = if lib.isList start then (if start == [ ] then null else lib.head start) else start;
      command = if first == null then null else "${first}";
      program = builtins.match "[@!+:-]*(/nix/store/[^ ]+).*" command;
    in
    if unit != null && (unit.enable or true) && command != null && program != null then
      # match drops the string's context; the policy build needs it to
      # see the file.
      lib.addContextFrom command (lib.head program)
    else
      null;

  dhcpcdProgram = programOf "dhcpcd";

  # A name usable in policy identifiers.
  identifier = lib.replaceStrings [ "-" "." "@" ":" ] [ "_" "_" "_" "_" ];

  services = lib.filterAttrs (_: service: service.enable) cfg.services;
  serviceProgram =
    service: if service.program != null then service.program else programOf service.unit;

  # Units with a domain of their own, for `nixos-selinux status`.
  builtinUnits =
    lib.optionalAttrs (cfg.confine.sshd && config.services.openssh.enable) { sshd = "sshd_t"; }
    // lib.optionalAttrs (cfg.confine.nscd && config.services.nscd.enable) { nscd = "nscd_t"; }
    // lib.optionalAttrs (cfg.confine.nix && config.nix.enable) { nix-daemon = "nix_daemon_t"; }
    // lib.optionalAttrs (cfg.confine.dhcpcd && dhcpcdProgram != null) { dhcpcd = "dhcpc_t"; }
    // lib.optionalAttrs refpolicy {
      systemd-journald = "syslogd_t";
      systemd-logind = "systemd_logind_t";
      systemd-udevd = "udev_t";
    }
    // lib.optionalAttrs (refpolicy && config.services.dbus.enable) {
      ${if config.services.dbus.implementation == "broker" then "dbus-broker" else "dbus"} =
        "system_dbusd_t";
    };

  builtinContexts = {
    sshd = lib.mkIf (cfg.confine.sshd && config.services.openssh.enable) {
      serviceConfig.SELinuxContext = "system_u:system_r:sshd_t:s0";
    };
    nscd = lib.mkIf (cfg.confine.nscd && config.services.nscd.enable) {
      serviceConfig.SELinuxContext = "system_u:system_r:nscd_t:s0";
    };
    nix-daemon = lib.mkIf (cfg.confine.nix && config.nix.enable) {
      serviceConfig.SELinuxContext = "system_u:system_r:nix_daemon_t:s0";
    };
  };
in
{
  options.security.selinux = {
    services = lib.mkOption {
      default = { };
      example = lib.literalExpression ''
        {
          # A service of your own, in a new domain that may only log.
          myservice.rules = '''
            logging_send_syslog_msg(myservice_t)
          ''';

          # A service the reference policy already has a domain for.
          nginx = {
            domain = "httpd_t";
            createDomain = false;
          };
        }
      '';
      description = ''
        systemd services to confine, by service name. For each one the
        module labels the program the service starts, makes systemd start
        it in its domain, and compiles the rules given here into the
        policy. A service that is not listed here or in
        {option}`security.selinux.confine` runs unconfined.

        Needs the `refpolicy` policy type.
      '';
      type = lib.types.attrsOf (
        lib.types.submodule (
          { name, config, ... }:
          {
            options = {
              enable = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Whether to confine this service.";
              };

              unit = lib.mkOption {
                type = lib.types.str;
                default = name;
                description = "Name of the systemd service, without `.service`.";
              };

              domain = lib.mkOption {
                type = lib.types.str;
                default = "${identifier name}_t";
                defaultText = lib.literalExpression ''"''${name}_t"'';
                description = ''
                  SELinux type the service's processes run as. By convention
                  it ends in `_t`.
                '';
              };

              createDomain = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Create {option}`domain` as a new domain that systemd may
                  start. A new domain may do almost nothing until
                  {option}`rules` allows it. Turn this off to use a domain
                  the policy already has, such as `httpd_t`.
                '';
              };

              rules = lib.mkOption {
                type = lib.types.lines;
                default = "";
                example = ''
                  logging_send_syslog_msg(myservice_t)
                  corenet_tcp_bind_generic_node(myservice_t)
                '';
                description = ''
                  What the domain may do, in the reference policy's
                  language: allow rules and calls of its interfaces.
                  `nixos-selinux denials --rules` prints rules for what was
                  denied.
                '';
              };

              permissive = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Log what the policy would deny this service instead of
                  denying it, while the rest of the system stays enforcing.
                  Use it to collect the rules a new service needs, then
                  turn it off.
                '';
              };

              program = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                defaultText = lib.literalMD "the program in the service's `ExecStart`";
                description = ''
                  The file in the Nix store that the service starts. Set it
                  when the module cannot tell it from the unit.
                '';
              };

              programType = lib.mkOption {
                type = lib.types.str;
                default = "${lib.removeSuffix "_t" config.domain}_exec_t";
                defaultText = lib.literalMD "{option}`domain` with `_t` replaced by `_exec_t`";
                description = ''
                  SELinux type for the program file. Starting a file of this
                  type is what moves the service into its domain.
                '';
              };
            };
          }
        )
      );
    };

    confinedUnits = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      internal = true;
      description = "systemd services and the domain each is expected to run in.";
    };

    confine = {
      sshd = lib.mkOption {
        type = lib.types.bool;
        default = refpolicy;
        defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
        description = "Run the OpenSSH daemon in the policy's `sshd_t` domain.";
      };

      nscd = lib.mkOption {
        type = lib.types.bool;
        default = refpolicy;
        defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
        description = ''
          Run the name service cache daemon in the policy's `nscd_t`
          domain. Confined programs resolve users and hosts through it.
        '';
      };

      getty = lib.mkOption {
        type = lib.types.bool;
        default = refpolicy;
        defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
        description = ''
          Run the console login prompt in `getty_t` and the login program
          in `local_login_t`. A user's session then starts in the context
          the policy maps the user to.
        '';
      };

      dhcpcd = lib.mkOption {
        type = lib.types.bool;
        default = refpolicy;
        defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
        description = "Run the DHCP client in the policy's `dhcpc_t` domain.";
      };

      nix = lib.mkOption {
        type = lib.types.bool;
        default = refpolicy;
        defaultText = lib.literalExpression ''config.security.selinux.type == "refpolicy"'';
        description = ''
          Run the Nix daemon in its own domain, `nix_daemon_t`. The domain
          is not restricted: the daemon manages the store as root. It is
          what {option}`security.selinux.confine.nixBuilds` builds on.
        '';
      };

      nixBuilds = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Run the builders the Nix daemon starts in the confined domain
          `nix_build_t`. A build may write only its outputs and its build
          directory, may not read the password database, and may not
          signal or trace other processes, in addition to the isolation
          Nix itself provides.

          Cannot be combined with remote builders, a `post-build-hook`
          or a disabled sandbox; the build says so.
        '';
      };
    };

  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.confine.nixBuilds -> cfg.confine.nix;
        message = "security.selinux.confine.nixBuilds needs security.selinux.confine.nix.";
      }
      {
        assertion =
          (cfg.confine.sshd || cfg.confine.nscd || cfg.confine.nix || cfg.confine.getty || cfg.confine.dhcpcd)
          -> refpolicy;
        message = "security.selinux.confine.* needs security.selinux.type = \"refpolicy\".";
      }
      {
        assertion =
          cfg.confine.nixBuilds
          -> !(
            config.nix.distributedBuilds
            || config.nix.settings ? post-build-hook
            || (config.nix.settings.sandbox or true) == false
          );
        message = ''
          security.selinux.confine.nixBuilds cannot be used with remote
          builders (nix.distributedBuilds), a post-build-hook or the
          sandbox turned off: each would run inside the confined build
          domain and fail. Turn security.selinux.confine.nixBuilds off.
        '';
      }
      {
        assertion = services != { } -> refpolicy;
        message = "security.selinux.services needs security.selinux.type = \"refpolicy\".";
      }
    ]
    ++ lib.mapAttrsToList (name: service: {
      assertion = serviceProgram service != null;
      message = ''
        security.selinux.services.${name}: cannot tell which program
        systemd.services.${service.unit} starts${
          lib.optionalString (
            !(config.systemd.services ? ${service.unit})
          ) ", because this configuration has no such service"
        }. Set security.selinux.services.${name}.program to the
        file in the Nix store, or .unit to the service's name.
      '';
    }) services;

    systemd.services = lib.mkMerge [
      (lib.mapAttrs' (
        _: service:
        lib.nameValuePair service.unit {
          serviceConfig.SELinuxContext = "system_u:system_r:${service.domain}:s0";
        }
      ) services)
      builtinContexts
    ];

    security.selinux = {
      confinedUnits =
        builtinUnits // lib.mapAttrs' (_: service: lib.nameValuePair service.unit service.domain) services;

      modules = lib.mapAttrs' (
        name: service:
        lib.nameValuePair "nixos_service_${identifier name}" {
          te =
            (
              if service.createDomain then
                ''
                  type ${service.domain};
                  type ${service.programType};
                  init_daemon_domain(${service.domain}, ${service.programType})
                ''
              else
                ''
                  gen_require(`
                    type ${service.domain};
                  ')
                ''
            )
            + lib.optionalString service.permissive ''
              permissive ${service.domain};
            ''
            + service.rules;
        }
      ) services;

      # Name the domain in the unit as well. The label on the program is
      # then necessary but not sufficient: if it is ever missing, the
      # service fails to start instead of running unconfined.
      booleans = lib.mkIf refpolicy {
        nix_confine_builds = cfg.confine.nixBuilds;
      };

      entrypoints = lib.mkMerge [
        (lib.mapAttrs' (
          name: service:
          lib.nameValuePair "service-${name}" {
            path = serviceProgram service;
            type = service.programType;
          }
        ) (lib.filterAttrs (_: service: serviceProgram service != null) services))
        (lib.mkIf cfg.confine.getty {
          agetty = {
            path = lib.getExe' pkgs.util-linux "agetty";
            type = "getty_exec_t";
          };
          login = {
            path = config.services.getty.loginProgram;
            type = "login_exec_t";
          };
        })
        # The DHCP client's module builds its own variant of the package
        # and does not expose it, so the program is taken from its unit.
        (lib.mkIf (cfg.confine.dhcpcd && dhcpcdProgram != null) {
          dhcpcd = {
            path = dhcpcdProgram;
            type = "dhcpc_exec_t";
          };
        })
        # The programs of the nix package are links to one file, which this
        # names through the link the daemon's unit starts.
        (lib.mkIf (cfg.confine.nix && config.nix.enable) {
          nix = {
            path = "${config.nix.package}/bin/nix";
            type = "nix_exec_t";
          };
        })
        (lib.mkIf (cfg.confine.sshd && config.services.openssh.enable) (
          lib.genAttrs' [ "bin/sshd" "libexec/sshd-session" "libexec/sshd-auth" ] (
            file:
            lib.nameValuePair "openssh-${baseNameOf file}" {
              path = "${config.services.openssh.package}/${file}";
              type = "sshd_exec_t";
            }
          )
        ))
        # The password checking helper. Confined programs such as sshd may
        # not read the shadow file themselves; they run this helper, which
        # enters its own domain. It is reached through a setuid wrapper,
        # which keeps a generic type and only executes this file.
        (lib.mkIf refpolicy {
          pam-unix-chkpwd = {
            path = "${config.security.pam.package}/bin/unix_chkpwd";
            type = "chkpwd_exec_t";
          };
        })
        (lib.mkIf (cfg.confine.nscd && config.services.nscd.enable) {
          nscd = {
            path =
              if config.services.nscd.enableNsncd then
                "${pkgs.nsncd}/bin/nsncd"
              else
                "${config.services.nscd.package}/bin/nscd";
            type = "nscd_exec_t";
          };
        })
      ];
    };
  };
}
