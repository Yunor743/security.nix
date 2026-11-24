# security.crowdsec, evaluated (CrowdSec needs its online hub at start, which
# NixOS VM tests cannot reach; the running path is tested on a real host):
# sources and collections follow the enabled services, simulation mode, the
# allow-list parser, progressive bans without `%` (tmpfiles specifiers), the
# central API off by default, the bouncer registered.
{
  lib,
  pkgs,
  self,
  nixpkgs,
}:

let
  eval =
    extra:
    (nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        self.nixosModules.crowdsec
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "25.05";
          services.openssh.enable = true;
          security.crowdsec.enable = true;
        }
        extra
      ];
    }).config;

  sim = eval {
    security.crowdsec.allowList = [
      "192.0.2.10"
      "100.64.0.0/10"
    ];
  };
  enforce = eval {
    security.crowdsec = {
      mode = "enforce";
      communityBlocklist = true;
      progressiveBans = false;
      banDuration = "2h";
    };
  };

  cs = c: c.services.crowdsec;
  newApi = (cs sim).settings ? config;
  profiles = c: if newApi then (cs c).settings.profiles else (cs c).localConfig.profiles;
  acquisitions = c: if newApi then (cs c).settings.acquisitions else (cs c).localConfig.acquisitions;
  enrich =
    c: if newApi then (cs c).settings.parsers.s02Enrich else (cs c).localConfig.parsers.s02Enrich;
  onlineClient =
    c:
    if newApi then
      (cs c).settings.config.api.server.online_client.credentials_path
    else
      (cs c).settings.general.api.server.online_client;

  checks = [
    {
      ok =
        lib.elem "crowdsecurity/sshd" (cs sim).hub.collections
        && lib.elem "crowdsecurity/linux" (cs sim).hub.collections;
      what = "sshd enabled -> linux + sshd collections";
    }
    {
      ok = lib.any (
        a: a.source == "journalctl" && a.journalctl_filter == [ "_SYSTEMD_UNIT=sshd.service" ]
      ) (acquisitions sim);
      what = "sshd journal acquisition";
    }
    {
      ok = (cs sim).settings.simulation.simulation && !(cs enforce).settings.simulation.simulation;
      what = "simulation flag follows the mode";
    }
    {
      ok =
        let
          p = enrich sim;
        in
        p != [ ]
        && (lib.head p).whitelist.ip == [ "192.0.2.10" ]
        && (lib.head p).whitelist.cidr == [ "100.64.0.0/10" ];
      what = "allow-list parser (ip / cidr split)";
    }
    {
      ok =
        let
          ip = lib.head (profiles sim);
        in
        ip ? duration_expr && !lib.hasInfix "%" ip.duration_expr && lib.hasInfix "* 240" ip.duration_expr;
      what = "progressive bans, no tmpfiles specifier, 4h base";
    }
    {
      ok =
        !(lib.head (profiles enforce) ? duration_expr)
        && (lib.head (lib.head (profiles enforce)).decisions).duration == "2h";
      what = "fixed ban duration";
    }
    {
      ok = onlineClient sim == null && onlineClient enforce != null;
      what = "central API off unless communityBlocklist";
    }
    {
      ok =
        sim.services.crowdsec-firewall-bouncer.enable
        && sim.services.crowdsec-firewall-bouncer.registerBouncer.enable;
      what = "firewall bouncer registered";
    }
  ];
  failed = lib.filter (c: !c.ok) checks;
in
pkgs.runCommandLocal "crowdsec-eval" { } (
  if failed == [ ] then
    ''
      echo "crowdsec: ${toString (lib.length checks)} checks passed (nixpkgs API: ${
        if newApi then "settings" else "localConfig"
      })"
      touch $out
    ''
  else
    throw "crowdsec-eval failed: ${lib.concatMapStringsSep "; " (c: c.what) failed}"
)
