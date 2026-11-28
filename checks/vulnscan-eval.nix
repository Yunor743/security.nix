# The vulnerability scanner modules, evaluated: how oci-containers are split
# between Trivy (registry images, rootless users) and sbomnix / vulnix
# (Nix-built images), the warnings for what is not covered, the privacy
# defaults, and the MiniSOC wiring.
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
        self.nixosModules.security
        (
          { pkgs, ... }:
          {
            boot.loader.grub.enable = false;
            fileSystems."/" = {
              device = "none";
              fsType = "tmpfs";
            };
            system.stateVersion = "26.05";
            virtualisation.podman.enable = true;
            users.users.alice = {
              isNormalUser = true;
              linger = true;
            };
            virtualisation.oci-containers.containers = {
              web.image = "docker.io/library/nginx:1.27";
              rootless = {
                image = "ghcr.io/example/app:1";
                podman.user = "alice";
              };
              streamed = {
                image = "streamed:1";
                imageStream = pkgs.dockerTools.streamLayeredImage {
                  name = "streamed";
                  tag = "1";
                  contents = [ pkgs.hello ];
                };
              };
              tarball = {
                image = "tarball:1";
                imageFile = pkgs.dockerTools.buildLayeredImage {
                  name = "tarball";
                  tag = "1";
                  contents = [ pkgs.hello ];
                };
              };
            };
            services.minisoc = {
              enable = true;
              users = [ "alice" ];
            };
            security.containerScan.enable = true;
          }
        )
        extra
      ];
    }).config;

  trivyOnly = eval { };
  withSbomnix = eval { security.sbomnix.enable = true; };
  withVulnix = eval { security.vulnix.enable = true; };
  both = eval {
    security.sbomnix.enable = true;
    security.vulnix.enable = true;
  };
  remote = eval {
    security.sbomnix = {
      enable = true;
      allowRemote.osv = true;
      allowRemote.triage = true;
    };
  };

  hasWarning = c: s: lib.any (lib.hasInfix s) c.warnings;
  script = c: unit: builtins.readFile c.systemd.services.${unit}.serviceConfig.ExecStart;

  checks = [
    {
      ok = trivyOnly.security.containerScan.podman.rootlessUsers == [ "alice" ];
      what = "rootless users from oci-containers podman.user";
    }
    {
      ok =
        hasWarning trivyOnly "imageFile` (tarball)"
        && hasWarning trivyOnly "only scanned by security.sbomnix or security.vulnix";
      what = "warnings: imageFile not scanned, imageStream needs sbomnix/vulnix";
    }
    {
      ok =
        withSbomnix.security.sbomnix.targets ? image-streamed
        && !(withSbomnix.security.sbomnix.targets ? image-tarball)
        && withSbomnix.security.sbomnix.targets ? system;
      what = "imageStream images become sbomnix targets";
    }
    {
      ok =
        lib.length withVulnix.security.vulnix.paths == 1
        && lib.hasInfix "stream-streamed" (lib.head withVulnix.security.vulnix.paths);
      what = "imageStream images become vulnix paths";
    }
    {
      ok = hasWarning both "both scan the system" && !(hasWarning withSbomnix "both scan the system");
      what = "duplicate warning when vulnix and sbomnix both scan the system";
    }
    {
      ok =
        let
          s = script withSbomnix "sbomnix";
        in
        lib.hasInfix "--skip-osv" s && !(lib.hasInfix "--triage" s);
      what = "sbomnix: OSV and triage off by default";
    }
    {
      ok =
        let
          s = script remote "sbomnix";
        in
        !(lib.hasInfix "--skip-osv" s) && lib.hasInfix "--triage" s;
      what = "sbomnix: allowRemote turns them on";
    }
    {
      ok = lib.hasInfix "--disable-telemetry --skip-version-check" (script trivyOnly "container-scan");
      what = "trivy: no telemetry, no update check";
    }
    {
      ok =
        trivyOnly.services.minisoc.sources ? container_scan
        && withSbomnix.services.minisoc.sources ? sbomnix
        && withVulnix.services.minisoc.sources ? vulnix
        && lib.elem "minisoc-collector.service" withSbomnix.systemd.services.sbomnix.after
        && lib.elem "minisoc-collector.service" trivyOnly.systemd.services.container-scan.after;
      what = "MiniSOC sources and ordering after the collector";
    }
  ];
  failed = lib.filter (c: !c.ok) checks;
in
pkgs.runCommandLocal "vulnscan-eval" { } (
  if failed == [ ] then
    ''
      echo "vulnscan: ${toString (lib.length checks)} checks passed"
      touch $out
    ''
  else
    throw "vulnscan-eval failed: ${lib.concatMapStringsSep "; " (c: c.what) failed}"
)
