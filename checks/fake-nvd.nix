# Fixtures of the vulnerability scanner tests: a fictional NVD mirror and a
# `hello` derivation for vulnix to match.
#
# The scanned package is built inside the VM: vulnix needs the deriver of
# every path, and the test VM's store database has none for the system
# closure (registered from closureInfo), so `scanSystem` cannot run there.
{ pkgs }:

rec {
  helloVersion = "2.12.1";

  # nix-build it in the VM (busybox must be in the VM's store).
  target = pkgs.writeText "vuln-target.nix" ''
    derivation {
      name = "hello-${helloVersion}";
      system = "${pkgs.stdenv.hostPlatform.system}";
      builder = "''${builtins.storePath "${pkgs.busybox}"}/bin/sh";
      args = [ "-c" "echo fictional > $out" ];
    }
  '';
  buildTarget = "mkdir -p /var/lib/vuln-target && nix-build ${target} -o /var/lib/vuln-target/result";
  targetPath = "/var/lib/vuln-target/result";

  cve = id: score: {
    cve = {
      inherit id;
      descriptions = [
        {
          lang = "en";
          value = "Fictional vulnerability for the security.nix tests";
        }
      ];
      configurations = [
        {
          nodes = [
            {
              cpeMatch = [
                {
                  vulnerable = true;
                  criteria = "cpe:2.3:a:gnu:hello:${helloVersion}:*:*:*:*:*:*:*";
                }
              ];
            }
          ];
        }
      ];
      metrics.cvssMetricV31 = [ { cvssData.baseScore = score; } ];
    };
  };

  feed = pkgs.writeText "nvdcve.json" (
    builtins.toJSON {
      format = "NVD_CVE";
      version = "2.0";
      vulnerabilities = [
        (cve "CVE-2099-0001" 9.8)
        (cve "CVE-2099-0002" 5.0)
      ];
    }
  );

  # vulnix fetches the feeds of the last six years (VM clock): serve a wide
  # range, all with the same content.
  mirror = pkgs.runCommandLocal "fake-nvd-mirror" { } ''
    mkdir $out
    for y in $(seq 2020 2045) modified; do
      gzip -c ${feed} > $out/nvdcve-2.0-$y.json.gz
    done
  '';
  mirrorUrl = "http://127.0.0.1:8000/";

  # NixOS configuration serving it on loopback.
  node = {
    environment.systemPackages = [ pkgs.busybox ];
    systemd.services.fake-nvd = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8000 --bind 127.0.0.1 --directory ${mirror}";
    };
  };
}
