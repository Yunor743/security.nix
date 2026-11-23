# MiniSOC example (system part). Import it next to fortress.nix; the flake
# already provides the security.nix module and overlay. The widget is
# configured with Home Manager, see docs/minisoc.md.
{ ... }:

{
  services.rustinel.enable = true;
  services.ollama.enable = true;

  services.minisoc = {
    enable = true;
    users = [ "admin" ];

    # Rustinel alerts are collected automatically; add any other log here.
    sources.applicationA = {
      paths = [ "/var/log/applicationA/*.log" ];
      parser = "grok";
      pattern = "%{TIMESTAMP_ISO8601:timestamp} %{IP:ip} %{WORD:level} %{GREEDYDATA:message}";
    };

    # Read-only rules, validated at build time.
    filter.systemRules = [
      {
        id = "rustinel_whoami_demo";
        description = "Demo Sigma rule shipped with the Rustinel module";
        match = {
          source = "rustinel";
          message.contains = "Whoami Execution";
        };
        action = "exclude";
      }
    ];

    # Optional local LLM analysis: nothing leaves the machine.
    ai = {
      enable = true;
      provider = "ollama";
      model = "qwen3:8b";
      analysis = {
        minimumSeverity = "medium";
        autoDiscard = true; # suggest mode: proposals wait for confirmation
      };
      autoFilter.enable = true; # suggest mode
    };
  };
}
