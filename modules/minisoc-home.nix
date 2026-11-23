# Home Manager module: MiniSOC desktop widget + per-user rules/prompts.
# The system part (collector, engine) lives in the NixOS module; this one is
# optional and never needs root.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.minisoc;

  uiConfig = lib.filterAttrs (_: v: v != null && v != { }) {
    inherit (cfg.ui)
      profile
      position
      layer
      margin
      opacity
      textOpacity
      detailsOpacity
      style
      margins
      screen
      font
      monoFont
      fontSize
      radius
      width
      detailsWidth
      visibleEvents
      maxHeight
      notify
      colors
      ;
  };

  rulesFile = "${config.xdg.configHome}/minisoc/alert_filter.yaml";

  seedRules = pkgs.runCommandLocal "minisoc-seed-rules.yaml" { } ''
    cp ${
      (pkgs.formats.yaml { }).generate "alert_filter.yaml" {
        version = 1;
        filters = cfg.filter.initialRules;
      }
    } $out
    ${lib.getExe cfg.cliPackage} --config /dev/null filter validate $out
  '';
in
{
  options.programs.minisoc = {
    enable = lib.mkEnableOption "the MiniSOC desktop widget";

    package = lib.mkPackageOption pkgs "minisoc-ui" { };
    cliPackage = lib.mkPackageOption pkgs "minisoc" { };

    ui = {
      autostart = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Start the widget with the graphical session (systemd user service).";
      };
      systemdTarget = lib.mkOption {
        type = lib.types.str;
        default = "graphical-session.target";
        description = ''
          Target the widget is bound to. Compositors started without
          systemd integration (no graphical-session.target) can instead run
          `minisoc-ui` from their autostart (e.g. Hyprland `exec-once`).
        '';
      };
      profile = lib.mkOption {
        type = lib.types.enum [
          "compact"
          "desktop"
          "analyst"
        ];
        default = "desktop";
        description = "`compact` (5 alerts), `desktop` (10 + stats), `analyst` (20 + management panel open, wide details).";
      };
      position = lib.mkOption {
        type = lib.types.enum [
          "top-left"
          "top-right"
          "bottom-left"
          "bottom-right"
        ];
        default = "bottom-left";
        description = ''
          Screen corner. In a bottom corner the widget grows upwards and the
          newest alert sits at the bottom of the stack, closest to the corner.
        '';
      };
      style = lib.mkOption {
        type = lib.types.enum [
          "minimal"
          "panel"
        ];
        default = "minimal";
        description = ''
          `minimal`: discreet text lines over the wallpaper (no title, no
          frame; details and actions on hover). `panel`: framed FUI panel
          with severity tiles.
        '';
      };
      layer = lib.mkOption {
        type = lib.types.enum [
          "background"
          "bottom"
          "top"
          "overlay"
        ];
        default = "bottom";
        description = "Layer-shell layer: `bottom` = desktop widget under windows, `top` = always visible.";
      };
      margin = lib.mkOption {
        type = lib.types.int;
        default = 24;
      };
      opacity = lib.mkOption {
        type = lib.types.nullOr lib.types.float;
        default = null;
        description = "Background opacity of the compact view (default: 0 in minimal style, 0.9 in panel style).";
      };
      textOpacity = lib.mkOption {
        type = lib.types.nullOr lib.types.float;
        default = null;
        description = "Resting opacity of alert text in minimal style (default 0.72; 1 on hover).";
      };
      detailsOpacity = lib.mkOption {
        type = lib.types.nullOr lib.types.float;
        default = null;
        description = "Background opacity of the details view (default 0.92).";
      };
      margins = lib.mkOption {
        type = lib.types.submodule {
          options = lib.genAttrs [ "top" "right" "bottom" "left" ] (
            side:
            lib.mkOption {
              type = lib.types.nullOr lib.types.int;
              default = null;
              description = "Distance to the  screen edge (default: `margin`).";
            }
          );
        };
        default = { };
        example = {
          left = 72;
        };
        description = "Per-side margins, e.g. to clear a vertical bar.";
      };
      screen = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "DP-1";
        description = "Output name (default: the compositor's choice).";
      };
      font = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "Inter";
      };
      monoFont = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "JetBrains Mono";
      };
      fontSize = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
      };
      radius = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
        description = "Corner radius (default 0: rectangular).";
      };
      width = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
        description = "Compact column width (default from the profile).";
      };
      detailsWidth = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
        description = "Extra width taken by the details view when an alert is opened.";
      };
      maxHeight = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
      };
      visibleEvents = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = null;
      };
      notify = lib.mkOption {
        type = lib.types.submodule {
          options = {
            enable = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Send a desktop notification (`notify-send`) for every new visible alert.";
            };
            minimumSeverity = lib.mkOption {
              type = lib.types.enum [
                "info"
                "low"
                "medium"
                "high"
                "critical"
              ];
              default = "low";
              description = "Notify only for alerts at least this severe (default: every detection).";
            };
          };
        };
        default = { };
        description = "Desktop notifications for new alerts (urgency and icon follow the severity).";
      };
      colors = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = {
          accent = "#4d9fff";
          background = "#000000";
        };
        description = ''
          Overrides among: background, panel, border, foreground, muted,
          accent, ai, critical, high, medium, low, info, unknown.
        '';
      };
    };

    filter.initialRules = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.attrs);
      default = null;
      description = ''
        Rules written to `~/.config/minisoc/alert_filter.yaml` (0600) only if
        that file does not exist yet: an existing file — which you, "Create
        filter" or the AI may have changed — is never overwritten.
      '';
    };

    prompts = lib.mkOption {
      type = lib.types.attrsOf lib.types.lines;
      default = { };
      example = {
        analysis = "Analyze the alert below...";
      };
      description = ''
        Prompt overrides installed in `~/.config/minisoc/prompts/<name>.md`
        (system, analysis, enrichment, classification, filter). They are
        managed (read-only); leave a prompt out to edit it from the UI.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [
      cfg.package
      cfg.cliPackage
    ];

    xdg.configFile = {
      "minisoc/ui.json".text = builtins.toJSON uiConfig;
    }
    // lib.mapAttrs' (
      n: text: lib.nameValuePair "minisoc/prompts/${n}.md" { inherit text; }
    ) cfg.prompts;

    home.activation.minisocSeedRules = lib.mkIf (cfg.filter.initialRules != null) (
      lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        if [ ! -e "${rulesFile}" ]; then
          run install -d -m 0700 "$(dirname "${rulesFile}")"
          run install -m 0600 ${seedRules} "${rulesFile}"
        fi
      ''
    );

    systemd.user.services.minisoc-ui = lib.mkIf cfg.ui.autostart {
      Unit = {
        Description = "MiniSOC desktop widget";
        PartOf = [ cfg.ui.systemdTarget ];
        After = [ cfg.ui.systemdTarget ];
      };
      Service = {
        ExecStart = lib.getExe cfg.package;
        Restart = "on-failure";
        RestartSec = 3;
      };
      Install.WantedBy = [ cfg.ui.systemdTarget ];
    };
  };
}
