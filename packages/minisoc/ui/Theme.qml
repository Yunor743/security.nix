import QtQuick

// Resolved look & layout: profile defaults < ui.json overrides.
QtObject {
    id: t
    property var cfg: ({})

    readonly property var profiles: ({
        compact: { width: 360, detailsWidth: 520, visibleEvents: 5, maxHeight: 560, showStats: false, manageOpen: false },
        desktop: { width: 440, detailsWidth: 600, visibleEvents: 10, maxHeight: 760, showStats: true, manageOpen: false },
        analyst: { width: 520, detailsWidth: 680, visibleEvents: 20, maxHeight: 1000, showStats: true, manageOpen: true }
    })

    function pick(key, dflt) {
        const v = cfg[key];
        if (v !== undefined && v !== null) return v;
        const p = profiles[profile] || profiles.desktop;
        return p[key] !== undefined ? p[key] : dflt;
    }
    function color(key, dflt) {
        const c = cfg.colors || {};
        return c[key] !== undefined && c[key] !== null ? c[key] : dflt;
    }

    readonly property string profile: profiles[cfg.profile] ? cfg.profile : "desktop"
    readonly property int width: pick("width", 440)
    readonly property int detailsWidth: pick("detailsWidth", 600)
    readonly property int visibleEvents: pick("visibleEvents", 10)
    readonly property int maxHeight: pick("maxHeight", 760)
    readonly property bool showStats: pick("showStats", true)
    readonly property bool manageOpen: pick("manageOpen", false)
    // "minimal": text lines over the wallpaper; "panel": framed FUI panel.
    readonly property bool minimal: (cfg.style || "minimal") !== "panel"
    readonly property string position: cfg.position || "bottom-left"
    readonly property bool bottomUp: position.startsWith("bottom")
    readonly property bool rightAligned: position.endsWith("right")
    readonly property string layer: cfg.layer || "bottom"
    readonly property int margin: cfg.margin !== undefined ? cfg.margin : 24
    function side(s) {
        const m = cfg.margins || {};
        return m[s] !== undefined && m[s] !== null ? m[s] : margin;
    }
    readonly property int marginTop: side("top")
    readonly property int marginBottom: side("bottom")
    readonly property int marginLeft: side("left")
    readonly property int marginRight: side("right")
    // Background of the compact view (0 = fully transparent in minimal).
    readonly property real opacity: cfg.opacity !== undefined ? cfg.opacity : (minimal ? 0 : 0.9)
    // Resting opacity of alert text in minimal style (1 on hover).
    readonly property real textOpacity: cfg.textOpacity !== undefined ? cfg.textOpacity : 0.72
    readonly property real detailsOpacity: cfg.detailsOpacity !== undefined ? cfg.detailsOpacity : 0.92
    readonly property string screen: cfg.screen || ""

    readonly property string font: cfg.font || "sans-serif"
    readonly property string mono: cfg.monoFont || "monospace"
    readonly property int fontSize: cfg.fontSize || 11
    readonly property int radius: cfg.radius !== undefined ? cfg.radius : 0

    readonly property color bg: color("background", "#000000")
    readonly property color panel: color("panel", "#0b0c0e")
    readonly property color border: color("border", "#24272c")
    readonly property color fg: color("foreground", "#e9ecef")
    readonly property color muted: color("muted", "#7d838b")
    readonly property color accent: color("accent", "#4d9fff")
    readonly property color ai: color("ai", "#a98bff")
    readonly property color critical: color("critical", "#ff3b4a")
    readonly property color high: color("high", "#ff8a1f")
    readonly property color medium: color("medium", "#f2c94c")
    readonly property color low: color("low", "#4d9fff")
    readonly property color info: color("info", "#9aa3ad")
    readonly property color unknown: color("unknown", "#5c636b")
    readonly property color shadow: color("shadow", "#c0000000")

    function sev(s) {
        return ({ critical: critical, high: high, medium: medium, low: low, info: info })[s] || unknown;
    }
    function sevShort(s) {
        return ({ critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO" })[s] || "UNK";
    }
}
