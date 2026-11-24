// MiniSOC desktop widget (Quickshell). Read-only view of the engine state
// ($XDG_RUNTIME_DIR/minisoc/state.json); every action goes through the
// `minisoc` CLI as the current user. Never runs as root.
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland

ShellRoot {
    id: root

    readonly property string bin: Quickshell.env("MINISOC_BIN") || "minisoc"
    readonly property string home: Quickshell.env("HOME") || ""
    readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || "/tmp"
    readonly property string statePath: Quickshell.env("MINISOC_STATE") || (runtimeDir + "/minisoc/state.json")
    readonly property string uiConfigPath: Quickshell.env("MINISOC_UI_CONFIG")
        || ((Quickshell.env("XDG_CONFIG_HOME") || (home + "/.config")) + "/minisoc/ui.json")

    property var st: ({})
    property string selectedId: ""
    property var details: null
    property string draft: ""
    property string note: ""
    property bool manageOpen: th.manageOpen
    // Opening the panel in a bottom corner: show its tabs (anchored edge).
    onManageOpenChanged: if (th.bottomUp) { flick.stick = true; Qt.callLater(flick.follow); }
    property string profileOverride: ""
    property real now: Date.now()
    // Alerts closed (TP/FP) from the widget, hidden at once (before the
    // engine republishes its state).
    property var hidden: ({})

    // Last state publication (kept apart from `st` so liveness updates do
    // not rebuild the lists).
    property string generatedAt: ""
    property string stateKey: ""
    readonly property bool engineAlive: generatedAt !== "" && (now - new Date(generatedAt).getTime()) < 45000
    readonly property bool expanded: selectedId !== ""

    function shown(list) {
        return (list || []).filter(e => !e.closed && !e.discarded && !root.hidden[e.id]);
    }
    readonly property var pinnedList: shown(st.pinned)
    readonly property var recentList: shown(st.recent).slice(0, th.visibleEvents)
    // Bottom corners: newest alert closest to the corner.
    readonly property var recentOrdered: th.bottomUp ? recentList.slice().reverse() : recentList

    Theme { id: th }

    function applyUi(text) {
        let c = {};
        try { c = JSON.parse(text || "{}"); } catch (e) { console.warn("minisoc: invalid ui.json: " + e); }
        if (root.profileOverride !== "") c.profile = root.profileOverride;
        th.cfg = c;
    }

    FileView {
        id: uiFile
        path: root.uiConfigPath
        watchChanges: true
        printErrors: false
        onFileChanged: reload()
        onLoaded: root.applyUi(text())
        onLoadFailed: root.applyUi("{}")
    }
    FileView {
        id: stateFile
        path: root.statePath
        watchChanges: true
        printErrors: false
        onFileChanged: reload()
        onLoaded: {
            const t = text();
            let parsed;
            try { parsed = JSON.parse(t); } catch (e) { return; }
            root.generatedAt = parsed.generated_at || "";
            // The engine republishes periodically: only apply real changes,
            // otherwise every list is rebuilt (scroll position, hover lost).
            const key = t.replace(/"generated_at":"[^"]*"/, "");
            if (key === root.stateKey) return;
            root.stateKey = key;
            root.st = parsed;
            // Forget local hides the engine has caught up with.
            const live = new Set([...(root.st.pinned || []), ...(root.st.recent || [])].filter(e => !e.discarded).map(e => e.id));
            const h = {};
            for (const id in root.hidden) if (live.has(id)) h[id] = true;
            root.hidden = h;
            root.notifyAlerts(parsed);
            if (root.selectedId !== "") root.loadDetails();
        }
    }
    Timer { // fallback when the state file is (re)created, and liveness clock
        interval: 5000; running: true; repeat: true
        onTriggered: {
            root.now = Date.now();
            stateFile.reload();
            // Home Manager swaps the ui.json symlink: no change event
            uiFile.reload();
        }
    }

    // ---------------------------------------------------------------- actions
    function run(args) { Quickshell.execDetached([root.bin].concat(args)); refresh.restart(); }

    // ---------------------------------------------- notify-send per detection
    // First state load only learns what already exists (no startup spam);
    // every later change notifies for unseen active alerts. Severity ranks
    // gate the noise; critical gets a sticky notification.
    property bool notifyInit: false
    property var seenAlerts: ({})

    function notifyAlerts(st) {
        const nc = (th.cfg && th.cfg.notify) ? th.cfg.notify : {};
        const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
        const want = rank[nc.minimumSeverity] !== undefined ? rank[nc.minimumSeverity] : 1;
        const fresh = [];
        for (const e of (st.recent || [])) {
            if (!e || !e.id || root.seenAlerts[e.id]) continue;
            root.seenAlerts[e.id] = true;
            if (!root.notifyInit) continue;
            if (e.discarded || e.filtered_by) continue;
            const r = rank[e.severity] !== undefined ? rank[e.severity] : -1;
            if (r < want) continue;
            fresh.push(e);
        }
        // Event ids are unique and stable (a recurring pattern keeps its id):
        // keep the seen set until a size cap, so an alert leaving and coming
        // back to the exported window is never notified twice.
        const ids = Object.keys(root.seenAlerts);
        if (ids.length > 2000) {
            const keep = new Set(ids.slice(ids.length - 1000));
            const s = {};
            for (const id of keep) s[id] = true;
            root.seenAlerts = s;
        }
        fresh.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
        for (const e of fresh) {
            const icons = { critical: "dialog-error", high: "dialog-warning", medium: "dialog-warning" };
            const urgent = e.severity === "critical" || e.severity === "high";
            Quickshell.execDetached(["notify-send",
                "--app-name=MiniSOC",
                "--icon=" + (icons[e.severity] || "dialog-information"),
                "--urgency=" + (urgent ? "critical" : "normal"),
                "--expire-time=" + (urgent ? 0 : 8000),
                (e.severity || "?").toUpperCase() + " - " + (e.source || "minisoc"),
                e.message || ""]);
        }
        root.notifyInit = true;
    }
    Timer { id: refresh; interval: 700; onTriggered: { stateFile.reload(); if (root.selectedId !== "") root.loadDetails(); } }

    function select(id) {
        if (root.selectedId === id) { root.close(); return; }
        root.draft = ""; root.note = "";
        root.details = null;
        root.selectedId = id;
        root.loadDetails();
    }
    function close() { root.selectedId = ""; root.details = null; root.draft = ""; root.note = ""; }
    function loadDetails() {
        if (showProc.running) return;
        showProc.command = [root.bin, "show", root.selectedId, "--json"];
        showProc.running = true;
    }

    function onAction(name, arg) {
        switch (name) {
        case "details": root.select(arg); break;
        case "close": root.close(); break;
        case "pin": case "unpin": root.run([name, arg]); break;
        case "restore": case "reopen": root.run(["reopen", arg]); break;
        // Close with a verdict: true positive (real) / false positive (noise).
        case "discard": case "tp": case "fp": {
            const h = Object.assign({}, root.hidden);
            h[arg] = true;
            root.hidden = h;
            if (root.selectedId === arg) root.close();
            root.run([name === "tp" ? "tp" : "fp", arg]);
            break;
        }
        case "discard-all": case "fp-all": {
            // Pinned alerts are kept (engine side too).
            const h = Object.assign({}, root.hidden);
            for (const e of root.shown(root.st.recent)) h[e.id] = true;
            root.hidden = h;
            if (root.selectedId !== "" && h[root.selectedId]) root.close();
            root.run(["fp", "--all"]);
            break;
        }
        case "ai": root.run(["analyze", arg]); root.note = "Analysis requested — results appear here when ready."; break;
        case "filter": root.select(arg); root.onAction("draft", arg); break;
        case "draft":
            draftProc.command = [root.bin, "filter", "draft", arg];
            draftProc.running = true; break;
        case "cancel-draft": root.draft = ""; break;
        case "create-filter": root.run(["filter", "create", arg]); root.draft = ""; root.note = "Rule added — the engine reloads it within a second."; break;
        case "explain":
            explainProc.command = [root.bin, "explain", arg];
            explainProc.running = true; break;
        case "accept": case "reject": root.run(["proposal", name, arg]); break;
        case "rollback": root.run(["filter", "rollback"]); break;
        case "open-rules":
            Quickshell.execDetached(["xdg-open", (st.filter || {}).user_file || ""]); break;
        case "open-ai-rules":
            Quickshell.execDetached(["xdg-open", (st.filter || {}).ai_file || ""]); break;
        case "edit-prompt": Quickshell.execDetached([root.bin, "prompts", "edit", arg]); break;
        }
    }

    Process {
        id: showProc
        stdout: StdioCollector {
            onStreamFinished: { try { root.details = JSON.parse(this.text); } catch (e) { root.details = null; } }
        }
    }
    Process {
        id: draftProc
        stdout: StdioCollector { onStreamFinished: root.draft = this.text }
        stderr: StdioCollector { onStreamFinished: if (this.text) root.note = this.text }
    }
    Process {
        id: explainProc
        stdout: StdioCollector { onStreamFinished: root.note = this.text }
    }

    // -------------------------------------------------------------------- IPC
    // `qs ipc -p <ui dir> call minisoc <fn>`: used by the VM test and handy
    // for keybindings (e.g. toggle the management panel).
    IpcHandler {
        target: "minisoc"
        function details(id: string): void { root.selectedId = ""; root.select(id); }
        function close(): void { root.close(); }
        function tp(id: string): void { root.onAction("tp", id); }
        function fp(id: string): void { root.onAction("fp", id); }
        function closeAllFp(): void { root.onAction("fp-all", ""); }
        // Former names (keybindings written against them).
        function discard(id: string): void { root.onAction("fp", id); }
        function discardAll(): void { root.onAction("fp-all", ""); }
        function toggleManage(): void { root.manageOpen = !root.manageOpen; }
        function setProfile(p: string): void { root.profileOverride = p; root.applyUi(uiFile.text()); }
        function windowWidth(): int { return win.implicitWidth; }
        function expanded(): bool { return root.expanded; }
        function detailsLoaded(): bool { return root.details !== null && root.details.id === root.selectedId; }
        function pinnedCount(): int { return root.pinnedList.length; }
        function shownCount(): int { return root.pinnedList.length + root.recentList.length; }
        function activeCount(): int { return ((root.st.counts || {}).active) || 0; }
    }

    // ----------------------------------------------------------------- window
    PanelWindow {
        id: win
        screen: {
            if (th.screen === "") return null;
            for (const s of Quickshell.screens) if (s.name === th.screen) return s;
            return null;
        }
        anchors {
            top: !th.bottomUp
            bottom: th.bottomUp
            left: !th.rightAligned
            right: th.rightAligned
        }
        margins { top: th.marginTop; bottom: th.marginBottom; left: th.marginLeft; right: th.marginRight }
        exclusionMode: ExclusionMode.Ignore
        focusable: false
        color: "transparent"
        WlrLayershell.namespace: "minisoc"
        WlrLayershell.layer: ({ background: WlrLayer.Background, bottom: WlrLayer.Bottom, top: WlrLayer.Top, overlay: WlrLayer.Overlay })[th.layer] ?? WlrLayer.Bottom

        readonly property int pad: th.minimal ? 4 : 10
        implicitWidth: th.width + (root.expanded ? th.detailsWidth + 8 : 0)
        // Fixed height: resizing a layer surface on expand made the list jump.
        // The mask keeps the transparent rest of the window click-through.
        implicitHeight: th.maxHeight
        mask: Region {
            item: flick
            regions: [
                Region { item: root.expanded ? details : null }
            ]
        }
        Behavior on implicitWidth { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }

        RowLayout {
            anchors.fill: parent
            spacing: 8
            layoutDirection: th.rightAligned ? Qt.RightToLeft : Qt.LeftToRight

            // ---------------------------------------------- compact view
            Item {
                id: compact
                Layout.preferredWidth: th.width
                Layout.fillHeight: true
                HoverHandler { id: compactHover }

                Rectangle { // panel style frame (and optional minimal backdrop)
                    anchors.fill: flick
                    anchors.margins: -win.pad
                    visible: !th.minimal || th.opacity > 0 || root.manageOpen
                    // Management panel: readable backdrop even in minimal style
                    color: Qt.alpha(th.bg, th.minimal && root.manageOpen ? Math.max(th.opacity, 0.85) : th.opacity)
                    border.width: th.minimal ? 0 : 1
                    border.color: th.border
                    radius: th.radius

                    Repeater { // FUI corner brackets (panel style)
                        model: th.minimal ? 0 : 4
                        Item {
                            required property int index
                            width: 10; height: 10
                            x: index % 2 === 0 ? -1 : parent.width - 9
                            y: index < 2 ? -1 : parent.height - 9
                            Rectangle { width: 10; height: 1; color: th.accent; y: index < 2 ? 0 : 9 }
                            Rectangle { width: 1; height: 10; color: th.accent; x: index % 2 === 0 ? 0 : 9 }
                        }
                    }
                }

                Flickable {
                    id: flick
                    x: win.pad
                    width: parent.width - 2 * win.pad
                    height: Math.min(parent.height - 2 * win.pad, main.implicitHeight)
                    // Stick to the anchored corner.
                    y: th.bottomUp ? parent.height - height - win.pad : win.pad
                    contentHeight: main.implicitHeight
                    // Follow the anchored corner unless the user scrolled away.
                    property bool stick: true
                    property bool adjusting: false
                    function follow() {
                        if (!th.bottomUp || !stick) return;
                        adjusting = true;
                        contentY = Math.max(0, contentHeight - height);
                        adjusting = false;
                    }
                    onContentHeightChanged: follow()
                    onHeightChanged: follow()
                    onContentYChanged: if (!adjusting) stick = contentY >= contentHeight - height - 4
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds

                    ColumnLayout {
                        id: main
                        width: parent.width
                        spacing: th.minimal ? 4 : 6

                        // Order: summary at the anchored edge, pinned, the
                        // feed. The management panel sits next to the
                        // summary: in bottom corners its tabs are just above
                        // the summary line (reachable without scrolling)
                        // and its content grows upwards.
                        Summary { visible: !th.bottomUp }
                        AlertList {
                            Layout.fillWidth: true
                            visible: root.pinnedList.length > 0
                            theme: th; model: root.pinnedList; selectedId: root.selectedId; rightAligned: th.rightAligned
                            onAction: (n, id) => root.onAction(n, id)
                        }
                        Rectangle { // pinned / feed separator
                            visible: th.minimal && root.pinnedList.length > 0 && root.recentList.length > 0
                            Layout.fillWidth: true; height: 1
                            color: Qt.alpha(th.accent, 0.25)
                        }
                        AlertList {
                            Layout.fillWidth: true
                            theme: th; model: root.recentOrdered; selectedId: root.selectedId; rightAligned: th.rightAligned
                            onAction: (n, id) => root.onAction(n, id)
                        }
                        ManagePanel {
                            visible: root.manageOpen && th.bottomUp
                            Layout.fillWidth: true
                            tabsAtBottom: true
                            theme: th; st: root.st; selectedId: root.selectedId
                            onAction: (n, a) => root.onAction(n, a)
                        }
                        Summary { visible: th.bottomUp }
                        ManagePanel {
                            visible: root.manageOpen && !th.bottomUp
                            Layout.fillWidth: true
                            theme: th; st: root.st; selectedId: root.selectedId
                            onAction: (n, a) => root.onAction(n, a)
                        }
                    }
                }
            }

            // ---------------------------------------------- details (expands)
            DetailsPane {
                id: details
                visible: root.expanded
                Layout.preferredWidth: th.detailsWidth
                Layout.fillHeight: true
                theme: th
                ev: root.details
                draft: root.draft
                note: root.note
                aiEnabled: (root.st.ai || {}).enabled === true
                onAction: (n, id) => root.onAction(n, id)
            }
        }
    }

    // Status line: engine state, non-zero counters, management toggle.
    component Summary: RowLayout {
        Layout.fillWidth: true
        spacing: 10
        layoutDirection: th.rightAligned ? Qt.RightToLeft : Qt.LeftToRight
        readonly property var bySev: ((root.st.counts || {}).active_by_severity) || ({})

        Rectangle {
            width: 6; height: 6; radius: th.minimal ? 3 : th.radius
            color: !root.engineAlive ? th.unknown : (parent.bySev.critical || 0) > 0 ? th.critical : th.accent
            SequentialAnimation on opacity {
                running: root.engineAlive; loops: Animation.Infinite
                NumberAnimation { to: 0.25; duration: 1400 }
                NumberAnimation { to: 0.9; duration: 1400 }
            }
        }
        Repeater {
            model: ["critical", "high", "medium", "low", "info", "unknown"]
            Text {
                required property string modelData
                readonly property int n: parent.bySev[modelData] || 0
                visible: n > 0
                text: n + " " + th.sevShort(modelData).toLowerCase()
                color: th.sev(modelData)
                opacity: compactHover.hovered ? 1 : th.textOpacity
                font.family: th.mono; font.pixelSize: th.fontSize - 2; font.letterSpacing: 1
                style: Text.Raised; styleColor: th.shadow
            }
        }
        Text {
            visible: !root.engineAlive || (root.st.filter !== undefined && root.st.filter.ok === false)
            text: !root.engineAlive ? "engine offline" : "rules file rejected · last valid version in force"
            color: th.high; font.family: th.mono; font.pixelSize: th.fontSize - 2
            style: Text.Raised; styleColor: th.shadow
        }
        Text {
            visible: root.engineAlive && root.pinnedList.length + root.recentList.length === 0
            text: "no active alert"
            color: th.muted; font.family: th.mono; font.pixelSize: th.fontSize - 2
            opacity: th.textOpacity
            style: Text.Raised; styleColor: th.shadow
        }
        Item { Layout.fillWidth: true }
        Text { // close every active alert as FP (pinned kept); second click confirms
            id: discardAll
            property bool armed: false
            visible: root.recentList.length > 0 && (!th.minimal || compactHover.hovered || armed)
            text: armed ? "confirm: close all as FP?" : "close all as FP"
            color: armed ? th.high : (discardAllMa.containsMouse ? th.fg : th.muted)
            font.family: th.mono; font.pixelSize: th.fontSize - 2; font.letterSpacing: 1
            style: Text.Raised; styleColor: th.shadow
            Timer { id: disarmAll; interval: 3000; onTriggered: discardAll.armed = false }
            MouseArea {
                id: discardAllMa
                anchors.fill: parent; anchors.margins: -4
                hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: {
                    if (!discardAll.armed) { discardAll.armed = true; disarmAll.restart(); return; }
                    discardAll.armed = false;
                    root.onAction("fp-all", "");
                }
            }
        }
        Text { // management panel toggle, only on hover in minimal style
            visible: !th.minimal || compactHover.hovered || root.manageOpen
            text: root.manageOpen ? "×" : "⋯"
            color: toggleMa.containsMouse ? th.fg : th.muted
            font.family: th.mono; font.pixelSize: th.fontSize + 1
            style: Text.Raised; styleColor: th.shadow
            MouseArea { id: toggleMa; anchors.fill: parent; anchors.margins: -4; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.manageOpen = !root.manageOpen }
        }
    }
}
