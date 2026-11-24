import QtQuick
import QtQuick.Layouts

// Full view of one alert. Original data, normalized data and AI-produced
// content are visually separated (AI sections use the `ai` color and are
// labelled with the provider/model).
Rectangle {
    id: d
    property var theme
    property var ev: null       // output of `minisoc show <id> --json`
    property string draft: ""   // YAML preview of "Create filter"
    property string note: ""    // explain output, action feedback
    property bool aiEnabled: false
    signal action(string name, string id)

    color: Qt.alpha(theme.panel, theme.detailsOpacity)
    border.width: 1
    border.color: theme.minimal ? Qt.alpha(theme.border, 0.6) : theme.border
    radius: theme.radius

    readonly property var an: ev && ev.analysis_full ? ev.analysis_full : null
    readonly property var res: an ? an.result : null

    function flatten(obj, depth, out) {
        if (out === undefined) out = [];
        const keys = Object.keys(obj || {});
        for (const k of keys) {
            const v = obj[k];
            if (v !== null && typeof v === "object" && !(Array.isArray(v) && v.every(x => x === null || typeof x !== "object"))) {
                out.push({ depth: depth, key: k, value: Array.isArray(v) ? "[" + v.length + "]" : "", container: true });
                flatten(v, depth + 1, out);
            } else {
                out.push({ depth: depth, key: k, value: Array.isArray(v) ? v.join(", ") : String(v), container: false });
            }
        }
        return out;
    }

    component Section: Text {
        property color tint: d.theme.muted
        color: tint; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2
        font.letterSpacing: 2; font.bold: true
        Layout.topMargin: 8
    }
    component Kv: RowLayout {
        property string k
        property string v
        property color vc: d.theme.fg
        visible: v !== "" && v !== "undefined" && v !== "null"
        Layout.fillWidth: true
        spacing: 8
        Text { text: parent.k; color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 1; Layout.preferredWidth: 110; Layout.alignment: Qt.AlignTop }
        Text { text: parent.v; color: parent.vc; font.family: d.theme.font; font.pixelSize: d.theme.fontSize; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText }
    }
    component Bullets: ColumnLayout {
        property string title
        property var items: []
        visible: items && items.length > 0
        Layout.fillWidth: true
        spacing: 1
        Text { text: parent.title; color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2 }
        Repeater {
            model: parent.items || []
            Text { required property string modelData; text: "· " + modelData; color: d.theme.fg; font.pixelSize: d.theme.fontSize; font.family: d.theme.font; wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText }
        }
    }

    Flickable {
        id: flick
        anchors.fill: parent
        anchors.margins: 12
        contentHeight: body.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: body
            width: flick.width
            spacing: 4

            RowLayout {
                Layout.fillWidth: true
                Rectangle { width: 10; height: 10; color: d.theme.sev(d.ev ? d.ev.severity : ""); radius: d.theme.radius }
                Text {
                    text: d.ev ? (d.ev.severity || "").toUpperCase() + " · " + (d.ev.source || "").toUpperCase() + " · " + (d.ev.event_type || "") : "LOADING…"
                    color: d.theme.fg; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize; font.letterSpacing: 1
                    Layout.fillWidth: true; elide: Text.ElideRight
                }
                Btn { theme: d.theme; label: "✕ CLOSE"; onClicked: d.action("close", "") }
            }
            Text {
                visible: d.ev !== null
                text: d.ev ? d.ev.message : ""
                color: d.theme.fg; font.family: d.theme.font; font.pixelSize: d.theme.fontSize + 2
                wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText
            }

            RowLayout {
                visible: d.ev !== null
                spacing: 4
                Btn { theme: d.theme; label: d.ev && d.ev.pinned ? "UNPIN" : "PIN"; tint: d.theme.accent
                      onClicked: d.action(d.ev.pinned ? "unpin" : "pin", d.ev.id) }
                Btn { theme: d.theme; label: "TP"; tint: d.theme.high; visible: d.ev && d.ev.verdict !== "tp"
                      onClicked: d.action("tp", d.ev.id) }
                Btn { theme: d.theme; label: "FP"; visible: d.ev && d.ev.verdict !== "fp"
                      onClicked: d.action("fp", d.ev.id) }
                Btn { theme: d.theme; label: "REOPEN"; tint: d.theme.accent; visible: d.ev && d.ev.closed === true
                      onClicked: d.action("reopen", d.ev.id) }
                Btn { theme: d.theme; label: "CREATE FILTER"; onClicked: d.action("draft", d.ev.id) }
                Btn { theme: d.theme; label: d.an ? "RE-ANALYZE" : "ANALYZE"; tint: d.theme.ai; visible: d.aiEnabled
                      onClicked: d.action("ai", d.ev.id) }
                Btn { theme: d.theme; label: "EXPLAIN"; onClicked: d.action("explain", d.ev.id) }
            }

            Text {
                visible: d.note !== ""
                text: d.note
                color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2
                wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText
            }

            // ---- Create filter preview
            Rectangle {
                visible: d.draft !== ""
                Layout.fillWidth: true
                implicitHeight: draftCol.implicitHeight + 12
                color: Qt.alpha(d.theme.accent, 0.06); border.width: 1; border.color: d.theme.accent; radius: d.theme.radius
                ColumnLayout {
                    id: draftCol
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 6 }
                    Text { text: "NEW EXCLUSION RULE (appended to your alert_filter.yaml, backup kept)"; color: d.theme.accent; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2; wrapMode: Text.Wrap; Layout.fillWidth: true }
                    Text { text: d.draft; color: d.theme.fg; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 1; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText }
                    RowLayout {
                        Btn { theme: d.theme; label: "ADD RULE"; tint: d.theme.accent; confirm: true; onClicked: d.action("create-filter", d.ev.id) }
                        Btn { theme: d.theme; label: "CANCEL"; onClicked: d.action("cancel-draft", "") }
                    }
                }
            }

            Section { text: "EVENT" }
            Kv { k: "id"; v: d.ev ? d.ev.id : "" }
            Kv { k: "time"; v: d.ev ? d.ev.timestamp : "" }
            Kv { k: "severity"; v: d.ev ? d.ev.severity : ""; vc: d.theme.sev(d.ev ? d.ev.severity : "") }
            Kv { k: "type"; v: d.ev ? d.ev.event_type : "" }
            Kv { k: "source"; v: d.ev ? d.ev.source + (d.ev.meta && d.ev.meta.file ? "  (" + d.ev.meta.file + ")" : "") : "" }
            Kv { k: "occurrences"; v: d.ev ? d.ev.occurrences + "  (first " + d.ev.first_seen + ", last " + d.ev.last_seen + ")" : "" }
            Kv { k: "similar"; v: d.ev && d.ev.similar ? d.ev.similar.events + " event(s), " + d.ev.similar.occurrences + " occurrence(s)" : "" }
            Kv {
                k: "state"
                v: d.ev ? [d.ev.pinned ? "pinned" : "",
                           d.ev.closed ? "closed as " + (d.ev.verdict === "tp" ? "true" : "false") + " positive by " + d.ev.closed_by : "",
                           d.ev.filtered_by ? "filtered" : "", d.ev.analyzed ? "analyzed" : "",
                           (!d.ev.closed && !d.ev.filtered_by) ? "active" : ""].filter(x => x).join(", ") : ""
            }

            Section { text: "FILTERING"; visible: d.ev && d.ev.filter_rule !== undefined }
            Kv { k: "excluded by"; v: d.ev && d.ev.filter_rule ? d.ev.filter_rule.id + (d.ev.filter_rule.generated_by ? "  [" + d.ev.filter_rule.generated_by + "]" : "") : "" }
            Kv { k: "rule"; v: d.ev && d.ev.filter_rule ? (d.ev.filter_rule.description || "") : "" }
            Kv { k: "match"; v: d.ev && d.ev.filter_rule && d.ev.filter_rule.match ? JSON.stringify(d.ev.filter_rule.match) : "" }

            // ---- AI analysis: distinct frame and color
            Rectangle {
                visible: d.res !== null
                Layout.fillWidth: true
                Layout.topMargin: 8
                implicitHeight: aiCol.implicitHeight + 14
                color: Qt.alpha(d.theme.ai, 0.07)
                border.width: 1; border.color: Qt.alpha(d.theme.ai, 0.7); radius: d.theme.radius
                ColumnLayout {
                    id: aiCol
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 7 }
                    spacing: 3
                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "AI ANALYSIS · SOC N1 · " + (d.an ? (d.an.provider + "/" + d.an.model) : "") + (d.an && d.an.cached ? " · cached" : "")
                            color: d.theme.ai; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2; font.letterSpacing: 1; font.bold: true
                            Layout.fillWidth: true; elide: Text.ElideRight
                        }
                    }
                    Text { text: "Generated by a language model — verify before acting."; color: d.theme.muted; font.pixelSize: d.theme.fontSize - 2; font.italic: true }
                    Text { text: d.res ? d.res.summary : ""; color: d.theme.fg; font.pixelSize: d.theme.fontSize + 1; wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText }
                    RowLayout {
                        spacing: 6
                        Text { text: "confidence"; color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2 }
                        Rectangle {
                            width: 120; height: 6; color: Qt.alpha(d.theme.ai, 0.2)
                            Rectangle { width: parent.width * (d.res ? d.res.confidence : 0); height: parent.height; color: d.theme.ai }
                        }
                        Text { text: d.res ? Math.round(d.res.confidence * 100) + "%" : ""; color: d.theme.ai; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2 }
                        Text { text: d.res ? "benign " + Math.round(d.res.benign_confidence * 100) + "%" : ""; color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2 }
                    }
                    Kv { k: "classification"; v: d.res ? d.res.classification : ""; vc: d.theme.ai }
                    Kv { k: "assessment"; v: d.res ? d.res.severity_assessment : ""; vc: d.theme.sev(d.res ? d.res.severity_assessment : "") }
                    Kv { k: "false positive"; v: d.res ? d.res.false_positive_likelihood : "" }
                    Kv { k: "suggested"; v: d.res ? d.res.suggested_action : ""; vc: d.theme.ai }
                    Kv { k: "context"; v: d.res && d.res.context ? d.res.context : "" }
                    Kv { k: "impact"; v: d.res && d.res.impact ? d.res.impact : "" }
                    Bullets { title: "Confirmed facts"; items: d.res ? d.res.facts : [] }
                    Bullets { title: "Indicators"; items: d.res ? d.res.indicators : [] }
                    Bullets { title: "Hypotheses"; items: d.res ? d.res.hypotheses : [] }
                    Bullets { title: "Missing information"; items: d.res ? d.res.missing_information : [] }
                    Bullets { title: "Investigation steps"; items: d.res ? d.res.recommended_investigations : [] }
                }
            }

            Section { text: "AI PROPOSALS"; tint: d.theme.ai; visible: d.ev && d.ev.proposals && d.ev.proposals.length > 0 }
            Repeater {
                model: d.ev && d.ev.proposals ? d.ev.proposals : []
                Text {
                    required property var modelData
                    text: "#" + modelData.id + " " + modelData.kind + " — " + modelData.status + (modelData.reason ? " — " + modelData.reason : "")
                    color: d.theme.ai; font.pixelSize: d.theme.fontSize - 1; wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText
                }
            }

            Section { text: "ORIGINAL FIELDS" }
            Repeater {
                model: d.ev ? d.flatten(d.ev.fields, 0) : []
                RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: modelData.depth * 12
                    spacing: 8
                    Text { text: modelData.key; color: modelData.container ? d.theme.accent : d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 1; Layout.preferredWidth: Math.min(220, implicitWidth); Layout.alignment: Qt.AlignTop; elide: Text.ElideMiddle }
                    Text { text: modelData.value; color: d.theme.fg; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 1; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText }
                }
            }

            Section { text: "RAW" }
            Text {
                text: d.ev ? d.ev.raw : ""
                color: d.theme.muted; font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2
                wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText
            }

            Section { text: "HISTORY" }
            Repeater {
                model: d.ev && d.ev.history ? d.ev.history : []
                Text {
                    required property var modelData
                    text: modelData.ts + "  " + modelData.actor + "  " + modelData.action
                          + (modelData.detail && Object.keys(modelData.detail).length ? "  " + JSON.stringify(modelData.detail) : "")
                    color: modelData.actor === "ai" ? d.theme.ai : d.theme.fg
                    font.family: d.theme.mono; font.pixelSize: d.theme.fontSize - 2
                    wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; textFormat: Text.PlainText
                }
            }
            Text {
                visible: d.ev && (!d.ev.history || d.ev.history.length === 0)
                text: "no action yet"; color: d.theme.muted; font.pixelSize: d.theme.fontSize - 1
            }
        }
    }
}
