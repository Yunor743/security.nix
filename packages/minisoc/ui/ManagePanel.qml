import QtQuick
import QtQuick.Layouts

// Management: closed (TP/FP) / filtered alerts, rules and their counters,
// AI proposals, AI status (filter review included) and prompts.
ColumnLayout {
    id: m
    property var theme
    property var st: ({})
    property string tab: "closed"
    property string selectedId: ""
    // Bottom corners: tabs under the content, next to the anchored edge,
    // so they stay reachable without scrolling.
    property bool tabsAtBottom: false
    signal action(string name, string arg)
    spacing: 4

    readonly property var ai: st.ai || ({ enabled: false })
    readonly property var filter: st.filter || ({})
    readonly property var counts: st.counts || ({})
    readonly property var review: ai.filter_review || ({ mode: "off" })

    function since(ts) {
        return ts ? Qt.formatDateTime(new Date(ts), "dd/MM HH:mm") : "?";
    }

    Tabs { visible: !m.tabsAtBottom }

    component Tabs: RowLayout {
        spacing: 3
        Repeater {
            model: [
                { id: "closed", label: "CLOSED " + (m.counts.closed || 0) + " (TP " + (m.counts.closed_tp || 0) + " · FP " + (m.counts.closed_fp || 0) + ")" },
                { id: "filtered", label: "FILTERED " + ((m.st.counts || {}).filtered || 0) },
                { id: "rules", label: "RULES " + (m.filter.rules || 0) },
                { id: "proposals", label: "AI PROPOSALS " + ((m.st.proposals || []).length) },
                { id: "ai", label: "AI" }
            ]
            Btn {
                required property var modelData
                theme: m.theme; label: modelData.label; active: m.tab === modelData.id
                tint: modelData.id === "proposals" || modelData.id === "ai" ? m.theme.ai : m.theme.fg
                onClicked: m.tab = modelData.id
            }
        }
    }

    component Muted: Text {
        color: m.theme.muted; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 2
        wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText
    }

    // ---- closed / filtered
    Repeater {
        model: m.tab === "closed" ? (m.st.closed || []) : m.tab === "filtered" ? (m.st.filtered || []) : []
        AlertRow {
            required property var modelData
            theme: m.theme; ev: modelData; mode: m.tab; selected: modelData.id === m.selectedId
            onAction: (name, id) => m.action(name, id)
        }
    }
    Muted {
        visible: (m.tab === "closed" && !(m.st.closed || []).length) || (m.tab === "filtered" && !(m.st.filtered || []).length)
        text: m.tab === "closed"
              ? "No closed alert. TP = real activity, handled; FP = noise. Closing never deletes logs; re-open anytime."
              : "No alert excluded by a rule."
    }

    // ---- rules
    ColumnLayout {
        visible: m.tab === "rules"
        Layout.fillWidth: true
        spacing: 3
        Repeater {
            model: m.filter.files || []
            Muted {
                required property var modelData
                text: (modelData.owner || (modelData.writable ? "user" : "system")).toUpperCase() + "  " + modelData.path + " — " + modelData.rules + " rule(s)"
                      + (modelData.error ? "\n  ✗ " + modelData.error + (modelData.using_last_good ? " (last valid version in force)" : "") : "")
                      + (modelData.warning ? "\n  ! " + modelData.warning : "")
                color: modelData.error ? m.theme.critical : modelData.warning ? m.theme.medium : m.theme.muted
            }
        }
        Repeater {
            model: m.filter.list || []
            Rectangle {
                required property var modelData
                Layout.fillWidth: true
                implicitHeight: rc.implicitHeight + 8
                color: m.theme.panel; border.width: 1; radius: m.theme.radius
                border.color: modelData.owner === "ai" ? Qt.alpha(m.theme.ai, 0.6) : m.theme.border
                ColumnLayout {
                    id: rc
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 5 }
                    spacing: 1
                    RowLayout {
                        Text { text: modelData.id; color: modelData.enabled ? m.theme.fg : m.theme.muted; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 1; Layout.fillWidth: true; elide: Text.ElideRight }
                        Text { visible: modelData.owner === "ai"; text: "AI"; color: m.theme.ai; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 2 }
                        // Alerts excluded since the rule was created or last modified.
                        Text { text: modelData.enabled ? modelData.hits + " filtered since " + m.since(modelData.since) : "disabled"; color: m.theme.muted; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 2 }
                    }
                    Muted { text: (modelData.description ? modelData.description + "\n" : "") + JSON.stringify(modelData.match) }
                }
            }
        }
        RowLayout {
            spacing: 4
            Btn { theme: m.theme; label: "OPEN RULES FILE"; onClicked: m.action("open-rules", "") }
            Btn { theme: m.theme; label: "OPEN AI RULES"; tint: m.theme.ai; onClicked: m.action("open-ai-rules", "") }
            Btn { theme: m.theme; label: "ROLLBACK LAST CHANGE"; confirm: true; visible: (m.filter.backups || 0) > 0; onClicked: m.action("rollback", "") }
        }
    }

    // ---- proposals
    ColumnLayout {
        visible: m.tab === "proposals"
        Layout.fillWidth: true
        spacing: 3
        Muted { visible: !(m.st.proposals || []).length; text: "No pending AI proposal." }
        Repeater {
            model: m.st.proposals || []
            Rectangle {
                required property var modelData
                Layout.fillWidth: true
                implicitHeight: pc.implicitHeight + 10
                color: Qt.alpha(m.theme.ai, 0.06); border.width: 1; border.color: Qt.alpha(m.theme.ai, 0.6); radius: m.theme.radius
                ColumnLayout {
                    id: pc
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 6 }
                    spacing: 2
                    Text {
                        text: "#" + modelData.id + " · "
                              + (modelData.kind === "filter" ? "NEW EXCLUSION RULE"
                                 : modelData.kind === "review" ? "FILTER REVIEW: " + ((modelData.payload || {}).action || "").toUpperCase() + " " + ((modelData.payload || {}).id || "")
                                 : "CLOSE AS FP")
                              + " · confidence " + Math.round((modelData.confidence || 0) * 100) + "%"
                        color: m.theme.ai; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 1; font.bold: true
                        wrapMode: Text.Wrap; Layout.fillWidth: true
                    }
                    Text {
                        visible: !!modelData.event_id
                        text: "[" + (modelData.severity || "?") + "] " + (modelData.source || "") + " — " + (modelData.message || "")
                        color: m.theme.fg; font.pixelSize: m.theme.fontSize - 1; wrapMode: Text.Wrap; Layout.fillWidth: true; textFormat: Text.PlainText
                    }
                    Muted { visible: !!modelData.reason; text: "why: " + modelData.reason; color: m.theme.fg }
                    Muted { visible: modelData.kind === "filter" || modelData.kind === "review"; text: modelData.payload && modelData.payload.rule ? JSON.stringify(modelData.payload.rule.match) : "" }
                    Muted { visible: modelData.kind === "discard"; text: modelData.payload && modelData.payload.reasons ? modelData.payload.reasons.join(" · ") : "" }
                    RowLayout {
                        spacing: 4
                        Btn { theme: m.theme; label: "ACCEPT"; tint: m.theme.ai; confirm: modelData.kind !== "discard"; onClicked: m.action("accept", String(modelData.id)) }
                        Btn { theme: m.theme; label: "REJECT"; onClicked: m.action("reject", String(modelData.id)) }
                        Btn { theme: m.theme; label: "ALERT"; visible: !!modelData.event_id; onClicked: m.action("details", modelData.event_id) }
                    }
                }
            }
        }
    }

    // ---- AI status, stats, prompts
    ColumnLayout {
        visible: m.tab === "ai"
        Layout.fillWidth: true
        spacing: 3
        Muted {
            visible: !m.ai.enabled
            text: "AI analysis is disabled. MiniSOC works fully without it (services.minisoc.ai.enable)."
        }
        Muted {
            visible: m.ai.enabled === true
            color: m.ai.remote ? m.theme.medium : m.theme.muted
            text: "provider  " + m.ai.provider + " / " + m.ai.model + "\n"
                  + "endpoint  " + (m.ai.endpoint_host || "") + (m.ai.remote ? "   ⚠ REMOTE: redacted alerts leave this machine" : "   (local)") + "\n"
                  + "state     " + m.ai.state + " · queue " + m.ai.queue + " · in flight " + m.ai.in_flight + " · dropped " + m.ai.dropped + "\n"
                  + "today     " + m.ai.requests_today + " / " + m.ai.daily_quota + " requests, " + m.ai.errors_today + " error(s)\n"
                  + "policies  auto-close FP: " + m.ai.auto_discard + " · auto-filter: " + m.ai.auto_filter + "\n"
                  + "analyzed  " + (m.counts.analyzed || 0) + " · closed as FP by AI " + (m.counts.closed_by_ai || 0)
                  + (m.ai.last_error ? "\nlast error  " + m.ai.last_error : "")
        }
        // Scheduled review of the AI rules from the user's FP / TP closures.
        Muted {
            visible: m.ai.enabled === true
            color: m.review.error ? m.theme.medium : m.theme.muted
            text: "filter review  " + m.review.mode
                  + (m.review.mode !== "off" ? " · every " + m.review.interval_hours + " h · last " + m.since(m.review.last_run) + " · next " + m.since(m.review.next_run) : "")
                  + (m.review.report ? "\n  " + (m.review.report.skipped || m.review.report.summary || "")
                     + "  (" + (m.review.report.applied || []).length + " applied, " + (m.review.report.proposed || []).length + " proposed, "
                     + (m.review.report.rejected || []).length + " rejected by the guardrails)" : "")
                  + (m.review.error ? "\n  last error: " + m.review.error : "")
        }
        Text { text: "PROMPTS (edits apply to the next request, no rebuild)"; color: m.theme.ai; font.family: m.theme.mono; font.pixelSize: m.theme.fontSize - 2; Layout.topMargin: 4 }
        Flow {
            Layout.fillWidth: true
            spacing: 4
            Repeater {
                model: ["system", "analysis", "enrichment", "classification", "filter", "review"]
                Btn { required property string modelData; theme: m.theme; label: "EDIT " + modelData.toUpperCase(); tint: m.theme.ai; onClicked: m.action("edit-prompt", modelData) }
            }
        }
    }

    Tabs { visible: m.tabsAtBottom }
}
