import QtQuick
import QtQuick.Layouts

// One alert in a list. Actions appear on hover (always visible when selected).
Rectangle {
    id: row
    property var theme
    property var ev: ({})
    property bool selected: false
    property string mode: "feed" // feed | discarded | filtered
    signal action(string name, string id)

    readonly property color sevColor: theme.sev(ev.severity)
    readonly property bool showActions: hover.hovered || selected

    Layout.fillWidth: true
    implicitHeight: col.implicitHeight + 10
    radius: theme.radius
    color: selected ? Qt.alpha(theme.accent, 0.12) : (hover.hovered ? Qt.alpha(theme.fg, 0.05) : theme.panel)
    border.width: 1
    border.color: ev.pinned ? theme.accent : (selected ? Qt.alpha(theme.accent, 0.6) : theme.border)

    HoverHandler { id: hover }

    MouseArea { // behind the content: buttons on top keep their own clicks
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: row.action("details", row.ev.id)
    }

    Rectangle { // severity bar
        width: 3; color: row.sevColor
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
    }

    function fmtTime(ts) {
        if (!ts) return "";
        const d = new Date(ts);
        const today = new Date();
        return d.toDateString() === today.toDateString()
            ? Qt.formatDateTime(d, "HH:mm:ss") : Qt.formatDateTime(d, "dd/MM HH:mm");
    }

    ColumnLayout {
        id: col
        anchors { left: parent.left; right: parent.right; top: parent.top; leftMargin: 10; rightMargin: 8; topMargin: 5 }
        spacing: 3

        RowLayout {
            Layout.fillWidth: true
            spacing: 6
            Text {
                text: row.theme.sevShort(row.ev.severity)
                color: row.sevColor; font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 2
                font.bold: true; font.letterSpacing: 1
                Layout.preferredWidth: 32
            }
            Text {
                text: (row.ev.source || "").toUpperCase()
                color: row.theme.muted; font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 2
                font.letterSpacing: 1
            }
            Text {
                visible: row.ev.pinned === true
                text: "◆ PINNED"; color: row.theme.accent
                font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 3; font.letterSpacing: 1
            }
            Text {
                visible: row.ev.analysis !== null && row.ev.analysis !== undefined
                text: "AI·" + ((row.ev.analysis && row.ev.analysis.classification) || "").toUpperCase()
                color: row.theme.ai; font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 3; font.letterSpacing: 1
            }
            Item { Layout.fillWidth: true }
            Text {
                visible: (row.ev.occurrences || 1) > 1
                text: "×" + row.ev.occurrences
                color: row.theme.fg; font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 2
            }
            Text {
                text: row.fmtTime(row.ev.timestamp)
                color: row.theme.muted; font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 2
            }
        }

        Text {
            Layout.fillWidth: true
            text: row.ev.message || ""
            color: row.theme.fg
            font.family: row.theme.font; font.pixelSize: row.theme.fontSize
            elide: Text.ElideRight
            maximumLineCount: row.selected ? 3 : 1
            wrapMode: row.selected ? Text.WrapAnywhere : Text.NoWrap
        }

        Text {
            visible: row.mode === "discarded" || row.mode === "filtered"
            Layout.fillWidth: true
            text: row.mode === "discarded" ? "discarded by " + (row.ev.discarded_by || "?") : "rule: " + (row.ev.filtered_by || "")
            color: row.ev.discarded_by === "ai" ? row.theme.ai : row.theme.muted
            font.family: row.theme.mono; font.pixelSize: row.theme.fontSize - 3
            elide: Text.ElideRight
        }

        RowLayout {
            visible: row.showActions
            spacing: 4
            Layout.bottomMargin: 2
            Btn { theme: row.theme; label: row.ev.pinned ? "UNPIN" : "PIN"; tint: row.theme.accent
                  visible: row.mode !== "filtered"
                  onClicked: row.action(row.ev.pinned ? "unpin" : "pin", row.ev.id) }
            Btn { theme: row.theme; label: "DETAILS"; active: row.selected
                  onClicked: row.action("details", row.ev.id) }
            Btn { theme: row.theme; label: "DISCARD"; visible: row.mode === "feed" && !row.ev.discarded
                  onClicked: row.action("discard", row.ev.id) }
            Btn { theme: row.theme; label: "RESTORE"; visible: row.mode === "discarded"; tint: row.theme.accent
                  onClicked: row.action("restore", row.ev.id) }
            Btn { theme: row.theme; label: "FILTER"; visible: row.mode === "feed"
                  onClicked: row.action("filter", row.ev.id) }
            Btn { theme: row.theme; label: "AI"; tint: row.theme.ai
                  onClicked: row.action("ai", row.ev.id) }
        }
    }

}
