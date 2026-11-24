import QtQuick
import QtQuick.Layouts

// Minimal style: one discreet line per alert, blending into the wallpaper.
// Source, type, counters and actions appear on hover (or when selected).
Item {
    id: l
    property var theme
    property var ev: ({})
    property bool selected: false
    property bool rightAligned: false
    signal action(string name, string id)

    readonly property bool active: hov.hovered || selected
    readonly property color sevColor: theme.sev(ev.severity)

    implicitHeight: col.implicitHeight + 6

    function fmtTime(ts) {
        if (!ts) return "";
        const d = new Date(ts);
        return d.toDateString() === new Date().toDateString()
            ? Qt.formatDateTime(d, "HH:mm") : Qt.formatDateTime(d, "dd/MM HH:mm");
    }

    component Link: Text {
        id: link
        property string act
        property color tint: l.theme.muted
        signal clicked()
        color: ma.containsMouse ? l.theme.fg : tint
        font.family: l.theme.mono; font.pixelSize: l.theme.fontSize - 2; font.letterSpacing: 1
        style: Text.Raised; styleColor: l.theme.shadow
        MouseArea { id: ma; anchors.fill: parent; anchors.margins: -3; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: link.clicked() }
    }

    HoverHandler { id: hov }

    Rectangle { // backdrop only while interacting
        anchors.fill: parent
        radius: l.theme.radius
        color: l.active ? Qt.alpha(l.theme.bg, 0.55) : "transparent"
        Behavior on color { ColorAnimation { duration: 120 } }
    }
    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: l.action("details", l.ev.id)
    }

    ColumnLayout {
        id: col
        anchors { left: parent.left; right: parent.right; top: parent.top; leftMargin: 6; rightMargin: 6; topMargin: 3 }
        spacing: 2

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            layoutDirection: l.rightAligned ? Qt.RightToLeft : Qt.LeftToRight

            Item {
                implicitWidth: 8; implicitHeight: 8
                Rectangle { // severity
                    visible: !l.ev.pinned
                    anchors.centerIn: parent
                    width: 6; height: 6; radius: 3
                    color: l.sevColor
                    opacity: l.active ? 1 : 0.85
                }
                Text { // pinned
                    visible: l.ev.pinned === true
                    anchors.centerIn: parent
                    text: "◆"; color: l.theme.accent; font.pixelSize: l.theme.fontSize - 1
                }
            }
            Text { // time, next to the severity
                text: l.fmtTime(l.ev.timestamp)
                color: l.theme.muted
                opacity: l.active ? 1 : l.theme.textOpacity
                font.family: l.theme.mono; font.pixelSize: l.theme.fontSize - 2
                style: Text.Raised; styleColor: l.theme.shadow
            }
            Text {
                Layout.fillWidth: true
                text: l.ev.message || ""
                color: l.theme.fg
                opacity: l.active ? 1 : l.theme.textOpacity
                font.family: l.theme.font; font.pixelSize: l.theme.fontSize
                horizontalAlignment: l.rightAligned ? Text.AlignRight : Text.AlignLeft
                elide: l.rightAligned ? Text.ElideLeft : Text.ElideRight
                maximumLineCount: l.selected ? 3 : 1
                wrapMode: l.selected ? Text.WrapAnywhere : Text.NoWrap
                style: Text.Raised; styleColor: l.theme.shadow
            }
            Text {
                visible: (l.ev.occurrences || 1) > 1
                text: "×" + l.ev.occurrences
                color: l.theme.muted
                opacity: l.active ? 1 : l.theme.textOpacity
                font.family: l.theme.mono; font.pixelSize: l.theme.fontSize - 2
                style: Text.Raised; styleColor: l.theme.shadow
            }
        }

        RowLayout {
            visible: l.active
            Layout.fillWidth: true
            spacing: 10
            layoutDirection: l.rightAligned ? Qt.RightToLeft : Qt.LeftToRight
            Layout.leftMargin: l.rightAligned ? 0 : 16
            Layout.rightMargin: l.rightAligned ? 16 : 0
            Text {
                text: [l.theme.sevShort(l.ev.severity), (l.ev.source || ""), (l.ev.event_type || "")].join(" · ").toLowerCase()
                      + (l.ev.analysis ? "  ·  ai: " + (l.ev.analysis.classification || "") : "")
                color: l.theme.muted; font.family: l.theme.mono; font.pixelSize: l.theme.fontSize - 3
                style: Text.Raised; styleColor: l.theme.shadow
                Layout.fillWidth: true
                horizontalAlignment: l.rightAligned ? Text.AlignRight : Text.AlignLeft
                elide: Text.ElideRight
            }
            Link { text: l.ev.pinned ? "unpin" : "pin"; tint: l.theme.accent; onClicked: l.action(l.ev.pinned ? "unpin" : "pin", l.ev.id) }
            Link { text: "details"; onClicked: l.action("details", l.ev.id) }
            Link { text: "tp"; tint: l.theme.high; onClicked: l.action("tp", l.ev.id) }
            Link { text: "fp"; onClicked: l.action("fp", l.ev.id) }
            Link { text: "filter"; onClicked: l.action("filter", l.ev.id) }
            Link { text: "ai"; tint: l.theme.ai; onClicked: l.action("ai", l.ev.id) }
        }
    }
}
