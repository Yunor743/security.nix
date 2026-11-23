import QtQuick

// Flat rectangular text button. `armed` mode asks for a second click.
Rectangle {
    id: b
    property var theme
    property string label: ""
    property color tint: theme.fg
    property bool active: false
    property bool confirm: false
    property bool armed: false
    signal clicked()

    implicitWidth: txt.implicitWidth + 12
    implicitHeight: 18
    radius: theme.radius
    color: active ? Qt.alpha(tint, 0.22) : (ma.containsMouse ? Qt.alpha(tint, 0.14) : "transparent")
    border.width: 1
    border.color: armed ? theme.critical : Qt.alpha(tint, ma.containsMouse || active ? 0.8 : 0.35)

    Text {
        id: txt
        anchors.centerIn: parent
        text: b.armed ? "CONFIRM?" : b.label
        color: b.armed ? b.theme.critical : b.tint
        font.family: b.theme.mono
        font.pixelSize: b.theme.fontSize - 2
        font.letterSpacing: 1
    }
    Timer { id: disarm; interval: 3000; onTriggered: b.armed = false }
    MouseArea {
        id: ma
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: {
            if (b.confirm && !b.armed) { b.armed = true; disarm.restart(); return; }
            b.armed = false;
            b.clicked();
        }
    }
}
