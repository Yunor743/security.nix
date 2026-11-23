import QtQuick
import QtQuick.Layouts

// A list of alerts drawn in the configured style (minimal lines or panels).
ColumnLayout {
    id: list
    property var theme
    property var model: []
    property string selectedId: ""
    property bool rightAligned: false
    signal action(string name, string id)
    spacing: list.theme.minimal ? 0 : 6

    Repeater {
        model: list.model
        Item {
            required property var modelData
            Layout.fillWidth: true
            implicitHeight: list.theme.minimal ? line.implicitHeight : panel.implicitHeight
            AlertLine {
                id: line
                visible: list.theme.minimal
                width: parent.width
                theme: list.theme; ev: modelData; rightAligned: list.rightAligned
                selected: modelData.id === list.selectedId
                onAction: (n, id) => list.action(n, id)
            }
            AlertRow {
                id: panel
                visible: !list.theme.minimal
                width: parent.width
                theme: list.theme; ev: modelData
                selected: modelData.id === list.selectedId
                onAction: (n, id) => list.action(n, id)
            }
        }
    }
}
