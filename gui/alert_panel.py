# gui/alert_panel.py — Alert list widget with "What Now?" button.

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analyzer.models import Alert
from gui.styles import SEVERITY_COLOURS


class AlertPanelWidget(QWidget):
    """Panel showing all fired alerts with a 'What Now?' button."""

    # Emitted when the user clicks 'What Now?' with the selected Alert.
    what_now_requested = pyqtSignal(object)  # carries an Alert

    _COLUMNS = ["Severity", "Type", "Source IP", "Message"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self._alerts: list[Alert] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # ── Table ───────────────────────────────────────────────────────────
        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setDefaultSectionSize(24)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        self._table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )
        layout.addWidget(self._table, stretch=1)

        # ── Bottom bar: count label + What Now button ────────────────────────
        bar = QHBoxLayout()
        self._count_label = QLabel("No alerts")
        self._count_label.setStyleSheet("color: #565f89;")
        bar.addWidget(self._count_label)
        bar.addStretch()

        self._what_now_btn = QPushButton("What Now?")
        self._what_now_btn.setObjectName("what_now")
        self._what_now_btn.setDisabled(True)
        self._what_now_btn.setToolTip("Select an alert to learn what it means and how to respond")
        self._what_now_btn.clicked.connect(self._on_what_now)
        bar.addWidget(self._what_now_btn)

        layout.addLayout(bar)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_alert(self, alert: Alert) -> None:
        """Append a new alert row to the table.

        Args:
            alert: The Alert to display.
        """
        self._alerts.append(alert)
        row = self._table.rowCount()
        self._table.insertRow(row)

        colour = QColor(SEVERITY_COLOURS.get(alert.severity.value, "#c0caf5"))

        values = [
            f"!! {alert.severity.value}",
            alert.alert_type,
            alert.src_ip,
            alert.message,
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            item.setForeground(colour)
            self._table.setItem(row, col, item)

        # Update count label, colouring it red once there are alerts.
        count = len(self._alerts)
        self._count_label.setText(f"{count} alert{'s' if count != 1 else ''}")
        self._count_label.setStyleSheet(
            "color: #f7768e; font-weight: bold;" if count else "color: #565f89;"
        )

        self._table.scrollToBottom()

    def clear(self) -> None:
        """Remove all alerts (called when a new capture starts)."""
        self._alerts.clear()
        self._table.setRowCount(0)
        self._count_label.setText("No alerts")
        self._count_label.setStyleSheet("color: #565f89;")
        self._what_now_btn.setDisabled(True)

    # ------------------------------------------------------------------
    # Private slots
    # ------------------------------------------------------------------

    def _on_selection_changed(self) -> None:
        """Enable the What Now button only when a row is selected."""
        has_selection = bool(self._table.selectedItems())
        self._what_now_btn.setEnabled(has_selection)

    def _on_what_now(self) -> None:
        """Emit what_now_requested with the currently selected Alert."""
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        row_idx = rows[0].row()
        if 0 <= row_idx < len(self._alerts):
            self.what_now_requested.emit(self._alerts[row_idx])
