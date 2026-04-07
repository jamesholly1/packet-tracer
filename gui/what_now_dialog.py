# gui/what_now_dialog.py — "What Now?" dialog shown when an alert is selected.
#
# Displays the static alert content from alert_content.py in a tabbed layout:
#   Tab 1 — Overview (what is this attack?)
#   Tab 2 — Immediate Actions (what to do right now)
#   Tab 3 — Prevention (long-term defences)

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from analyzer.models import Alert, Severity
from gui.alert_content import get_content
from gui.styles import SEVERITY_COLOURS


class WhatNowDialog(QDialog):
    """Modal dialog presenting educational content for a selected alert."""

    def __init__(self, alert: Alert, parent=None) -> None:
        """
        Args:
            alert:  The Alert whose content to display.
            parent: Parent widget (the main window).
        """
        super().__init__(parent)
        content = get_content(alert.alert_type)

        self.setWindowTitle(f"What Now?  —  {content.title}")
        self.setMinimumSize(700, 520)
        self.resize(760, 560)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # ── Alert summary header ────────────────────────────────────────────
        layout.addWidget(self._build_header(alert))

        # ── Tabbed content ──────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.addTab(self._make_tab(content.overview),   "Overview")
        tabs.addTab(self._make_tab(content.immediate),  "Immediate Actions")
        tabs.addTab(self._make_tab(content.prevent),    "Prevention")
        layout.addWidget(tabs, stretch=1)

        # ── Close button ────────────────────────────────────────────────────
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_header(self, alert: Alert) -> QWidget:
        """Return a widget showing alert type, severity, source, and message."""
        container = QWidget()
        container.setStyleSheet(
            "background-color: #1f2335; border: 1px solid #3b4261;"
            "border-radius: 4px; padding: 2px;"
        )
        row = QHBoxLayout(container)
        row.setContentsMargins(12, 8, 12, 8)
        row.setSpacing(16)

        # Severity badge
        colour = SEVERITY_COLOURS.get(alert.severity.value, "#c0caf5")
        sev_label = QLabel(f"!! {alert.severity.value}")
        sev_label.setStyleSheet(
            f"color: {colour}; font-weight: bold; font-size: 13px;"
        )
        row.addWidget(sev_label)

        # Type
        type_label = QLabel(alert.alert_type)
        type_label.setStyleSheet("color: #7aa2f7; font-weight: bold;")
        row.addWidget(type_label)

        # Separator
        sep = QLabel("·")
        sep.setStyleSheet("color: #565f89;")
        row.addWidget(sep)

        # Source IP
        src_label = QLabel(f"Source: {alert.src_ip}")
        src_label.setStyleSheet("color: #c0caf5;")
        row.addWidget(src_label)

        row.addStretch()

        # Short message
        msg_label = QLabel(alert.message)
        msg_label.setStyleSheet("color: #a9b1d6; font-style: italic;")
        msg_label.setWordWrap(True)
        msg_label.setMaximumWidth(320)
        row.addWidget(msg_label)

        return container

    def _make_tab(self, html: str) -> QTextBrowser:
        """Return a QTextBrowser pre-loaded with HTML content."""
        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)

        # Wrap in a base HTML document with consistent font and spacing.
        full_html = f"""
        <html><head><style>
            body  {{ font-family: Consolas, monospace; font-size: 12px;
                    color: #c0caf5; line-height: 1.6; margin: 8px; }}
            h3    {{ color: #7aa2f7; margin-top: 14px; margin-bottom: 4px; }}
            p     {{ margin: 4px 0 8px 0; }}
            ul, ol {{ margin: 4px 0 8px 16px; padding: 0; }}
            li    {{ margin-bottom: 4px; }}
            b     {{ color: #e0af68; }}
            code  {{ background: #24283b; color: #9ece6a;
                    padding: 1px 4px; border-radius: 3px; }}
        </style></head><body>{html}</body></html>
        """
        browser.setHtml(full_html)
        return browser
