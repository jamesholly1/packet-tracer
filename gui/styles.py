# gui/styles.py — Dark theme stylesheet for the desktop GUI.
#
# Colours follow a dark slate palette that's easy on the eyes during long
# monitoring sessions. All widget styles are defined here so they can be
# applied in one call: app.setStyleSheet(DARK_THEME)

DARK_THEME = """
/* ── Base ── */
QMainWindow, QWidget, QDialog {
    background-color: #1a1b26;
    color: #c0caf5;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}

/* ── Group boxes ── */
QGroupBox {
    border: 1px solid #3b4261;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 6px;
    font-weight: bold;
    color: #7aa2f7;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
}

/* ── Tables ── */
QTableWidget {
    background-color: #1f2335;
    alternate-background-color: #24283b;
    border: 1px solid #3b4261;
    border-radius: 4px;
    gridline-color: #2a2d3e;
    selection-background-color: #364a82;
    selection-color: #c0caf5;
}
QTableWidget::item {
    padding: 3px 6px;
    border: none;
}
QHeaderView::section {
    background-color: #24283b;
    color: #7aa2f7;
    padding: 4px 6px;
    border: none;
    border-bottom: 1px solid #3b4261;
    font-weight: bold;
}
QHeaderView::section:horizontal:first {
    border-top-left-radius: 4px;
}

/* ── Buttons ── */
QPushButton {
    background-color: #364a82;
    color: #c0caf5;
    border: 1px solid #4a6096;
    border-radius: 4px;
    padding: 5px 14px;
    font-weight: bold;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #4a6096;
}
QPushButton:pressed {
    background-color: #2a3a6a;
}
QPushButton:disabled {
    background-color: #2a2d3e;
    color: #565f89;
    border-color: #3b4261;
}
QPushButton#danger {
    background-color: #6b2737;
    border-color: #8c3a4a;
}
QPushButton#danger:hover {
    background-color: #8c3a4a;
}
QPushButton#what_now {
    background-color: #4a3728;
    border-color: #e0af68;
    color: #e0af68;
}
QPushButton#what_now:hover {
    background-color: #6b5237;
}
QPushButton#what_now:disabled {
    background-color: #2a2d3e;
    color: #565f89;
    border-color: #3b4261;
}

/* ── Dropdowns ── */
QComboBox {
    background-color: #24283b;
    border: 1px solid #3b4261;
    border-radius: 4px;
    padding: 4px 8px;
    color: #c0caf5;
    min-width: 180px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #24283b;
    border: 1px solid #3b4261;
    selection-background-color: #364a82;
    color: #c0caf5;
}

/* ── Radio buttons ── */
QRadioButton {
    spacing: 6px;
    color: #c0caf5;
}
QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border-radius: 7px;
    border: 2px solid #3b4261;
    background-color: #1f2335;
}
QRadioButton::indicator:checked {
    background-color: #7aa2f7;
    border-color: #7aa2f7;
}

/* ── Labels ── */
QLabel {
    color: #c0caf5;
}
QLabel#section_title {
    color: #7aa2f7;
    font-weight: bold;
    font-size: 13px;
}
QLabel#status_ok {
    color: #9ece6a;
}
QLabel#status_alert {
    color: #f7768e;
    font-weight: bold;
}

/* ── Status bar ── */
QStatusBar {
    background-color: #16161e;
    color: #565f89;
    border-top: 1px solid #3b4261;
}
QStatusBar::item {
    border: none;
}

/* ── Text areas ── */
QTextBrowser {
    background-color: #1f2335;
    border: 1px solid #3b4261;
    border-radius: 4px;
    color: #c0caf5;
    padding: 8px;
    line-height: 1.5;
}

/* ── Splitter ── */
QSplitter::handle {
    background-color: #3b4261;
}
QSplitter::handle:horizontal {
    width: 2px;
}
QSplitter::handle:vertical {
    height: 2px;
}

/* ── Scroll bars ── */
QScrollBar:vertical {
    background: #1a1b26;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #3b4261;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #4a5374;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background: #1a1b26;
    height: 8px;
}
QScrollBar::handle:horizontal {
    background: #3b4261;
    border-radius: 4px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* ── Line edit ── */
QLineEdit {
    background-color: #24283b;
    border: 1px solid #3b4261;
    border-radius: 4px;
    padding: 4px 8px;
    color: #c0caf5;
}
QLineEdit:focus {
    border-color: #7aa2f7;
}

/* ── Dialog buttons ── */
QDialogButtonBox QPushButton {
    min-width: 70px;
}

/* ── Tab widget (used in What Now dialog) ── */
QTabWidget::pane {
    border: 1px solid #3b4261;
    border-radius: 4px;
    background-color: #1f2335;
}
QTabBar::tab {
    background-color: #24283b;
    color: #565f89;
    padding: 6px 16px;
    border: 1px solid #3b4261;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: #1f2335;
    color: #7aa2f7;
    font-weight: bold;
}
QTabBar::tab:hover:!selected {
    background-color: #2a2d3e;
    color: #c0caf5;
}
"""

# Severity colours used in table rows — applied via item foreground.
SEVERITY_COLOURS = {
    "HIGH":   "#f7768e",   # red
    "MEDIUM": "#e0af68",   # amber
    "LOW":    "#7dcfff",   # blue
}

# Protocol label colours used in the packet table.
PROTOCOL_COLOURS = {
    "HTTP":  "#7dcfff",   # cyan
    "DNS":   "#bb9af7",   # purple
    "TCP":   "#7aa2f7",   # blue
    "UDP":   "#9ece6a",   # green
    "ARP":   "#e0af68",   # amber
    "OTHER": "#565f89",   # dim
}
