from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QAbstractItemView,
    QGroupBox,
    QTextEdit,
    QSplitter,
    QWidget,
    QProgressBar,
)

from urh.awre.ProtocolMatcher import ProtocolMatch


class ProtocolMatchDialog(QDialog):
    """Dialog showing protocol matching results with confidence scores."""

    match_selected = pyqtSignal(object)  # Emits the selected ProtocolMatch

    def __init__(self, matches: list, parent=None):
        super().__init__(parent)
        self.matches = matches
        self.selected_match = None
        self.setWindowTitle("Auto Protocol Identification")
        self.setMinimumSize(750, 500)
        self.setup_ui()
        self.populate()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Header
        header = QLabel(
            "Protocol matches found based on rtl_433 database analysis.\n"
            "Select a protocol to apply its field labels, or cancel to skip."
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        # Splitter for table + details
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ["Confidence", "Protocol Name", "Modulation", "Fields"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.table.setAlternatingRowColors(True)
        self.table.currentCellChanged.connect(self.on_selection_changed)
        splitter.addWidget(self.table)

        # Details panel
        details_group = QGroupBox("Match Details")
        details_layout = QVBoxLayout(details_group)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)
        splitter.addWidget(details_group)

        layout.addWidget(splitter)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_apply = QPushButton("Apply Selected Protocol")
        self.btn_apply.setEnabled(False)
        self.btn_apply.setDefault(True)
        self.btn_apply.clicked.connect(self.on_apply)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)

        btn_layout.addWidget(self.btn_apply)
        btn_layout.addWidget(self.btn_cancel)
        layout.addLayout(btn_layout)

    def populate(self):
        self.table.setRowCount(len(self.matches))
        for row, match in enumerate(self.matches):
            # Confidence with color-coded progress bar
            conf_widget = QWidget()
            conf_layout = QHBoxLayout(conf_widget)
            conf_layout.setContentsMargins(4, 2, 4, 2)
            pbar = QProgressBar()
            pbar.setRange(0, 100)
            pbar.setValue(match.percentage)
            pbar.setTextVisible(True)
            pbar.setFormat(f"{match.percentage}%")
            if match.percentage >= 60:
                pbar.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")
            elif match.percentage >= 30:
                pbar.setStyleSheet("QProgressBar::chunk { background-color: #FFC107; }")
            else:
                pbar.setStyleSheet("QProgressBar::chunk { background-color: #FF5722; }")
            pbar.setFixedHeight(20)
            conf_layout.addWidget(pbar)
            self.table.setCellWidget(row, 0, conf_widget)

            # Protocol name
            name_item = QTableWidgetItem(match.name)
            name_item.setFont(QFont("", -1, QFont.Weight.Bold))
            self.table.setItem(row, 1, name_item)

            # Modulation
            mod = match.entry.get("modulation", "")
            mod_short = mod.replace("OOK_PULSE_", "OOK/").replace("FSK_PULSE_", "FSK/")
            self.table.setItem(row, 2, QTableWidgetItem(mod_short))

            # Fields
            fields = match.entry.get("fields", [])
            fields_str = ", ".join(f for f in fields if f != "model")
            self.table.setItem(row, 3, QTableWidgetItem(fields_str))

        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(2)

    def on_selection_changed(self, row, col, prev_row, prev_col):
        if 0 <= row < len(self.matches):
            match = self.matches[row]
            self.selected_match = match
            self.btn_apply.setEnabled(True)

            # Build details text
            lines = [f"<b>{match.name}</b>"]
            lines.append(f"Confidence: <b>{match.percentage}%</b>")
            lines.append("")

            entry = match.entry
            if entry.get("modulation"):
                lines.append(f"Modulation: {entry['modulation']}")
            if entry.get("short_width"):
                lines.append(
                    f"Pulse widths: short={entry['short_width']}us, "
                    f"long={entry.get('long_width', '?')}us"
                )
            if entry.get("msg_len_bits"):
                lines.append(f"Expected message length: {entry['msg_len_bits']} bits")
            if entry.get("checksum"):
                lines.append(f"Checksum: {entry['checksum']}")
            if entry.get("preamble_bits"):
                lines.append(f"Preamble: 0x{entry['preamble_bits']}")
            if entry.get("sync_bytes"):
                lines.append(f"Sync word: 0x{entry['sync_bytes']}")

            if match.recommended_decoder:
                lines.append(
                    f"<br><b>Recommended decoder:</b>"
                    f" {match.recommended_decoder.name}"
                )
            if match.leading_zeros_count > 0:
                lines.append(
                    f"<b>Leading zeros:</b>"
                    f" {match.leading_zeros_count} bits"
                    f" (will be labeled as noise)"
                )

            lines.append("")
            lines.append("<b>Scoring details:</b>")
            for key, val in match.details.items():
                lines.append(f"  {key}: {val}")

            self.details_text.setHtml("<br>".join(lines))
        else:
            self.btn_apply.setEnabled(False)
            self.details_text.clear()

    def on_apply(self):
        if self.selected_match:
            self.match_selected.emit(self.selected_match)
            self.accept()
