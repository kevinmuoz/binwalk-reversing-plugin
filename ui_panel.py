from __future__ import annotations

from typing import Any, Callable, List, Dict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPushButton,
    QComboBox,
    QLabel,
    QTextEdit,
    QAbstractItemView,
)

class BinwalkPanel(QWidget):
    """
    Shared Qt widget.
    Host must provide callbacks for scan/extract/jump/output picker.
    """

    def __init__(
        self,
        get_target_label: Callable[[], str],
        scan_cb: Callable[[bool], None],
        extract_cb: Callable[[bool], None],
        jump_cb: Callable[[int], None],
    ):
        super().__init__()

        self._get_target_label = get_target_label
        self._scan_cb = scan_cb
        self._extract_cb = extract_cb
        self._jump_cb = jump_cb

        self._results: List[Any] = []

        root = QVBoxLayout()
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        self.lbl_target = QLabel("Target: <none>")
        self.lbl_target.setStyleSheet("font-weight: bold;")
        root.addWidget(self.lbl_target)

        controls = QHBoxLayout()
        controls.setSpacing(6)

        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Fast", "Deep"])

        self.btn_scan = QPushButton("Scan")
        self.btn_extract = QPushButton("Extract...")

        self.btn_scan.clicked.connect(self._on_scan)
        self.btn_extract.clicked.connect(self._on_extract)

        controls.addWidget(QLabel("Mode:"))
        controls.addWidget(self.combo_mode)
        controls.addStretch(1)
        controls.addWidget(self.btn_scan)
        controls.addWidget(self.btn_extract)

        root.addLayout(controls)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["FileOff", "Name", "Conf", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        root.addWidget(self.table)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(100)
        self.log_box.setStyleSheet("font-family: monospace; font-size: 10px;")
        root.addWidget(self.log_box)

        self.setLayout(root)
        self.refresh_target()

    def refresh_target(self) -> None:
        try:
            self.lbl_target.setText(f"Target: {self._get_target_label()}")
        except Exception:
            self.lbl_target.setText("Target: <error>")

    def log(self, msg: str, error: bool = False) -> None:
        color = "red" if error else "green"
        try:
            self.log_box.append(f'<span style="color:{color}">> {msg}</span>')
            self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())
        except Exception:
            pass

    def set_results(self, results: List[Any]) -> None:
        self._results = results or []
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._results))
        self.table.setSortingEnabled(False)

        for row, r in enumerate(self._results):
            try:
                off = int(getattr(r, "offset", 0))
                name = str(getattr(r, "name", ""))
                conf = str(getattr(r, "confidence", ""))
                desc = str(getattr(r, "description", ""))
            except Exception:
                off = 0
                name = "<error>"
                conf = "0"
                desc = str(r)

            it_off = QTableWidgetItem(f"0x{off:X}")
            it_off.setData(Qt.UserRole, off)

            self.table.setItem(row, 0, it_off)
            self.table.setItem(row, 1, QTableWidgetItem(name))
            self.table.setItem(row, 2, QTableWidgetItem(conf))
            self.table.setItem(row, 3, QTableWidgetItem(desc))

        self.table.setSortingEnabled(True)

    def show_extract_summary(self, success: int, job_dir: str, stats: Dict[str, int]) -> None:
        attempted = int(stats.get("attempted", 0))
        matches = int(stats.get("matches", 0))
        declined = int(stats.get("declined", 0))
        no_extractor = int(stats.get("no_extractor", 0))
        external_missing = int(stats.get("external_missing", 0))

        self.log(f"Extraction done. success={success} attempted={attempted} matches={matches}")
        if success == 0:
            if matches == 0:
                self.log("0 extracted: no matches found.", error=True)
            elif external_missing > 0:
                self.log("0 extracted: missing external extractor dependencies (see logs).", error=True)
            elif no_extractor == matches:
                self.log("0 extracted: matches have no extractor.", error=True)
            elif declined == matches:
                self.log("0 extracted: extraction declined by signatures.", error=True)
            else:
                self.log("0 extracted: extraction attempted but nothing succeeded.", error=True)
        self.log(f"Output: {job_dir}")

    def _deep_selected(self) -> bool:
        return self.combo_mode.currentText() == "Deep"

    def _on_scan(self) -> None:
        self.refresh_target()
        self._scan_cb(self._deep_selected())

    def _on_extract(self) -> None:
        self.refresh_target()
        self._extract_cb(self._deep_selected())

    def _on_double_click(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if not item:
            return
        off = item.data(Qt.UserRole)
        if off is None:
            return
        try:
            self._jump_cb(int(off))
        except Exception:
            pass
