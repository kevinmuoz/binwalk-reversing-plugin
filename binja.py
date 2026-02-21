from __future__ import annotations

import os
import binaryninja as bn
from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    Sidebar,
    UIContext,
)

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QVBoxLayout, QFileDialog
from PySide6.QtGui import QImage, QPainter, QFont, QColor

from . import core
from . import ui_panel

_core = core.BinwalkCore(extracted_suffix="__extracted")
_results_cache: dict[str, list] = {}

def _bv_path(bv: bn.BinaryView | None) -> str:
    try:
        if not bv or not bv.file:
            return ""
        for attr in ("original_filename", "filename"):
            p = getattr(bv.file, attr, None)
            if p and os.path.isfile(p):
                return p
        return bv.file.filename or ""
    except Exception:
        return ""


def _log(msg: str, *, error: bool = False):
    (bn.log_error if error else bn.log_info)(f"[Binwalk] {msg}")


class _Task(bn.BackgroundTaskThread):
    def __init__(self, msg: str, work, done):
        super().__init__(msg, False)
        self._work = work
        self._done = done

    def run(self):
        try:
            res = self._work()
            bn.mainthread.execute_on_main_thread(lambda: self._done(res, None))
        except Exception as e:
            bn.mainthread.execute_on_main_thread(
                lambda: self._done(None, f"{type(e).__name__}: {e}")
            )

class BinwalkSidebarWidget(SidebarWidget):
    def __init__(self, name: str, frame, data):
        super().__init__(name)
        self.bv: bn.BinaryView | None = data
        self._destroyed = False
        self.destroyed.connect(self._mark_destroyed)

        self.panel = ui_panel.BinwalkPanel(
            get_target_label=self._target_label,
            scan_cb=self._scan,
            extract_cb=self._extract,
            jump_cb=self._jump,
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.panel)

        QTimer.singleShot(0, self._deferred_refresh)

    def _mark_destroyed(self):
        self._destroyed = True

    def _alive(self) -> bool:
        if self._destroyed:
            return False
        try:
            self.isVisible()
            return True
        except:
            self._destroyed = True
            return False

    def notifyViewChanged(self, view_frame):
        if not self._alive():
            return
        try:
            self.bv = view_frame.getCurrentBinaryView() if view_frame else None
        except Exception:
            self.bv = None
        QTimer.singleShot(0, self._deferred_refresh)

    def _deferred_refresh(self):
        if not self._alive():
            return
        try:
            self.panel.refresh_target()
            self._restore_results()
        except Exception as e:
            _log(f"refresh: {e}", error=True)

    def _restore_results(self):
        p = _bv_path(self.bv)
        if p and p in _results_cache:
            self.panel.set_results(_results_cache[p])

    def _cache_results(self, results: list):
        p = _bv_path(self.bv)
        if p:
            _results_cache[p] = results

    def _target_label(self) -> str:
        return os.path.basename(_bv_path(self.bv)) if self.bv else "<no file>"

    def _scan(self, deep: bool):
        if not self._alive() or not self.bv:
            return
        path = _bv_path(self.bv)
        if not path or not os.path.isfile(path):
            self.panel.log("No valid disk path for this file.", error=True)
            return

        self.panel.log(f"Scanning ({'Deep' if deep else 'Fast'})…")

        def work():
            return _core.scan_disk(path, deep)

        def done(res, err):
            if not self._alive():
                return
            if err:
                self.panel.log(f"Scan failed: {err}", error=True)
                return
            res = res or []
            self.panel.log(f"Done — {len(res)} signature(s).")
            self.panel.set_results(res)
            self._cache_results(res)

        _Task("Binwalk: scanning…", work, done).start()

    def _extract(self, deep: bool):
        if not self._alive() or not self.bv:
            return
        path = _bv_path(self.bv)
        if not path or not os.path.isfile(path):
            self.panel.log("No valid disk path for this file.", error=True)
            return

        out_root = QFileDialog.getExistingDirectory(self, "Output directory")
        if not out_root:
            return

        self.panel.log(f"Extracting to {out_root}")

        def work():
            old_cwd = os.getcwd()
            try:
                os.chdir(os.path.dirname(path))
                return _core.extract_disk(path, out_root, deep)
            finally:
                os.chdir(old_cwd)

        def done(res, err):
            if not self._alive():
                return
            if err:
                self.panel.log(f"Extraction failed: {err}", error=True)
                return
            if res:
                self.panel.show_extract_summary(*res)

        _Task("Binwalk: extracting…", work, done).start()
    def _jump(self, file_off: int):
        if not self._alive() or not self.bv:
            return
        try:
            addr = self.bv.get_address_for_data_offset(file_off)
            target = addr if addr is not None else file_off
            ctx = UIContext.activeContext()
            vf = ctx.getCurrentViewFrame() if ctx else None
            if vf:
                vf.navigate(self.bv, target)
        except Exception as e:
            _log(f"jump: {e}", error=True)


class BinwalkSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(Qt.transparent)
        p = QPainter(icon)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(70, 130, 180))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(icon.rect().adjusted(2, 2, -2, -2), 10, 10)
        p.setFont(QFont("sans-serif", 18, QFont.Bold))
        p.setPen(QColor(255, 255, 255))
        p.drawText(icon.rect(), Qt.AlignCenter, "BW")
        p.end()
        super().__init__(icon, "Binwalk")

    def createWidget(self, frame, data):
        return BinwalkSidebarWidget("Binwalk", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext


def _open_sidebar_and_run(action: str, deep: bool = False):
    """Open Binwalk sidebar and trigger scan or extract."""
    try:
        ctx = UIContext.activeContext()
        if not ctx:
            return
        sidebar = ctx.sidebar()
        if not sidebar:
            return
        sidebar.activate("Binwalk")
        widget = sidebar.widget("Binwalk")
        if widget and hasattr(widget, action):
            getattr(widget, action)(deep)
    except Exception as e:
        _log(f"sidebar dispatch faileddd: {e}", error=True)


def _register():
    Sidebar.addSidebarWidgetType(BinwalkSidebarWidgetType())

    def _cmd_scan(bv: bn.BinaryView):
        _open_sidebar_and_run("_scan", deep=False)

    def _cmd_extract(bv: bn.BinaryView):
        _open_sidebar_and_run("_extract", deep=False)

    bn.PluginCommand.register("Binwalk\\Scan (Fast)", "Fast binwalk scan", _cmd_scan)
    bn.PluginCommand.register("Binwalk\\Extract...", "Extract embedded content", _cmd_extract)