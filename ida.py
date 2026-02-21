from __future__ import annotations

import os
import threading
from typing import Optional, Dict

import ida_kernwin
import ida_loader
import ida_nalt
import idaapi

from PySide6.QtWidgets import QFileDialog
from PySide6.QtWidgets import QVBoxLayout
from PySide6.QtCore import QStandardPaths

import core
import ui_panel

def LOG(msg: str) -> None:
    ida_kernwin.msg(f"[Binwalk][IDA] {msg}\n")

def _input_path() -> str:
    try:
        p = ida_nalt.get_input_file_path()
        if p:
            return p
    except Exception:
        pass
    try:
        # fallbck
        return ida_loader.get_input_file_path() or ""
    except Exception:
        return ""

def _basename(p: str) -> str:
    try:
        return os.path.basename(p) if p else "<no file>"
    except Exception:
        return "<no file>"

def _jumpto_file_offset(file_off: int) -> None:
    try:
        ea = ida_loader.get_fileregion_ea(file_off)
        ida_kernwin.jumpto(ea if ea != idaapi.BADADDR else file_off)
    except Exception:
        LOG("[Binwalk][IDA] Failed to jump to file offset: %d", file_off)
        pass

class _ActionBase(idaapi.action_handler_t):
    plugin = None
    label = ""

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__

    @classmethod
    def register(cls, plugin: "BinwalkIDAPlugin", label: str) -> None:
        cls.plugin = plugin
        cls.label = label
        idaapi.register_action(idaapi.action_desc_t(cls.get_name(), cls.label, cls()))

    @classmethod
    def unregister(cls) -> None:
        try:
            idaapi.unregister_action(cls.get_name())
        except Exception:
            pass

class ScanAction(_ActionBase):
    @classmethod
    def activate(cls, ctx):
        cls.plugin.command_scan_fast()
        return 1

    @classmethod
    def update(cls, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExtractAction(_ActionBase):
    @classmethod
    def activate(cls, ctx):
        cls.plugin.command_extract()
        return 1

    @classmethod
    def update(cls, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class BinwalkPopupHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = idaapi.get_widget_type(widget)
        if wtype in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
            idaapi.attach_action_to_popup(widget, popup, ScanAction.get_name(), "Binwalk/")
            idaapi.attach_action_to_popup(widget, popup, ExtractAction.get_name(), "Binwalk/")

class BinwalkDock(ida_kernwin.PluginForm):
    def __init__(self, plugin: "BinwalkIDAPlugin"):
        super().__init__()
        self.plugin = plugin
        self.panel: Optional[ui_panel.BinwalkPanel] = None

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self.panel = ui_panel.BinwalkPanel(
            get_target_label=self.plugin.get_target_label,
            scan_cb=self.plugin.scan_callback,
            extract_cb=self.plugin.extract_callback,
            jump_cb=self.plugin.jump_from_ui,
        )
        layout = parent.layout()
        if layout is None:
            layout = QVBoxLayout(parent)
            parent.setLayout(layout)
        layout.addWidget(self.panel)
        self.plugin._panel = self.panel

    def OnClose(self, form):
        self.plugin._panel = None
        self.panel = None

class BinwalkIDAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Binwalk plugin for IDA Pro"
    help = "Scan and extract embedded content with pybinwalk"
    wanted_name = "Binwalk"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self._hooks: Optional[BinwalkPopupHooks] = None
        self._dock: Optional[BinwalkDock] = None
        self._panel: Optional[ui_panel.BinwalkPanel] = None
        self._core = core.BinwalkCore(extracted_suffix="__extracted")

    def get_target_label(self) -> str:
        return _basename(_input_path())

    def ensure_dock(self) -> None:
        try:
            if self._dock is None:
                self._dock = BinwalkDock(self)

            self._dock.Show("Binwalk")
            idaapi.set_dock_pos("Binwalk", "", idaapi.DP_RIGHT)
        except Exception:
            LOG("[Binwalk][IDA] Failed to create dock widgett")
            pass

    def command_scan_fast(self) -> None:
        self.ensure_dock()
        self.scan_callback(deep=False)

    def command_extract(self) -> None:
        self.ensure_dock()
        if self._panel:
            self._panel.log("Extract requested")
            self.extract_callback(deep=False)

    def scan_callback(self, deep: bool) -> None:
        path = _input_path()
        if not path:
            if self._panel:
                self._panel.log("No input file path.", error=True)
            return

        if self._panel:
            self._panel.log(f"Scanning ({'Deep' if deep else 'Fast'})...")

        def worker():
            err = None
            results = []
            try:
                results = self._core.scan_disk(path, deep)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"

            def notify() -> int:
                if not self._panel:
                    return 1
                if err:
                    self._panel.log(f"Scan failed: {err}", error=True)
                else:
                    self._panel.log(f"Scan finished. Found {len(results)} signatures.")
                    self._panel.set_results(results)
                return 1

            ida_kernwin.execute_sync(notify, ida_kernwin.MFF_FAST)

        threading.Thread(target=worker, daemon=True).start()

    def extract_callback(self, deep: bool) -> None:
        path = _input_path()
        if not path:
            if self._panel:
                self._panel.log("No input file path.", error=True)
            return

        default_path = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        if not default_path:
            default_path = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)

        out_root = QFileDialog.getExistingDirectory(None, "Select Output Directory", default_path)
        if not out_root:
            if self._panel:
                self._panel.log("Extraction cancelled.")
            return

        if self._panel:
            self._panel.log(f"Extracting to: {out_root}")

        def worker():
            err = None
            success = 0
            job_dir = ""
            stats: Dict[str, int] = {}
            try:
                success, job_dir, stats = self._core.extract_disk(path, out_root, deep=deep)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"

            def notify() -> int:
                if not self._panel:
                    return 1
                if err:
                    self._panel.log(f"Extraction failed: {err}", error=True)
                else:
                    self._panel.show_extract_summary(success, job_dir, stats)
                    ida_kernwin.info(f"Binwalk extraction complete.\nExtracted items: {success}")
                return 1

            ida_kernwin.execute_sync(notify, ida_kernwin.MFF_FAST)

        threading.Thread(target=worker, daemon=True).start()

    def jump_from_ui(self, file_off: int) -> None:
        _jumpto_file_offset(file_off)

    def init(self):
        try:
            LOG("init() starting")

            ScanAction.register(self, "Scan")
            ExtractAction.register(self, "Extract...")

            try:
                idaapi.attach_action_to_menu("Edit/Plugins/", ScanAction.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Plugins/", ExtractAction.get_name(), idaapi.SETMENU_APP)
            except Exception as e:
                LOG(f"attach_action_to_menu failed: {type(e).__name__}: {e}")

            self._hooks = BinwalkPopupHooks()
            self._hooks.hook()
            LOG("UI hooks installed")

            def _show() -> int:
                try:
                    self.ensure_dock()
                    LOG("dock scheduled/show attempted")
                except Exception as e:
                    LOG(f"ensure_dock failed (ui): {type(e).__name__}: {e}")
                return 1

            ida_kernwin.execute_sync(_show, ida_kernwin.MFF_FAST)

            LOG("init() done")
            return idaapi.PLUGIN_KEEP

        except Exception as e:
            LOG(f"init() crashed: {type(e).__name__}: {e}")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        self.ensure_dock()

    def term(self):
        if self._hooks:
            try:
                self._hooks.unhook()
            except Exception:
                pass
            self._hooks = None

        ScanAction.unregister()
        ExtractAction.unregister()
        self._dock = None
        self._panel = None

def PLUGIN_ENTRY():
    return BinwalkIDAPlugin()