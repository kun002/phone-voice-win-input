#!/usr/bin/env python3
"""Send phone voice-typed text into the active Windows input box.

Run this on Windows, open the printed URL from a phone on the same LAN,
voice-type into the page with the phone keyboard, then send it to paste into
the currently focused Windows text box.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import html
import ipaddress
import json
import pathlib
import queue
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from qr_util import QrError, make_qr_ascii, make_qr_matrix, make_qr_png_bytes, make_qr_svg


APP_NAME = "Phone Voice to Windows Input"
APP_VERSION = "v36"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 256 * 1024
PORT_RETRY_COUNT = 50
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEVICE_TIMEOUT_SECONDS = 12
PREVIEW_SNIPPET_CHARS = 120
MAX_ERROR_LOG = 20
PROJECT_DIR = pathlib.Path(__file__).resolve().parent
LAST_QR_PATH = PROJECT_DIR / "last-phone-qr.png"
TOKEN_PATH = PROJECT_DIR / ".phone_voice_token"
SETTINGS_PATH = PROJECT_DIR / ".phone_voice_settings.json"
DEFAULT_INPUT_MODE = "mirror"
DEFAULT_SYNC_SPEED = "fast"
DEFAULT_WRITE_METHOD = "unicode"
DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS = 60
DEFAULT_AUTO_FINISH_DELAY_MS = 15000
DEFAULT_TAIL_REVISION_MAX_CHARS = 200
INPUT_MODE_VALUES = {"mirror", "pause_clear", "manual_clear", "preview_only"}
SYNC_SPEED_VALUES = {"turbo", "fast", "stable"}
WRITE_METHOD_VALUES = {"clipboard", "unicode"}
TARGET_LOCK_TIMEOUT_MIN_SECONDS = 0
TARGET_LOCK_TIMEOUT_MAX_SECONDS = 60
TARGET_LOCK_TIMEOUT_SUGGESTED_SECONDS = (0, 15, 30, 60)
AUTO_FINISH_DELAY_MIN_SECONDS = 0
AUTO_FINISH_DELAY_MAX_SECONDS = 60
AUTO_FINISH_DELAY_SUGGESTED_SECONDS = (0, 3, 5, 8, 15, 30, 60)
TAIL_REVISION_MIN_CHARS = 0
TAIL_REVISION_LIMIT_MAX_CHARS = 500
TAIL_REVISION_SUGGESTED_CHARS = (0, 20, 50, 100, 200, 500)


class InputError(RuntimeError):
    """Raised when Windows text injection fails."""


@dataclass(frozen=True)
class InjectionResult:
    action: str
    method: str
    chars: int
    clipboard_restored: bool = False
    clipboard_restore_skipped: bool = False
    clipboard_restore_reason: str = ""
    target_locked: bool = False
    target_restored: bool = False
    target_restore_reason: str = ""
    target_title: str = ""
    previous_foreground_restored: bool = False


@dataclass(frozen=True)
class TargetLock:
    device_id: str
    top_hwnd: int
    focus_hwnd: int
    thread_id: int
    title: str
    class_name: str
    focus_class_name: str = ""
    click_offset_x: int = 0
    click_offset_y: int = 0
    click_source: str = ""
    captured_at: float = field(default_factory=time.time)

    def payload(self) -> dict[str, Any]:
        return {
            "ok": True,
            "targetLocked": True,
            "targetTitle": self.title,
            "targetClass": self.class_name,
            "targetFocusClass": self.focus_class_name,
            "targetClickRestore": self.click_source in {"caret", "focus"},
            "targetClickSource": self.click_source,
            "targetCapturedAt": self.captured_at,
        }


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class POINT(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_long),
        ("y", ctypes.c_long),
    ]


class GUITHREADINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("hwndActive", ctypes.c_void_p),
        ("hwndFocus", ctypes.c_void_p),
        ("hwndCapture", ctypes.c_void_p),
        ("hwndMenuOwner", ctypes.c_void_p),
        ("hwndMoveSize", ctypes.c_void_p),
        ("hwndCaret", ctypes.c_void_p),
        ("rcCaret", RECT),
    ]


ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", ctypes.c_ulong),
        ("wParamL", ctypes.c_ushort),
        ("wParamH", ctypes.c_ushort),
    ]


class INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT),
    ]


class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("union", INPUT_UNION),
    ]


class WindowsTextInjector:
    def __init__(
        self,
        dry_run: bool = False,
        paste_delay: float = 0.08,
        protect_clipboard: bool = True,
        prefer_native_write: bool = True,
        target_click_restore: bool = True,
        foreground_restore: bool = True,
        return_previous_foreground: bool = False,
        write_method: str = DEFAULT_WRITE_METHOD,
        restore_delay: float = 0.12,
    ) -> None:
        self.dry_run = dry_run
        self.paste_delay = paste_delay
        self.protect_clipboard = protect_clipboard
        self.prefer_native_write = prefer_native_write
        self.target_click_restore = target_click_restore
        self.foreground_restore = foreground_restore
        self.return_previous_foreground = return_previous_foreground
        self.write_method = write_method if write_method in WRITE_METHOD_VALUES else DEFAULT_WRITE_METHOD
        self.restore_delay = restore_delay
        self.last_text = ""
        self._target_lock = threading.RLock()
        self._targets: dict[str, TargetLock] = {}

    def copy_text(self, text: str) -> InjectionResult:
        self.last_text = text
        if self.dry_run:
            return InjectionResult(action="copy", method="clipboard", chars=len(text))
        self._ensure_windows()
        self._set_clipboard(text)
        return InjectionResult(action="copy", method="clipboard", chars=len(text))

    def capture_target(self, device_id: str) -> TargetLock:
        device_key = device_id or "default"
        if self.dry_run:
            target = TargetLock(
                device_id=device_key,
                top_hwnd=1,
                focus_hwnd=1,
                thread_id=0,
                title="Dry-run target",
                class_name="dry-run",
                focus_class_name="Edit",
            )
        else:
            self._ensure_windows()
            target = self._capture_foreground_target(device_key)
        with self._target_lock:
            self._targets[device_key] = target
        return target

    def release_target(self, device_id: str) -> dict[str, Any]:
        device_key = device_id or "default"
        with self._target_lock:
            target = self._targets.pop(device_key, None)
        return {
            "ok": True,
            "targetLocked": False,
            "targetReleased": target is not None,
            "targetTitle": target.title if target else "",
        }

    def release_all_targets(self) -> dict[str, Any]:
        with self._target_lock:
            count = len(self._targets)
            self._targets.clear()
        return {
            "ok": True,
            "targetLocked": False,
            "targetReleased": count > 0,
            "targetReleasedCount": count,
        }

    def target_info(self, device_id: str) -> dict[str, Any]:
        target = self._target_for_device(device_id)
        if target is None:
            return {"ok": True, "targetLocked": False}
        payload = target.payload()
        payload["targetAgeSeconds"] = round(time.time() - target.captured_at, 1)
        return payload

    def has_target(self, device_id: str) -> bool:
        return self._target_for_device(device_id) is not None

    def paste_text(self, text: str, press_enter: bool = False, target_device_id: str = "") -> InjectionResult:
        return self._paste_via_clipboard(
            text,
            action="paste_enter" if press_enter else "paste",
            press_enter=press_enter,
            target_device_id=target_device_id,
        )

    def replace_text(self, text: str, press_enter: bool = False, target_device_id: str = "") -> InjectionResult:
        return self._paste_via_clipboard(
            text,
            action="replace_enter" if press_enter else "replace",
            press_enter=press_enter,
            select_all=True,
            target_device_id=target_device_id,
        )

    def revise_tail(self, text: str, delete_chars: int, target_device_id: str = "") -> InjectionResult:
        return self._revise_tail_via_clipboard(
            text,
            delete_chars=max(0, int(delete_chars or 0)),
            target_device_id=target_device_id,
        )

    def undo_last(self, target_device_id: str = "") -> InjectionResult:
        locked_target = self._target_for_device(target_device_id)
        if self.dry_run:
            return InjectionResult(
                action="undo",
                method="keyboard",
                chars=0,
                target_locked=locked_target is not None,
                target_restored=locked_target is not None,
                target_title=locked_target.title if locked_target else "",
            )
        self._ensure_windows()
        if locked_target is None:
            raise InputError("Target is not locked. Nothing safe to undo.")
        if not self.foreground_restore:
            raise InputError("Target restore disabled: foreground_restore_disabled")
        previous_foreground = self._foreground_window() if self.return_previous_foreground else 0
        previous_foreground_restored = False
        target_restored = False
        try:
            target_restored, target_restore_reason = self._restore_target(locked_target)
            if not target_restored:
                raise InputError(f"Target restore failed: {target_restore_reason}")
            time.sleep(0.04)
            self._send_ctrl_z()
        finally:
            if target_restored and self.return_previous_foreground:
                previous_foreground_restored = self._restore_previous_foreground(previous_foreground, locked_target.top_hwnd)
        return InjectionResult(
            action="undo",
            method="keyboard",
            chars=0,
            target_locked=True,
            target_restored=True,
            target_title=locked_target.title,
            previous_foreground_restored=previous_foreground_restored,
        )

    def _paste_via_clipboard(
        self,
        text: str,
        action: str,
        press_enter: bool = False,
        select_all: bool = False,
        target_device_id: str = "",
    ) -> InjectionResult:
        self.last_text = text
        locked_target = self._target_for_device(target_device_id)
        if self.dry_run:
            return InjectionResult(
                action=action,
                method="clipboard",
                chars=len(text),
                target_locked=locked_target is not None,
                target_restored=locked_target is not None,
                target_title=locked_target.title if locked_target else "",
            )
        self._ensure_windows()
        if locked_target is not None and self.prefer_native_write:
            native_result = self._try_native_control_write(
                locked_target,
                text,
                action=action,
                press_enter=press_enter,
                select_all=select_all,
            )
            if native_result is not None:
                return native_result
        if self.write_method == "unicode" and not select_all:
            return self._type_text_via_unicode_keyboard(
                text,
                action=action,
                press_enter=press_enter,
                target_device_id=target_device_id,
            )
        original_text = self._get_clipboard_text() if self.protect_clipboard else None
        self._set_clipboard(text)
        time.sleep(self.paste_delay)
        method = "clipboard"
        target_restored = False
        target_restore_reason = ""
        previous_foreground = (
            self._foreground_window()
            if locked_target is not None and self.foreground_restore and self.return_previous_foreground
            else 0
        )
        previous_foreground_restored = False
        should_restore_previous = False
        preserve_current_caret = bool(locked_target and self._foreground_window() == locked_target.top_hwnd)
        try:
            if locked_target is not None:
                if not self.foreground_restore:
                    if not self._try_background_message_paste(
                        locked_target,
                        press_enter=press_enter,
                        select_all=select_all,
                    ):
                        raise InputError("Target restore disabled: foreground_restore_disabled")
                    method = "background_message"
                    target_restore_reason = "background_message"
                    time.sleep(max(self.restore_delay, 0.25))
                else:
                    target_restored, target_restore_reason = self._restore_target(locked_target)
                    if not target_restored:
                        raise InputError(f"Target restore failed: {target_restore_reason}")
                    should_restore_previous = self.return_previous_foreground
                    time.sleep(0.04)
                    if select_all:
                        self._send_ctrl_a()
                        time.sleep(0.04)
                    elif not preserve_current_caret:
                        self._move_caret_to_end()
                    self._send_ctrl_v()
                    if press_enter:
                        time.sleep(0.05)
                        self._tap_key(0x0D)  # VK_RETURN
            else:
                if select_all:
                    self._send_ctrl_a()
                    time.sleep(0.04)
                self._send_ctrl_v()
                if press_enter:
                    time.sleep(0.05)
                    self._tap_key(0x0D)  # VK_RETURN
        except Exception:
            if self.protect_clipboard and original_text is not None and self._get_clipboard_text() == text:
                self._set_clipboard(original_text)
            raise
        finally:
            if should_restore_previous:
                previous_foreground_restored = self._restore_previous_foreground(previous_foreground, locked_target.top_hwnd if locked_target else 0)
        if not self.protect_clipboard:
            return InjectionResult(
                action=action,
                method=method,
                chars=len(text),
                target_locked=locked_target is not None,
                target_restored=target_restored,
                target_restore_reason=target_restore_reason,
                target_title=locked_target.title if locked_target else "",
                previous_foreground_restored=previous_foreground_restored,
            )

        time.sleep(self.restore_delay)
        current_text = self._get_clipboard_text()
        if current_text != text:
            return InjectionResult(
                action=action,
                method=method,
                chars=len(text),
                clipboard_restore_skipped=True,
                clipboard_restore_reason="clipboard_changed",
                target_locked=locked_target is not None,
                target_restored=target_restored,
                target_restore_reason=target_restore_reason,
                target_title=locked_target.title if locked_target else "",
                previous_foreground_restored=previous_foreground_restored,
            )
        if original_text is None:
            return InjectionResult(
                action=action,
                method=method,
                chars=len(text),
                clipboard_restore_skipped=True,
                clipboard_restore_reason="no_original_text",
                target_locked=locked_target is not None,
                target_restored=target_restored,
                target_restore_reason=target_restore_reason,
                target_title=locked_target.title if locked_target else "",
                previous_foreground_restored=previous_foreground_restored,
            )

        self._set_clipboard(original_text)
        return InjectionResult(
            action=action,
            method=method,
            chars=len(text),
            clipboard_restored=True,
            target_locked=locked_target is not None,
            target_restored=target_restored,
            target_restore_reason=target_restore_reason,
            target_title=locked_target.title if locked_target else "",
            previous_foreground_restored=previous_foreground_restored,
        )

    def _revise_tail_via_clipboard(
        self,
        text: str,
        delete_chars: int,
        target_device_id: str = "",
    ) -> InjectionResult:
        self.last_text = text
        locked_target = self._target_for_device(target_device_id)
        if self.dry_run:
            return InjectionResult(
                action="revise_tail",
                method="keyboard_clipboard",
                chars=len(text),
                target_locked=locked_target is not None,
                target_restored=locked_target is not None,
                target_title=locked_target.title if locked_target else "",
            )
        self._ensure_windows()
        if locked_target is None:
            raise InputError("Target is not locked. Nothing safe to revise.")
        if self.prefer_native_write:
            native_result = self._try_native_tail_revision(locked_target, text, delete_chars)
            if native_result is not None:
                return native_result
        if self.write_method == "unicode":
            return self._revise_tail_via_unicode_keyboard(text, delete_chars, target_device_id)
        if not self.foreground_restore:
            raise InputError("Target restore disabled: foreground_restore_disabled")

        original_text = self._get_clipboard_text() if self.protect_clipboard else None
        previous_foreground = self._foreground_window() if self.return_previous_foreground else 0
        previous_foreground_restored = False
        target_restored = False
        target_restore_reason = ""
        should_restore_previous = False
        preserve_current_caret = self._foreground_window() == locked_target.top_hwnd
        try:
            target_restored, target_restore_reason = self._restore_target(locked_target)
            if not target_restored:
                raise InputError(f"Target restore failed: {target_restore_reason}")
            should_restore_previous = self.return_previous_foreground
            time.sleep(0.04)
            if not preserve_current_caret:
                self._move_caret_to_end()
            for _ in range(min(delete_chars, 200)):
                self._tap_key(0x08)  # VK_BACK
                time.sleep(0.002)
            if text:
                self._set_clipboard(text)
                time.sleep(self.paste_delay)
                self._send_ctrl_v()
        except Exception:
            if self.protect_clipboard and original_text is not None and self._get_clipboard_text() == text:
                self._set_clipboard(original_text)
            raise
        finally:
            if should_restore_previous:
                previous_foreground_restored = self._restore_previous_foreground(previous_foreground, locked_target.top_hwnd)

        if self.protect_clipboard:
            time.sleep(self.restore_delay)
            if original_text is not None and self._get_clipboard_text() == text:
                self._set_clipboard(original_text)
                clipboard_restored = True
                clipboard_restore_skipped = False
                clipboard_restore_reason = ""
            else:
                clipboard_restored = False
                clipboard_restore_skipped = True
                clipboard_restore_reason = "clipboard_changed" if original_text is not None else "no_original_text"
        else:
            clipboard_restored = False
            clipboard_restore_skipped = False
            clipboard_restore_reason = ""

        return InjectionResult(
            action="revise_tail",
            method="keyboard_clipboard",
            chars=len(text),
            clipboard_restored=clipboard_restored,
            clipboard_restore_skipped=clipboard_restore_skipped,
            clipboard_restore_reason=clipboard_restore_reason,
            target_locked=True,
            target_restored=target_restored,
            target_restore_reason=target_restore_reason,
            target_title=locked_target.title,
            previous_foreground_restored=previous_foreground_restored,
        )

    def _type_text_via_unicode_keyboard(
        self,
        text: str,
        action: str,
        press_enter: bool = False,
        target_device_id: str = "",
    ) -> InjectionResult:
        self.last_text = text
        locked_target = self._target_for_device(target_device_id)
        if self.dry_run:
            return InjectionResult(
                action=action,
                method="unicode_keyboard",
                chars=len(text),
                target_locked=locked_target is not None,
                target_restored=locked_target is not None,
                target_title=locked_target.title if locked_target else "",
            )
        self._ensure_windows()
        previous_foreground = self._foreground_window() if locked_target is not None and self.return_previous_foreground else 0
        previous_foreground_restored = False
        target_restored = False
        target_restore_reason = ""
        should_restore_previous = False
        preserve_current_caret = bool(locked_target and self._foreground_window() == locked_target.top_hwnd)
        try:
            if locked_target is not None:
                if not self.foreground_restore:
                    raise InputError("Target restore disabled: foreground_restore_disabled")
                target_restored, target_restore_reason = self._restore_target(locked_target)
                if not target_restored:
                    raise InputError(f"Target restore failed: {target_restore_reason}")
                should_restore_previous = self.return_previous_foreground
                time.sleep(0.04)
                if not preserve_current_caret:
                    self._move_caret_to_end()
            if text:
                self._send_unicode_text(text)
            if press_enter:
                time.sleep(0.05)
                self._tap_key(0x0D)  # VK_RETURN
        finally:
            if should_restore_previous:
                previous_foreground_restored = self._restore_previous_foreground(previous_foreground, locked_target.top_hwnd if locked_target else 0)
        return InjectionResult(
            action=action,
            method="unicode_keyboard",
            chars=len(text),
            target_locked=locked_target is not None,
            target_restored=target_restored,
            target_restore_reason=target_restore_reason,
            target_title=locked_target.title if locked_target else "",
            previous_foreground_restored=previous_foreground_restored,
        )

    def _revise_tail_via_unicode_keyboard(
        self,
        text: str,
        delete_chars: int,
        target_device_id: str = "",
    ) -> InjectionResult:
        self.last_text = text
        locked_target = self._target_for_device(target_device_id)
        if self.dry_run:
            return InjectionResult(
                action="revise_tail",
                method="unicode_keyboard",
                chars=len(text),
                target_locked=locked_target is not None,
                target_restored=locked_target is not None,
                target_title=locked_target.title if locked_target else "",
            )
        self._ensure_windows()
        if locked_target is None:
            raise InputError("Target is not locked. Nothing safe to revise.")
        if not self.foreground_restore:
            raise InputError("Target restore disabled: foreground_restore_disabled")
        previous_foreground = self._foreground_window() if self.return_previous_foreground else 0
        previous_foreground_restored = False
        target_restored = False
        target_restore_reason = ""
        should_restore_previous = False
        preserve_current_caret = self._foreground_window() == locked_target.top_hwnd
        try:
            target_restored, target_restore_reason = self._restore_target(locked_target)
            if not target_restored:
                raise InputError(f"Target restore failed: {target_restore_reason}")
            should_restore_previous = self.return_previous_foreground
            time.sleep(0.04)
            if not preserve_current_caret:
                self._move_caret_to_end()
            for _ in range(max(0, int(delete_chars or 0))):
                self._tap_key(0x08)  # VK_BACK
                time.sleep(0.002)
            if text:
                self._send_unicode_text(text)
        finally:
            if should_restore_previous:
                previous_foreground_restored = self._restore_previous_foreground(previous_foreground, locked_target.top_hwnd)
        return InjectionResult(
            action="revise_tail",
            method="unicode_keyboard",
            chars=len(text),
            target_locked=True,
            target_restored=target_restored,
            target_restore_reason=target_restore_reason,
            target_title=locked_target.title,
            previous_foreground_restored=previous_foreground_restored,
        )

    def _target_for_device(self, device_id: str) -> TargetLock | None:
        if not device_id:
            return None
        with self._target_lock:
            return self._targets.get(device_id)

    def _capture_foreground_target(self, device_id: str) -> TargetLock:
        user32 = ctypes.windll.user32
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.GetWindowThreadProcessId.restype = ctypes.c_uint
        user32.GetGUIThreadInfo.argtypes = [ctypes.c_uint, ctypes.POINTER(GUITHREADINFO)]
        user32.GetGUIThreadInfo.restype = ctypes.c_int

        top_hwnd = self._handle_value(user32.GetForegroundWindow())
        if not top_hwnd:
            raise InputError("No foreground Windows target to lock.")

        thread_id = int(user32.GetWindowThreadProcessId(ctypes.c_void_p(top_hwnd), None))
        focus_hwnd = 0
        gui_info: GUITHREADINFO | None = None
        if thread_id:
            info = GUITHREADINFO()
            info.cbSize = ctypes.sizeof(GUITHREADINFO)
            if user32.GetGUIThreadInfo(thread_id, ctypes.byref(info)):
                gui_info = info
                focus_hwnd = self._handle_value(info.hwndFocus) or self._handle_value(info.hwndActive)

        class_name = self._window_class(top_hwnd)
        focus_class_name = self._window_class(focus_hwnd) if focus_hwnd else ""
        title = self._window_text(top_hwnd) or class_name or f"HWND {top_hwnd}"
        click_offset_x, click_offset_y, click_source = self._capture_click_restore_point(
            top_hwnd,
            focus_hwnd,
            focus_class_name,
            gui_info,
        )
        return TargetLock(
            device_id=device_id,
            top_hwnd=top_hwnd,
            focus_hwnd=focus_hwnd,
            thread_id=thread_id,
            title=title,
            class_name=class_name,
            focus_class_name=focus_class_name,
            click_offset_x=click_offset_x,
            click_offset_y=click_offset_y,
            click_source=click_source,
        )

    def _capture_click_restore_point(
        self,
        top_hwnd: int,
        focus_hwnd: int,
        focus_class_name: str,
        gui_info: GUITHREADINFO | None,
    ) -> tuple[int, int, str]:
        top_rect = self._window_rect(top_hwnd)
        if top_rect is None:
            return 0, 0, ""

        if gui_info is not None:
            caret_hwnd = self._handle_value(gui_info.hwndCaret)
            caret_point = self._screen_point_from_caret(caret_hwnd, gui_info.rcCaret)
            if caret_point and self._point_in_rect(caret_point[0], caret_point[1], top_rect):
                return caret_point[0] - top_rect[0], caret_point[1] - top_rect[1], "caret"

        focus_point = self._safe_focus_click_point(top_hwnd, focus_hwnd, focus_class_name)
        if focus_point and self._point_in_rect(focus_point[0], focus_point[1], top_rect):
            return focus_point[0] - top_rect[0], focus_point[1] - top_rect[1], "focus"

        cursor_point = self._cursor_point()
        if cursor_point and self._point_in_rect(cursor_point[0], cursor_point[1], top_rect):
            return cursor_point[0] - top_rect[0], cursor_point[1] - top_rect[1], "cursor"
        return 0, 0, ""

    def _screen_point_from_caret(self, caret_hwnd: int, caret_rect: RECT) -> tuple[int, int] | None:
        if not caret_hwnd:
            return None
        width = max(1, int(caret_rect.right - caret_rect.left))
        height = max(1, int(caret_rect.bottom - caret_rect.top))
        point = POINT(int(caret_rect.left + min(2, width)), int(caret_rect.top + height // 2))
        user32 = ctypes.windll.user32
        user32.ClientToScreen.argtypes = [ctypes.c_void_p, ctypes.POINTER(POINT)]
        user32.ClientToScreen.restype = ctypes.c_int
        if not user32.ClientToScreen(ctypes.c_void_p(caret_hwnd), ctypes.byref(point)):
            return None
        return int(point.x), int(point.y)

    def _safe_focus_click_point(
        self,
        top_hwnd: int,
        focus_hwnd: int,
        focus_class_name: str,
    ) -> tuple[int, int] | None:
        if not focus_hwnd or focus_hwnd == top_hwnd:
            return None
        top_rect = self._window_rect(top_hwnd)
        focus_rect = self._window_rect(focus_hwnd)
        if top_rect is None or focus_rect is None:
            return None
        if not self._rect_inside(focus_rect, top_rect):
            return None
        focus_area = self._rect_area(focus_rect)
        top_area = self._rect_area(top_rect)
        if not self._native_write_supported_class(focus_class_name) and focus_area > top_area * 0.65:
            return None
        return (focus_rect[0] + focus_rect[2]) // 2, (focus_rect[1] + focus_rect[3]) // 2

    def _try_native_control_write(
        self,
        target: TargetLock,
        text: str,
        action: str,
        press_enter: bool = False,
        select_all: bool = False,
    ) -> InjectionResult | None:
        if self.dry_run or press_enter or not target.focus_hwnd:
            return None
        if not self._native_write_supported_class(target.focus_class_name):
            return None
        user32 = ctypes.windll.user32
        user32.IsWindow.argtypes = [ctypes.c_void_p]
        user32.IsWindow.restype = ctypes.c_int
        user32.IsChild.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.IsChild.restype = ctypes.c_int
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        top = ctypes.c_void_p(target.top_hwnd)
        focus = ctypes.c_void_p(target.focus_hwnd)
        if not user32.IsWindow(top):
            self.release_target(target.device_id)
            raise InputError("Target restore failed: target_window_closed")
        if not user32.IsWindow(focus):
            return None
        if target.focus_hwnd != target.top_hwnd and not user32.IsChild(top, focus):
            return None

        normalized_text = self._native_control_text(text)
        if select_all:
            ok = self._send_text_message(target.focus_hwnd, 0x000C, 0, normalized_text)  # WM_SETTEXT
        else:
            ok = self._send_text_message(target.focus_hwnd, 0x00C2, 1, normalized_text)  # EM_REPLACESEL
        if not ok:
            return None
        self.last_text = text
        return InjectionResult(
            action=action,
            method="native_control",
            chars=len(text),
            target_locked=True,
            target_restored=True,
            target_title=target.title,
        )

    def _try_native_tail_revision(
        self,
        target: TargetLock,
        text: str,
        delete_chars: int,
    ) -> InjectionResult | None:
        if self.dry_run or not target.focus_hwnd:
            return None
        if not self._native_write_supported_class(target.focus_class_name):
            return None
        user32 = ctypes.windll.user32
        user32.IsWindow.argtypes = [ctypes.c_void_p]
        user32.IsWindow.restype = ctypes.c_int
        user32.IsChild.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.IsChild.restype = ctypes.c_int
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        top = ctypes.c_void_p(target.top_hwnd)
        focus = ctypes.c_void_p(target.focus_hwnd)
        if not user32.IsWindow(top):
            self.release_target(target.device_id)
            raise InputError("Target restore failed: target_window_closed")
        if not user32.IsWindow(focus):
            return None
        if target.focus_hwnd != target.top_hwnd and not user32.IsChild(top, focus):
            return None

        current_length = max(0, int(user32.GetWindowTextLengthW(focus)))
        selection = self._native_selection(target.focus_hwnd)
        selection_start, selection_end = selection if selection is not None else (current_length, current_length)
        start = max(0, selection_start - max(0, int(delete_chars or 0)))
        if not self._send_numeric_message(target.focus_hwnd, 0x00B1, start, selection_end):  # EM_SETSEL
            return None
        normalized_text = self._native_control_text(text)
        if not self._send_text_message(target.focus_hwnd, 0x00C2, 1, normalized_text):  # EM_REPLACESEL
            return None
        self.last_text = text
        return InjectionResult(
            action="revise_tail",
            method="native_control",
            chars=len(text),
            target_locked=True,
            target_restored=True,
            target_title=target.title,
        )

    @staticmethod
    def _native_write_supported_class(class_name: str) -> bool:
        lowered = class_name.lower()
        return (
            lowered == "edit"
            or lowered.startswith("richedit")
            or lowered.startswith("richedit20")
            or lowered.startswith("richedit50")
            or lowered.startswith("windowsforms10.edit.")
            or lowered.startswith("thunderrt6textbox")
        )

    @staticmethod
    def _native_control_text(text: str) -> str:
        return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    @staticmethod
    def _send_text_message(hwnd: int, message: int, wparam: int, text: str) -> bool:
        user32 = ctypes.windll.user32
        user32.SendMessageTimeoutW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_size_t,
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        user32.SendMessageTimeoutW.restype = ctypes.c_void_p
        result = ctypes.c_size_t()
        delivered = user32.SendMessageTimeoutW(
            ctypes.c_void_p(hwnd),
            message,
            ctypes.c_size_t(wparam),
            ctypes.c_wchar_p(text),
            0x0002,  # SMTO_ABORTIFHUNG
            800,
            ctypes.byref(result),
        )
        if not delivered:
            return False
        if message == 0x000C and result.value == 0:
            return False
        return True

    @staticmethod
    def _send_numeric_message(hwnd: int, message: int, wparam: int, lparam: int) -> bool:
        user32 = ctypes.windll.user32
        user32.SendMessageTimeoutW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        user32.SendMessageTimeoutW.restype = ctypes.c_void_p
        result = ctypes.c_size_t()
        delivered = user32.SendMessageTimeoutW(
            ctypes.c_void_p(hwnd),
            message,
            ctypes.c_size_t(max(0, int(wparam or 0))),
            ctypes.c_size_t(max(0, int(lparam or 0))),
            0x0002,  # SMTO_ABORTIFHUNG
            800,
            ctypes.byref(result),
        )
        return bool(delivered)

    @staticmethod
    def _native_selection(hwnd: int) -> tuple[int, int] | None:
        user32 = ctypes.windll.user32
        user32.SendMessageTimeoutW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        user32.SendMessageTimeoutW.restype = ctypes.c_void_p
        result = ctypes.c_size_t()
        delivered = user32.SendMessageTimeoutW(
            ctypes.c_void_p(hwnd),
            0x00B0,  # EM_GETSEL
            0,
            0,
            0x0002,  # SMTO_ABORTIFHUNG
            800,
            ctypes.byref(result),
        )
        if not delivered:
            return None
        packed = int(result.value)
        if packed == 0xFFFFFFFF:
            return None
        return packed & 0xFFFF, (packed >> 16) & 0xFFFF

    def _try_background_message_paste(
        self,
        target: TargetLock,
        press_enter: bool = False,
        select_all: bool = False,
    ) -> bool:
        user32 = ctypes.windll.user32
        user32.IsWindow.argtypes = [ctypes.c_void_p]
        user32.IsWindow.restype = ctypes.c_int
        user32.IsChild.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.IsChild.restype = ctypes.c_int
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
        user32.PostMessageW.restype = ctypes.c_int

        if select_all or press_enter:
            return False

        top = ctypes.c_void_p(target.top_hwnd)
        if not user32.IsWindow(top):
            self.release_target(target.device_id)
            raise InputError("Target restore failed: target_window_closed")

        hwnds: list[int] = []
        if target.focus_hwnd and user32.IsWindow(ctypes.c_void_p(target.focus_hwnd)):
            if target.focus_hwnd == target.top_hwnd or user32.IsChild(top, ctypes.c_void_p(target.focus_hwnd)):
                hwnds.append(target.focus_hwnd)
        if target.top_hwnd not in hwnds:
            hwnds.append(target.top_hwnd)

        if not hwnds:
            return False

        wm_paste = 0x0302

        def post(hwnd: int, message: int, wparam: int, lparam: int = 0) -> bool:
            return bool(user32.PostMessageW(ctypes.c_void_p(hwnd), message, ctypes.c_size_t(wparam), ctypes.c_ssize_t(lparam)))

        delivered = False
        for hwnd in hwnds:
            delivered = post(hwnd, wm_paste, 0, 0) or delivered
            time.sleep(0.03)
        return delivered

    @staticmethod
    def _foreground_window() -> int:
        if not sys.platform.startswith("win"):
            return 0
        user32 = ctypes.windll.user32
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        return WindowsTextInjector._handle_value(user32.GetForegroundWindow())

    @staticmethod
    def _restore_previous_foreground(previous_hwnd: int, target_hwnd: int) -> bool:
        if not previous_hwnd or previous_hwnd == target_hwnd:
            return False
        user32 = ctypes.windll.user32
        user32.IsWindow.argtypes = [ctypes.c_void_p]
        user32.IsWindow.restype = ctypes.c_int
        user32.IsIconic.argtypes = [ctypes.c_void_p]
        user32.IsIconic.restype = ctypes.c_int
        user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.ShowWindow.restype = ctypes.c_int
        user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
        user32.SetForegroundWindow.restype = ctypes.c_int
        previous = ctypes.c_void_p(previous_hwnd)
        if not user32.IsWindow(previous):
            return False
        if user32.IsIconic(previous):
            user32.ShowWindow(previous, 9)  # SW_RESTORE only when minimized
        if not user32.SetForegroundWindow(previous):
            return False
        return WindowsTextInjector._foreground_window() == previous_hwnd

    def _restore_target(self, target: TargetLock) -> tuple[bool, str]:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.IsWindow.argtypes = [ctypes.c_void_p]
        user32.IsWindow.restype = ctypes.c_int
        user32.IsIconic.argtypes = [ctypes.c_void_p]
        user32.IsIconic.restype = ctypes.c_int
        user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.ShowWindow.restype = ctypes.c_int
        user32.BringWindowToTop.argtypes = [ctypes.c_void_p]
        user32.BringWindowToTop.restype = ctypes.c_int
        user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
        user32.SetForegroundWindow.restype = ctypes.c_int
        user32.SetActiveWindow.argtypes = [ctypes.c_void_p]
        user32.SetActiveWindow.restype = ctypes.c_void_p
        user32.SetFocus.argtypes = [ctypes.c_void_p]
        user32.SetFocus.restype = ctypes.c_void_p
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.GetWindowThreadProcessId.restype = ctypes.c_uint
        user32.AttachThreadInput.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
        user32.AttachThreadInput.restype = ctypes.c_int
        kernel32.GetCurrentThreadId.argtypes = []
        kernel32.GetCurrentThreadId.restype = ctypes.c_uint

        top = ctypes.c_void_p(target.top_hwnd)
        if not user32.IsWindow(top):
            self.release_target(target.device_id)
            return False, "target_window_closed"

        current_thread = int(kernel32.GetCurrentThreadId())
        target_thread = target.thread_id or int(user32.GetWindowThreadProcessId(top, None))
        foreground_hwnd = self._handle_value(user32.GetForegroundWindow())
        was_target_foreground = foreground_hwnd == target.top_hwnd
        foreground_thread = (
            int(user32.GetWindowThreadProcessId(ctypes.c_void_p(foreground_hwnd), None))
            if foreground_hwnd
            else 0
        )
        attached_threads: list[int] = []
        for thread_id in {target_thread, foreground_thread}:
            if thread_id and thread_id != current_thread:
                if user32.AttachThreadInput(current_thread, thread_id, 1):
                    attached_threads.append(thread_id)
        try:
            if user32.IsIconic(top):
                user32.ShowWindow(top, 9)  # SW_RESTORE only when minimized
            user32.BringWindowToTop(top)
            user32.SetForegroundWindow(top)
            user32.SetActiveWindow(top)
            if target.focus_hwnd and user32.IsWindow(ctypes.c_void_p(target.focus_hwnd)):
                user32.SetFocus(ctypes.c_void_p(target.focus_hwnd))
        finally:
            for thread_id in attached_threads:
                user32.AttachThreadInput(current_thread, thread_id, 0)

        time.sleep(0.05)
        restored_hwnd = self._handle_value(user32.GetForegroundWindow())
        if restored_hwnd != target.top_hwnd:
            return False, "foreground_not_restored"
        should_click_restore = (
            self.target_click_restore
            and target.click_source in {"caret", "focus"}
            and not was_target_foreground
        )
        if should_click_restore:
            self._click_target_restore_point(target)
        return True, ""

    def _click_target_restore_point(self, target: TargetLock) -> bool:
        rect = self._window_rect(target.top_hwnd)
        if rect is None:
            return False
        x = int(rect[0] + target.click_offset_x)
        y = int(rect[1] + target.click_offset_y)
        if not self._point_in_rect(x, y, rect):
            return False
        self._click_screen_point(x, y)
        time.sleep(0.04)
        return True

    @staticmethod
    def _click_screen_point(x: int, y: int) -> None:
        user32 = ctypes.windll.user32
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.GetCursorPos.restype = ctypes.c_int
        user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
        user32.SetCursorPos.restype = ctypes.c_int
        user32.mouse_event.argtypes = [
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_size_t,
        ]
        user32.mouse_event.restype = None
        original = POINT()
        has_original = bool(user32.GetCursorPos(ctypes.byref(original)))
        try:
            if not user32.SetCursorPos(int(x), int(y)):
                return
            time.sleep(0.01)
            user32.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
            user32.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
        finally:
            if has_original:
                user32.SetCursorPos(int(original.x), int(original.y))

    @staticmethod
    def _cursor_point() -> tuple[int, int] | None:
        user32 = ctypes.windll.user32
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.GetCursorPos.restype = ctypes.c_int
        point = POINT()
        if not user32.GetCursorPos(ctypes.byref(point)):
            return None
        return int(point.x), int(point.y)
    @staticmethod
    def _window_text(hwnd: int) -> str:
        user32 = ctypes.windll.user32
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        user32.GetWindowTextW.restype = ctypes.c_int
        length = user32.GetWindowTextLengthW(ctypes.c_void_p(hwnd))
        if length <= 0:
            return ""
        buffer = ctypes.create_unicode_buffer(length + 1)
        if not user32.GetWindowTextW(ctypes.c_void_p(hwnd), buffer, length + 1):
            return ""
        return buffer.value

    @staticmethod
    def _window_class(hwnd: int) -> str:
        user32 = ctypes.windll.user32
        user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        user32.GetClassNameW.restype = ctypes.c_int
        buffer = ctypes.create_unicode_buffer(256)
        if not user32.GetClassNameW(ctypes.c_void_p(hwnd), buffer, len(buffer)):
            return ""
        return buffer.value

    @staticmethod
    def _window_rect(hwnd: int) -> tuple[int, int, int, int] | None:
        if not hwnd:
            return None
        user32 = ctypes.windll.user32
        user32.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(RECT)]
        user32.GetWindowRect.restype = ctypes.c_int
        rect = RECT()
        if not user32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(rect)):
            return None
        return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)

    @staticmethod
    def _point_in_rect(x: int, y: int, rect: tuple[int, int, int, int]) -> bool:
        return rect[0] <= x < rect[2] and rect[1] <= y < rect[3]

    @staticmethod
    def _rect_inside(inner: tuple[int, int, int, int], outer: tuple[int, int, int, int]) -> bool:
        return inner[0] >= outer[0] and inner[1] >= outer[1] and inner[2] <= outer[2] and inner[3] <= outer[3]

    @staticmethod
    def _rect_area(rect: tuple[int, int, int, int]) -> int:
        return max(0, rect[2] - rect[0]) * max(0, rect[3] - rect[1])

    @staticmethod
    def _handle_value(value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        return int(value.value or 0)

    @staticmethod
    def _ensure_windows() -> None:
        if not sys.platform.startswith("win"):
            raise InputError("This injector only works on Windows.")

    @staticmethod
    def _set_clipboard(text: str) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = ctypes.c_int
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p
        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = ctypes.c_int
        user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = ctypes.c_int

        cf_unicode_text = 13
        gmem_moveable = 0x0002
        data = (text + "\0").encode("utf-16le")

        handle = kernel32.GlobalAlloc(gmem_moveable, len(data))
        if not handle:
            raise InputError("GlobalAlloc failed while preparing clipboard text.")

        locked = kernel32.GlobalLock(handle)
        if not locked:
            kernel32.GlobalFree(handle)
            raise InputError("GlobalLock failed while preparing clipboard text.")

        ctypes.memmove(locked, data, len(data))
        kernel32.GlobalUnlock(handle)

        if not user32.OpenClipboard(None):
            kernel32.GlobalFree(handle)
            raise InputError("OpenClipboard failed. Another app may be using it.")

        clipboard_owns_handle = False
        try:
            if not user32.EmptyClipboard():
                raise InputError("EmptyClipboard failed.")
            if not user32.SetClipboardData(cf_unicode_text, handle):
                raise InputError("SetClipboardData failed.")
            clipboard_owns_handle = True
        finally:
            user32.CloseClipboard()
            if not clipboard_owns_handle:
                kernel32.GlobalFree(handle)

    @staticmethod
    def _get_clipboard_text() -> str | None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = ctypes.c_int
        user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
        user32.IsClipboardFormatAvailable.restype = ctypes.c_int
        user32.GetClipboardData.argtypes = [ctypes.c_uint]
        user32.GetClipboardData.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = ctypes.c_int

        cf_unicode_text = 13
        if not user32.OpenClipboard(None):
            return None
        try:
            if not user32.IsClipboardFormatAvailable(cf_unicode_text):
                return None
            handle = user32.GetClipboardData(cf_unicode_text)
            if not handle:
                return None
            locked = kernel32.GlobalLock(handle)
            if not locked:
                return None
            try:
                return ctypes.wstring_at(locked)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

    @staticmethod
    def _move_caret_to_end() -> None:
        WindowsTextInjector._send_key_chord(0x11, 0x23, key_flags=0x0001)  # Ctrl+extended End
        time.sleep(0.02)

    @staticmethod
    def _send_ctrl_v() -> None:
        WindowsTextInjector._send_key_chord(0x11, 0x56)

    @staticmethod
    def _send_ctrl_a() -> None:
        WindowsTextInjector._send_key_chord(0x11, 0x41)

    @staticmethod
    def _send_ctrl_z() -> None:
        WindowsTextInjector._send_key_chord(0x11, 0x5A)

    @staticmethod
    def _send_key_chord(modifier_vk: int, key_vk: int, key_flags: int = 0) -> None:
        key_up = 0x0002
        WindowsTextInjector._release_common_modifiers()
        time.sleep(0.01)
        try:
            WindowsTextInjector._send_input_events([
                (modifier_vk, 0),
                (key_vk, key_flags),
                (key_vk, key_flags | key_up),
                (modifier_vk, key_up),
            ])
        except InputError:
            WindowsTextInjector._key_down(modifier_vk)
            try:
                WindowsTextInjector._keybd_event(key_vk, key_flags)
                WindowsTextInjector._keybd_event(key_vk, key_flags | key_up)
            finally:
                WindowsTextInjector._key_up(modifier_vk)
        finally:
            WindowsTextInjector._release_common_modifiers()

    @staticmethod
    def _tap_key(vk_code: int) -> None:
        key_up = 0x0002
        try:
            WindowsTextInjector._send_input_events([(vk_code, 0), (vk_code, key_up)])
        except InputError:
            WindowsTextInjector._key_down(vk_code)
            WindowsTextInjector._key_up(vk_code)

    @staticmethod
    def _release_common_modifiers() -> None:
        key_up = 0x0002
        modifiers = (0x11, 0xA2, 0xA3, 0x10, 0xA0, 0xA1, 0x12, 0xA4, 0xA5, 0x5B, 0x5C)
        try:
            WindowsTextInjector._send_input_events([(vk, key_up) for vk in modifiers])
        except InputError:
            for vk in modifiers:
                WindowsTextInjector._keybd_event(vk, key_up)

    @staticmethod
    def _send_input_events(events: list[tuple[int, int]]) -> None:
        if not events:
            return
        user32 = ctypes.windll.user32
        user32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]
        user32.SendInput.restype = ctypes.c_uint
        inputs = (INPUT * len(events))()
        for index, (vk_code, flags) in enumerate(events):
            inputs[index].type = 1  # INPUT_KEYBOARD
            inputs[index].union.ki = KEYBDINPUT(
                wVk=int(vk_code),
                wScan=0,
                dwFlags=int(flags),
                time=0,
                dwExtraInfo=0,
            )
        sent = int(user32.SendInput(len(inputs), inputs, ctypes.sizeof(INPUT)))
        if sent != len(events):
            raise InputError(f"SendInput sent {sent}/{len(events)} keyboard events.")

    @staticmethod
    def _send_unicode_text(text: str) -> None:
        units = WindowsTextInjector._utf16_units(text)
        chunk_size = 64
        for offset in range(0, len(units), chunk_size):
            WindowsTextInjector._send_unicode_units(units[offset : offset + chunk_size])

    @staticmethod
    def _utf16_units(text: str) -> list[int]:
        encoded = text.encode("utf-16-le", "surrogatepass")
        return [int.from_bytes(encoded[index : index + 2], "little") for index in range(0, len(encoded), 2)]

    @staticmethod
    def _send_unicode_units(units: list[int]) -> None:
        if not units:
            return
        key_up = 0x0002
        keyeventf_unicode = 0x0004
        events: list[tuple[int, int]] = []
        for unit in units:
            events.append((unit, keyeventf_unicode))
            events.append((unit, keyeventf_unicode | key_up))
        user32 = ctypes.windll.user32
        user32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]
        user32.SendInput.restype = ctypes.c_uint
        inputs = (INPUT * len(events))()
        for index, (scan_code, flags) in enumerate(events):
            inputs[index].type = 1  # INPUT_KEYBOARD
            inputs[index].union.ki = KEYBDINPUT(
                wVk=0,
                wScan=int(scan_code),
                dwFlags=int(flags),
                time=0,
                dwExtraInfo=0,
            )
        sent = int(user32.SendInput(len(inputs), inputs, ctypes.sizeof(INPUT)))
        if sent != len(events):
            raise InputError(f"SendInput sent {sent}/{len(events)} unicode keyboard events.")

    @staticmethod
    def _key_down(vk_code: int) -> None:
        WindowsTextInjector._keybd_event(vk_code, 0)

    @staticmethod
    def _key_up(vk_code: int) -> None:
        WindowsTextInjector._keybd_event(vk_code, 0x0002)

    @staticmethod
    def _keybd_event(vk_code: int, flags: int) -> None:
        user32 = ctypes.windll.user32
        user32.keybd_event.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ulong, ULONG_PTR]
        user32.keybd_event.restype = None
        user32.keybd_event(vk_code, 0, flags, 0)


@dataclass
class DeviceSession:
    device_id: str
    name: str
    address: str
    user_agent: str
    transport: str
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    preview_text: str = ""
    target_locked: bool = False
    target_title: str = ""
    target_locked_at: float = 0.0
    target_activity_at: float = 0.0
    clear_sequence: int = 0


@dataclass
class RuntimeSettings:
    clipboard_protect: bool = True
    native_write: bool = True
    target_click_restore: bool = True
    foreground_restore: bool = True
    return_previous_foreground: bool = False
    target_lock_timeout_seconds: int = DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS
    auto_finish_delay_ms: int = DEFAULT_AUTO_FINISH_DELAY_MS
    tail_revision_max_chars: int = DEFAULT_TAIL_REVISION_MAX_CHARS
    default_input_mode: str = DEFAULT_INPUT_MODE
    default_sync_speed: str = DEFAULT_SYNC_SPEED
    write_method: str = DEFAULT_WRITE_METHOD

    def snapshot(self) -> dict[str, Any]:
        return {
            "clipboardProtect": self.clipboard_protect,
            "nativeWrite": self.native_write,
            "targetClickRestore": self.target_click_restore,
            "foregroundRestore": self.foreground_restore,
            "returnPreviousForeground": self.return_previous_foreground,
            "targetLockTimeoutSeconds": self.target_lock_timeout_seconds,
            "autoFinishDelayMs": self.auto_finish_delay_ms,
            "tailRevisionMaxChars": self.tail_revision_max_chars,
            "defaultInputMode": self.default_input_mode,
            "defaultSyncSpeed": self.default_sync_speed,
            "writeMethod": self.write_method,
        }


@dataclass
class ErrorEvent:
    category: str
    message: str
    device_id: str = ""
    device_name: str = ""
    action: str = ""
    address: str = ""
    text_chars: int = 0
    created_at: float = field(default_factory=time.time)


class ServerState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.devices: dict[str, DeviceSession] = {}
        self.latest_text = ""
        self.latest_action = ""
        self.latest_result: dict[str, Any] | None = None
        self.receiving_paused = False
        self.settings = RuntimeSettings()
        self.errors: list[ErrorEvent] = []
        self.active_device_id = ""
        self.active_device_since = 0.0

    def touch_device(
        self,
        device_id: str,
        name: str,
        address: str,
        user_agent: str,
        transport: str,
    ) -> DeviceSession:
        now = time.time()
        with self._lock:
            device = self.devices.get(device_id)
            if device is None:
                device = DeviceSession(
                    device_id=device_id,
                    name=name or "手机浏览器",
                    address=address,
                    user_agent=user_agent,
                    transport=transport,
                    connected_at=now,
                    last_seen=now,
                )
                self.devices[device_id] = device
            else:
                device.name = name or device.name
                device.address = address
                device.user_agent = user_agent or device.user_agent
                device.transport = transport
                device.last_seen = now
            return device

    def update_preview(self, device_id: str, text: str, client_clear_sequence: int | None = None) -> bool:
        now = time.time()
        with self._lock:
            device = self.devices.get(device_id)
            if device is not None:
                if client_clear_sequence is not None and client_clear_sequence < device.clear_sequence:
                    return False
                changed = device.preview_text != text
                device.preview_text = text
                device.last_seen = now
                if changed and device.target_locked:
                    device.target_activity_at = now
            self.latest_text = text
            return True

    def device_preview_text(self, device_id: str) -> str:
        with self._lock:
            device = self.devices.get(device_id)
            return device.preview_text if device is not None else ""

    def request_device_clear(self, device_id: str) -> int:
        with self._lock:
            device = self.devices.get(device_id)
            if device is None:
                return 0
            device.preview_text = ""
            device.clear_sequence += 1
            return device.clear_sequence

    def device_clear_sequence(self, device_id: str) -> int:
        with self._lock:
            device = self.devices.get(device_id)
            return device.clear_sequence if device is not None else 0

    def mark_target_activity(self, device_id: str) -> None:
        if not device_id:
            return
        with self._lock:
            device = self.devices.get(device_id)
            if device is not None and device.target_locked:
                device.target_activity_at = time.time()

    def record_result(self, action: str, text: str, result: dict[str, Any]) -> None:
        with self._lock:
            self.latest_action = action
            self.latest_text = text
            self.latest_result = result

    def record_error(
        self,
        category: str,
        message: str,
        *,
        device_id: str = "",
        device_name: str = "",
        action: str = "",
        address: str = "",
        text_chars: int = 0,
    ) -> None:
        safe_message = " ".join(str(message).split())
        if len(safe_message) > 180:
            safe_message = safe_message[:177].rstrip() + "..."
        with self._lock:
            self.errors.append(
                ErrorEvent(
                    category=category,
                    message=safe_message,
                    device_id=device_id,
                    device_name=device_name,
                    action=action,
                    address=address,
                    text_chars=max(0, int(text_chars or 0)),
                )
            )
            if len(self.errors) > MAX_ERROR_LOG:
                self.errors = self.errors[-MAX_ERROR_LOG:]

    def set_target_lock(self, device_id: str, locked: bool, title: str = "", touch_activity: bool = True) -> None:
        now = time.time()
        with self._lock:
            device = self.devices.get(device_id)
            if device is None:
                return
            was_locked = device.target_locked
            device.target_locked = locked
            device.target_title = title if locked else ""
            if locked:
                if not was_locked or not device.target_locked_at:
                    device.target_locked_at = now
                if touch_activity or not device.target_activity_at:
                    device.target_activity_at = now
            else:
                device.target_locked_at = 0.0
                device.target_activity_at = 0.0
            if locked:
                self.active_device_id = device_id
                self.active_device_since = self.active_device_since or now
            elif self.active_device_id == device_id:
                self.active_device_id = ""
                self.active_device_since = 0.0

    def release_all_targets(self) -> None:
        with self._lock:
            for device in self.devices.values():
                device.target_locked = False
                device.target_title = ""
                device.target_locked_at = 0.0
                device.target_activity_at = 0.0
            self.active_device_id = ""
            self.active_device_since = 0.0

    def stale_target_device_ids(self, timeout_seconds: int) -> list[str]:
        if timeout_seconds <= 0:
            return []
        now = time.time()
        with self._lock:
            stale: list[str] = []
            for device in self.devices.values():
                if not device.target_locked:
                    continue
                activity_at = device.target_activity_at or device.target_locked_at
                if activity_at and now - activity_at >= timeout_seconds:
                    stale.append(device.device_id)
            return stale

    def acquire_active_device(self, device_id: str) -> dict[str, Any]:
        if not device_id:
            raise ValueError("Missing device id.")
        now = time.time()
        with self._lock:
            active = self.devices.get(self.active_device_id) if self.active_device_id else None
            active_is_stale = active is None or (now - active.last_seen) > DEVICE_TIMEOUT_SECONDS * 2
            if self.active_device_id and self.active_device_id != device_id and not active_is_stale:
                active_name = active.name if active else self.active_device_id
                raise ValueError(f"Another device is active: {active_name}. Release it before writing from this device.")
            if self.active_device_id != device_id:
                self.active_device_id = device_id
                self.active_device_since = now
            return self.active_device_snapshot_locked(now)

    def require_active_device(self, device_id: str) -> None:
        if not device_id:
            return
        now = time.time()
        with self._lock:
            if not self.active_device_id:
                self.active_device_id = device_id
                self.active_device_since = now
                return
            if self.active_device_id == device_id:
                return
            active = self.devices.get(self.active_device_id)
            if active is None or (now - active.last_seen) > DEVICE_TIMEOUT_SECONDS * 2:
                self.active_device_id = device_id
                self.active_device_since = now
                return
            active_name = active.name if active else self.active_device_id
            raise ValueError(f"Another device is active: {active_name}. Release it before writing from this device.")

    def release_active_device(self, device_id: str = "") -> bool:
        with self._lock:
            if not self.active_device_id:
                return False
            if device_id and self.active_device_id != device_id:
                return False
            self.active_device_id = ""
            self.active_device_since = 0.0
            return True

    def active_device_snapshot_locked(self, now: float) -> dict[str, Any]:
        if not self.active_device_id:
            return {"activeDeviceId": "", "activeDeviceName": "", "activeDeviceSeconds": 0}
        device = self.devices.get(self.active_device_id)
        return {
            "activeDeviceId": self.active_device_id,
            "activeDeviceName": device.name if device else "",
            "activeDeviceSeconds": round(now - self.active_device_since, 1) if self.active_device_since else 0,
        }

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.receiving_paused = paused

    def is_paused(self) -> bool:
        with self._lock:
            return self.receiving_paused

    def update_settings(
        self,
        *,
        clipboard_protect: bool | None = None,
        native_write: bool | None = None,
        target_click_restore: bool | None = None,
        foreground_restore: bool | None = None,
        return_previous_foreground: bool | None = None,
        target_lock_timeout_seconds: int | None = None,
        auto_finish_delay_ms: int | None = None,
        tail_revision_max_chars: int | None = None,
        default_input_mode: str | None = None,
        default_sync_speed: str | None = None,
        write_method: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if clipboard_protect is not None:
                self.settings.clipboard_protect = bool(clipboard_protect)
            if native_write is not None:
                self.settings.native_write = bool(native_write)
            if target_click_restore is not None:
                self.settings.target_click_restore = bool(target_click_restore)
            if foreground_restore is not None:
                self.settings.foreground_restore = bool(foreground_restore)
            if return_previous_foreground is not None:
                self.settings.return_previous_foreground = bool(return_previous_foreground)
            if target_lock_timeout_seconds is not None:
                timeout_seconds = int(target_lock_timeout_seconds)
                if not (TARGET_LOCK_TIMEOUT_MIN_SECONDS <= timeout_seconds <= TARGET_LOCK_TIMEOUT_MAX_SECONDS):
                    raise ValueError(
                        f"Unsupported target lock timeout: {timeout_seconds}. Use 0-{TARGET_LOCK_TIMEOUT_MAX_SECONDS} seconds."
                    )
                self.settings.target_lock_timeout_seconds = timeout_seconds
            if auto_finish_delay_ms is not None:
                delay_ms = int(auto_finish_delay_ms)
                max_delay_ms = AUTO_FINISH_DELAY_MAX_SECONDS * 1000
                if not (AUTO_FINISH_DELAY_MIN_SECONDS * 1000 <= delay_ms <= max_delay_ms):
                    raise ValueError(
                        f"Unsupported auto finish delay: {delay_ms}. Use 0-{AUTO_FINISH_DELAY_MAX_SECONDS} seconds."
                    )
                self.settings.auto_finish_delay_ms = delay_ms
            if tail_revision_max_chars is not None:
                max_chars = int(tail_revision_max_chars)
                if max_chars not in TAIL_REVISION_SUGGESTED_CHARS:
                    options = "/".join(str(item) for item in TAIL_REVISION_SUGGESTED_CHARS)
                    raise ValueError(f"Unsupported tail revision max chars: {max_chars}. Use one of {options} chars.")
                self.settings.tail_revision_max_chars = max_chars
            if default_input_mode is not None:
                if default_input_mode not in INPUT_MODE_VALUES:
                    raise ValueError(f"Unsupported input mode: {default_input_mode}")
                self.settings.default_input_mode = default_input_mode
            if default_sync_speed is not None:
                if default_sync_speed not in SYNC_SPEED_VALUES:
                    raise ValueError(f"Unsupported sync speed: {default_sync_speed}")
                self.settings.default_sync_speed = default_sync_speed
            if write_method is not None:
                if write_method not in WRITE_METHOD_VALUES:
                    raise ValueError(f"Unsupported write method: {write_method}")
                self.settings.write_method = write_method
            return self.settings.snapshot()

    def settings_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self.settings.snapshot()

    @staticmethod
    def preview_snippet(text: str, limit: int = PREVIEW_SNIPPET_CHARS) -> str:
        normalized = " ".join(text.split())
        if len(normalized) <= limit:
            return normalized
        return normalized[:limit].rstrip() + "..."

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            timeout_seconds = self.settings.target_lock_timeout_seconds
            devices = []
            for device in self.devices.values():
                age = now - device.last_seen
                target_activity_age = (
                    round(now - (device.target_activity_at or device.target_locked_at), 1)
                    if device.target_locked and (device.target_activity_at or device.target_locked_at)
                    else 0
                )
                devices.append(
                    {
                        "id": device.device_id,
                        "name": device.name,
                        "address": device.address,
                        "transport": device.transport,
                        "connected": age <= DEVICE_TIMEOUT_SECONDS,
                        "lastSeenSeconds": round(age, 1),
                        "previewChars": len(device.preview_text),
                        "previewText": self.preview_snippet(device.preview_text),
                        "clearSequence": device.clear_sequence,
                        "targetLocked": device.target_locked,
                        "targetTitle": device.target_title,
                        "active": device.device_id == self.active_device_id,
                        "targetLockedSeconds": round(now - device.target_locked_at, 1)
                        if device.target_locked and device.target_locked_at
                        else 0,
                        "targetActivitySeconds": target_activity_age,
                        "targetTimeoutSeconds": max(0, int(timeout_seconds - target_activity_age))
                        if device.target_locked and timeout_seconds > 0
                        else 0,
                        "userAgent": device.user_agent,
                    }
                )
            return {
                "ok": True,
                "devices": sorted(devices, key=lambda item: item["lastSeenSeconds"]),
                "latestAction": self.latest_action,
                "latestChars": len(self.latest_text),
                "latestResult": self.latest_result,
                "receivingPaused": self.receiving_paused,
                **self.active_device_snapshot_locked(now),
                "settings": self.settings.snapshot(),
                "errors": [
                    {
                        "category": error.category,
                        "message": error.message,
                        "deviceId": error.device_id,
                        "deviceName": error.device_name,
                        "action": error.action,
                        "address": error.address,
                        "textChars": error.text_chars,
                        "ageSeconds": round(now - error.created_at, 1),
                    }
                    for error in reversed(self.errors)
                ],
            }


@dataclass
class ServerConfig:
    token: str
    injector: WindowsTextInjector
    state: ServerState
    settings_path: pathlib.Path | None = None


def network_diagnostics(
    host: str,
    port: int,
    token: str,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    urls = make_urls(host, port, token)
    parsed_hosts = [urllib.parse.urlsplit(url).hostname or "" for url in urls]
    local_only = host in ("127.0.0.1", "localhost", "::1") or bool(parsed_hosts) and all(
        item.startswith("127.") or item in ("localhost", "::1")
        for item in parsed_hosts
    )
    lan_hosts = [
        item for item in parsed_hosts
        if item and not item.startswith("127.") and item not in ("localhost", "::1")
    ]
    devices = list((snapshot or {}).get("devices", []))
    connected_devices = [item for item in devices if item.get("connected")]
    hints: list[str] = []
    if local_only:
        hints.append("当前只监听本机地址，手机通常无法访问；手机使用时建议用 --host 0.0.0.0。")
    if not lan_hosts:
        hints.append("没有检测到可用局域网 IPv4 地址；确认电脑已连接网线/Wi-Fi，且手机在同一网段。")
    if not connected_devices:
        hints.append("如果手机扫码后打不开页面，请允许 Windows 防火墙中的 Python 专用网络访问。")
    return {
        "bindHost": host,
        "port": port,
        "phoneUrls": urls,
        "lanHosts": lan_hosts,
        "localOnly": local_only,
        "deviceCount": len(devices),
        "connectedDeviceCount": len(connected_devices),
        "hints": hints,
    }


def parse_body(raw_body: bytes, content_type: str) -> dict[str, Any]:
    content_type = content_type.split(";", 1)[0].strip().lower()
    if not raw_body:
        return {}
    if content_type == "application/json":
        data = json.loads(raw_body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON payload must be an object.")
        return data

    decoded = raw_body.decode("utf-8")
    parsed = urllib.parse.parse_qs(decoded, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def result_payload(result: InjectionResult, dry_run: bool) -> dict[str, Any]:
    return {
        "ok": True,
        "action": result.action,
        "method": result.method,
        "chars": result.chars,
        "dry_run": dry_run,
        "clipboardRestored": result.clipboard_restored,
        "clipboardRestoreSkipped": result.clipboard_restore_skipped,
        "clipboardRestoreReason": result.clipboard_restore_reason,
        "targetLocked": result.target_locked,
        "targetRestored": result.target_restored,
        "targetRestoreReason": result.target_restore_reason,
        "targetTitle": result.target_title,
        "previousForegroundRestored": result.previous_foreground_restored,
    }


def cleanup_stale_targets(config: ServerConfig) -> list[str]:
    timeout_seconds = int(config.state.settings_snapshot().get("targetLockTimeoutSeconds", 0) or 0)
    stale_device_ids = config.state.stale_target_device_ids(timeout_seconds)
    for device_id in stale_device_ids:
        config.injector.release_target(device_id)
        config.state.set_target_lock(device_id, False)
        config.state.record_error(
            "target_timeout",
            f"Target lock released after {timeout_seconds} seconds without phone text activity.",
            device_id=device_id,
            action="target.timeout",
        )
    return stale_device_ids


def handle_text_action(
    config: ServerConfig,
    text: str,
    action: str,
    device_id: str = "",
    require_target_lock: bool = False,
    delete_chars: int = 0,
) -> dict[str, Any]:
    cleanup_stale_targets(config)
    if config.state.is_paused() and action != "copy":
        raise ValueError("Receiving is paused.")
    if action != "copy":
        config.state.require_active_device(device_id)
    if require_target_lock and action != "copy" and not config.injector.has_target(device_id):
        raise ValueError("Target is not locked. Focus the Windows input box, then start a new phone input.")
    if action == "copy":
        result = config.injector.copy_text(text)
    elif action == "undo":
        result = config.injector.undo_last(target_device_id=device_id)
    elif action == "replace":
        result = config.injector.replace_text(text, press_enter=False, target_device_id=device_id)
    elif action == "replace_enter":
        result = config.injector.replace_text(text, press_enter=True, target_device_id=device_id)
    elif action == "paste_enter":
        result = config.injector.paste_text(text, press_enter=True, target_device_id=device_id)
    elif action == "paste":
        result = config.injector.paste_text(text, press_enter=False, target_device_id=device_id)
    elif action == "revise_tail":
        result = config.injector.revise_tail(text, delete_chars=delete_chars, target_device_id=device_id)
    else:
        raise ValueError("Unknown action.")

    payload = result_payload(result, config.injector.dry_run)
    if action != "copy":
        config.state.mark_target_activity(device_id)
    config.state.record_result(action, text, payload)
    return payload


def handle_target_lock(config: ServerConfig, device_id: str) -> dict[str, Any]:
    cleanup_stale_targets(config)
    active = config.state.acquire_active_device(device_id)
    try:
        target = config.injector.capture_target(device_id)
    except Exception:
        config.state.release_active_device(device_id)
        raise
    config.state.set_target_lock(device_id, True, target.title)
    payload = target.payload()
    payload.update(active)
    return payload


def handle_target_release(
    config: ServerConfig,
    device_id: str,
    reason: str = "",
    clear_device: bool = True,
) -> dict[str, Any]:
    payload = config.injector.release_target(device_id)
    active_released = config.state.release_active_device(device_id)
    config.state.set_target_lock(device_id, False)
    clear_sequence = config.state.request_device_clear(device_id) if clear_device else config.state.device_clear_sequence(device_id)
    payload["activeReleased"] = active_released
    payload["releaseReason"] = reason
    payload["clearSequence"] = clear_sequence
    if payload.get("targetReleased"):
        config.state.record_result("target_release", "", payload)
    return payload


def handle_target_status(config: ServerConfig, device_id: str) -> dict[str, Any]:
    cleanup_stale_targets(config)
    payload = config.injector.target_info(device_id)
    if payload.get("targetLocked"):
        config.state.set_target_lock(device_id, True, str(payload.get("targetTitle", "")), touch_activity=False)
    else:
        config.state.set_target_lock(device_id, False)
    return payload


def handle_target_release_all(config: ServerConfig) -> dict[str, Any]:
    payload = config.injector.release_all_targets()
    clear_sequences = {
        device_id: config.state.request_device_clear(device_id)
        for device_id in list(config.state.devices.keys())
    }
    config.state.release_all_targets()
    payload["activeReleased"] = True
    payload["clearSequences"] = clear_sequences
    return payload


def handle_pause(config: ServerConfig, paused: bool) -> dict[str, Any]:
    config.state.set_paused(paused)
    return {"ok": True, "receivingPaused": paused}


def update_runtime_settings_from_data(state: ServerState, data: dict[str, Any]) -> dict[str, Any]:
    clipboard_protect = data.get("clipboardProtect") if "clipboardProtect" in data else None
    native_write = data.get("nativeWrite") if "nativeWrite" in data else None
    target_click_restore = data.get("targetClickRestore") if "targetClickRestore" in data else None
    foreground_restore = data.get("foregroundRestore") if "foregroundRestore" in data else None
    return_previous_foreground = data.get("returnPreviousForeground") if "returnPreviousForeground" in data else None
    target_lock_timeout = data.get("targetLockTimeoutSeconds") if "targetLockTimeoutSeconds" in data else None
    auto_finish_delay = data.get("autoFinishDelayMs") if "autoFinishDelayMs" in data else None
    tail_revision_max = data.get("tailRevisionMaxChars") if "tailRevisionMaxChars" in data else None
    default_input_mode = str(data.get("defaultInputMode", "")) if "defaultInputMode" in data else None
    default_sync_speed = str(data.get("defaultSyncSpeed", "")) if "defaultSyncSpeed" in data else None
    write_method = str(data.get("writeMethod", "")) if "writeMethod" in data else None
    return state.update_settings(
        clipboard_protect=bool(clipboard_protect) if clipboard_protect is not None else None,
        native_write=bool(native_write) if native_write is not None else None,
        target_click_restore=bool(target_click_restore) if target_click_restore is not None else None,
        foreground_restore=bool(foreground_restore) if foreground_restore is not None else None,
        return_previous_foreground=bool(return_previous_foreground) if return_previous_foreground is not None else None,
        target_lock_timeout_seconds=int(target_lock_timeout) if target_lock_timeout is not None else None,
        auto_finish_delay_ms=int(auto_finish_delay) if auto_finish_delay is not None else None,
        tail_revision_max_chars=int(tail_revision_max) if tail_revision_max is not None else None,
        default_input_mode=default_input_mode,
        default_sync_speed=default_sync_speed,
        write_method=write_method,
    )


def apply_settings_to_injector(injector: WindowsTextInjector, settings: dict[str, Any]) -> None:
    injector.protect_clipboard = bool(settings["clipboardProtect"])
    injector.prefer_native_write = bool(settings["nativeWrite"])
    injector.target_click_restore = bool(settings["targetClickRestore"])
    injector.foreground_restore = bool(settings["foregroundRestore"])
    injector.return_previous_foreground = bool(settings["returnPreviousForeground"])
    injector.write_method = str(settings["writeMethod"])


def load_runtime_settings(path: pathlib.Path = SETTINGS_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    data = raw.get("settings", raw)
    if not isinstance(data, dict):
        return {}
    allowed = set(RuntimeSettings().snapshot().keys())
    state = ServerState()
    valid_count = 0
    for key, value in data.items():
        if key not in allowed:
            continue
        try:
            update_runtime_settings_from_data(state, {key: value})
            valid_count += 1
        except Exception:
            continue
    return state.settings_snapshot() if valid_count else {}


def save_runtime_settings(settings: dict[str, Any], path: pathlib.Path = SETTINGS_PATH) -> None:
    payload = {"version": APP_VERSION, "settings": settings}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def handle_settings_update(config: ServerConfig, data: dict[str, Any]) -> dict[str, Any]:
    settings = update_runtime_settings_from_data(config.state, data)
    apply_settings_to_injector(config.injector, settings)
    if config.settings_path is not None:
        save_runtime_settings(settings, config.settings_path)
    return {"ok": True, "settings": settings}


def handle_token_reset(
    config: ServerConfig,
    host: str,
    port: int,
    token_path: pathlib.Path = TOKEN_PATH,
) -> dict[str, Any]:
    if not config.token:
        raise ValueError("Token protection is disabled.")
    new_token = load_or_create_token(reset=True, path=token_path)
    config.token = new_token
    release_payload = handle_target_release_all(config)
    phone_urls = make_urls(host, port, new_token)
    desktop_url = make_desktop_url(host, port, new_token)
    config.state.record_result(
        "token_reset",
        "",
        {
            "ok": True,
            "action": "token_reset",
            "targetReleasedCount": release_payload.get("targetReleasedCount", 0),
        },
    )
    return {
        "ok": True,
        "token": new_token,
        "phoneUrls": phone_urls,
        "desktopUrl": desktop_url,
        "targetReleasedCount": release_payload.get("targetReleasedCount", 0),
    }


def handle_test_paste(
    config: ServerConfig,
    device_id: str,
    text: str = "【测试输入】",
    undo_after: bool = True,
) -> dict[str, Any]:
    cleanup_stale_targets(config)
    if config.state.is_paused():
        raise ValueError("Receiving is paused.")
    if not config.injector.has_target(device_id):
        raise ValueError("Target is not locked. Start input from the phone first, then test paste.")
    paste_result = config.injector.paste_text(text, press_enter=False, target_device_id=device_id)
    undo_payload: dict[str, Any] | None = None
    if undo_after:
        undo_result = config.injector.undo_last(target_device_id=device_id)
        undo_payload = result_payload(undo_result, config.injector.dry_run)
    payload = result_payload(paste_result, config.injector.dry_run)
    payload.update(
        {
            "action": "test_paste",
            "testText": text,
            "undoAfter": undo_after,
            "undoResult": undo_payload,
        }
    )
    config.state.record_result("test_paste", text, payload)
    return payload


def handle_preview_send(config: ServerConfig, device_id: str) -> dict[str, Any]:
    text = config.state.device_preview_text(device_id)
    if not text.strip():
        raise ValueError("No preview text to send.")
    if not config.injector.has_target(device_id):
        raise ValueError("Target is not locked. Click the Windows input box, then start phone input first.")
    payload = handle_text_action(config, text, "replace", device_id, require_target_lock=True)
    clear_sequence = config.state.request_device_clear(device_id)
    release_payload = handle_target_release(config, device_id, "desktop_send", clear_device=False)
    payload.update(
        {
            "action": "preview_send",
            "clearSequence": clear_sequence,
            "targetRelease": release_payload,
        }
    )
    config.state.record_result("preview_send", text, payload)
    return payload


def handle_preview_clear(config: ServerConfig, device_id: str) -> dict[str, Any]:
    clear_sequence = config.state.request_device_clear(device_id)
    release_payload = handle_target_release(config, device_id, "preview_clear", clear_device=False)
    payload = {
        "ok": True,
        "action": "preview_clear",
        "clearSequence": clear_sequence,
        "targetRelease": release_payload,
    }
    config.state.record_result("preview_clear", "", payload)
    return payload


def load_or_create_token(reset: bool = False, path: pathlib.Path = TOKEN_PATH) -> str:
    if not reset:
        try:
            token = path.read_text(encoding="utf-8").strip()
            if token:
                return token
        except FileNotFoundError:
            pass
    token = secrets.token_urlsafe(16)
    path.write_text(token + "\n", encoding="utf-8")
    return token


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def text_response(handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str) -> None:
    encoded = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(encoded)


def binary_response(handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def render_page(token: str, settings: dict[str, Any] | None = None) -> str:
    token_json = json.dumps(token).replace("<", "\\u003c")
    settings_json = json.dumps(settings or RuntimeSettings().snapshot()).replace("<", "\\u003c")
    token_query = urllib.parse.urlencode({"token": token}) if token else ""
    version = html.escape(APP_VERSION)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#2563eb">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-title" content="语音输入">
  <link rel="manifest" href="/manifest.webmanifest{html.escape('?' + token_query) if token_query else ''}">
  <link rel="icon" href="/icon.svg" type="image/svg+xml">
  <link rel="apple-touch-icon" href="/icon.svg">
  <title>{html.escape(APP_NAME)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #5c667a;
      --accent: #2563eb;
      --accent-strong: #1d4ed8;
      --border: #d8deea;
      --danger: #b42318;
      --ok: #047857;
      --warn: #a16207;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(560px, 100%);
      margin: 0 auto;
      padding: 10px;
    }}
    header {{
      margin: 8px 0 16px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: 0;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.45;
    }}
    .capture-panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      box-shadow: 0 4px 14px rgba(22, 32, 51, 0.06);
    }}
    .capture-panel.paused {{
      border-color: #f59e0b;
      box-shadow: 0 8px 24px rgba(245, 158, 11, 0.16);
    }}
    .status-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 8px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #f8fafc;
      color: var(--muted);
      font-size: 14px;
    }}
    .target-row {{
      margin-bottom: 8px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fff;
      color: var(--muted);
      font-size: 14px;
    }}
    #targetStatus {{
      display: block;
      color: var(--text);
      font-weight: 650;
    }}
    #targetTitle {{
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    button:disabled {{
      opacity: 0.55;
    }}
    .dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--warn);
      flex: 0 0 auto;
    }}
    .dot.ok {{
      background: var(--ok);
    }}
    .dot.bad {{
      background: var(--danger);
    }}
    .connection {{
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }}
    .connection span:last-child {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .capture-box {{
      position: relative;
    }}
    .capture-pad {{
      width: 100%;
      min-height: 92px;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      color: var(--text);
      display: grid;
      place-items: center;
      text-align: center;
      font: inherit;
      cursor: pointer;
    }}
    .capture-pad.active {{
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }}
    .capture-pad strong {{
      display: block;
      margin-bottom: 8px;
      font-size: 18px;
    }}
    .capture-pad span {{
      color: var(--muted);
      line-height: 1.45;
    }}
    .capture-input {{
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      opacity: 0.02;
      resize: none;
      border: 0;
      padding: 0;
      outline: none;
      color: transparent;
      -webkit-text-fill-color: transparent;
      caret-color: transparent;
      background: transparent;
      font-size: 16px;
      z-index: 2;
    }}
    .meter {{
      margin-top: 10px;
      color: var(--muted);
      font-size: 14px;
    }}
    #status {{
      min-height: 0;
      margin-top: 8px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    #status.error {{
      color: var(--danger);
    }}
    #status:empty {{
      display: none;
    }}
    .version {{
      margin-top: 8px;
      color: #94a3b8;
      font-size: 11px;
      text-align: center;
      user-select: none;
    }}
  </style>
</head>
<body>
  <main aria-label="手机语音输入到 Windows">
    <section id="inputPanel" class="capture-panel">
      <div class="status-row">
        <div class="connection">
          <span id="connectionDot" class="dot"></span>
          <span id="connectionStatus">连接中...</span>
        </div>
        <span id="transportStatus">HTTP 备用</span>
      </div>
      <div class="target-row">
        <div>
          <span id="targetStatus">目标未锁定</span>
          <span id="targetTitle">输入时自动锁定电脑输入框</span>
        </div>
      </div>
      <div class="capture-box">
        <button id="capturePad" class="capture-pad" type="button" tabindex="-1">
          <span>
            <strong>点这里说话</strong>
            打开手机输入法麦克风
          </span>
        </button>
        <textarea id="text" class="capture-input" autocomplete="off" autocapitalize="sentences" spellcheck="true" aria-label="语音输入承载区"></textarea>
      </div>
      <div id="charCount" class="meter">传输 0 字</div>
      <div id="status" role="status" aria-live="polite"></div>
    </section>
    <div class="version">{version}</div>
  </main>
  <script>
    const token = {token_json};
    const serverDefaults = {settings_json};
    const panel = document.querySelector("#inputPanel");
    const text = document.querySelector("#text");
    const statusEl = document.querySelector("#status");
    const capturePad = document.querySelector("#capturePad");
    const charCount = document.querySelector("#charCount");
    const connectionDot = document.querySelector("#connectionDot");
    const connectionStatus = document.querySelector("#connectionStatus");
    const transportStatus = document.querySelector("#transportStatus");
    const targetStatus = document.querySelector("#targetStatus");
    const targetTitle = document.querySelector("#targetTitle");
    let socket = null;
    let heartbeatTimer = null;
    let reconnectTimer = null;
    let updateTimer = null;
    let targetSyncTimer = null;
    let segmentProtectTimer = null;
    let autoFinishTimer = null;
    let emptyFinishTimer = null;
    let observedText = "";
    let lastTargetSyncText = "";
    let pendingTargetSyncText = "";
    let protectedPrefixLength = 0;
    let lastSuccessfulSyncAt = 0;
    let pollTimer = null;
    let targetLocked = false;
    let targetLockPending = false;
    let targetReleasePending = false;
    let targetLockPromise = null;
    let exitReleaseSent = false;
    let receivingPaused = false;
    let reconnectDelay = 800;
    let pollDelayMs = 80;
    let segmentProtectDelayMs = 700;
    let autoFinishDelayMs = 15000;
    let tailRevisionMaxChars = 200;
    const deviceIdKey = "phoneVoiceWinInput.deviceId";
    let lastClearSequence = 0;

    function storageGet(key) {{
      try {{
        return localStorage.getItem(key) || "";
      }} catch (error) {{
        return "";
      }}
    }}

    function storageSet(key, value) {{
      try {{
        localStorage.setItem(key, value);
      }} catch (error) {{}}
    }}

    function storageRemove(key) {{
      try {{
        localStorage.removeItem(key);
      }} catch (error) {{}}
    }}

    function applyServerDefaults(settings) {{
      if (!settings) return;
      const finishDelay = Number(settings.autoFinishDelayMs);
      if (!Number.isNaN(finishDelay)) {{
        const nextAutoFinishDelayMs = Math.max(0, finishDelay);
        if (nextAutoFinishDelayMs !== autoFinishDelayMs) {{
          autoFinishDelayMs = nextAutoFinishDelayMs;
          clearTimeout(autoFinishTimer);
          clearTimeout(emptyFinishTimer);
          if (autoFinishDelayMs > 0 && text.value.trim()) {{
            scheduleAutoFinish(text.value, autoFinishDelayMs);
          }}
        }} else {{
          autoFinishDelayMs = nextAutoFinishDelayMs;
        }}
      }}
      const tailMax = Number(settings.tailRevisionMaxChars);
      if (!Number.isNaN(tailMax)) {{
        tailRevisionMaxChars = Math.max(0, tailMax);
      }}
    }}

    const storedDeviceId = storageGet(deviceIdKey);
    const deviceId = storedDeviceId || ((window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : String(Date.now()) + "-" + Math.random().toString(16).slice(2));
    storageSet(deviceIdKey, deviceId);
    applyServerDefaults(serverDefaults);
    let deviceName = detectDeviceName();
    startPolling();

    function setStatus(message, isError = false) {{
      if (!isError) {{
        statusEl.textContent = "";
        statusEl.className = "";
        return;
      }}
      statusEl.textContent = message;
      statusEl.className = "error";
    }}

    function setConnection(message, state = "warn", transport = "HTTP 备用") {{
      connectionStatus.textContent = message;
      connectionDot.className = "dot" + (state === "ok" ? " ok" : state === "bad" ? " bad" : "");
      transportStatus.textContent = transport;
    }}

    function detectDeviceName() {{
      const ua = navigator.userAgent || "";
      if (/iPhone/i.test(ua)) return "iPhone";
      if (/iPad/i.test(ua)) return "iPad";
      if (/Android/i.test(ua)) return "Android";
      return "手机浏览器";
    }}

    function websocketUrl() {{
      const scheme = location.protocol === "https:" ? "wss:" : "ws:";
      return scheme + "//" + location.host + "/ws" + (token ? "?token=" + encodeURIComponent(token) : "");
    }}

    function wsReady() {{
      return socket && socket.readyState === WebSocket.OPEN;
    }}

    function sendWs(message) {{
      if (!wsReady()) return false;
      socket.send(JSON.stringify(message));
      return true;
    }}

    function apiPath(path) {{
      return path + (token ? "?token=" + encodeURIComponent(token) : "");
    }}

    async function postJson(path, payload) {{
      const response = await fetch(apiPath(path), {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify(Object.assign({{ deviceId, deviceName }}, payload || {{}}))
      }});
      const data = await response.json();
      if (!response.ok || !data.ok) {{
        throw new Error(data.error || "请求失败");
      }}
      return data;
    }}

    function setTargetState(locked, title = "", detail = "", clickRestore = false) {{
      targetLocked = locked;
      if (locked) {{
        targetStatus.textContent = "目标已锁定";
        const suffix = clickRestore ? "（已记录输入位置）" : "";
        targetTitle.textContent = title ? ("锁定到：" + title + suffix) : ("已锁定 Windows 当前输入框" + suffix);
        return;
      }}
      targetStatus.textContent = detail || "目标未锁定";
      targetTitle.textContent = "输入时自动锁定电脑输入框";
    }}

    function setPausedState(paused) {{
      receivingPaused = paused;
      panel.classList.toggle("paused", paused);
      if (paused) {{
        setStatus("已暂停接收：手机输入会保留，但不会写入 Windows。");
      }}
    }}

    function applyControlMessage(data) {{
      if (data.action === "pause" && data.ok) {{
        setPausedState(Boolean(data.receivingPaused));
      }}
    }}

    function applyClearSequence(data) {{
      const nextSequence = Number(data && data.clearSequence ? data.clearSequence : 0);
      if (!nextSequence || nextSequence <= lastClearSequence) return;
      lastClearSequence = nextSequence;
      resetTextState();
      sendPreview("");
      setTargetState(false);
      setStatus("电脑端已处理，手机缓存已清空。");
    }}

    function applyTargetLockMessage(data) {{
      targetLockPromise = null;
      if (data.action === "lock") {{
        targetLockPending = false;
        if (data.ok) {{
          setTargetState(true, data.targetTitle || "", "", Boolean(data.targetClickRestore));
          return;
        }}
        setTargetState(false);
        setStatus("目标锁定失败：" + (data.error || "未知错误"), true);
        return;
      }}
      if (data.action === "release") {{
        targetLockPending = false;
        targetReleasePending = false;
        setTargetState(false);
      }}
    }}

    async function ensureTargetLocked() {{
      if (targetLocked) return true;
      if (targetLockPending) return targetLockPromise || true;
      targetLockPending = true;
      setTargetState(false, "", "目标锁定中...");
      const message = {{ type: "target.lock", deviceId, deviceName }};
      if (sendWs(message)) {{
        targetLockPromise = Promise.resolve(true);
        return true;
      }}
      targetLockPromise = (async () => {{
        try {{
          const data = await postJson("/api/target/lock");
          targetLockPending = false;
          setTargetState(true, data.targetTitle || "", "", Boolean(data.targetClickRestore));
          return true;
        }} catch (error) {{
          targetLockPending = false;
          setTargetState(false);
          setStatus("目标锁定失败：" + (error.message || String(error)), true);
          return false;
        }} finally {{
          targetLockPromise = null;
        }}
      }})();
      return targetLockPromise;
    }}

    async function releaseTarget(reason = "") {{
      if (!targetLocked && !targetLockPending) return true;
      const wasLocked = targetLocked;
      targetReleasePending = true;
      targetLockPending = false;
      targetLockPromise = null;
      setTargetState(false, "", "目标释放中...");
      const message = {{ type: "target.release", deviceId, deviceName, reason }};
      if (sendWs(message)) {{
        return true;
      }}
      try {{
        await postJson("/api/target/release", {{ reason }});
        targetReleasePending = false;
        setTargetState(false);
        return true;
      }} catch (error) {{
        targetReleasePending = false;
        setTargetState(wasLocked);
        setStatus("目标释放失败：" + (error.message || String(error)), true);
        return false;
      }}
    }}

    function releaseTargetOnPageExit(reason) {{
      if (exitReleaseSent || (!targetLocked && !targetLockPending)) return;
      exitReleaseSent = true;
      targetLocked = false;
      targetLockPending = false;
      targetReleasePending = false;
      const payload = JSON.stringify({{ deviceId, deviceName, reason }});
      const url = apiPath("/api/target/release");
      try {{
        if (navigator.sendBeacon) {{
          const blob = new Blob([payload], {{ type: "application/json" }});
          if (navigator.sendBeacon(url, blob)) return;
        }}
      }} catch (error) {{}}
      try {{
        fetch(url, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: payload,
          keepalive: true
        }}).catch(() => {{}});
        return;
      }} catch (error) {{}}
      try {{
        sendWs({{ type: "target.release", deviceId, deviceName, reason }});
      }} catch (error) {{}}
    }}

    function resetTextState() {{
      clearTimeout(targetSyncTimer);
      clearTimeout(segmentProtectTimer);
      clearTimeout(autoFinishTimer);
      clearTimeout(emptyFinishTimer);
      text.value = "";
      observedText = "";
      lastTargetSyncText = "";
      pendingTargetSyncText = "";
      protectedPrefixLength = 0;
      lastSuccessfulSyncAt = 0;
      updateCharCount();
    }}

    function connectSocket() {{
      clearTimeout(reconnectTimer);
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
      setConnection("连接中...", "warn", "WebSocket");
      try {{
        socket = new WebSocket(websocketUrl());
      }} catch (error) {{
        setConnection("WebSocket 不可用", "bad", "HTTP 备用");
        scheduleReconnect();
        return;
      }}

      socket.addEventListener("open", () => {{
        reconnectDelay = 800;
        setConnection("已连接电脑", "ok", "WebSocket");
        sendWs({{ type: "hello", deviceId, deviceName }});
        if (text.value) {{
          sendWs({{ type: "text.update", deviceId, text: text.value, clearSequence: lastClearSequence }});
        }}
        clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(() => {{
          sendWs({{ type: "heartbeat", deviceId, time: Date.now() }});
        }}, 1000);
      }});

      socket.addEventListener("message", (event) => {{
        try {{
          const data = JSON.parse(event.data);
          handleServerMessage(data);
        }} catch (error) {{
          setStatus("收到无法解析的电脑端消息。", true);
        }}
      }});

      socket.addEventListener("close", () => {{
        clearInterval(heartbeatTimer);
        setConnection("连接断开，重连中...", "bad", "HTTP 备用");
        scheduleReconnect();
      }});

      socket.addEventListener("error", () => {{
        setConnection("连接出错，使用 HTTP 备用", "bad", "HTTP 备用");
      }});
    }}

    function scheduleReconnect() {{
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connectSocket, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 1.6, 6000);
    }}

    function handleServerMessage(data) {{
      applyClearSequence(data);
      if (data.type === "hello") {{
        applyServerDefaults(data.settings);
        setPausedState(Boolean(data.receivingPaused));
        if (data.targetLocked) {{
          setTargetState(true, data.targetTitle || "", "", Boolean(data.targetClickRestore));
        }} else if (!targetLockPending && !targetReleasePending) {{
          setTargetState(false);
        }}
        return;
      }}
      if (data.type === "heartbeat") {{
        applyServerDefaults(data.settings);
        return;
      }}
      if (data.type === "target") {{
        applyTargetLockMessage(data);
        return;
      }}
      if (data.type === "control") {{
        applyControlMessage(data);
        return;
      }}
      if (data.type === "status") {{
        if (!data.ok) {{
          pendingTargetSyncText = "";
          if ((data.error || "").includes("Target is not locked")) {{
            targetLockPending = false;
            setTargetState(false);
          }}
          setStatus(friendlyError(data.error || data.message || "电脑端处理失败。"), true);
        }} else if (pendingTargetSyncText) {{
          markSyncSettled(pendingTargetSyncText);
          setStatus("已同步到电脑输入框；说完后可直接在电脑端发送。");
          if (text.value !== lastTargetSyncText) {{
            scheduleTargetSync(text.value);
          }}
        }}
      }}
    }}

    function friendlyError(message) {{
      const text = String(message || "");
      if (text.includes("foreground_restore_disabled")) {{
        return "已关闭写入时置前目标窗口；当前目标不能安全后台写入，所以本次没有发送。可开启“写入时置前目标窗口”，或改用支持原生后台写入的 Windows 文本控件。";
      }}
      return text;
    }}

    function moveCaretToEnd() {{
      const end = text.value.length;
      try {{
        if (text.selectionStart !== end || text.selectionEnd !== end) {{
          text.setSelectionRange(end, end);
        }}
      }} catch (error) {{}}
      try {{
        text.scrollTop = text.scrollHeight;
      }} catch (error) {{}}
    }}

    function scheduleCaretToEnd() {{
      setTimeout(moveCaretToEnd, 0);
      setTimeout(moveCaretToEnd, 80);
    }}
    function noteTextChanged() {{
      scheduleCaretToEnd();
      const current = text.value;
      if (current === observedText) return;
      observedText = current;
      updateCharCount();
      if (receivingPaused) {{
        return;
      }}
      if (current.trim()) {{
        clearTimeout(emptyFinishTimer);
        ensureTargetLocked();
      }} else {{
        handleTransientEmptyText();
        return;
      }}

      clearTimeout(updateTimer);
      updateTimer = setTimeout(() => {{
        sendPreview(current);
      }}, 120);
      scheduleTargetSync(current);
      scheduleAutoFinish(current);
    }}

    text.addEventListener("input", noteTextChanged);
    text.addEventListener("change", noteTextChanged);
    text.addEventListener("keyup", noteTextChanged);
    text.addEventListener("compositionend", noteTextChanged);

    function updateCharCount() {{
      charCount.textContent = "传输 " + text.value.length + " 字";
    }}

    async function sendPreview(value) {{
      if (sendWs({{ type: "text.update", deviceId, text: value, clearSequence: lastClearSequence }})) {{
        return true;
      }}
      try {{
        await postJson("/api/preview/update", {{ text: value, clearSequence: lastClearSequence }});
        return true;
      }} catch (error) {{
        setStatus("预览同步失败：" + (error.message || String(error)), true);
        return false;
      }}
    }}

    function commonPrefixLength(left, right) {{
      const limit = Math.min(left.length, right.length);
      let index = 0;
      while (index < limit && left[index] === right[index]) {{
        index += 1;
      }}
      return index;
    }}

    function refreshProtectedPrefix(now = Date.now()) {{
      if (!lastTargetSyncText || pendingTargetSyncText || !lastSuccessfulSyncAt) {{
        return;
      }}
      if (now - lastSuccessfulSyncAt >= segmentProtectDelayMs) {{
        protectedPrefixLength = Math.max(protectedPrefixLength, lastTargetSyncText.length);
      }}
    }}

    function markSyncSettled(value) {{
      lastTargetSyncText = value;
      pendingTargetSyncText = "";
      lastSuccessfulSyncAt = Date.now();
      scheduleSegmentProtection();
    }}

    function detachProtectedRewrite(value, message) {{
      lastTargetSyncText = value;
      pendingTargetSyncText = "";
      protectedPrefixLength = value.length;
      lastSuccessfulSyncAt = Date.now();
      scheduleSegmentProtection();
      setStatus(message);
    }}

    function scheduleSegmentProtection() {{
      clearTimeout(segmentProtectTimer);
      segmentProtectTimer = setTimeout(() => {{
        refreshProtectedPrefix(Date.now());
      }}, segmentProtectDelayMs);
    }}

    function handleTransientEmptyText() {{
      clearTimeout(emptyFinishTimer);
      refreshProtectedPrefix(Date.now());
    }}

    function scheduleAutoFinish(value, delay = autoFinishDelayMs) {{
      clearTimeout(autoFinishTimer);
      clearTimeout(emptyFinishTimer);
      if (!value.trim() || delay <= 0) {{
        return;
      }}
      autoFinishTimer = setTimeout(() => {{
        if (pendingTargetSyncText) {{
          scheduleAutoFinish(value, delay);
          return;
        }}
        if (text.value !== value && text.value.trim()) {{
          scheduleAutoFinish(text.value, delay);
          return;
        }}
        refreshProtectedPrefix(Date.now());
        finishCurrentInput("idle_finish").catch((error) => {{
          setStatus("\\u7ed3\\u675f\\u5f53\\u524d\\u6bb5\\u5931\\u8d25\\uff1a" + (error.message || String(error)), true);
        }});
      }}, delay);
    }}

    async function finishCurrentInput(reason = "idle_finish") {{
      if (!text.value.trim() && !targetLocked && !targetLockPending) {{
        return true;
      }}
      resetTextState();
      sendPreview("");
      await releaseTarget(reason);
      setStatus("本段已自动收尾，下一次输入会重新锁定当前电脑输入框。");
      return true;
    }}

    function scheduleTargetSync(value) {{
      clearTimeout(targetSyncTimer);
      if (!value.trim()) {{
        pendingTargetSyncText = "";
        refreshProtectedPrefix(Date.now());
        return;
      }}
      targetSyncTimer = setTimeout(() => {{
        syncTargetText(value);
      }}, 80);
    }}

    async function syncTargetText(value) {{
      if (pendingTargetSyncText) {{
        return false;
      }}
      refreshProtectedPrefix(Date.now());
      const baseText = lastTargetSyncText;
      if (receivingPaused || !value.trim() || value === baseText) {{
        return false;
      }}
      let action = "paste";
      let payloadText = baseText ? value.slice(baseText.length) : value;
      let deleteChars = 0;
      if (baseText && !value.startsWith(baseText)) {{
        const prefixLength = commonPrefixLength(baseText, value);
        if (prefixLength < protectedPrefixLength) {{
          detachProtectedRewrite(value, "检测到已保护前文被手机输入法改动，已从当前位置重新开始同步。");
          return false;
        }}
        deleteChars = baseText.length - prefixLength;
        const maxDeletableChars = protectedPrefixLength ? Math.max(0, baseText.length - protectedPrefixLength) : baseText.length;
        if (deleteChars > maxDeletableChars) {{
          detachProtectedRewrite(value, "尾部修正越过保护区，已从当前位置重新开始同步。");
          return false;
        }}
        payloadText = value.slice(prefixLength);
        action = "revise_tail";
        if (tailRevisionMaxChars <= 0 || deleteChars > tailRevisionMaxChars) {{
          detachProtectedRewrite(value, "手机输入法修正范围太长，已从当前位置重新开始同步；需要整段重写时点电脑端“发送预览”。");
          return false;
        }}
      }}
      if (!payloadText && !deleteChars) {{
        markSyncSettled(value);
        return false;
      }}
      if (!targetLocked) {{
        if (targetLockPending) {{
          scheduleTargetSync(value);
          return false;
        }}
        await ensureTargetLocked();
        scheduleTargetSync(value);
        return false;
      }}
      const payload = {{ type: "text.commit", deviceId, text: payloadText, action, deleteChars, requireTargetLock: true }};
      if (sendWs(payload)) {{
        pendingTargetSyncText = value;
        setStatus("正在同步到电脑输入框...");
        return true;
      }}
      try {{
        await postJson("/api/send", {{ text: payloadText, action, deleteChars, requireTargetLock: true }});
        markSyncSettled(value);
        setStatus("已同步到电脑输入框；说完后可直接在电脑端发送。");
        return true;
      }} catch (error) {{
        setStatus("同步到电脑输入框失败：" + friendlyError(error.message || String(error)), true);
        return false;
      }}
    }}

    function focusCapture() {{
      text.focus();
      scheduleCaretToEnd();
      capturePad.classList.add("active");
      setStatus("正在接收手机输入法文字；识别结果会自动同步到电脑输入框。");
    }}

    capturePad.addEventListener("click", focusCapture);
    text.addEventListener("focus", () => {{
      capturePad.classList.add("active");
      scheduleCaretToEnd();
    }});
    ["click", "touchend", "keyup", "compositionend", "input"].forEach((eventName) => {{
      text.addEventListener(eventName, scheduleCaretToEnd);
    }});
    document.addEventListener("selectionchange", () => {{
      if (document.activeElement === text) scheduleCaretToEnd();
    }});
    text.addEventListener("blur", () => capturePad.classList.remove("active"));

    function startPolling() {{
      clearInterval(pollTimer);
      pollTimer = setInterval(noteTextChanged, pollDelayMs);
    }}

    window.addEventListener("pagehide", () => {{
      releaseTargetOnPageExit("pagehide");
    }});

    window.addEventListener("beforeunload", () => {{
      releaseTargetOnPageExit("beforeunload");
    }});

    if ("serviceWorker" in navigator) {{
      navigator.serviceWorker.register("/sw.js", {{ updateViaCache: "none" }}).then((registration) => {{
        registration.update().catch(() => {{}});
      }}).catch(() => {{}});
    }}
    fetch("/api/connect" + (token ? "?token=" + encodeURIComponent(token) : ""), {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ deviceId, deviceName }})
    }}).then((response) => response.json()).then((data) => {{
      if (data) {{
        applyClearSequence(data);
        applyServerDefaults(data.settings);
        setPausedState(Boolean(data.receivingPaused));
      }}
      if (data && data.targetLocked) {{
        setTargetState(true, data.targetTitle || "", "", Boolean(data.targetClickRestore));
      }} else if (!targetLockPending && !targetReleasePending) {{
        setTargetState(false);
      }}
    }}).catch(() => {{}});
    connectSocket();
    observedText = text.value;
    updateCharCount();
    setStatus("点蓝色区域后使用输入法麦克风；文字只在电脑端预览。");
  </script>
</body>
</html>"""


def manifest_payload(token: str = "") -> dict[str, Any]:
    token_query = urllib.parse.urlencode({"token": token}) if token else ""
    start_url = "/" + (f"?{token_query}" if token_query else "")
    return {
        "name": "手机语音输入到 Windows",
        "short_name": "语音输入",
        "start_url": start_url,
        "scope": "/",
        "display": "standalone",
        "background_color": "#f5f7fb",
        "theme_color": "#2563eb",
        "icons": [
            {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"},
        ],
    }


def render_service_worker() -> str:
    return """const CACHE_NAME = "phone-voice-win-input-v36";
const APP_SHELL = ["/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).catch(() => undefined));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  if (event.request.mode === "navigate") {
    event.respondWith(fetch(event.request));
    return;
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
"""


def render_icon_svg() -> str:
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="24" fill="#2563eb"/>
  <path d="M44 50c0-11 9-20 20-20s20 9 20 20v15c0 11-9 20-20 20s-20-9-20-20V50z" fill="#fff"/>
  <path d="M34 62a6 6 0 0 1 12 0c0 10 8 18 18 18s18-8 18-18a6 6 0 0 1 12 0c0 14-10 26-24 29v11h12a5 5 0 0 1 0 10H46a5 5 0 0 1 0-10h12V91c-14-3-24-15-24-29z" fill="#dbeafe"/>
</svg>"""


def render_desktop_page(token: str, phone_urls: list[str]) -> str:
    token_query = urllib.parse.urlencode({"token": token}) if token else ""
    token_json = json.dumps(token).replace("<", "\\u003c")
    phone_urls_json = json.dumps(phone_urls).replace("<", "\\u003c")
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(APP_NAME)} 状态</title>
  <style>
    body {{
      margin: 0;
      min-height: 100vh;
      background: #f5f7fb;
      color: #172033;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(980px, 100%);
      margin: 0 auto;
      padding: 24px;
      display: grid;
      grid-template-columns: minmax(280px, 360px) 1fr;
      gap: 24px;
    }}
    h1 {{ margin: 0 0 12px; font-size: 24px; }}
    p {{ color: #5c667a; line-height: 1.45; }}
    .panel {{
      background: #fff;
      border: 1px solid #d8deea;
      border-radius: 8px;
      padding: 12px;
      box-shadow: 0 4px 14px rgba(22, 32, 51, 0.06);
    }}
    img {{
      width: 100%;
      height: auto;
      border: 1px solid #d8deea;
      border-radius: 8px;
    }}
    .qr-list {{
      display: grid;
      gap: 14px;
    }}
    .qr-item {{
      border-bottom: 1px solid #e6ebf3;
      padding-bottom: 14px;
    }}
    .qr-item:last-child {{
      border-bottom: 0;
      padding-bottom: 0;
    }}
    code {{
      display: block;
      margin-top: 8px;
      padding: 10px;
      background: #f8fafc;
      border: 1px solid #d8deea;
      border-radius: 8px;
      overflow-wrap: anywhere;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
    }}
    th, td {{
      padding: 9px 8px;
      border-bottom: 1px solid #e6ebf3;
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: #5c667a; font-size: 13px; }}
    .ok {{ color: #047857; font-weight: 700; }}
    .bad {{ color: #b42318; font-weight: 700; }}
    .hint-list {{
      margin: 10px 0 0;
      padding: 10px 12px 10px 28px;
      border: 1px solid #f8d7a8;
      border-radius: 8px;
      background: #fff8eb;
      color: #7a4a08;
    }}
    .hint-list:empty {{
      display: none;
    }}
    button {{
      min-height: 38px;
      border: 1px solid #d8deea;
      border-radius: 8px;
      padding: 0 12px;
      background: #fff;
      color: #172033;
      font: inherit;
      font-weight: 650;
    }}
    button:disabled {{
      opacity: 0.55;
    }}
    select, input[type="number"] {{
      min-height: 38px;
      border: 1px solid #d8deea;
      border-radius: 8px;
      padding: 0 10px;
      background: #fff;
      color: #172033;
      font: inherit;
    }}
    .input-with-unit {{
      display: grid;
      grid-template-columns: 1fr auto;
      align-items: center;
      gap: 6px;
    }}
    .input-with-unit span {{
      color: #5c667a;
      font-size: 13px;
      white-space: nowrap;
    }}
    .actions {{
      display: grid;
      gap: 6px;
    }}
    .settings-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(118px, 1fr)) auto;
      align-items: end;
      gap: 10px;
      margin: 14px 0 12px;
      padding: 12px;
      border: 1px solid #e6ebf3;
      border-radius: 8px;
      background: #f8fafc;
    }}
    .settings-grid label {{
      display: grid;
      gap: 6px;
      color: #5c667a;
      font-size: 13px;
      font-weight: 650;
    }}
    .settings-grid label.checkbox {{
      grid-template-columns: auto 1fr;
      align-items: center;
      color: #172033;
      font-size: 14px;
    }}
    @media (max-width: 760px) {{
      main {{ grid-template-columns: 1fr; padding: 12px; }}
      .settings-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <h1>手机连接二维码</h1>
      <p>如果有多个二维码，优先扫和手机同网段的地址，例如同为 192.168.x.x。</p>
      <div id="qrList" class="qr-list"></div>
    </section>
    <section class="panel">
      <h1>连接状态</h1>
      <p id="summary">正在读取状态...</p>
      <ul id="networkHints" class="hint-list"></ul>
      <div class="settings-grid">
        <label class="checkbox"><input id="clipboardProtect" type="checkbox">保护剪贴板</label>
        <label class="checkbox"><input id="nativeWrite" type="checkbox">原生控件后台写入</label>
        <label class="checkbox"><input id="targetClickRestore" type="checkbox">目标位置回点</label>
        <label class="checkbox"><input id="foregroundRestore" type="checkbox">写入时置前目标窗口</label>
        <label class="checkbox"><input id="returnPreviousForeground" type="checkbox">粘贴后回原窗口（实验）</label>
        <label>写入方式
          <select id="writeMethod">
            <option value="unicode">Unicode 直打（远程，默认）</option>
            <option value="clipboard">剪贴板 Ctrl+V</option>
          </select>
        </label>
        <label>目标锁超时
          <div class="input-with-unit">
            <input id="targetLockTimeoutSeconds" type="number" min="0" max="60" step="1" list="targetLockTimeoutOptions">
            <span>秒</span>
          </div>
          <datalist id="targetLockTimeoutOptions">
            <option value="15"></option>
            <option value="30"></option>
            <option value="60"></option>
            <option value="0"></option>
          </datalist>
        </label>
        <label>自动收尾
          <div class="input-with-unit">
            <input id="autoFinishDelaySeconds" type="number" min="0" max="60" step="1" list="autoFinishDelayOptions">
            <span>秒</span>
          </div>
          <datalist id="autoFinishDelayOptions">
            <option value="15"></option>
            <option value="30"></option>
            <option value="60"></option>
            <option value="0"></option>
          </datalist>
        </label>
        <label>尾部纠错
          <select id="tailRevisionMaxChars">
            <option value="0">关闭（0 字）</option>
            <option value="20">20 字</option>
            <option value="50">50 字</option>
            <option value="100">100 字</option>
            <option value="200">200 字</option>
            <option value="500">500 字</option>
          </select>
        </label>
        <button id="saveSettings" type="button">保存设置</button>
      </div>
      <button id="pauseReceiving" type="button">暂停接收</button>
      <button id="releaseAllTargets" type="button">释放全部目标</button>
      <button id="resetToken" type="button">重生成 token</button>
      <table>
        <thead><tr><th>设备</th><th>状态</th><th>传输</th><th>预览</th><th>目标</th><th>最近心跳</th><th>操作</th></tr></thead>
        <tbody id="devices"></tbody>
      </table>
      <h2>最近错误</h2>
      <table>
        <thead><tr><th>时间</th><th>类型</th><th>设备/动作</th><th>原因</th></tr></thead>
        <tbody id="errors"></tbody>
      </table>
    </section>
  </main>
  <script>
    let token = {token_json};
    let fixedPhoneUrls = {phone_urls_json};
    let query = token ? "?token=" + encodeURIComponent(token) : "";
    let phoneUrls = fixedPhoneUrls.length ? fixedPhoneUrls : [location.origin + "/" + query];
    function renderQrList() {{
      document.querySelector("#qrList").innerHTML = phoneUrls.map((url, index) => `
        <div class="qr-item">
          <img src="/qr.png?url=${{encodeURIComponent(url)}}" alt="手机连接二维码 ${{index + 1}}">
          <code>${{escapeHtml(url)}}</code>
        </div>
      `).join("");
    }}
    renderQrList();
    function applySettings(settings) {{
      if (!settings) return;
      document.querySelector("#clipboardProtect").checked = Boolean(settings.clipboardProtect);
      document.querySelector("#nativeWrite").checked = settings.nativeWrite !== false;
      document.querySelector("#targetClickRestore").checked = settings.targetClickRestore !== false;
      document.querySelector("#foregroundRestore").checked = settings.foregroundRestore !== false;
      document.querySelector("#returnPreviousForeground").checked = Boolean(settings.returnPreviousForeground);
      document.querySelector("#writeMethod").value = String(settings.writeMethod || "unicode");
      document.querySelector("#targetLockTimeoutSeconds").value = String(settings.targetLockTimeoutSeconds ?? 60);
      document.querySelector("#autoFinishDelaySeconds").value = String(Math.round(Number(settings.autoFinishDelayMs ?? 15000) / 1000));
      document.querySelector("#tailRevisionMaxChars").value = String(settings.tailRevisionMaxChars ?? 200);
    }}
    function readNumberInput(selector, fallback) {{
      const raw = document.querySelector(selector).value.trim();
      const value = raw === "" ? fallback : Number(raw);
      return Number.isFinite(value) ? value : fallback;
    }}
    document.querySelector("#saveSettings").addEventListener("click", async () => {{
      try {{
        const response = await fetch("/api/settings" + query, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{
            clipboardProtect: document.querySelector("#clipboardProtect").checked,
            nativeWrite: document.querySelector("#nativeWrite").checked,
            targetClickRestore: document.querySelector("#targetClickRestore").checked,
            foregroundRestore: document.querySelector("#foregroundRestore").checked,
            returnPreviousForeground: document.querySelector("#returnPreviousForeground").checked,
            writeMethod: document.querySelector("#writeMethod").value,
            targetLockTimeoutSeconds: readNumberInput("#targetLockTimeoutSeconds", 60),
            autoFinishDelayMs: readNumberInput("#autoFinishDelaySeconds", 15) * 1000,
            tailRevisionMaxChars: readNumberInput("#tailRevisionMaxChars", 200)
          }})
        }});
        const data = await response.json();
        if (!response.ok || !data.ok) {{
          throw new Error(data.error || "保存失败");
        }}
        applySettings(data.settings);
        document.querySelector("#summary").textContent = "设置已保存。";
      }} catch (error) {{
        document.querySelector("#summary").textContent = "保存设置失败：" + error.message;
      }}
    }});
    document.querySelector("#releaseAllTargets").addEventListener("click", async () => {{
      try {{
        const response = await fetch("/api/target/release-all" + query, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: "{{}}"
        }});
        const data = await response.json();
        document.querySelector("#summary").textContent = data.targetReleased ?
          "已释放 " + (data.targetReleasedCount || 0) + " 个目标。" :
          "当前没有锁定目标。";
        refresh();
      }} catch (error) {{
        document.querySelector("#summary").textContent = "释放目标失败：" + error.message;
      }}
    }});
    document.querySelector("#resetToken").addEventListener("click", async () => {{
      if (!token) {{
        document.querySelector("#summary").textContent = "当前已关闭 token 校验，无需重生成。";
        return;
      }}
      if (!confirm("重生成 token 后，旧手机链接会失效，已锁定目标会释放。继续？")) return;
      try {{
        const response = await fetch("/api/token/reset" + query, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: "{{}}"
        }});
        const data = await response.json();
        if (!response.ok || !data.ok) {{
          throw new Error(data.error || "重生成失败");
        }}
        token = data.token || "";
        query = token ? "?token=" + encodeURIComponent(token) : "";
        fixedPhoneUrls = Array.isArray(data.phoneUrls) ? data.phoneUrls : [];
        phoneUrls = fixedPhoneUrls.length ? fixedPhoneUrls : [location.origin + "/" + query];
        history.replaceState(null, "", "/desktop" + query);
        renderQrList();
        document.querySelector("#summary").textContent = "token 已重生成，旧手机链接已失效，请重新扫码。";
        refresh();
      }} catch (error) {{
        document.querySelector("#summary").textContent = "重生成 token 失败：" + error.message;
      }}
    }});
    document.querySelector("#pauseReceiving").addEventListener("click", async () => {{
      const paused = document.querySelector("#pauseReceiving").dataset.paused !== "1";
      try {{
        const response = await fetch("/api/control/pause" + query, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ paused }})
        }});
        const data = await response.json();
        document.querySelector("#summary").textContent = data.receivingPaused ? "已暂停接收。" : "已恢复接收。";
        refresh();
      }} catch (error) {{
        document.querySelector("#summary").textContent = "切换暂停失败：" + error.message;
      }}
    }});
    document.querySelector("#devices").addEventListener("click", async (event) => {{
      const sendPreviewButton = event.target.closest("button[data-send-preview]");
      if (sendPreviewButton) {{
        try {{
          const response = await fetch("/api/preview/send" + query, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{
              deviceId: sendPreviewButton.dataset.sendPreview,
              deviceName: sendPreviewButton.dataset.deviceName || "手机浏览器"
            }})
          }});
          const data = await response.json();
          if (!response.ok || !data.ok) {{
            throw new Error(data.error || "发送失败");
          }}
          document.querySelector("#summary").textContent = "已发送预览到锁定目标，手机缓存会自动清空。";
          refresh();
        }} catch (error) {{
          document.querySelector("#summary").textContent = "发送预览失败：" + error.message;
        }}
        return;
      }}
      const clearPreviewButton = event.target.closest("button[data-clear-preview]");
      if (clearPreviewButton) {{
        try {{
          const response = await fetch("/api/preview/clear" + query, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{
              deviceId: clearPreviewButton.dataset.clearPreview,
              deviceName: clearPreviewButton.dataset.deviceName || "手机浏览器"
            }})
          }});
          const data = await response.json();
          if (!response.ok || !data.ok) {{
            throw new Error(data.error || "清空失败");
          }}
          document.querySelector("#summary").textContent = "已清空该设备预览，手机缓存会自动清空。";
          refresh();
        }} catch (error) {{
          document.querySelector("#summary").textContent = "清空预览失败：" + error.message;
        }}
        return;
      }}
      const releaseButton = event.target.closest("button[data-release-device]");
      if (releaseButton) {{
        try {{
          const response = await fetch("/api/target/release" + query, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ deviceId: releaseButton.dataset.releaseDevice, reason: "desktop" }})
          }});
          const data = await response.json();
          if (!response.ok || !data.ok) {{
            throw new Error(data.error || "释放失败");
          }}
          document.querySelector("#summary").textContent = data.targetReleased ?
            "已释放该设备的锁定目标。" :
            "该设备当前没有锁定目标。";
          refresh();
        }} catch (error) {{
          document.querySelector("#summary").textContent = "释放目标失败：" + error.message;
        }}
        return;
      }}
      const button = event.target.closest("button[data-test-device]");
      if (!button) return;
      try {{
        const response = await fetch("/api/test-paste" + query, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ deviceId: button.dataset.testDevice, undoAfter: true }})
        }});
        const data = await response.json();
        if (!response.ok || !data.ok) {{
          throw new Error(data.error || "测试失败");
        }}
        document.querySelector("#summary").textContent = data.undoResult ?
          "测试粘贴完成，已尝试撤销测试文本。" :
          "测试粘贴完成。";
        refresh();
      }} catch (error) {{
        document.querySelector("#summary").textContent = "测试粘贴失败：" + error.message;
      }}
    }});
    async function refresh() {{
      try {{
        const response = await fetch("/api/status" + query);
        const data = await response.json();
        const devices = data.devices || [];
        const errors = data.errors || [];
        applySettings(data.settings);
        document.querySelector("#pauseReceiving").dataset.paused = data.receivingPaused ? "1" : "0";
        document.querySelector("#pauseReceiving").textContent = data.receivingPaused ? "恢复接收" : "暂停接收";
        const activeText = data.activeDeviceId ? "激活：" + (data.activeDeviceName || data.activeDeviceId) + "。 " : "无激活设备。 ";
        const settings = data.settings || {{}};
        const latest = data.latestResult || {{}};
        const writeMethodText = settings.writeMethod === "clipboard" ? "剪贴板 Ctrl+V" : "Unicode 直打";
        const latestMethodText = latest.method ? " 最近实际方法：" + latest.method + "。" : "";
        document.querySelector("#summary").textContent = devices.length ?
          (data.receivingPaused ? "接收已暂停。 " : "") + activeText + "写入方式：" + writeMethodText + "。" + latestMethodText + " 已记录 " + devices.length + " 台设备，最近动作字符数：" + (data.latestChars || 0) :
          "还没有手机连接。写入方式：" + writeMethodText + "。";
        renderNetworkHints(data.network || {{}});
        document.querySelector("#devices").innerHTML = devices.map((item) => `
          <tr>
            <td>${{escapeHtml(item.name)}}<br><small>${{escapeHtml(item.address)}}</small></td>
            <td class="${{item.connected ? "ok" : "bad"}}">${{item.connected ? "在线" : "离线"}}${{item.active ? "<br><small>激活输入</small>" : ""}}</td>
            <td>${{escapeHtml(item.transport)}}</td>
            <td>${{escapeHtml(item.previewText || "")}}<br><small>${{item.previewChars || 0}} 字符</small></td>
            <td>${{item.targetLocked ? "已锁定" : "未锁定"}}<br><small>${{escapeHtml(item.targetTitle || "")}}${{formatTargetTimeout(item)}}</small></td>
            <td>${{item.lastSeenSeconds}} 秒前</td>
            <td>
              <div class="actions">
                <button type="button" data-send-preview="${{escapeHtml(item.id)}}" data-device-name="${{escapeHtml(item.name)}}" ${{item.targetLocked && item.previewChars ? "" : "disabled"}}>发送预览</button>
                <button type="button" data-clear-preview="${{escapeHtml(item.id)}}" data-device-name="${{escapeHtml(item.name)}}" ${{item.previewChars ? "" : "disabled"}}>清空预览</button>
                <button type="button" data-test-device="${{escapeHtml(item.id)}}" ${{item.targetLocked ? "" : "disabled"}}>测试粘贴</button>
                ${{item.targetLocked ? `<button type="button" data-release-device="${{escapeHtml(item.id)}}">释放目标</button>` : ""}}
              </div>
            </td>
          </tr>
        `).join("");
        document.querySelector("#errors").innerHTML = errors.length ? errors.map((item) => `
          <tr>
            <td>${{item.ageSeconds}} 秒前</td>
            <td>${{escapeHtml(item.category || "")}}</td>
            <td>${{escapeHtml(item.deviceName || item.deviceId || item.address || "")}}<br><small>${{escapeHtml(item.action || "")}}${{item.textChars ? " / " + item.textChars + " 字符" : ""}}</small></td>
            <td>${{escapeHtml(item.message || "")}}</td>
          </tr>
        `).join("") : `<tr><td colspan="4">暂无错误。</td></tr>`;
      }} catch (error) {{
        document.querySelector("#summary").textContent = "读取状态失败：" + error.message;
      }}
    }}
    function escapeHtml(value) {{
      return String(value).replace(/[&<>"']/g, (char) => ({{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}}[char]));
    }}
    function formatTargetTimeout(item) {{
      if (!item.targetLocked || !item.targetTimeoutSeconds) return "";
      const seconds = Number(item.targetTimeoutSeconds || 0);
      if (!seconds) return "";
      return "<br>自动释放：" + (seconds >= 60 ? Math.ceil(seconds / 60) + " 分钟内" : seconds + " 秒内");
    }}
    function renderNetworkHints(network) {{
      const hints = Array.isArray(network.hints) ? network.hints : [];
      document.querySelector("#networkHints").innerHTML = hints.map((hint) => `<li>${{escapeHtml(hint)}}</li>`).join("");
    }}
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"""


def websocket_send_json(sock: socket.socket, payload: dict[str, Any]) -> None:
    websocket_send_text(sock, json.dumps(payload, ensure_ascii=False))


def websocket_send_text(sock: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.extend([126, (length >> 8) & 0xFF, length & 0xFF])
    else:
        header.append(127)
        header.extend(length.to_bytes(8, "big"))
    sock.sendall(bytes(header) + payload)


def websocket_read_text(sock: socket.socket) -> str | None:
    header = _recv_exact(sock, 2)
    if not header:
        return None
    first, second = header[0], header[1]
    opcode = first & 0x0F
    masked = (second & 0x80) != 0
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(_recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_recv_exact(sock, 8), "big")
    mask_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length)
    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    if opcode == 0x8:
        return None
    if opcode == 0x9:
        _websocket_send_control(sock, 0xA, payload)
        return ""
    if opcode != 0x1:
        return ""
    return payload.decode("utf-8", errors="replace")


def _websocket_send_control(sock: socket.socket, opcode: int, payload: bytes) -> None:
    if len(payload) > 125:
        payload = payload[:125]
    sock.sendall(bytes([0x80 | opcode, len(payload)]) + payload)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("WebSocket connection closed.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def first_query_value(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name, [])
    return values[-1] if values else ""


def make_handler(config: ServerConfig) -> type[BaseHTTPRequestHandler]:
    class PhoneVoiceHandler(BaseHTTPRequestHandler):
        server_version = "PhoneVoiceWinInput/0.1"
        protocol_version = "HTTP/1.1"

        def handle(self) -> None:
            try:
                super().handle()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                return

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/ws":
                if not self._authorized(query=query):
                    text_response(self, HTTPStatus.FORBIDDEN, "Forbidden: bad token", "text/plain")
                    return
                self._handle_websocket()
                return
            if parsed.path == "/health":
                json_response(self, HTTPStatus.OK, {"ok": True})
                return
            if parsed.path == "/api/status":
                if not self._authorized(query=query):
                    json_response(self, HTTPStatus.FORBIDDEN, {"ok": False, "error": "Bad token."})
                    return
                cleanup_stale_targets(config)
                snapshot = config.state.snapshot()
                snapshot["network"] = network_diagnostics(
                    self.server.server_address[0],
                    self.server.server_address[1],
                    config.token,
                    snapshot,
                )
                json_response(self, HTTPStatus.OK, snapshot)
                return
            if parsed.path == "/manifest.webmanifest":
                manifest_token = ""
                supplied_token = first_query_value(query, "token")
                if config.token and secrets.compare_digest(supplied_token, config.token):
                    manifest_token = supplied_token
                json_response(self, HTTPStatus.OK, manifest_payload(manifest_token))
                return
            if parsed.path == "/sw.js":
                text_response(self, HTTPStatus.OK, render_service_worker(), "application/javascript")
                return
            if parsed.path == "/icon.svg":
                text_response(self, HTTPStatus.OK, render_icon_svg(), "image/svg+xml")
                return
            if parsed.path == "/qr.svg":
                url = first_query_value(query, "url")
                if not url:
                    text_response(self, HTTPStatus.BAD_REQUEST, "Missing url", "text/plain")
                    return
                try:
                    text_response(self, HTTPStatus.OK, make_qr_svg(url), "image/svg+xml")
                except QrError as exc:
                    text_response(self, HTTPStatus.BAD_REQUEST, str(exc), "text/plain")
                return
            if parsed.path == "/qr.png":
                url = first_query_value(query, "url")
                if not url:
                    text_response(self, HTTPStatus.BAD_REQUEST, "Missing url", "text/plain")
                    return
                try:
                    binary_response(self, HTTPStatus.OK, make_qr_png_bytes(url), "image/png")
                except QrError as exc:
                    text_response(self, HTTPStatus.BAD_REQUEST, str(exc), "text/plain")
                return
            if parsed.path == "/desktop":
                if not self._authorized(query=query):
                    text_response(self, HTTPStatus.FORBIDDEN, "Forbidden: bad token", "text/plain")
                    return
                phone_urls = make_urls(self.server.server_address[0], self.server.server_address[1], config.token)
                text_response(self, HTTPStatus.OK, render_desktop_page(config.token, phone_urls), "text/html")
                return
            if parsed.path in ("", "/"):
                if not self._authorized(query=query):
                    text_response(self, HTTPStatus.FORBIDDEN, "Forbidden: bad token", "text/plain")
                    return
                text_response(self, HTTPStatus.OK, render_page(config.token, config.state.settings_snapshot()), "text/html")
                return
            text_response(self, HTTPStatus.NOT_FOUND, "Not found", "text/plain")

        def do_POST(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path not in (
                "/api/send",
                "/api/connect",
                "/api/target/lock",
                "/api/target/release",
                "/api/target/release-all",
                "/api/target/status",
                "/api/control/pause",
                "/api/settings",
                "/api/token/reset",
                "/api/test-paste",
                "/api/preview/send",
                "/api/preview/clear",
                "/api/preview/update",
            ):
                text_response(self, HTTPStatus.NOT_FOUND, "Not found", "text/plain")
                return

            length_header = self.headers.get("Content-Length", "0")
            try:
                length = int(length_header)
            except ValueError:
                json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid Content-Length."})
                return
            if length > MAX_BODY_BYTES:
                json_response(self, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "Payload too large."})
                return

            raw = self.rfile.read(length)
            try:
                data = parse_body(raw, self.headers.get("Content-Type", ""))
            except Exception as exc:
                config.state.record_error(
                    "bad_payload",
                    str(exc),
                    address=self.client_address[0],
                    action=parsed.path,
                )
                json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"Bad payload: {exc}"})
                return

            query = urllib.parse.parse_qs(parsed.query)
            if not self._authorized(query=query, data=data):
                config.state.record_error(
                    "auth",
                    "Bad token.",
                    device_id=str(data.get("deviceId", "")),
                    device_name=str(data.get("deviceName", "")),
                    address=self.client_address[0],
                    action=parsed.path,
                )
                json_response(self, HTTPStatus.FORBIDDEN, {"ok": False, "error": "Bad token."})
                return

            if parsed.path == "/api/connect":
                device_id = str(data.get("deviceId", "")) or self._fallback_device_id()
                device_name = str(data.get("deviceName", "手机浏览器"))
                config.state.touch_device(
                    device_id=device_id,
                    name=device_name,
                    address=self.client_address[0],
                    user_agent=self.headers.get("User-Agent", ""),
                    transport="http",
                )
                target_payload = handle_target_status(config, device_id)
                json_response(
                    self,
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "deviceId": device_id,
                        "receivingPaused": config.state.is_paused(),
                        "settings": config.state.settings_snapshot(),
                        "clearSequence": config.state.device_clear_sequence(device_id),
                        **target_payload,
                    },
                )
                return

            if parsed.path == "/api/settings":
                try:
                    payload = handle_settings_update(config, data)
                except Exception as exc:
                    config.state.record_error(
                        "settings",
                        str(exc),
                        address=self.client_address[0],
                        action=parsed.path,
                    )
                    json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                    return
                json_response(self, HTTPStatus.OK, payload)
                return

            if parsed.path == "/api/token/reset":
                try:
                    payload = handle_token_reset(
                        config,
                        self.server.server_address[0],
                        self.server.server_address[1],
                    )
                except Exception as exc:
                    config.state.record_error(
                        "token_reset",
                        str(exc),
                        address=self.client_address[0],
                        action=parsed.path,
                    )
                    json_response(self, HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                    return
                json_response(self, HTTPStatus.OK, payload)
                return

            device_id = str(data.get("deviceId", "")) or self._fallback_device_id()
            device_name = str(data.get("deviceName", "手机浏览器"))
            config.state.touch_device(
                device_id=device_id,
                name=device_name,
                address=self.client_address[0],
                user_agent=self.headers.get("User-Agent", ""),
                transport="http",
            )
            if parsed.path == "/api/target/lock":
                try:
                    payload = handle_target_lock(config, device_id)
                except Exception as exc:
                    config.state.record_error(
                        "target_lock",
                        str(exc),
                        device_id=device_id,
                        device_name=device_name,
                        address=self.client_address[0],
                        action="target.lock",
                    )
                    json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
                    return
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/target/release":
                payload = handle_target_release(config, device_id, str(data.get("reason", "")))
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/target/release-all":
                payload = handle_target_release_all(config)
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/target/status":
                payload = handle_target_status(config, device_id)
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/control/pause":
                payload = handle_pause(config, bool(data.get("paused")))
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/test-paste":
                test_text = str(data.get("text", "【测试输入】")) or "【测试输入】"
                undo_after = data.get("undoAfter", True) is not False
                try:
                    payload = handle_test_paste(config, device_id, test_text, undo_after=undo_after)
                except Exception as exc:
                    config.state.record_error(
                        "test_paste",
                        str(exc),
                        device_id=device_id,
                        device_name=device_name,
                        address=self.client_address[0],
                        action="test_paste",
                        text_chars=len(test_text),
                    )
                    json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
                    return
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/preview/send":
                try:
                    payload = handle_preview_send(config, device_id)
                except Exception as exc:
                    config.state.record_error(
                        "preview_send",
                        str(exc),
                        device_id=device_id,
                        device_name=device_name,
                        address=self.client_address[0],
                        action="preview_send",
                        text_chars=len(config.state.device_preview_text(device_id)),
                    )
                    json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
                    return
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/preview/clear":
                payload = handle_preview_clear(config, device_id)
                json_response(self, HTTPStatus.OK, payload)
                return
            if parsed.path == "/api/preview/update":
                updated = config.state.update_preview(
                    device_id,
                    str(data.get("text", "")),
                    int(data.get("clearSequence", 0) or 0),
                )
                json_response(
                    self,
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "action": "preview_update",
                        "ignored": not updated,
                        "clearSequence": config.state.device_clear_sequence(device_id),
                    },
                )
                return

            text = str(data.get("text", ""))
            action = str(data.get("action", "paste"))
            require_target_lock = bool(data.get("requireTargetLock"))
            delete_chars = int(data.get("deleteChars", 0) or 0)
            try:
                payload = handle_text_action(config, text, action, device_id, require_target_lock, delete_chars)
            except Exception as exc:
                config.state.record_error(
                    "input",
                    str(exc),
                    device_id=device_id,
                    device_name=device_name,
                    address=self.client_address[0],
                    action=action,
                    text_chars=len(text) + max(0, delete_chars),
                )
                json_response(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
                return

            json_response(self, HTTPStatus.OK, payload)

        def _authorized(
            self,
            query: dict[str, list[str]] | None = None,
            data: dict[str, Any] | None = None,
        ) -> bool:
            if not config.token:
                return True
            candidates = [
                first_query_value(query or {}, "token"),
                self.headers.get("X-Token", ""),
                str((data or {}).get("token", "")),
            ]
            return any(secrets.compare_digest(candidate, config.token) for candidate in candidates)

        def _fallback_device_id(self) -> str:
            return "http-" + self.client_address[0].replace(":", "-")

        def _handle_websocket(self) -> None:
            key = self.headers.get("Sec-WebSocket-Key", "")
            if not key:
                text_response(self, HTTPStatus.BAD_REQUEST, "Missing Sec-WebSocket-Key", "text/plain")
                return
            accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
            self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()

            device_id = "ws-" + self.client_address[0].replace(":", "-")
            device_name = "手机浏览器"
            try:
                while True:
                    message = websocket_read_text(self.connection)
                    if message is None:
                        break
                    if message == "":
                        continue
                    try:
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        config.state.record_error(
                            "websocket",
                            "Bad JSON.",
                            device_id=device_id,
                            device_name=device_name,
                            address=self.client_address[0],
                            action="websocket.message",
                        )
                        websocket_send_json(self.connection, {"type": "status", "ok": False, "error": "Bad JSON."})
                        continue
                    msg_type = str(data.get("type", ""))
                    device_id = str(data.get("deviceId", device_id)) or device_id
                    device_name = str(data.get("deviceName", device_name)) or device_name
                    config.state.touch_device(
                        device_id=device_id,
                        name=device_name,
                        address=self.client_address[0],
                        user_agent=self.headers.get("User-Agent", ""),
                        transport="websocket",
                    )
                    if msg_type == "hello":
                        target_payload = handle_target_status(config, device_id)
                        websocket_send_json(
                            self.connection,
                            {
                                "type": "hello",
                                "ok": True,
                                "deviceId": device_id,
                                "receivingPaused": config.state.is_paused(),
                                "settings": config.state.settings_snapshot(),
                                "clearSequence": config.state.device_clear_sequence(device_id),
                                **target_payload,
                            },
                        )
                    elif msg_type == "heartbeat":
                        websocket_send_json(
                            self.connection,
                            {
                                "type": "heartbeat",
                                "ok": True,
                                "time": time.time(),
                                "clearSequence": config.state.device_clear_sequence(device_id),
                                "settings": config.state.settings_snapshot(),
                            },
                        )
                    elif msg_type == "control.pause":
                        payload = handle_pause(config, bool(data.get("paused")))
                        payload["type"] = "control"
                        payload["action"] = "pause"
                        websocket_send_json(self.connection, payload)
                    elif msg_type == "target.lock":
                        try:
                            payload = handle_target_lock(config, device_id)
                            payload["type"] = "target"
                            payload["action"] = "lock"
                            websocket_send_json(self.connection, payload)
                        except Exception as exc:
                            config.state.record_error(
                                "target_lock",
                                str(exc),
                                device_id=device_id,
                                device_name=device_name,
                                address=self.client_address[0],
                                action="target.lock",
                            )
                            websocket_send_json(
                                self.connection,
                                {"type": "target", "action": "lock", "ok": False, "error": str(exc)},
                            )
                    elif msg_type == "target.release":
                        payload = handle_target_release(config, device_id, str(data.get("reason", "")))
                        payload["type"] = "target"
                        payload["action"] = "release"
                        websocket_send_json(self.connection, payload)
                    elif msg_type == "text.update":
                        config.state.update_preview(
                            device_id,
                            str(data.get("text", "")),
                            int(data.get("clearSequence", 0) or 0),
                        )
                    elif msg_type == "text.commit":
                        text = str(data.get("text", ""))
                        action = str(data.get("action", "paste"))
                        require_target_lock = bool(data.get("requireTargetLock"))
                        delete_chars = int(data.get("deleteChars", 0) or 0)
                        try:
                            payload = handle_text_action(config, text, action, device_id, require_target_lock, delete_chars)
                            payload["type"] = "status"
                            websocket_send_json(self.connection, payload)
                        except Exception as exc:
                            config.state.record_error(
                                "input",
                                str(exc),
                                device_id=device_id,
                                device_name=device_name,
                                address=self.client_address[0],
                                action=action,
                                text_chars=len(text) + max(0, delete_chars),
                            )
                            websocket_send_json(self.connection, {"type": "status", "ok": False, "error": str(exc)})
                    else:
                        config.state.record_error(
                            "websocket",
                            "Unknown message type.",
                            device_id=device_id,
                            device_name=device_name,
                            address=self.client_address[0],
                            action=msg_type or "unknown",
                        )
                        websocket_send_json(self.connection, {"type": "status", "ok": False, "error": "Unknown message type."})
            except (ConnectionError, OSError):
                return

    return PhoneVoiceHandler


def get_lan_ips() -> list[str]:
    candidates: list[str] = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            candidates.append(sock.getsockname()[0])
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            candidates.append(item[4][0])
    except OSError:
        pass

    return normalize_lan_ips(candidates)


def normalize_lan_ips(candidates: list[str]) -> list[str]:
    seen: set[str] = set()
    private_ips: list[str] = []
    fallback_ips: list[str] = []
    for ip in candidates:
        if ip in seen:
            continue
        seen.add(ip)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            continue
        if address.is_private:
            private_ips.append(ip)
        else:
            fallback_ips.append(ip)
    if private_ips:
        return sorted(private_ips, key=lan_ip_sort_key)
    return sorted(fallback_ips, key=lan_ip_sort_key)


def lan_ip_sort_key(ip: str) -> tuple[int, str]:
    try:
        parts = [int(part) for part in ip.split(".")]
    except ValueError:
        return (99, ip)
    if len(parts) != 4:
        return (99, ip)
    if parts[0] == 192 and parts[1] == 168:
        return (0, ip)
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return (1, ip)
    if parts[0] == 10:
        return (2, ip)
    return (3, ip)


def make_urls(host: str, port: int, token: str) -> list[str]:
    query = urllib.parse.urlencode({"token": token}) if token else ""
    suffix = f"?{query}" if query else ""
    hosts = get_lan_ips() if host in ("", "0.0.0.0", "::") else [host]
    if not hosts:
        hosts = ["127.0.0.1"]
    return [f"http://{item}:{port}/{suffix}" for item in hosts]


def make_desktop_url(host: str, port: int, token: str) -> str:
    query = urllib.parse.urlencode({"token": token}) if token else ""
    suffix = f"?{query}" if query else ""
    display_host = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host
    return f"http://{display_host}:{port}/desktop{suffix}"


def is_retryable_bind_error(exc: OSError) -> bool:
    retryable_errno = {errno.EACCES, errno.EADDRINUSE, 10013, 10048}
    retryable_winerror = {10013, 10048}
    return exc.errno in retryable_errno or getattr(exc, "winerror", None) in retryable_winerror


def create_server(
    host: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
    strict_port: bool = False,
) -> tuple[ThreadingHTTPServer, list[tuple[int, OSError]]]:
    attempts = 1 if strict_port else PORT_RETRY_COUNT
    failures: list[tuple[int, OSError]] = []
    for candidate in range(port, port + attempts):
        try:
            return ThreadingHTTPServer((host, candidate), handler), failures
        except OSError as exc:
            failures.append((candidate, exc))
            if strict_port or not is_retryable_bind_error(exc):
                raise
    raise failures[-1][1]


def run_self_test() -> None:
    page = render_page("test-token")
    assert "手机语音输入到 Windows" in page
    assert "test-token" in page
    assert "manifest.webmanifest" in page
    assert "manifest.webmanifest?token=test-token" in page
    assert manifest_payload("abc")["start_url"] == "/?token=abc"
    assert manifest_payload("")["start_url"] == "/"
    assert normalize_lan_ips(["28.0.0.1", "10.20.30.40", "192.168.50.23"]) == ["192.168.50.23", "10.20.30.40"]
    assert normalize_lan_ips(["127.0.0.1", "169.254.1.1"]) == []
    assert "new WebSocket" in page
    assert 'id="targetStatus"' in page
    assert 'id="capturePad"' in page
    assert 'class="capture-input"' in page
    assert "点这里说话" in page
    assert "识别出的文字不会显示在手机上" not in page
    assert "text.commit" in page
    assert 'let action = "paste"' in page
    assert '"revise_tail"' in page
    assert "commonPrefixLength" in page
    assert "deleteChars" in page
    assert "protectedPrefixLength" in page
    assert "scheduleSegmentProtection" in page
    assert "handleTransientEmptyText" in page
    assert "moveCaretToEnd" in page
    assert "scheduleCaretToEnd" in page
    assert "scheduleEmptyFinish" not in page
    assert 'finishCurrentInput("empty")' not in page
    assert "refreshProtectedPrefix" in page
    assert "detachProtectedRewrite" in page
    assert "maxDeletableChars" in page
    assert "finishCurrentInput" in page
    assert "autoFinishDelayMs" in page
    assert RuntimeSettings().snapshot()["autoFinishDelayMs"] == 15000
    assert "nextAutoFinishDelayMs" in page
    assert "clearTimeout(autoFinishTimer)" in page
    assert "tailRevisionMaxChars" in page
    assert "/api/preview/update" in page
    assert "clearSequence" in page
    assert 'id="inputMode"' not in page
    assert 'id="syncSpeed"' not in page
    assert 'id="releaseTargetButton"' not in page
    assert 'id="undoButton"' not in page
    assert 'id="pauseButton"' not in page
    assert 'id="deviceNameInput"' not in page
    assert 'id="sendSentenceButton"' not in page
    assert 'id="deleteSentenceButton"' not in page
    assert 'id="clearParagraphButton"' not in page
    assert 'id="historyList"' not in page
    assert 'id="clearHistoryButton"' not in page
    assert 'data-quick-insert="comma"' not in page
    assert "target.lock" in page
    assert "requireTargetLock" in page
    assert "activeInputMode" not in page
    assert "activeSyncSpeed" not in page
    assert "draftKey" not in page
    assert "restoreDraft" not in page
    assert "historyKey" not in page
    assert "rememberCommittedText" not in page
    assert "resendHistoryItem" not in page
    assert "最近发送" not in page
    assert "inputModeKey" not in page
    assert "syncSpeedKey" not in page
    assert "storageGet" in page
    assert "已恢复上次未清空的手机草稿" not in page
    assert "releaseTargetOnPageExit" in page
    assert "navigator.sendBeacon" in page
    assert "keepalive: true" in page
    assert "pagehide" in page
    assert "text.update" in page
    assert "serverDefaults" in page
    assert "syncDeviceName" not in page
    assert "normalizeDeviceName" not in page
    assert "targetClickRestore" in page
    assert "foregroundRestore" in page
    assert "returnPreviousForeground" in page
    assert "friendlyError" in page
    assert "foreground_restore_disabled" in page
    assert "targetLockTimeoutSeconds" in page
    custom_page = render_page(
        "test-token",
        {
            "clipboardProtect": False,
            "nativeWrite": False,
            "targetClickRestore": False,
            "foregroundRestore": False,
            "returnPreviousForeground": True,
            "targetLockTimeoutSeconds": 30,
            "autoFinishDelayMs": 8000,
            "tailRevisionMaxChars": 50,
            "defaultInputMode": "pause_clear",
            "defaultSyncSpeed": "stable",
            "writeMethod": "unicode",
        },
    )
    assert '"nativeWrite": false' in custom_page
    assert '"targetClickRestore": false' in custom_page
    assert '"foregroundRestore": false' in custom_page
    assert '"returnPreviousForeground": true' in custom_page
    assert '"targetLockTimeoutSeconds": 30' in custom_page
    assert '"autoFinishDelayMs": 8000' in custom_page
    assert '"tailRevisionMaxChars": 50' in custom_page
    assert '"defaultInputMode": "pause_clear"' in custom_page
    assert '"defaultSyncSpeed": "stable"' in custom_page
    assert '"writeMethod": "unicode"' in custom_page
    assert "SpeechRecognition" not in page
    assert "continuousSpeechButton" not in page
    assert "liveToggle" not in page
    assert APP_VERSION in page
    assert "phone-voice-win-input-v36" in render_service_worker()
    assert WindowsTextInjector._native_write_supported_class("Edit") is True
    assert WindowsTextInjector._native_write_supported_class("RichEdit20W") is True
    assert WindowsTextInjector._native_write_supported_class("WindowsForms10.EDIT.app.0.141b42a_r8_ad1") is True
    assert WindowsTextInjector._native_write_supported_class("Chrome_WidgetWin_1") is False
    assert WindowsTextInjector._native_control_text("a\nb") == "a\r\nb"
    assert "_move_caret_to_end" in dir(WindowsTextInjector)
    source_text = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert 'target.click_source in {"caret", "focus"}' in source_text
    assert "key_flags=0x0001" in source_text
    assert source_text.count("preserve_current_caret") >= 8
    captured_key_events: list[tuple[int, int]] = []
    original_send_input_events = WindowsTextInjector._send_input_events
    original_release_modifiers = WindowsTextInjector._release_common_modifiers
    try:
        WindowsTextInjector._send_input_events = staticmethod(lambda events: captured_key_events.extend(events))
        WindowsTextInjector._release_common_modifiers = staticmethod(lambda: None)
        WindowsTextInjector._send_key_chord(0x11, 0x23, key_flags=0x0001)
    finally:
        WindowsTextInjector._send_input_events = staticmethod(original_send_input_events)
        WindowsTextInjector._release_common_modifiers = staticmethod(original_release_modifiers)
    assert captured_key_events == [(0x11, 0), (0x23, 0x0001), (0x23, 0x0003), (0x11, 0x0002)]
    assert WindowsTextInjector._point_in_rect(5, 5, (0, 0, 10, 10)) is True
    assert WindowsTextInjector._point_in_rect(10, 5, (0, 0, 10, 10)) is False
    assert WindowsTextInjector._rect_inside((1, 1, 4, 4), (0, 0, 10, 10)) is True
    assert WindowsTextInjector._rect_area((0, 0, 5, 4)) == 20
    lock_payload = TargetLock(
        device_id="device",
        top_hwnd=1,
        focus_hwnd=2,
        thread_id=3,
        title="Target",
        class_name="Window",
        click_offset_x=12,
        click_offset_y=34,
        click_source="caret",
    ).payload()
    assert lock_payload["targetClickRestore"] is True
    assert lock_payload["targetClickSource"] == "caret"
    cursor_payload = TargetLock(device_id="device", top_hwnd=1, focus_hwnd=1, thread_id=3, title="Remote", class_name="Window", click_source="cursor").payload()
    assert cursor_payload["targetClickRestore"] is False
    assert cursor_payload["targetClickSource"] == "cursor"
    assert parse_body(b'{"text":"hello","action":"copy"}', "application/json")["text"] == "hello"
    form = parse_body(b"text=%E4%BD%A0%E5%A5%BD&action=paste_enter", "application/x-www-form-urlencoded")
    assert form["text"] == "你好"
    injector = WindowsTextInjector(dry_run=True)
    result = injector.paste_text("hello", press_enter=True)
    assert injector.last_text == "hello"
    assert result.action == "paste_enter"
    replace_result = injector.replace_text("mirror")
    assert replace_result.action == "replace"
    assert injector.last_text == "mirror"
    revise_result = injector.revise_tail("正", 1, target_device_id="device")
    assert revise_result.action == "revise_tail"
    assert revise_result.chars == 1
    config = ServerConfig(token="", injector=injector, state=ServerState())
    settings_payload = handle_settings_update(
        config,
        {
            "clipboardProtect": False,
            "nativeWrite": False,
            "targetClickRestore": False,
            "foregroundRestore": False,
            "returnPreviousForeground": True,
            "targetLockTimeoutSeconds": 30,
            "autoFinishDelayMs": 15000,
            "tailRevisionMaxChars": 100,
            "defaultInputMode": "manual_clear",
            "defaultSyncSpeed": "stable",
            "writeMethod": "unicode",
        },
    )
    assert settings_payload["settings"]["clipboardProtect"] is False
    assert settings_payload["settings"]["nativeWrite"] is False
    assert settings_payload["settings"]["targetClickRestore"] is False
    assert settings_payload["settings"]["foregroundRestore"] is False
    assert settings_payload["settings"]["returnPreviousForeground"] is True
    assert settings_payload["settings"]["targetLockTimeoutSeconds"] == 30
    assert settings_payload["settings"]["autoFinishDelayMs"] == 15000
    assert settings_payload["settings"]["tailRevisionMaxChars"] == 100
    assert RuntimeSettings().snapshot()["writeMethod"] == "unicode"
    assert settings_payload["settings"]["writeMethod"] == "unicode"
    assert injector.protect_clipboard is False
    assert injector.prefer_native_write is False
    assert injector.target_click_restore is False
    assert injector.foreground_restore is False
    assert injector.return_previous_foreground is True
    assert injector.write_method == "unicode"
    test_settings_path = PROJECT_DIR / ".self-test-settings.json"
    try:
        persisted_injector = WindowsTextInjector(dry_run=True)
        persisted_config = ServerConfig(token="", injector=persisted_injector, state=ServerState(), settings_path=test_settings_path)
        persisted_payload = handle_settings_update(
            persisted_config,
            {
                "clipboardProtect": False,
                "nativeWrite": False,
                "targetClickRestore": False,
                "foregroundRestore": False,
                "returnPreviousForeground": True,
                "targetLockTimeoutSeconds": 15,
                "autoFinishDelayMs": 30000,
                "tailRevisionMaxChars": 500,
                "writeMethod": "clipboard",
            },
        )
        saved_payload = json.loads(test_settings_path.read_text(encoding="utf-8"))
        assert saved_payload["version"] == APP_VERSION
        assert saved_payload["settings"]["writeMethod"] == "clipboard"
        loaded_settings = load_runtime_settings(test_settings_path)
        assert loaded_settings["clipboardProtect"] is False
        assert loaded_settings["foregroundRestore"] is False
        assert loaded_settings["returnPreviousForeground"] is True
        assert loaded_settings["targetLockTimeoutSeconds"] == 15
        assert loaded_settings["autoFinishDelayMs"] == 30000
        assert loaded_settings["tailRevisionMaxChars"] == 500
        assert loaded_settings["writeMethod"] == "clipboard"
        assert persisted_payload["settings"] == loaded_settings
        test_settings_path.write_text(json.dumps({"settings": {"writeMethod": "clipboard", "tailRevisionMaxChars": 137}}, ensure_ascii=False), encoding="utf-8")
        partially_loaded = load_runtime_settings(test_settings_path)
        assert partially_loaded["writeMethod"] == "clipboard"
        assert partially_loaded["tailRevisionMaxChars"] == DEFAULT_TAIL_REVISION_MAX_CHARS
    finally:
        try:
            test_settings_path.unlink()
        except FileNotFoundError:
            pass
    handle_settings_update(
        config,
        {
            "clipboardProtect": True,
            "nativeWrite": True,
            "targetClickRestore": True,
            "foregroundRestore": True,
            "returnPreviousForeground": False,
        },
    )
    assert config.state.snapshot()["settings"]["defaultInputMode"] == "manual_clear"
    config.state.touch_device("device-1", "phone", "127.0.0.1", "ua", "websocket")
    try:
        handle_text_action(config, "locked", "paste", "device-1", require_target_lock=True)
        raise AssertionError("Expected missing target lock to fail.")
    except ValueError:
        pass
    target = handle_target_lock(config, "device-1")
    assert target["targetLocked"] is True
    status_payload = handle_target_status(config, "device-1")
    assert status_payload["targetLocked"] is True
    assert status_payload["targetTitle"] == "Dry-run target"
    config.state.update_preview("device-1", "电脑端确认发送")
    preview_payload = handle_preview_send(config, "device-1")
    assert preview_payload["action"] == "preview_send"
    assert preview_payload["targetLocked"] is True
    assert preview_payload["clearSequence"] == 1
    preview_snapshot = config.state.snapshot()["devices"][0]
    assert preview_snapshot["previewChars"] == 0
    assert preview_snapshot["clearSequence"] == 1
    assert config.state.snapshot()["activeDeviceId"] == ""
    handle_target_lock(config, "device-1")
    config.state.update_preview("device-1", "待清空")
    clear_payload = handle_preview_clear(config, "device-1")
    assert clear_payload["action"] == "preview_clear"
    assert clear_payload["clearSequence"] == 2
    assert config.state.snapshot()["devices"][0]["previewChars"] == 0
    assert config.state.update_preview("device-1", "旧手机未清空", client_clear_sequence=1) is False
    assert config.state.snapshot()["devices"][0]["previewChars"] == 0
    assert config.state.update_preview("device-1", "清空后新输入", client_clear_sequence=2) is True
    handle_target_lock(config, "device-1")
    locked_result = handle_text_action(config, "locked", "paste", "device-1", require_target_lock=True)
    assert locked_result["targetLocked"] is True
    assert locked_result["targetRestored"] is True
    undo_result = handle_text_action(config, "", "undo", "device-1", require_target_lock=True)
    assert undo_result["action"] == "undo"
    assert undo_result["targetRestored"] is True
    test_paste = handle_test_paste(config, "device-1")
    assert test_paste["action"] == "test_paste"
    assert test_paste["targetRestored"] is True
    assert test_paste["undoResult"]["action"] == "undo"
    handle_pause(config, True)
    assert config.state.snapshot()["receivingPaused"] is True
    try:
        handle_text_action(config, "paused", "paste", "device-1", require_target_lock=True)
        raise AssertionError("Expected paused receiving to fail.")
    except ValueError:
        pass
    handle_pause(config, False)
    assert config.state.snapshot()["receivingPaused"] is False
    release_after_pause = handle_target_release(config, "device-1")
    assert release_after_pause["targetReleased"] is True
    assert release_after_pause["clearSequence"] == 3
    assert config.state.snapshot()["devices"][0]["previewChars"] == 0
    config.state.touch_device("device-2", "second phone", "127.0.0.2", "ua2", "websocket")
    handle_target_lock(config, "device-1")
    assert config.state.snapshot()["activeDeviceId"] == "device-1"
    try:
        handle_target_lock(config, "device-2")
        raise AssertionError("Expected active device conflict.")
    except ValueError:
        pass
    try:
        handle_text_action(config, "other", "paste", "device-2", require_target_lock=False)
        raise AssertionError("Expected inactive device write to fail.")
    except ValueError:
        pass
    release_payload = handle_target_release(config, "device-1")
    assert release_payload["activeReleased"] is True
    assert release_payload["releaseReason"] == ""
    assert config.state.snapshot()["activeDeviceId"] == ""
    handle_target_lock(config, "device-2")
    assert config.state.snapshot()["activeDeviceId"] == "device-2"
    pagehide_release = handle_target_release(config, "device-2", "pagehide")
    assert pagehide_release["targetReleased"] is True
    assert pagehide_release["releaseReason"] == "pagehide"
    assert config.state.snapshot()["latestAction"] == "target_release"
    handle_target_lock(config, "device-2")
    release_all_payload = handle_target_release_all(config)
    assert release_all_payload["targetReleasedCount"] == 1
    assert config.state.snapshot()["activeDeviceId"] == ""
    timeout_injector = WindowsTextInjector(dry_run=True)
    timeout_config = ServerConfig(token="", injector=timeout_injector, state=ServerState())
    timeout_config.state.touch_device("timeout-device", "phone", "127.0.0.3", "ua3", "websocket")
    handle_target_lock(timeout_config, "timeout-device")
    handle_settings_update(timeout_config, {"targetLockTimeoutSeconds": 60})
    with timeout_config.state._lock:
        timeout_config.state.devices["timeout-device"].target_activity_at = time.time() - 61
    assert cleanup_stale_targets(timeout_config) == ["timeout-device"]
    timeout_snapshot = timeout_config.state.snapshot()
    assert timeout_snapshot["devices"][0]["targetLocked"] is False
    assert timeout_snapshot["activeDeviceId"] == ""
    assert timeout_snapshot["errors"][0]["category"] == "target_timeout"
    local_network = network_diagnostics("127.0.0.1", 8765, "abc", {"devices": []})
    assert local_network["localOnly"] is True
    assert any("防火墙" in hint for hint in local_network["hints"])
    lan_network = network_diagnostics(
        "192.168.1.2",
        8765,
        "abc",
        {"devices": [{"connected": True}]},
    )
    assert lan_network["localOnly"] is False
    assert lan_network["connectedDeviceCount"] == 1
    assert lan_network["hints"] == []
    assert make_urls("127.0.0.1", 8765, "abc")[0] == "http://127.0.0.1:8765/?token=abc"
    assert make_desktop_url("0.0.0.0", 8765, "abc") == "http://127.0.0.1:8765/desktop?token=abc"
    desktop_page = render_desktop_page("abc", ["http://192.168.1.2:8765/?token=abc"])
    assert "fixedPhoneUrls" in desktop_page
    assert "192.168.1.2" in desktop_page
    assert "/api/test-paste" in desktop_page
    assert "/api/preview/send" in desktop_page
    assert "/api/preview/clear" in desktop_page
    assert "/api/token/reset" in desktop_page
    assert 'id="resetToken"' in desktop_page
    assert "重生成 token" in desktop_page
    assert "/api/target/release" in desktop_page
    assert "/api/settings" in desktop_page
    assert 'id="clipboardProtect"' in desktop_page
    assert 'id="nativeWrite"' in desktop_page
    assert 'id="targetClickRestore"' in desktop_page
    assert 'id="foregroundRestore"' in desktop_page
    assert 'id="returnPreviousForeground"' in desktop_page
    assert 'id="writeMethod"' in desktop_page
    assert 'id="targetLockTimeoutSeconds"' in desktop_page
    assert 'type="number"' in desktop_page
    assert 'max="60"' in desktop_page
    assert 'value="15"' in desktop_page
    assert 'id="autoFinishDelaySeconds"' in desktop_page
    assert 'id="autoFinishDelayOptions"' in desktop_page
    assert 'id="tailRevisionMaxChars"' in desktop_page
    assert "关闭（0 字）" in desktop_page
    assert "500 字" in desktop_page
    assert 'id="networkHints"' in desktop_page
    assert 'id="saveSettings"' in desktop_page
    assert 'id="errors"' in desktop_page
    assert "最近错误" in desktop_page
    assert "activeDeviceId" in desktop_page
    assert "激活输入" in desktop_page
    assert "data-test-device" in desktop_page
    assert "data-release-device" in desktop_page
    assert "data-send-preview" in desktop_page
    assert "data-clear-preview" in desktop_page
    assert "previewText" in desktop_page
    source_text = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "class WindowsTrayIcon" in source_text
    assert "Shell_NotifyIconW" in source_text
    assert "PostMessageW" in source_text
    assert "_try_background_message_paste" in source_text
    assert "_restore_previous_foreground" in source_text
    assert "显示/隐藏窗口" in source_text
    assert "隐藏到托盘" in source_text
    assert "notebook.add(connect_tab" in source_text
    assert "restore_default_settings" in source_text
    assert "设备与日志" in source_text
    assert "refresh(True)" in source_text
    assert "def run_legacy_gui" in source_text
    assert "from phone_voice_gui import run_modern_gui" in source_text
    modern_gui_path = PROJECT_DIR / "phone_voice_gui.py"
    assert modern_gui_path.exists()
    modern_gui_source = modern_gui_path.read_text(encoding="utf-8")
    assert "class ModernMainWindow" in modern_gui_source
    assert "QSystemTrayIcon" in modern_gui_source
    assert "恢复推荐默认" in modern_gui_source
    assert "send_preview" in modern_gui_source
    assert "mouse_event" in source_text
    assert "--no-target-click-restore" in source_text
    assert "--no-foreground-restore" in source_text
    assert "--return-previous-foreground" in source_text
    assert "--target-lock-timeout" in source_text
    assert "Connection tips:" in source_text
    assert "renderNetworkHints" in source_text
    assert '"/api/token/reset"' in source_text
    modifiers, vk, label = parse_hotkey_spec("ctrl+alt+p")
    assert modifiers == (HOTKEY_MODIFIERS["ctrl"] | HOTKEY_MODIFIERS["alt"])
    assert vk == ord("P")
    assert label == "Ctrl+Alt+P"
    modifiers, vk, label = parse_hotkey_spec("shift+f12")
    assert modifiers == HOTKEY_MODIFIERS["shift"]
    assert vk == 0x7B
    assert label == "Shift+F12"
    try:
        parse_hotkey_spec("p")
        raise AssertionError("Expected modifier-less hotkey to fail.")
    except ValueError:
        pass
    assert "class WindowsHotkeyListener" in source_text
    assert "RegisterHotKey" in source_text
    assert "--hotkey" in source_text
    assert is_retryable_bind_error(OSError(errno.EACCES, "blocked"))
    state = ServerState()
    state.touch_device("id", "phone", "127.0.0.1", "ua", "websocket")
    state.update_preview("id", "第一句。\n第二句。")
    state.set_target_lock("id", True, "Agent window")
    state.record_error("input", "Target restore failed: foreground_not_restored", device_id="id", action="paste", text_chars=12)
    assert state.snapshot()["devices"][0]["connected"] is True
    assert state.snapshot()["devices"][0]["targetLocked"] is True
    assert state.snapshot()["devices"][0]["active"] is True
    assert state.snapshot()["activeDeviceId"] == "id"
    assert state.snapshot()["devices"][0]["previewText"] == "第一句。 第二句。"
    assert state.snapshot()["errors"][0]["category"] == "input"
    assert state.snapshot()["errors"][0]["textChars"] == 12
    assert "第一句" not in json.dumps(state.snapshot()["errors"], ensure_ascii=False)
    long_preview = ServerState.preview_snippet("x" * (PREVIEW_SNIPPET_CHARS + 10))
    assert long_preview.endswith("...")
    assert len(long_preview) <= PREVIEW_SNIPPET_CHARS + 3
    assert make_qr_svg("http://127.0.0.1:8765/?token=abc").startswith("<svg")
    assert make_qr_png_bytes("http://127.0.0.1:8765/?token=abc").startswith(b"\x89PNG")
    test_token_path = PROJECT_DIR / ".self-test-token"
    test_reset_token_path = PROJECT_DIR / ".self-test-reset-token"
    try:
        first_token = load_or_create_token(reset=True, path=test_token_path)
        second_token = load_or_create_token(path=test_token_path)
        assert first_token == second_token
        assert load_or_create_token(reset=True, path=test_token_path) != first_token
        reset_injector = WindowsTextInjector(dry_run=True)
        reset_config = ServerConfig(token="old-token", injector=reset_injector, state=ServerState())
        reset_config.state.touch_device("reset-device", "phone", "127.0.0.4", "ua4", "websocket")
        handle_target_lock(reset_config, "reset-device")
        token_payload = handle_token_reset(reset_config, "127.0.0.1", 8765, token_path=test_reset_token_path)
        assert token_payload["ok"] is True
        assert token_payload["token"] == reset_config.token
        assert token_payload["token"] != "old-token"
        assert token_payload["phoneUrls"][0].endswith("token=" + urllib.parse.quote(reset_config.token))
        assert reset_config.state.snapshot()["activeDeviceId"] == ""
        assert reset_config.state.snapshot()["latestAction"] == "token_reset"
    finally:
        try:
            test_token_path.unlink()
        except FileNotFoundError:
            pass
        try:
            test_reset_token_path.unlink()
        except FileNotFoundError:
            pass
    print("Self-test passed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default="0.0.0.0", help="Bind host. Default: 0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Bind port. Default: {DEFAULT_PORT}")
    parser.add_argument("--token", default="", help="Access token. Default: persisted local token.")
    parser.add_argument("--reset-token", action="store_true", help="Generate and save a new default token.")
    parser.add_argument("--no-token", action="store_true", help="Disable token protection on the LAN page.")
    parser.add_argument("--strict-port", action="store_true", help="Do not try nearby ports if the requested port fails.")
    parser.add_argument("--no-clipboard-protect", action="store_true", help="Do not restore the previous text clipboard after paste.")
    parser.add_argument("--no-target-click-restore", action="store_true", help="Do not click the locked caret position before fallback paste.")
    parser.add_argument("--no-foreground-restore", action="store_true", help="Do not bring the locked target window to the foreground for fallback paste.")
    parser.add_argument("--return-previous-foreground", action="store_true", help="Experimental: try to return to the previously active window after fallback paste.")
    parser.add_argument(
        "--target-lock-timeout",
        type=int,
        default=None,
        help=f"Release an idle locked target after this many seconds (0-60). Default: saved setting or {DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS}.",
    )
    parser.add_argument("--no-qr", action="store_true", help="Do not print the terminal QR code at startup.")
    parser.add_argument("--gui", action="store_true", help="Open a small desktop window with QR code and connection status.")
    parser.add_argument("--hotkey", default="", help="Optional global hotkey to toggle pause, for example ctrl+alt+p.")
    parser.add_argument("--dry-run", action="store_true", help="Accept requests without touching clipboard or keyboard.")
    parser.add_argument("--self-test", action="store_true", help="Run local tests and exit.")
    return parser


def run_legacy_gui(
    server: ThreadingHTTPServer,
    config: ServerConfig,
    state: ServerState,
    phone_url: str,
    desktop_url: str,
) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except Exception as exc:
        raise RuntimeError(f"GUI is unavailable: {exc}") from exc

    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("820x720")
    root.minsize(680, 580)
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"))
        style.configure("Subtitle.TLabel", foreground="#5c667a")
        style.configure("Summary.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Notice.TLabel", foreground="#245d3b")
        style.configure("Error.TLabel", foreground="#a12622")
        style.configure("Muted.TLabel", foreground="#5c667a")
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
    except Exception:
        pass
    tray_actions: queue.Queue[str] = queue.Queue()
    tray = WindowsTrayIcon(APP_NAME, tray_actions, state.is_paused)
    tray_available = tray.start()

    shell = ttk.Frame(root, padding=(16, 12))
    shell.pack(fill="both", expand=True)
    header = ttk.Frame(shell)
    header.pack(fill="x")
    title = ttk.Label(header, text="手机语音输入到 Windows", style="Title.TLabel")
    title.pack(side="left")
    ttk.Label(header, text=APP_VERSION, style="Muted.TLabel").pack(side="right", padx=(8, 0))
    subtitle_text = "手机扫码连接；关闭窗口可隐藏到托盘继续运行。" if tray_available else "手机扫码连接；关闭窗口可选择退出或最小化继续运行。"
    subtitle = ttk.Label(shell, text=subtitle_text, style="Subtitle.TLabel")
    subtitle.pack(fill="x", pady=(2, 10))

    notebook = ttk.Notebook(shell)
    notebook.pack(fill="both", expand=True)
    connect_tab = ttk.Frame(notebook, padding=12)
    settings_tab = ttk.Frame(notebook, padding=12)
    diagnostics_tab = ttk.Frame(notebook, padding=12)
    notebook.add(connect_tab, text="连接")
    notebook.add(settings_tab, text="设置")
    notebook.add(diagnostics_tab, text="设备与日志")

    current_phone_url = phone_url
    current_desktop_url = desktop_url

    connection_body = ttk.Frame(connect_tab)
    connection_body.pack(fill="both", expand=True)
    connection_body.columnconfigure(1, weight=1)
    connection_body.rowconfigure(0, weight=1)
    qr_frame = tk.Frame(connection_body, bg="white", padx=10, pady=10, highlightthickness=1, highlightbackground="#d7dce5")
    qr_frame.grid(row=0, column=0, sticky="n", padx=(0, 16))
    canvas_size = 260
    canvas = tk.Canvas(qr_frame, width=canvas_size, height=canvas_size, bg="white", highlightthickness=0)
    canvas.pack()
    draw_qr_on_canvas(canvas, current_phone_url, canvas_size)

    url_var = tk.StringVar(value=current_phone_url)
    control_panel = ttk.Frame(connection_body)
    control_panel.grid(row=0, column=1, sticky="nsew")
    control_panel.columnconfigure(0, weight=1)
    ttk.Label(control_panel, text="手机连接地址", style="Summary.TLabel").grid(row=0, column=0, sticky="w")
    url_entry = ttk.Entry(control_panel, textvariable=url_var, state="readonly")
    url_entry.grid(row=1, column=0, sticky="ew", pady=(6, 10))

    button_row = ttk.Frame(control_panel)
    button_row.grid(row=2, column=0, sticky="ew")
    for column in range(2):
        button_row.columnconfigure(column, weight=1)

    def copy_url() -> None:
        root.clipboard_clear()
        root.clipboard_append(current_phone_url)
        status_var.set("手机 URL 已复制。")

    def open_desktop_page() -> None:
        import webbrowser

        webbrowser.open(current_desktop_url)

    ttk.Button(button_row, text="复制手机链接", command=copy_url).grid(row=0, column=0, sticky="ew", padx=(0, 4), pady=4)
    ttk.Button(button_row, text="打开状态页", command=open_desktop_page).grid(row=0, column=1, sticky="ew", padx=(4, 0), pady=4)

    def reset_token_gui() -> None:
        nonlocal current_phone_url, current_desktop_url
        if not config.token:
            status_var.set("当前已关闭 token 校验，无需重生成。")
            return
        if not messagebox.askyesno("重生成 token", "旧手机链接会失效，已锁定目标会释放。继续？"):
            return
        try:
            payload = handle_token_reset(config, server.server_address[0], server.server_address[1])
            phone_urls = payload.get("phoneUrls") or []
            current_phone_url = str(phone_urls[0]) if phone_urls else make_urls(server.server_address[0], server.server_address[1], config.token)[0]
            current_desktop_url = str(payload.get("desktopUrl") or make_desktop_url(server.server_address[0], server.server_address[1], config.token))
            url_var.set(current_phone_url)
            draw_qr_on_canvas(canvas, current_phone_url, canvas_size)
            try:
                save_qr_pngs([str(url) for url in phone_urls] or [current_phone_url])
            except Exception:
                pass
            status_var.set("token 已重生成，旧手机链接已失效，请重新扫码。")
        except Exception as exc:
            status_var.set(f"重生成 token 失败：{exc}")
        refresh()

    ttk.Button(button_row, text="重生成连接码", command=reset_token_gui).grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=4)

    def release_all_targets() -> None:
        payload = handle_target_release_all(config)
        status_var.set(f"已释放 {payload.get('targetReleasedCount', 0)} 个目标。")
        refresh()

    ttk.Button(button_row, text="释放全部目标", command=release_all_targets).grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=4)

    def test_locked_target() -> None:
        snapshot = state.snapshot()
        target_device = next((item for item in snapshot.get("devices", []) if item.get("targetLocked")), None)
        if not target_device:
            status_var.set("没有锁定目标，先从手机开始输入后再测试。")
            return
        try:
            payload = handle_test_paste(config, str(target_device.get("id", "")), undo_after=True)
            status_var.set(
                "测试粘贴完成，已尝试撤销测试文本。"
                if payload.get("undoResult")
                else "测试粘贴完成。"
            )
        except Exception as exc:
            status_var.set(f"测试粘贴失败：{exc}")
        refresh()

    ttk.Button(button_row, text="测试锁定目标", command=test_locked_target).grid(row=2, column=0, sticky="ew", padx=(0, 4), pady=4)

    def toggle_pause() -> None:
        paused = not state.is_paused()
        handle_pause(config, paused)
        status_var.set("已暂停接收。" if paused else "已恢复接收。")
        pause_button.configure(text="恢复接收" if paused else "暂停接收")
        refresh()

    pause_button = ttk.Button(button_row, text="暂停接收", command=toggle_pause)
    pause_button.grid(row=2, column=1, sticky="ew", padx=(4, 0), pady=4)

    preview_row = ttk.Frame(control_panel)
    preview_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
    preview_row.columnconfigure(0, weight=1)
    preview_row.columnconfigure(1, weight=1)

    def preview_device_snapshot() -> dict[str, Any] | None:
        devices = state.snapshot().get("devices", [])
        candidates = [
            lambda item: item.get("active") and item.get("previewChars"),
            lambda item: item.get("targetLocked") and item.get("previewChars"),
            lambda item: item.get("connected") and item.get("previewChars"),
            lambda item: item.get("previewChars"),
        ]
        for predicate in candidates:
            found = next((item for item in devices if predicate(item)), None)
            if found:
                return found
        return None

    def send_preview_gui() -> None:
        device = preview_device_snapshot()
        if not device:
            status_var.set("没有可发送的手机预览。")
            return
        if not device.get("targetLocked"):
            status_var.set("该设备还没有锁定目标，先在 Windows 输入框点出光标并从手机开始输入。")
            return
        try:
            handle_preview_send(config, str(device.get("id", "")))
            status_var.set("已发送预览到锁定目标，手机缓存会自动清空。")
        except Exception as exc:
            status_var.set(f"发送预览失败：{exc}")
        refresh()

    def clear_preview_gui() -> None:
        device = preview_device_snapshot()
        if not device:
            status_var.set("没有可清空的手机预览。")
            return
        try:
            handle_preview_clear(config, str(device.get("id", "")))
            status_var.set("已清空手机预览，手机缓存会自动清空。")
        except Exception as exc:
            status_var.set(f"清空预览失败：{exc}")
        refresh()

    ttk.Button(preview_row, text="发送当前预览", command=send_preview_gui, style="Primary.TButton").grid(
        row=0, column=0, sticky="ew", padx=(0, 4)
    )
    ttk.Button(preview_row, text="清空手机缓存", command=clear_preview_gui).grid(
        row=0, column=1, sticky="ew", padx=(4, 0)
    )

    def show_window() -> None:
        root.deiconify()
        root.lift()
        try:
            root.focus_force()
        except Exception:
            pass

    def hide_window() -> None:
        status_var.set("窗口已隐藏到托盘，服务继续运行。" if tray_available else "窗口已最小化，服务继续运行。")
        if tray_available:
            root.withdraw()
        else:
            root.iconify()

    def toggle_window() -> None:
        if root.state() in ("withdrawn", "iconic"):
            show_window()
        else:
            hide_window()

    def exit_app() -> None:
        tray.stop()
        server.shutdown()
        root.destroy()

    summary_var = tk.StringVar(value="等待手机连接...")
    status_var = tk.StringVar(value="服务已启动，等待手机连接。")
    ttk.Separator(control_panel).grid(row=4, column=0, sticky="ew", pady=(16, 10))
    ttk.Label(control_panel, text="运行状态", style="Summary.TLabel").grid(row=5, column=0, sticky="w")
    ttk.Label(control_panel, textvariable=summary_var, wraplength=430, justify="left").grid(
        row=6, column=0, sticky="ew", pady=(6, 0)
    )
    notice_label = ttk.Label(control_panel, textvariable=status_var, style="Notice.TLabel", wraplength=430, justify="left")
    notice_label.grid(row=7, column=0, sticky="ew", pady=(10, 0))

    def update_notice_style(*_args: Any) -> None:
        message = status_var.get()
        is_error = any(marker in message for marker in ("失败", "错误", "无法", "没有锁定目标"))
        notice_label.configure(style="Error.TLabel" if is_error else "Notice.TLabel")

    status_var.trace_add("write", update_notice_style)

    ttk.Label(settings_tab, text="输入与目标设置", style="Summary.TLabel").pack(anchor="w")
    ttk.Label(
        settings_tab,
        text="修改后点击保存，设置会立即生效并在下次启动时保留。0 秒表示关闭对应超时。",
        style="Muted.TLabel",
        wraplength=720,
        justify="left",
    ).pack(fill="x", pady=(2, 10))
    settings_frame = ttk.LabelFrame(settings_tab, text="运行设置", padding=12)
    settings_frame.pack(fill="x")
    clipboard_var = tk.BooleanVar(value=config.injector.protect_clipboard)
    native_write_var = tk.BooleanVar(value=config.injector.prefer_native_write)
    target_click_var = tk.BooleanVar(value=config.injector.target_click_restore)
    foreground_restore_var = tk.BooleanVar(value=config.injector.foreground_restore)
    return_previous_var = tk.BooleanVar(value=config.injector.return_previous_foreground)

    def format_timeout_seconds(value: Any) -> str:
        try:
            numeric_value = int(value)
        except (TypeError, ValueError):
            numeric_value = DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS
        return str(numeric_value)

    def parse_timeout_seconds(value: str) -> int:
        numeric_value = int(str(value).strip() or DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS)
        if not (TARGET_LOCK_TIMEOUT_MIN_SECONDS <= numeric_value <= TARGET_LOCK_TIMEOUT_MAX_SECONDS):
            raise ValueError(f"目标锁超时需要在 0-{TARGET_LOCK_TIMEOUT_MAX_SECONDS} 秒之间，0 表示关闭。")
        return numeric_value

    def format_auto_finish_seconds(value: Any) -> str:
        try:
            numeric_value = int(value)
        except (TypeError, ValueError):
            numeric_value = DEFAULT_AUTO_FINISH_DELAY_MS
        return str(int(round(max(0, numeric_value) / 1000)))

    def parse_auto_finish_seconds(value: str) -> int:
        numeric_value = int(str(value).strip() or int(DEFAULT_AUTO_FINISH_DELAY_MS / 1000))
        if not (AUTO_FINISH_DELAY_MIN_SECONDS <= numeric_value <= AUTO_FINISH_DELAY_MAX_SECONDS):
            raise ValueError(f"自动收尾需要在 0-{AUTO_FINISH_DELAY_MAX_SECONDS} 秒之间，0 表示关闭。")
        return numeric_value * 1000

    write_method_options = [
        ("Unicode 直打（远程，默认）", "unicode"),
        ("剪贴板 Ctrl+V", "clipboard"),
    ]
    write_method_label_by_value = {value: label for label, value in write_method_options}
    write_method_value_by_label = {label: value for label, value in write_method_options}
    tail_revision_options = [("关闭（0 字）", 0), ("20 字", 20), ("50 字", 50), ("100 字", 100), ("200 字", 200), ("500 字", 500)]
    tail_revision_label_by_value = {value: label for label, value in tail_revision_options}
    tail_revision_value_by_label = {label: value for label, value in tail_revision_options}

    def format_write_method(value: Any) -> str:
        return write_method_label_by_value.get(str(value), write_method_label_by_value[DEFAULT_WRITE_METHOD])

    def parse_write_method(value: str) -> str:
        return write_method_value_by_label.get(value, value)

    def format_tail_revision_chars(value: Any) -> str:
        try:
            numeric_value = int(value)
        except (TypeError, ValueError):
            numeric_value = DEFAULT_TAIL_REVISION_MAX_CHARS
        return tail_revision_label_by_value.get(numeric_value, str(numeric_value))

    def parse_tail_revision_chars(value: str) -> int:
        if value in tail_revision_value_by_label:
            return tail_revision_value_by_label[value]
        numeric_value = int(str(value).strip() or DEFAULT_TAIL_REVISION_MAX_CHARS)
        if numeric_value not in TAIL_REVISION_SUGGESTED_CHARS:
            options = "/".join(str(item) for item in TAIL_REVISION_SUGGESTED_CHARS)
            raise ValueError(f"尾部纠错请使用固定选项：{options} 字，0 表示关闭。")
        return numeric_value

    timeout_var = tk.StringVar(value=format_timeout_seconds(state.settings_snapshot().get("targetLockTimeoutSeconds", DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS)))
    auto_finish_var = tk.StringVar(value=format_auto_finish_seconds(state.settings_snapshot().get("autoFinishDelayMs", DEFAULT_AUTO_FINISH_DELAY_MS)))
    tail_revision_var = tk.StringVar(value=format_tail_revision_chars(state.settings_snapshot().get("tailRevisionMaxChars", DEFAULT_TAIL_REVISION_MAX_CHARS)))
    write_method_var = tk.StringVar(value=format_write_method(state.settings_snapshot().get("writeMethod", DEFAULT_WRITE_METHOD)))

    ttk.Checkbutton(settings_frame, text="保护文本剪贴板", variable=clipboard_var).grid(
        row=0, column=0, columnspan=2, sticky="w", padx=(0, 8)
    )
    ttk.Checkbutton(settings_frame, text="原生控件后台写入", variable=native_write_var).grid(
        row=0, column=2, columnspan=2, sticky="w", padx=(8, 0)
    )
    ttk.Checkbutton(settings_frame, text="目标位置回点", variable=target_click_var).grid(
        row=1, column=0, columnspan=2, sticky="w", padx=(0, 8), pady=(8, 0)
    )
    ttk.Checkbutton(settings_frame, text="写入时置前目标窗口", variable=foreground_restore_var).grid(
        row=1, column=2, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
    )
    ttk.Checkbutton(settings_frame, text="粘贴后回原窗口（实验）", variable=return_previous_var).grid(
        row=2, column=0, columnspan=4, sticky="w", pady=(8, 0)
    )
    ttk.Label(settings_frame, text="写入方式").grid(row=3, column=0, sticky="w", pady=(12, 0))
    ttk.Combobox(
        settings_frame,
        textvariable=write_method_var,
        values=[label for label, _value in write_method_options],
        state="readonly",
        width=24,
    ).grid(row=3, column=1, sticky="ew", pady=(12, 0))
    tk.Label(settings_frame, text="目标锁超时").grid(row=4, column=0, sticky="w", pady=(8, 0))
    timeout_box = tk.Frame(settings_frame)
    timeout_box.grid(row=4, column=1, sticky="ew", pady=(8, 0))
    tk.Entry(timeout_box, textvariable=timeout_var, width=8).pack(side="left", fill="x", expand=True)
    tk.Label(timeout_box, text="秒").pack(side="left", padx=(6, 0))
    tk.Label(settings_frame, text="自动收尾").grid(row=4, column=2, sticky="w", pady=(8, 0), padx=(8, 0))
    auto_finish_box = tk.Frame(settings_frame)
    auto_finish_box.grid(row=4, column=3, sticky="ew", pady=(8, 0))
    tk.Entry(auto_finish_box, textvariable=auto_finish_var, width=8).pack(side="left", fill="x", expand=True)
    tk.Label(auto_finish_box, text="秒").pack(side="left", padx=(6, 0))
    tk.Label(settings_frame, text="尾部纠错").grid(row=5, column=0, sticky="w", pady=(8, 0))
    ttk.Combobox(
        settings_frame,
        textvariable=tail_revision_var,
        values=[label for label, _value in tail_revision_options],
        state="readonly",
        width=12,
    ).grid(row=5, column=1, sticky="ew", pady=(8, 0))
    settings_frame.columnconfigure(1, weight=1)
    settings_frame.columnconfigure(3, weight=1)

    def load_settings_into_gui(settings: dict[str, Any]) -> None:
        clipboard_var.set(bool(settings.get("clipboardProtect", True)))
        native_write_var.set(settings.get("nativeWrite") is not False)
        target_click_var.set(settings.get("targetClickRestore") is not False)
        foreground_restore_var.set(settings.get("foregroundRestore") is not False)
        return_previous_var.set(bool(settings.get("returnPreviousForeground")))
        write_method_var.set(format_write_method(settings.get("writeMethod", DEFAULT_WRITE_METHOD)))
        timeout_var.set(format_timeout_seconds(settings.get("targetLockTimeoutSeconds", DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS)))
        auto_finish_var.set(format_auto_finish_seconds(settings.get("autoFinishDelayMs", DEFAULT_AUTO_FINISH_DELAY_MS)))
        tail_revision_var.set(format_tail_revision_chars(settings.get("tailRevisionMaxChars", DEFAULT_TAIL_REVISION_MAX_CHARS)))

    def current_gui_settings() -> dict[str, Any]:
        return {
            "clipboardProtect": clipboard_var.get(),
            "nativeWrite": native_write_var.get(),
            "targetClickRestore": target_click_var.get(),
            "foregroundRestore": foreground_restore_var.get(),
            "returnPreviousForeground": return_previous_var.get(),
            "writeMethod": parse_write_method(write_method_var.get()),
            "targetLockTimeoutSeconds": parse_timeout_seconds(timeout_var.get()),
            "autoFinishDelayMs": parse_auto_finish_seconds(auto_finish_var.get()),
            "tailRevisionMaxChars": parse_tail_revision_chars(tail_revision_var.get()),
        }

    def apply_gui_settings() -> None:
        try:
            payload = handle_settings_update(config, current_gui_settings())
            load_settings_into_gui(payload.get("settings", {}))
            status_var.set("运行设置已保存并立即生效。")
        except Exception as exc:
            status_var.set(f"保存设置失败：{exc}")

    def restore_default_settings() -> None:
        if not messagebox.askyesno("恢复默认", "恢复推荐默认设置并立即保存？"):
            return
        defaults = {
            "clipboardProtect": True,
            "nativeWrite": True,
            "targetClickRestore": True,
            "foregroundRestore": True,
            "returnPreviousForeground": False,
            "writeMethod": DEFAULT_WRITE_METHOD,
            "targetLockTimeoutSeconds": DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS,
            "autoFinishDelayMs": DEFAULT_AUTO_FINISH_DELAY_MS,
            "tailRevisionMaxChars": DEFAULT_TAIL_REVISION_MAX_CHARS,
            "defaultInputMode": DEFAULT_INPUT_MODE,
            "defaultSyncSpeed": DEFAULT_SYNC_SPEED,
        }
        try:
            payload = handle_settings_update(config, defaults)
            load_settings_into_gui(payload.get("settings", {}))
            status_var.set("已恢复推荐默认设置。")
        except Exception as exc:
            status_var.set(f"恢复默认失败：{exc}")

    settings_footer = ttk.Frame(settings_frame)
    settings_footer.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(12, 0))
    settings_footer.columnconfigure(0, weight=1)
    ttk.Label(settings_footer, text="保存位置：.phone_voice_settings.json", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Button(settings_footer, text="恢复默认", command=restore_default_settings).grid(row=0, column=1, padx=(8, 4))
    ttk.Button(settings_footer, text="保存设置", command=apply_gui_settings, style="Primary.TButton").grid(row=0, column=2, padx=(4, 0))

    diagnostics_toolbar = ttk.Frame(diagnostics_tab)
    diagnostics_toolbar.pack(fill="x", pady=(0, 8))
    ttk.Label(diagnostics_toolbar, text="设备、目标与最近错误", style="Summary.TLabel").pack(side="left")
    diagnostics_body = ttk.Frame(diagnostics_tab)
    diagnostics_body.pack(fill="both", expand=True)
    devices_text = tk.Text(
        diagnostics_body,
        height=12,
        wrap="word",
        state="disabled",
        relief="solid",
        borderwidth=1,
        padx=10,
        pady=8,
        font=("Consolas", 9),
    )
    devices_scroll = ttk.Scrollbar(diagnostics_body, orient="vertical", command=devices_text.yview)
    devices_text.configure(yscrollcommand=devices_scroll.set)
    devices_text.pack(side="left", fill="both", expand=True)
    devices_scroll.pack(side="right", fill="y")

    def copy_diagnostics() -> None:
        content = devices_text.get("1.0", "end-1c")
        root.clipboard_clear()
        root.clipboard_append(content)
        status_var.set("设备与日志已复制。")

    ttk.Button(diagnostics_toolbar, text="复制日志", command=copy_diagnostics).pack(side="right")
    ttk.Button(diagnostics_toolbar, text="立即刷新", command=lambda: refresh()).pack(side="right", padx=(0, 8))

    def refresh(schedule_next: bool = False) -> None:
        cleanup_stale_targets(config)
        snapshot = state.snapshot()
        network = network_diagnostics(server.server_address[0], server.server_address[1], config.token, snapshot)
        devices = snapshot.get("devices", [])
        online = [item for item in devices if item.get("connected")]
        pause_button.configure(text="恢复接收" if snapshot.get("receivingPaused") else "暂停接收")
        pause_text = "接收已暂停 / " if snapshot.get("receivingPaused") else ""
        active_text = f"激活：{snapshot.get('activeDeviceName') or snapshot.get('activeDeviceId')} / " if snapshot.get("activeDeviceId") else "无激活设备 / "
        settings = snapshot.get("settings", {})
        write_method = settings.get("writeMethod", DEFAULT_WRITE_METHOD)
        latest_method = (snapshot.get("latestResult") or {}).get("method", "")
        method_text = "Unicode直打" if write_method == "unicode" else "剪贴板Ctrl+V"
        latest_text = f" / 最近方法：{latest_method}" if latest_method else ""
        summary_var.set(f"{pause_text}{active_text}写入：{method_text}{latest_text}\n在线设备：{len(online)} / 已记录设备：{len(devices)} / 最近动作：{snapshot.get('latestChars', 0)} 字")
        lines = []
        for item in devices:
            state_label = ("在线 / 激活" if item.get("active") else "在线") if item.get("connected") else "离线"
            target_label = f"目标：{item.get('targetTitle')}" if item.get("targetLocked") else "目标：未锁定"
            if item.get("targetLocked") and item.get("targetTimeoutSeconds"):
                target_label += f" / 自动释放：{item.get('targetTimeoutSeconds')} 秒内"
            preview_label = f"预览：{item.get('previewText')}" if item.get("previewText") else "预览：空"
            lines.append(
                f"{item.get('name', '手机浏览器')} [{state_label}] {item.get('transport')} "
                f"{item.get('lastSeenSeconds')} 秒前\n{item.get('address', '')}\n{preview_label}\n{target_label}\n"
            )
        errors = snapshot.get("errors", [])
        if errors:
            lines.append("最近错误：")
            for error in errors[:5]:
                detail = f"{error.get('category', '')} / {error.get('action', '')}".strip(" /")
                chars = f" / {error.get('textChars')} 字符" if error.get("textChars") else ""
                lines.append(
                    f"{error.get('ageSeconds')} 秒前 {detail}{chars}\n"
                    f"{error.get('deviceName') or error.get('deviceId') or error.get('address') or ''}\n"
                    f"{error.get('message', '')}\n"
                )
        hints = network.get("hints", [])
        if hints:
            lines.append("网络诊断：")
            lines.extend(str(hint) for hint in hints)
        devices_text.configure(state="normal")
        devices_text.delete("1.0", "end")
        devices_text.insert("1.0", "\n".join(lines) if lines else "还没有手机连接。")
        devices_text.configure(state="disabled")
        if schedule_next:
            root.after(1500, lambda: refresh(True))

    def close() -> None:
        choice = messagebox.askyesnocancel(
            "关闭窗口",
            "选择“是”会停止服务并退出；选择“否”会隐藏窗口并继续运行。"
        )
        if choice is True:
            exit_app()
        elif choice is False:
            hide_window()

    def process_tray_actions() -> None:
        while True:
            try:
                action = tray_actions.get_nowait()
            except queue.Empty:
                break
            if action == "toggle":
                toggle_window()
            elif action == "copy":
                copy_url()
            elif action == "open":
                open_desktop_page()
            elif action == "pause":
                toggle_pause()
            elif action == "exit":
                exit_app()
                return
        root.after(200, process_tray_actions)

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(200, process_tray_actions)
    refresh(True)
    root.mainloop()


def run_gui(
    server: ThreadingHTTPServer,
    config: ServerConfig,
    state: ServerState,
    phone_url: str,
    desktop_url: str,
) -> None:
    try:
        from phone_voice_gui import run_modern_gui
    except ImportError as exc:
        print(f"Modern GUI unavailable ({exc}); falling back to Tkinter.", file=sys.stderr)
        run_legacy_gui(server, config, state, phone_url, desktop_url)
        return

    def snapshot_payload() -> dict[str, Any]:
        cleanup_stale_targets(config)
        snapshot = state.snapshot()
        return {
            "snapshot": snapshot,
            "network": network_diagnostics(server.server_address[0], server.server_address[1], config.token, snapshot),
        }

    def reset_token() -> dict[str, Any]:
        if not config.token:
            raise InputError("当前已关闭 token 校验，无需重新生成连接码。")
        payload = handle_token_reset(config, server.server_address[0], server.server_address[1])
        phone_urls = [str(url) for url in payload.get("phoneUrls") or []]
        if phone_urls:
            save_qr_pngs(phone_urls)
        return payload

    def toggle_pause() -> bool:
        paused = not state.is_paused()
        handle_pause(config, paused)
        return paused

    def release_targets() -> dict[str, Any]:
        return handle_target_release_all(config)

    def test_target() -> dict[str, Any]:
        snapshot = state.snapshot()
        target_device = next((item for item in snapshot.get("devices", []) if item.get("targetLocked")), None)
        if not target_device:
            raise InputError("没有锁定目标，请先在电脑输入框放置光标并从手机开始输入。")
        payload = handle_test_paste(config, str(target_device.get("id", "")), undo_after=True)
        payload["message"] = "测试完成，已尝试撤销测试文本。" if payload.get("undoResult") else "测试文本已写入。"
        return payload

    def preview_device() -> dict[str, Any] | None:
        devices = state.snapshot().get("devices", [])
        predicates = (
            lambda item: item.get("active") and item.get("previewChars"),
            lambda item: item.get("targetLocked") and item.get("previewChars"),
            lambda item: item.get("connected") and item.get("previewChars"),
            lambda item: item.get("previewChars"),
        )
        for predicate in predicates:
            found = next((item for item in devices if predicate(item)), None)
            if found:
                return found
        return None

    def send_preview() -> dict[str, Any]:
        device = preview_device()
        if not device:
            raise InputError("没有可发送的手机预览。")
        if not device.get("targetLocked"):
            raise InputError("当前手机没有锁定目标。")
        return handle_preview_send(config, str(device.get("id", "")))

    def clear_preview() -> dict[str, Any]:
        device = preview_device()
        if not device:
            raise InputError("没有可清空的手机预览。")
        return handle_preview_clear(config, str(device.get("id", "")))

    def restore_defaults() -> dict[str, Any]:
        return handle_settings_update(
            config,
            {
                "clipboardProtect": True,
                "nativeWrite": True,
                "targetClickRestore": True,
                "foregroundRestore": True,
                "returnPreviousForeground": False,
                "writeMethod": DEFAULT_WRITE_METHOD,
                "targetLockTimeoutSeconds": DEFAULT_TARGET_LOCK_TIMEOUT_SECONDS,
                "autoFinishDelayMs": DEFAULT_AUTO_FINISH_DELAY_MS,
                "tailRevisionMaxChars": DEFAULT_TAIL_REVISION_MAX_CHARS,
                "defaultInputMode": DEFAULT_INPUT_MODE,
                "defaultSyncSpeed": DEFAULT_SYNC_SPEED,
            },
        )

    bridge: dict[str, Callable[..., Any]] = {
        "snapshot": snapshot_payload,
        "settings": state.settings_snapshot,
        "update_settings": lambda data: handle_settings_update(config, data),
        "restore_defaults": restore_defaults,
        "reset_token": reset_token,
        "toggle_pause": toggle_pause,
        "release_targets": release_targets,
        "test_target": test_target,
        "send_preview": send_preview,
        "clear_preview": clear_preview,
        "shutdown": server.shutdown,
    }
    run_modern_gui(APP_NAME, APP_VERSION, phone_url, desktop_url, bridge)

class WindowsTrayIcon:
    def __init__(
        self,
        title: str,
        actions: "queue.Queue[str]",
        paused_provider: Any,
    ) -> None:
        self.title = title[:127]
        self.actions = actions
        self.paused_provider = paused_provider
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._available = False
        self._hwnd = 0
        self._wndproc: Any = None
        self.error = ""

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> bool:
        if sys.platform != "win32":
            self.error = "not_windows"
            return False
        self._thread = threading.Thread(target=self._run, name="phone-voice-tray", daemon=True)
        self._thread.start()
        self._ready.wait(2.0)
        return self._available

    def stop(self) -> None:
        if not self._hwnd:
            return
        try:
            ctypes.windll.user32.PostMessageW(ctypes.c_void_p(self._hwnd), 0x0010, 0, 0)
        except Exception:
            pass

    def _enqueue(self, action: str) -> None:
        self.actions.put(action)

    def _run(self) -> None:
        try:
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            kernel32 = ctypes.windll.kernel32

            WM_CLOSE = 0x0010
            WM_DESTROY = 0x0002
            WM_COMMAND = 0x0111
            WM_RBUTTONUP = 0x0205
            WM_LBUTTONDBLCLK = 0x0203
            WM_TRAYICON = 0x8000 + 23
            NIM_ADD = 0x00000000
            NIM_DELETE = 0x00000002
            NIF_MESSAGE = 0x00000001
            NIF_ICON = 0x00000002
            NIF_TIP = 0x00000004
            IDI_APPLICATION = 32512
            MF_STRING = 0x00000000
            MF_SEPARATOR = 0x00000800
            TPM_RIGHTBUTTON = 0x00000002
            CMD_TOGGLE = 1001
            CMD_COPY = 1002
            CMD_OPEN = 1003
            CMD_PAUSE = 1004
            CMD_EXIT = 1005

            LRESULT = ctypes.c_ssize_t
            WPARAM_T = ctypes.c_size_t
            LPARAM_T = ctypes.c_ssize_t

            WNDPROC = ctypes.WINFUNCTYPE(
                LRESULT,
                wintypes.HWND,
                wintypes.UINT,
                WPARAM_T,
                LPARAM_T,
            )
            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM_T, LPARAM_T]
            user32.DefWindowProcW.restype = LRESULT

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", wintypes.UINT),
                    ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE),
                    ("hbrBackground", wintypes.HANDLE),
                    ("lpszMenuName", wintypes.LPCWSTR),
                    ("lpszClassName", wintypes.LPCWSTR),
                ]

            class NOTIFYICONDATAW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("hWnd", wintypes.HWND),
                    ("uID", wintypes.UINT),
                    ("uFlags", wintypes.UINT),
                    ("uCallbackMessage", wintypes.UINT),
                    ("hIcon", wintypes.HICON),
                    ("szTip", ctypes.c_wchar * 128),
                ]

            def add_menu_item(menu: Any, command_id: int, label: str) -> None:
                user32.AppendMenuW(menu, MF_STRING, command_id, label)

            def show_menu(hwnd: Any) -> None:
                point = wintypes.POINT()
                user32.GetCursorPos(ctypes.byref(point))
                menu = user32.CreatePopupMenu()
                if not menu:
                    return
                add_menu_item(menu, CMD_TOGGLE, "显示/隐藏窗口")
                add_menu_item(menu, CMD_COPY, "复制手机链接")
                add_menu_item(menu, CMD_OPEN, "打开状态页")
                user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                pause_label = "恢复接收" if self.paused_provider() else "暂停接收"
                add_menu_item(menu, CMD_PAUSE, pause_label)
                add_menu_item(menu, CMD_EXIT, "退出")
                user32.SetForegroundWindow(hwnd)
                user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, None)
                user32.DestroyMenu(menu)

            def delete_icon(hwnd: Any) -> None:
                nid = NOTIFYICONDATAW()
                nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
                nid.hWnd = hwnd
                nid.uID = 1
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))

            def to_lparam(value: int) -> Any:
                bits = ctypes.sizeof(ctypes.c_void_p) * 8
                mask = (1 << bits) - 1
                normalized = int(value) & mask
                if normalized >= (1 << (bits - 1)):
                    normalized -= 1 << bits
                return LPARAM_T(normalized)

            def wndproc(hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
                if msg == WM_TRAYICON:
                    tray_event = int(lparam) & 0xFFFF
                    if tray_event == WM_LBUTTONDBLCLK:
                        self._enqueue("toggle")
                    elif tray_event == WM_RBUTTONUP:
                        show_menu(hwnd)
                    return 0
                if msg == WM_COMMAND:
                    command = int(wparam) & 0xFFFF
                    action = {
                        CMD_TOGGLE: "toggle",
                        CMD_COPY: "copy",
                        CMD_OPEN: "open",
                        CMD_PAUSE: "pause",
                        CMD_EXIT: "exit",
                    }.get(command)
                    if action:
                        self._enqueue(action)
                    return 0
                if msg == WM_CLOSE:
                    delete_icon(hwnd)
                    user32.DestroyWindow(hwnd)
                    return 0
                if msg == WM_DESTROY:
                    self._hwnd = 0
                    self._available = False
                    user32.PostQuitMessage(0)
                    return 0
                return int(user32.DefWindowProcW(hwnd, msg, WPARAM_T(int(wparam)), to_lparam(int(lparam))))

            self._wndproc = WNDPROC(wndproc)
            instance = kernel32.GetModuleHandleW(None)
            class_name = f"PhoneVoiceTrayWindow-{id(self)}"
            window_class = WNDCLASSW()
            window_class.lpfnWndProc = self._wndproc
            window_class.hInstance = instance
            window_class.lpszClassName = class_name
            if not user32.RegisterClassW(ctypes.byref(window_class)):
                raise ctypes.WinError()

            hwnd = user32.CreateWindowExW(
                0,
                class_name,
                self.title,
                0,
                0,
                0,
                0,
                0,
                None,
                None,
                instance,
                None,
            )
            if not hwnd:
                raise ctypes.WinError()
            self._hwnd = int(hwnd)
            icon = user32.LoadIconW(None, ctypes.c_void_p(IDI_APPLICATION))
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAYICON
            nid.hIcon = icon
            nid.szTip = self.title
            if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                raise ctypes.WinError()
            self._available = True
            self._ready.set()

            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
        except Exception as exc:
            self.error = str(exc)
            self._ready.set()


HOTKEY_MODIFIERS = {
    "ctrl": 0x0002,
    "control": 0x0002,
    "alt": 0x0001,
    "shift": 0x0004,
    "win": 0x0008,
    "windows": 0x0008,
}


def parse_hotkey_spec(spec: str) -> tuple[int, int, str]:
    parts = [part.strip().lower() for part in spec.replace("-", "+").split("+") if part.strip()]
    if not parts:
        raise ValueError("Hotkey is empty.")
    modifiers = 0
    key = ""
    labels: list[str] = []
    for part in parts:
        if part in HOTKEY_MODIFIERS:
            modifiers |= HOTKEY_MODIFIERS[part]
            label = {"ctrl": "Ctrl", "control": "Ctrl", "alt": "Alt", "shift": "Shift", "win": "Win", "windows": "Win"}[part]
            if label not in labels:
                labels.append(label)
            continue
        if key:
            raise ValueError(f"Hotkey has multiple keys: {key}, {part}")
        key = part
    if not modifiers:
        raise ValueError("Hotkey needs at least one modifier, for example ctrl+alt+p.")
    if not key:
        raise ValueError("Hotkey needs a key, for example ctrl+alt+p.")
    key_map = {
        "space": 0x20,
        "esc": 0x1B,
        "escape": 0x1B,
        "pause": 0x13,
        "break": 0x13,
    }
    if key in key_map:
        vk = key_map[key]
        key_label = "Space" if key == "space" else ("Esc" if key in ("esc", "escape") else "Pause")
    elif len(key) == 1 and key.isalnum():
        vk = ord(key.upper())
        key_label = key.upper()
    elif key.startswith("f") and key[1:].isdigit() and 1 <= int(key[1:]) <= 24:
        vk = 0x70 + int(key[1:]) - 1
        key_label = key.upper()
    else:
        raise ValueError(f"Unsupported hotkey key: {key}")
    return modifiers, vk, "+".join(labels + [key_label])


class WindowsHotkeyListener:
    def __init__(self, spec: str, callback: Any) -> None:
        self.spec = spec
        self.modifiers, self.vk, self.label = parse_hotkey_spec(spec)
        self.callback = callback
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._available = False
        self._thread_id = 0
        self._hotkey_id = (id(self) & 0xBFFF) or 1
        self.error = ""

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> bool:
        if sys.platform != "win32":
            self.error = "not_windows"
            return False
        self._thread = threading.Thread(target=self._run, name="phone-voice-hotkey", daemon=True)
        self._thread.start()
        self._ready.wait(2.0)
        return self._available

    def stop(self) -> None:
        if not self._thread_id:
            return
        try:
            ctypes.windll.user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)  # WM_QUIT
        except Exception:
            pass
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        try:
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentThreadId.argtypes = []
            kernel32.GetCurrentThreadId.restype = ctypes.c_uint
            user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_uint, ctypes.c_uint]
            user32.RegisterHotKey.restype = ctypes.c_int
            user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.UnregisterHotKey.restype = ctypes.c_int

            self._thread_id = int(kernel32.GetCurrentThreadId())
            if not user32.RegisterHotKey(None, self._hotkey_id, self.modifiers, self.vk):
                raise ctypes.WinError()
            self._available = True
            self._ready.set()
            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message == 0x0312 and int(message.wParam) == self._hotkey_id:  # WM_HOTKEY
                    try:
                        self.callback()
                    except Exception as exc:
                        self.error = str(exc)
                else:
                    user32.TranslateMessage(ctypes.byref(message))
                    user32.DispatchMessageW(ctypes.byref(message))
        except Exception as exc:
            self.error = str(exc)
            self._ready.set()
        finally:
            if self._available:
                try:
                    ctypes.windll.user32.UnregisterHotKey(None, self._hotkey_id)
                except Exception:
                    pass
            self._available = False
            self._thread_id = 0


def draw_qr_on_canvas(canvas: Any, text: str, canvas_size: int) -> None:
    modules = make_qr_matrix(text)
    border = 4
    module_count = len(modules) + border * 2
    scale = canvas_size / module_count
    canvas.create_rectangle(0, 0, canvas_size, canvas_size, fill="white", outline="white")
    for row_index, row in enumerate(modules):
        for col_index, dark in enumerate(row):
            if not dark:
                continue
            x1 = (col_index + border) * scale
            y1 = (row_index + border) * scale
            x2 = x1 + scale
            y2 = y1 + scale
            canvas.create_rectangle(x1, y1, x2, y2, fill="#111111", outline="#111111")


def save_qr_png(text: str, path: pathlib.Path = LAST_QR_PATH) -> pathlib.Path:
    path.write_bytes(make_qr_png_bytes(text))
    return path


def save_qr_pngs(urls: list[str]) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for stale_path in PROJECT_DIR.glob("last-phone-qr-*.png"):
        try:
            stale_path.unlink()
        except OSError:
            pass
    for index, url in enumerate(urls, start=1):
        path = PROJECT_DIR / f"last-phone-qr-{index}.png"
        path.write_bytes(make_qr_png_bytes(url))
        paths.append(path)
        if index == 1:
            LAST_QR_PATH.write_bytes(path.read_bytes())
            paths.insert(0, LAST_QR_PATH)
    return paths


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = build_parser().parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0

    token = "" if args.no_token else (args.token or load_or_create_token(reset=args.reset_token))
    state = ServerState()
    persisted_settings = load_runtime_settings(SETTINGS_PATH)
    if persisted_settings:
        update_runtime_settings_from_data(state, persisted_settings)
    settings = state.settings_snapshot()
    injector = WindowsTextInjector(
        dry_run=args.dry_run,
        protect_clipboard=bool(settings["clipboardProtect"]),
        target_click_restore=bool(settings["targetClickRestore"]),
        foreground_restore=bool(settings["foregroundRestore"]),
        return_previous_foreground=bool(settings["returnPreviousForeground"]),
        write_method=str(settings["writeMethod"]),
    )
    config = ServerConfig(token=token, injector=injector, state=state, settings_path=SETTINGS_PATH)
    cli_settings: dict[str, Any] = {}
    if args.no_clipboard_protect:
        cli_settings["clipboardProtect"] = False
    if args.no_target_click_restore:
        cli_settings["targetClickRestore"] = False
    if args.no_foreground_restore:
        cli_settings["foregroundRestore"] = False
    if args.return_previous_foreground:
        cli_settings["returnPreviousForeground"] = True
    if args.target_lock_timeout is not None:
        cli_settings["targetLockTimeoutSeconds"] = args.target_lock_timeout
    if cli_settings:
        settings = update_runtime_settings_from_data(state, cli_settings)
        apply_settings_to_injector(injector, settings)
    handler = make_handler(config)

    try:
        server, bind_failures = create_server(args.host, args.port, handler, strict_port=args.strict_port)
    except OSError as exc:
        print(f"Failed to start server on {args.host}:{args.port}: {exc}", file=sys.stderr)
        if is_retryable_bind_error(exc):
            print("Try another port, for example: .\\start.ps1 -Port 8876", file=sys.stderr)
        return 2

    actual_port = server.server_address[1]
    print(f"{APP_NAME}")
    print(f"Listening on {args.host}:{actual_port}")
    if bind_failures:
        skipped = ", ".join(str(item[0]) for item in bind_failures[:8])
        more = "..." if len(bind_failures) > 8 else ""
        print(f"Skipped unavailable port(s): {skipped}{more}")
    if args.dry_run:
        print("Dry run: clipboard and keyboard injection are disabled.")
    print()
    print("Open one of these URLs on your phone:")
    urls = make_urls(args.host, actual_port, token)
    for url in urls:
        print(f"  {url}")
    if urls:
        desktop_url = make_desktop_url(args.host, actual_port, token)
        print()
        print(f"Desktop status page: {desktop_url}")
        diagnostics = network_diagnostics(args.host, actual_port, token, {"devices": []})
        if diagnostics.get("hints"):
            print()
            print("Connection tips:")
            for hint in diagnostics["hints"]:
                print(f"  - {hint}")
        if not args.no_qr:
            try:
                png_paths = save_qr_pngs(urls)
                print("QR PNG files:")
                for path in png_paths:
                    print(f"  {path}")
                print()
                print("Scan this QR code with your phone. If terminal scanning fails, open one of the PNG files above:")
                print(make_qr_ascii(urls[0]))
            except QrError as exc:
                print(f"QR code unavailable: {exc}")
    print()
    print("Usage: focus the target Windows input box, then send text from the phone page.")
    print("Press Ctrl+C here to stop.")

    hotkey_listener: WindowsHotkeyListener | None = None
    if args.hotkey:
        try:
            def toggle_pause_from_hotkey() -> None:
                paused = not state.is_paused()
                handle_pause(config, paused)
                print(f"Hotkey {hotkey_listener.label if hotkey_listener else args.hotkey}: {'paused' if paused else 'resumed'} receiving.")

            hotkey_listener = WindowsHotkeyListener(args.hotkey, toggle_pause_from_hotkey)
        except ValueError as exc:
            print(f"Invalid hotkey: {exc}", file=sys.stderr)
            server.server_close()
            return 2
        if hotkey_listener.start():
            print(f"Hotkey enabled: {hotkey_listener.label} toggles pause/resume.")
        else:
            message = hotkey_listener.error or "unavailable"
            state.record_error("hotkey", message, action=args.hotkey)
            print(f"Hotkey unavailable ({args.hotkey}): {message}", file=sys.stderr)

    if args.gui:
        if not urls:
            print("GUI requires at least one phone URL.", file=sys.stderr)
            if hotkey_listener:
                hotkey_listener.stop()
            server.server_close()
            return 2
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            run_gui(server, config, state, urls[0], desktop_url)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            server.shutdown()
            server.server_close()
            return 2
        finally:
            if hotkey_listener:
                hotkey_listener.stop()
            server.shutdown()
            server.server_close()
        return 0

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        if hotkey_listener:
            hotkey_listener.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
