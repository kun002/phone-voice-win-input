"""Modern PySide6 desktop control center for Phone Voice to Windows Input."""

from __future__ import annotations

import html
import os
from typing import Any, Callable

from PySide6.QtCore import QTimer, Qt, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QFont, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QStyle,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from qr_util import make_qr_png_bytes


Bridge = dict[str, Callable[..., Any]]


APP_STYLE = """
QWidget {
    color: #1d2733;
    background: #f7f8fa;
    font-family: "Microsoft YaHei UI", "Segoe UI";
    font-size: 9.5pt;
}
QMainWindow, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {
    background: #f7f8fa;
}
QFrame#Sidebar {
    background: #ffffff;
    border-right: 1px solid #e2e6eb;
}
QLabel#Brand {
    color: #1d2733;
    font-size: 13pt;
    font-weight: 700;
    background: transparent;
}
QLabel#BrandSubtle, QLabel#SidebarVersion, QLabel#Muted, QLabel#PageSubtitle {
    color: #748092;
    background: transparent;
}
QPushButton#NavButton {
    background: transparent;
    color: #465365;
    border: none;
    border-radius: 6px;
    padding: 8px 10px;
    text-align: left;
    font-weight: 600;
}
QPushButton#NavButton:hover { background: #f0f3f5; }
QPushButton#NavButton:checked {
    background: #e2f0ec;
    color: #226557;
}
QPushButton#ExitButton {
    background: transparent;
    color: #8b4545;
    border: none;
    border-radius: 6px;
    padding: 8px 10px;
    text-align: left;
}
QPushButton#ExitButton:hover { background: #faeeee; }
QLabel#PageTitle {
    font-size: 16pt;
    font-weight: 700;
    color: #1d2733;
}
QFrame#Card {
    background: #ffffff;
    border: 1px solid #e0e5ea;
    border-radius: 7px;
}
QFrame#Card QLabel { background: transparent; }
QLabel#SectionTitle, QLabel#CardTitle {
    color: #687588;
    font-size: 9pt;
    font-weight: 600;
    background: transparent;
}
QLabel#MetricValue {
    color: #1d2733;
    font-size: 11pt;
    font-weight: 700;
    background: transparent;
}
QLabel#StatusChip {
    background: #e2f0ec;
    color: #226557;
    border: 1px solid #c3dfd7;
    border-radius: 7px;
    padding: 4px 8px;
    font-weight: 600;
}
QLabel#StatusChip[status="warn"] {
    background: #fff3dc;
    color: #795718;
    border-color: #edd59f;
}
QLabel#StatusChip[status="error"] {
    background: #f9e3e3;
    color: #842d2d;
    border-color: #e8bcbc;
}
QPushButton {
    background: #ffffff;
    border: 1px solid #d2d8df;
    border-radius: 6px;
    padding: 7px 11px;
    font-weight: 600;
}
QPushButton:hover { background: #f2f5f7; border-color: #adb8c5; }
QPushButton:pressed { background: #e8ecef; }
QPushButton#PrimaryButton {
    background: #347b6d;
    color: #ffffff;
    border-color: #347b6d;
}
QPushButton#PrimaryButton:hover { background: #2c6a5e; }
QPushButton#DangerButton { color: #9a3d3d; border-color: #e3c2c2; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background: #ffffff;
    border: 1px solid #d2d8df;
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: #347b6d;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: #347b6d; }
QCheckBox { spacing: 7px; background: transparent; }
QCheckBox::indicator { width: 16px; height: 16px; }
QScrollBar:vertical { background: transparent; width: 9px; margin: 2px; }
QScrollBar::handle:vertical { background: #c0c8d1; border-radius: 4px; min-height: 26px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class ModernMainWindow(QMainWindow):
    def __init__(
        self,
        app_name: str,
        app_version: str,
        phone_url: str,
        desktop_url: str,
        bridge: Bridge,
    ) -> None:
        super().__init__()
        self.app_name = app_name
        self.app_version = app_version
        self.phone_url = phone_url
        self.desktop_url = desktop_url
        self.bridge = bridge
        self.allow_close = False
        self.nav_buttons: list[QPushButton] = []
        self.status_chips: list[QLabel] = []

        self.setWindowTitle(app_name)
        self.resize(780, 560)
        self.setMinimumSize(700, 500)
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self._build_ui()
        self._build_tray()
        self._load_settings()
        self.refresh()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(1500)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(154)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(12, 16, 12, 12)
        side_layout.setSpacing(4)

        brand = QLabel("手机语音输入")
        brand.setObjectName("Brand")
        brand_subtle = QLabel("Windows 小工具")
        brand_subtle.setObjectName("BrandSubtle")
        side_layout.addWidget(brand)
        side_layout.addWidget(brand_subtle)
        side_layout.addSpacing(14)

        self.pages = QStackedWidget()
        page_specs = [
            ("主页", self._build_home_page()),
            ("设置", self._build_settings_page()),
            ("日志", self._build_diagnostics_page()),
        ]
        for index, (label, page) in enumerate(page_specs):
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, page_index=index: self._select_page(page_index))
            self.nav_buttons.append(button)
            side_layout.addWidget(button)
            self.pages.addWidget(page)

        side_layout.addStretch(1)
        version = QLabel(self.app_version)
        version.setObjectName("SidebarVersion")
        side_layout.addWidget(version)
        exit_button = QPushButton("退出服务")
        exit_button.setObjectName("ExitButton")
        exit_button.clicked.connect(self.exit_application)
        side_layout.addWidget(exit_button)

        root.addWidget(sidebar)
        root.addWidget(self.pages, 1)
        self._select_page(0)

    def _page(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(11)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("PageSubtitle")
        subtitle_label.setWordWrap(True)
        title_box.addWidget(title_label)
        title_box.addWidget(subtitle_label)
        header.addLayout(title_box, 1)
        status_chip = QLabel("服务运行中")
        status_chip.setObjectName("StatusChip")
        self.status_chips.append(status_chip)
        header.addWidget(status_chip, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)
        return page, layout

    def _build_home_page(self) -> QWidget:
        page, layout = self._page("手机语音输入", "扫码后直接使用手机输入法麦克风，文字会同步到当前目标。")
        body = QHBoxLayout()
        body.setSpacing(12)

        qr_card = QFrame()
        qr_card.setObjectName("Card")
        qr_card.setFixedWidth(216)
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setContentsMargins(12, 12, 12, 12)
        qr_layout.setSpacing(8)
        qr_title = QLabel("手机扫码连接")
        qr_title.setObjectName("SectionTitle")
        self.qr_label = QLabel()
        self.qr_label.setFixedSize(190, 190)
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_layout.addWidget(qr_title)
        qr_layout.addWidget(self.qr_label, 0, Qt.AlignmentFlag.AlignCenter)
        qr_hint = QLabel("手机和电脑需在同一网络")
        qr_hint.setObjectName("Muted")
        qr_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_layout.addWidget(qr_hint)
        qr_layout.addStretch(1)
        body.addWidget(qr_card, 0, Qt.AlignmentFlag.AlignTop)

        right = QVBoxLayout()
        right.setSpacing(10)

        summary_card = QFrame()
        summary_card.setObjectName("Card")
        summary_layout = QGridLayout(summary_card)
        summary_layout.setContentsMargins(14, 12, 14, 12)
        summary_layout.setHorizontalSpacing(14)
        summary_layout.setVerticalSpacing(5)
        for column, title in enumerate(("手机", "目标", "写入")):
            label = QLabel(title)
            label.setObjectName("SectionTitle")
            summary_layout.addWidget(label, 0, column)
        self.phone_status_value = QLabel("未连接")
        self.target_status_value = QLabel("未锁定")
        self.method_status_value = QLabel("Unicode")
        for column, value_label in enumerate((self.phone_status_value, self.target_status_value, self.method_status_value)):
            value_label.setObjectName("MetricValue")
            value_label.setWordWrap(True)
            summary_layout.addWidget(value_label, 1, column)
            summary_layout.setColumnStretch(column, 1)
        self.activity_label = QLabel("等待手机连接。")
        self.activity_label.setObjectName("Muted")
        self.activity_label.setWordWrap(True)
        summary_layout.addWidget(self.activity_label, 2, 0, 1, 3)
        right.addWidget(summary_card)

        connection_card = QFrame()
        connection_card.setObjectName("Card")
        connection_layout = QVBoxLayout(connection_card)
        connection_layout.setContentsMargins(14, 11, 14, 11)
        connection_layout.setSpacing(7)
        connection_title = QLabel("连接地址")
        connection_title.setObjectName("SectionTitle")
        connection_layout.addWidget(connection_title)
        self.url_edit = QLineEdit(self.phone_url)
        self.url_edit.setReadOnly(True)
        connection_layout.addWidget(self.url_edit)
        connection_buttons = QHBoxLayout()
        copy_button = QPushButton("复制链接")
        copy_button.setObjectName("PrimaryButton")
        copy_button.clicked.connect(self.copy_phone_url)
        reset_button = QPushButton("换连接码")
        reset_button.clicked.connect(self.reset_token)
        connection_buttons.addWidget(copy_button)
        connection_buttons.addWidget(reset_button)
        connection_layout.addLayout(connection_buttons)
        right.addWidget(connection_card)

        actions_card = QFrame()
        actions_card.setObjectName("Card")
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setContentsMargins(14, 11, 14, 11)
        actions_layout.setSpacing(7)
        actions_title = QLabel("操作")
        actions_title.setObjectName("SectionTitle")
        actions_layout.addWidget(actions_title)
        action_grid = QGridLayout()
        action_grid.setSpacing(6)
        self.pause_button = QPushButton("暂停接收")
        self.pause_button.clicked.connect(self.toggle_pause)
        send_button = QPushButton("发送预览")
        send_button.setObjectName("PrimaryButton")
        send_button.clicked.connect(self.send_preview)
        clear_button = QPushButton("清空缓存")
        clear_button.clicked.connect(self.clear_preview)
        release_button = QPushButton("释放目标")
        release_button.clicked.connect(self.release_targets)
        test_button = QPushButton("测试目标")
        test_button.clicked.connect(self.test_target)
        open_button = QPushButton("状态页")
        open_button.clicked.connect(self.open_desktop_page)
        for index, button in enumerate((self.pause_button, send_button, clear_button, release_button, test_button, open_button)):
            action_grid.addWidget(button, index // 3, index % 3)
            action_grid.setColumnStretch(index % 3, 1)
        actions_layout.addLayout(action_grid)
        right.addWidget(actions_card)
        right.addStretch(1)
        body.addLayout(right, 1)
        layout.addLayout(body, 1)
        self._update_qr()
        return page
    def _build_settings_page(self) -> QWidget:
        page, layout = self._page("设置", "这些选项只保存在电脑端，保存后立即生效。")
        settings_card = QFrame()
        settings_card.setObjectName("Card")
        card_layout = QHBoxLayout(settings_card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(22)

        behavior = QVBoxLayout()
        behavior.setSpacing(9)
        behavior_title = QLabel("写入行为")
        behavior_title.setObjectName("SectionTitle")
        behavior.addWidget(behavior_title)
        self.clipboard_check = QCheckBox("保护文本剪贴板")
        self.native_check = QCheckBox("原生控件后台写入")
        self.click_check = QCheckBox("恢复记录的输入位置")
        self.foreground_check = QCheckBox("必要时置前目标窗口")
        self.return_check = QCheckBox("写入后回原窗口（实验）")
        for control in (
            self.clipboard_check,
            self.native_check,
            self.click_check,
            self.foreground_check,
            self.return_check,
        ):
            behavior.addWidget(control)
        behavior.addStretch(1)
        card_layout.addLayout(behavior, 1)

        parameters = QVBoxLayout()
        parameters.setSpacing(8)
        parameters_title = QLabel("同步参数")
        parameters_title.setObjectName("SectionTitle")
        parameters.addWidget(parameters_title)
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(9)
        self.method_combo = QComboBox()
        self.method_combo.addItem("Unicode 直打", "unicode")
        self.method_combo.addItem("剪贴板 Ctrl+V", "clipboard")
        self.lock_spin = QSpinBox()
        self.lock_spin.setRange(0, 60)
        self.lock_spin.setSuffix(" 秒")
        self.lock_spin.setSpecialValueText("关闭")
        self.finish_spin = QSpinBox()
        self.finish_spin.setRange(0, 60)
        self.finish_spin.setSuffix(" 秒")
        self.finish_spin.setSpecialValueText("关闭")
        self.tail_combo = QComboBox()
        for value in (0, 20, 50, 100, 200, 500):
            self.tail_combo.addItem("关闭" if value == 0 else f"{value} 字", value)
        form.addRow("写入方式", self.method_combo)
        form.addRow("目标锁", self.lock_spin)
        form.addRow("自动收尾", self.finish_spin)
        form.addRow("尾部纠错", self.tail_combo)
        parameters.addLayout(form)
        parameters.addStretch(1)
        card_layout.addLayout(parameters, 1)
        layout.addWidget(settings_card)

        footer = QHBoxLayout()
        hint = QLabel("0 秒表示关闭对应超时")
        hint.setObjectName("Muted")
        footer.addWidget(hint)
        footer.addStretch(1)
        defaults_button = QPushButton("恢复默认")
        defaults_button.clicked.connect(self.restore_defaults)
        save_button = QPushButton("保存")
        save_button.setObjectName("PrimaryButton")
        save_button.clicked.connect(self.save_settings)
        footer.addWidget(defaults_button)
        footer.addWidget(save_button)
        layout.addLayout(footer)
        layout.addStretch(1)
        return page
    def _build_diagnostics_page(self) -> QWidget:
        page, layout = self._page("设备与日志", "查看手机连接、锁定目标、网络诊断和最近错误。")
        toolbar = QHBoxLayout()
        toolbar.addStretch(1)
        refresh_button = QPushButton("立即刷新")
        refresh_button.clicked.connect(self.refresh)
        copy_button = QPushButton("复制日志")
        copy_button.clicked.connect(self.copy_diagnostics)
        toolbar.addWidget(refresh_button)
        toolbar.addWidget(copy_button)
        layout.addLayout(toolbar)
        self.diagnostics_edit = QPlainTextEdit()
        self.diagnostics_edit.setReadOnly(True)
        self.diagnostics_edit.setFont(QFont("Microsoft YaHei UI", 9))
        self.diagnostics_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.diagnostics_edit, 1)
        return page

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self.windowIcon(), self)
        menu = QMenu()
        show_action = menu.addAction("显示窗口")
        show_action.triggered.connect(self.show_from_tray)
        self.tray_pause_action = menu.addAction("暂停接收")
        self.tray_pause_action.triggered.connect(self.toggle_pause)
        copy_action = menu.addAction("复制手机链接")
        copy_action.triggered.connect(self.copy_phone_url)
        open_action = menu.addAction("打开状态页")
        open_action.triggered.connect(self.open_desktop_page)
        menu.addSeparator()
        exit_action = menu.addAction("退出服务")
        exit_action.triggered.connect(self.exit_application)
        self.tray.setContextMenu(menu)
        self.tray.setToolTip(self.app_name)
        self.tray.activated.connect(self._tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _select_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for button_index, button in enumerate(self.nav_buttons):
            button.setChecked(button_index == index)

    def _call(self, name: str, *args: Any) -> Any:
        callback = self.bridge.get(name)
        if callback is None:
            raise RuntimeError(f"GUI bridge callback is missing: {name}")
        return callback(*args)

    def _notify(self, message: str, error: bool = False) -> None:
        self.statusBar().setStyleSheet("color: #9a3131;" if error else "color: #245d50;")
        self.statusBar().showMessage(message, 7000)

    def _update_qr(self) -> None:
        try:
            pixmap = QPixmap()
            if not pixmap.loadFromData(make_qr_png_bytes(self.phone_url), "PNG"):
                raise RuntimeError("二维码图像加载失败")
            self.qr_label.setPixmap(
                pixmap.scaled(
                    self.qr_label.size(),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.FastTransformation,
                )
            )
        except Exception as exc:
            self.qr_label.setText(f"二维码生成失败\n{html.escape(str(exc))}")

    def _load_settings(self) -> None:
        settings = self._call("settings")
        self.clipboard_check.setChecked(bool(settings.get("clipboardProtect", True)))
        self.native_check.setChecked(settings.get("nativeWrite") is not False)
        self.click_check.setChecked(settings.get("targetClickRestore") is not False)
        self.foreground_check.setChecked(settings.get("foregroundRestore") is not False)
        self.return_check.setChecked(bool(settings.get("returnPreviousForeground")))
        method_index = self.method_combo.findData(str(settings.get("writeMethod", "unicode")))
        self.method_combo.setCurrentIndex(max(0, method_index))
        self.lock_spin.setValue(int(settings.get("targetLockTimeoutSeconds", 60)))
        self.finish_spin.setValue(max(0, int(settings.get("autoFinishDelayMs", 15000))) // 1000)
        tail_index = self.tail_combo.findData(int(settings.get("tailRevisionMaxChars", 200)))
        self.tail_combo.setCurrentIndex(max(0, tail_index))

    def save_settings(self) -> None:
        payload = {
            "clipboardProtect": self.clipboard_check.isChecked(),
            "nativeWrite": self.native_check.isChecked(),
            "targetClickRestore": self.click_check.isChecked(),
            "foregroundRestore": self.foreground_check.isChecked(),
            "returnPreviousForeground": self.return_check.isChecked(),
            "writeMethod": self.method_combo.currentData(),
            "targetLockTimeoutSeconds": self.lock_spin.value(),
            "autoFinishDelayMs": self.finish_spin.value() * 1000,
            "tailRevisionMaxChars": self.tail_combo.currentData(),
        }
        try:
            self._call("update_settings", payload)
            self._load_settings()
            self._notify("设置已保存并立即生效。")
            self.refresh()
        except Exception as exc:
            self._notify(f"保存设置失败：{exc}", True)

    def restore_defaults(self) -> None:
        answer = QMessageBox.question(self, "恢复推荐默认", "恢复推荐默认设置并立即保存？")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._call("restore_defaults")
            self._load_settings()
            self._notify("已恢复推荐默认设置。")
            self.refresh()
        except Exception as exc:
            self._notify(f"恢复默认失败：{exc}", True)

    def copy_phone_url(self) -> None:
        QApplication.clipboard().setText(self.phone_url)
        self._notify("手机连接地址已复制。")

    def open_desktop_page(self) -> None:
        QDesktopServices.openUrl(QUrl(self.desktop_url))

    def reset_token(self) -> None:
        answer = QMessageBox.question(
            self,
            "重新生成连接码",
            "旧手机链接会立即失效，当前锁定目标也会释放。继续？",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self._call("reset_token")
            phone_urls = result.get("phoneUrls") or []
            if phone_urls:
                self.phone_url = str(phone_urls[0])
            self.desktop_url = str(result.get("desktopUrl") or self.desktop_url)
            self.url_edit.setText(self.phone_url)
            self._update_qr()
            self._notify("连接码已更新，请让手机重新扫码。")
        except Exception as exc:
            self._notify(f"重新生成连接码失败：{exc}", True)

    def toggle_pause(self) -> None:
        try:
            paused = bool(self._call("toggle_pause"))
            self._notify("已暂停接收。" if paused else "已恢复接收。")
            self.refresh()
        except Exception as exc:
            self._notify(f"切换接收状态失败：{exc}", True)

    def release_targets(self) -> None:
        try:
            result = self._call("release_targets")
            self._notify(f"已释放 {result.get('targetReleasedCount', 0)} 个目标。")
            self.refresh()
        except Exception as exc:
            self._notify(f"释放目标失败：{exc}", True)

    def test_target(self) -> None:
        try:
            result = self._call("test_target")
            self._notify(str(result.get("message") or "目标测试完成。"))
            self.refresh()
        except Exception as exc:
            self._notify(f"测试锁定目标失败：{exc}", True)

    def copy_diagnostics(self) -> None:
        QApplication.clipboard().setText(self.diagnostics_edit.toPlainText())
        self._notify("设备与日志已复制。")

    def send_preview(self) -> None:
        try:
            self._call("send_preview")
            self._notify("当前手机预览已发送，手机缓存会自动清空。")
            self.refresh()
        except Exception as exc:
            self._notify(f"发送预览失败：{exc}", True)

    def clear_preview(self) -> None:
        try:
            self._call("clear_preview")
            self._notify("手机缓存已清空。")
            self.refresh()
        except Exception as exc:
            self._notify(f"清空手机缓存失败：{exc}", True)

    def _set_status_chips(self, text: str, status: str) -> None:
        for chip in self.status_chips:
            chip.setText(text)
            chip.setProperty("status", status)
            chip.style().unpolish(chip)
            chip.style().polish(chip)

    def refresh(self) -> None:
        try:
            payload = self._call("snapshot")
            snapshot = payload.get("snapshot", {})
            network = payload.get("network", {})
            devices = snapshot.get("devices", [])
            online = [item for item in devices if item.get("connected")]
            locked = [item for item in devices if item.get("targetLocked")]
            paused = bool(snapshot.get("receivingPaused"))
            settings = snapshot.get("settings", {})
            latest = snapshot.get("latestResult") or {}
            method = settings.get("writeMethod", "unicode")
            method_text = "Unicode 直打" if method == "unicode" else "剪贴板 Ctrl+V"

            self._set_status_chips("接收已暂停" if paused else "服务运行中", "warn" if paused else "ok")
            self.pause_button.setText("恢复接收" if paused else "暂停接收")
            self.tray_pause_action.setText("恢复接收" if paused else "暂停接收")

            self.phone_status_value.setText(f"{len(online)} 台在线" if online else "未连接")
            if locked:
                target_title = str(locked[0].get("targetTitle") or "输入框")
                self.target_status_value.setText(target_title if len(target_title) <= 12 else target_title[:11] + "…")
            else:
                self.target_status_value.setText("未锁定")
            self.method_status_value.setText("Unicode" if method == "unicode" else "Ctrl+V")
            latest_method = str(latest.get("method") or "尚未写入")
            active_name = snapshot.get("activeDeviceName") or snapshot.get("activeDeviceId")
            self.activity_label.setText(
                f"设备：{active_name or '无'}  ·  最近：{snapshot.get('latestChars', 0)} 字  ·  {latest_method}"
            )

            lines: list[str] = []
            for item in devices:
                state_label = "在线" if item.get("connected") else "离线"
                if item.get("active"):
                    state_label += " / 激活"
                lines.append(
                    f"{item.get('name', '手机浏览器')} [{state_label}] {item.get('transport', '')}\n"
                    f"地址：{item.get('address', '')}  最近：{item.get('lastSeenSeconds', 0)} 秒前\n"
                    f"预览：{item.get('previewText') or '空'}\n"
                    f"目标：{item.get('targetTitle') if item.get('targetLocked') else '未锁定'}\n"
                )
            errors = snapshot.get("errors", [])
            if errors:
                lines.append("最近错误")
                lines.append("-" * 48)
                for error in errors[:8]:
                    lines.append(
                        f"{error.get('ageSeconds', 0)} 秒前 | {error.get('category', '')} | {error.get('action', '')}\n"
                        f"{error.get('message', '')}\n"
                    )
            hints = network.get("hints", [])
            if hints:
                lines.append("网络诊断")
                lines.append("-" * 48)
                lines.extend(str(hint) for hint in hints)
            self.diagnostics_edit.setPlainText("\n".join(lines) if lines else "还没有手机连接，也没有错误记录。")
        except Exception as exc:
            self._set_status_chips("状态读取失败", "error")
            self._notify(f"刷新状态失败：{exc}", True)

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_from_tray()

    def exit_application(self) -> None:
        answer = QMessageBox.question(self, "退出服务", "退出后手机将无法继续向电脑输入。确认退出？")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.allow_close = True
        self.refresh_timer.stop()
        self.tray.hide()
        try:
            self._call("shutdown")
        finally:
            QApplication.instance().quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.allow_close:
            event.accept()
            return
        if self.tray.isVisible():
            self.hide()
            self.tray.showMessage(
                self.app_name,
                "窗口已隐藏到系统托盘，手机输入服务仍在运行。",
                QSystemTrayIcon.MessageIcon.Information,
                2500,
            )
            event.ignore()
            return
        answer = QMessageBox.question(self, "退出服务", "系统托盘不可用，关闭窗口将停止服务。确认退出？")
        if answer == QMessageBox.StandardButton.Yes:
            self.allow_close = True
            try:
                self._call("shutdown")
            finally:
                event.accept()
        else:
            event.ignore()


def run_modern_gui(
    app_name: str,
    app_version: str,
    phone_url: str,
    desktop_url: str,
    bridge: Bridge,
) -> None:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName(app_name)
    app.setApplicationVersion(app_version)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(APP_STYLE)
    window = ModernMainWindow(app_name, app_version, phone_url, desktop_url, bridge)
    window.show()
    smoke_ms = max(0, int(os.environ.get("PHONE_VOICE_GUI_SMOKE_MS", "0") or 0))
    if smoke_ms:
        def finish_smoke_test() -> None:
            window.allow_close = True
            window.tray.hide()
            window.close()
            app.exit(0)

        QTimer.singleShot(smoke_ms, finish_smoke_test)
    app.exec()