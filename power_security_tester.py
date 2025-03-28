import sys
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QComboBox, QLineEdit, QPushButton, 
                            QTextEdit, QLabel, QSpinBox, QMessageBox, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
                            QListWidget, QFrame, QButtonGroup)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor
import pymodbus.client
from scapy.all import *
import nmap
import threading
import queue
import time
from config import DEVICE_CONFIGS, TEST_TYPES, TEST_CONFIG, LOG_CONFIG, EXPLOIT_CONFIG
from exploit_module import ExploitModule

# 配置日志
logging.basicConfig(
    level=getattr(logging, LOG_CONFIG["level"]),
    format=LOG_CONFIG["format"],
    filename=LOG_CONFIG["file"]
)
logger = logging.getLogger(__name__)

class TestWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    exploit_result = pyqtSignal(dict)

    def __init__(self, device_type, device_model, test_type, target_ip, target_port, threads):
        super().__init__()
        self.device_type = device_type
        self.device_model = device_model
        self.test_type = test_type
        self.target_ip = target_ip
        self.target_port = target_port
        self.threads = threads
        self.is_running = True

    def run(self):
        try:
            self.progress.emit(f"开始测试 {self.device_type} - {self.device_model}")
            self.progress.emit(f"目标: {self.target_ip}:{self.target_port}")
            
            if self.test_type == "端口扫描":
                self.port_scan()
            elif self.test_type == "协议测试":
                self.protocol_test()
            elif self.test_type == "漏洞扫描":
                self.vulnerability_scan()
            elif self.test_type == "配置检查":
                self.config_check()
            elif self.test_type == "漏洞利用":
                self.run_exploits()
            
            self.progress.emit("测试完成")
            self.finished.emit()
            
        except Exception as e:
            self.error.emit(str(e))

    def run_exploits(self):
        """运行漏洞利用测试"""
        self.progress.emit("\n开始漏洞利用测试...")
        exploit_module = ExploitModule(self.target_ip, self.target_port, self.device_type, self.device_model)
        results = exploit_module.run_all_exploits()
        
        for result in results:
            self.progress.emit(f"\n发现漏洞: {result['type']}")
            self.progress.emit(f"描述: {result['description']}")
            self.progress.emit(f"严重程度: {result['severity']}")
            self.progress.emit(f"详细信息: {result['details']}")
            self.exploit_result.emit(result)

    def port_scan(self):
        self.progress.emit("执行端口扫描...")
        nm = nmap.PortScanner()
        device_config = DEVICE_CONFIGS[self.device_type]
        ports = ','.join(map(str, device_config["ports"]))
        nm.scan(self.target_ip, ports, arguments='-sV -sS -sC')
        
        for host in nm.all_hosts():
            self.progress.emit(f"\n主机 {host} 扫描结果:")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    self.progress.emit(f"端口 {port}/{proto}: {state} ({service})")

    def protocol_test(self):
        self.progress.emit("\n执行协议测试...")
        device_config = DEVICE_CONFIGS[self.device_type]
        for protocol in device_config["protocols"]:
            self.progress.emit(f"\n测试 {protocol} 协议...")
            if protocol == "Modbus":
                try:
                    client = pymodbus.client.ModbusTcpClient(self.target_ip, port=self.target_port)
                    client.connect()
                    if client.is_socket_open():
                        self.progress.emit("Modbus协议连接成功")
                        result = client.read_holding_registers(0, 10)
                        if result.isError():
                            self.progress.emit("读取寄存器失败")
                        else:
                            self.progress.emit(f"寄存器数据: {result.registers}")
                    client.close()
                except Exception as e:
                    self.progress.emit(f"Modbus协议测试失败: {str(e)}")
            # 可以添加其他协议的测试

    def vulnerability_scan(self):
        self.progress.emit("\n执行漏洞扫描...")
        device_config = DEVICE_CONFIGS[self.device_type]
        for vuln in device_config["vulnerabilities"]:
            self.progress.emit(f"正在检查: {vuln}")
            time.sleep(1)  # 模拟扫描过程

    def config_check(self):
        self.progress.emit("\n执行配置检查...")
        device_config = DEVICE_CONFIGS[self.device_type]
        self.progress.emit(f"检查设备型号: {self.device_model}")
        self.progress.emit(f"支持的协议: {', '.join(device_config['protocols'])}")
        self.progress.emit(f"默认端口: {', '.join(map(str, device_config['ports']))}")

    def stop(self):
        self.is_running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("发电设备安全测试工具")
        self.setMinimumSize(1200, 800)
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # 创建顶部标签栏
        self.tab_bar = QTabWidget()
        self.tab_bar.setStyleSheet("""
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                padding: 8px 100px;
                background: #f0f0f0;
            }
            QTabBar::tab:selected {
                background: #00C957;
                color: white;
            }
        """)
        
        # 存储每个标签页的设备按钮组和框架
        self.device_frames = {}
        self.button_groups = {}
        self.vuln_combos = {}  # 存储每个标签页的漏洞选择下拉框
        
        device_types = ["火力发电", "水力发电", "风力发电", "光伏发电"]
        for device_type in device_types:
            tab = QWidget()
            tab_layout = QHBoxLayout(tab)
            
            # 左侧设备选择区域
            left_panel = QWidget()
            left_layout = QVBoxLayout(left_panel)
            left_layout.setContentsMargins(20, 20, 20, 20)
            left_layout.setSpacing(15)
            
            # 设备选择标题
            device_select_label = QLabel("设备选择")
            device_select_label.setStyleSheet("""
                QLabel {
                    font-size: 16px;
                    font-weight: bold;
                    color: #333;
                    padding: 10px 0;
                    border-bottom: 2px solid #00C957;
                    margin-bottom: 15px;
                }
            """)
            left_layout.addWidget(device_select_label)
            
            # 设备型号按钮组
            device_frame = QFrame()
            device_frame.setObjectName(f"{device_type}_frame")
            device_frame.setStyleSheet("""
                QFrame {
                    background: white;
                    border-radius: 8px;
                    padding: 10px;
                }
            """)
            device_buttons_layout = QVBoxLayout(device_frame)
            device_buttons_layout.setSpacing(10)
            device_buttons_layout.setContentsMargins(10, 10, 10, 10)
            
            # 创建按钮组实现单选
            button_group = QButtonGroup(self)
            button_group.setExclusive(True)
            
            # 添加设备型号按钮
            device_config_key = f"{device_type}机组"
            if device_config_key in DEVICE_CONFIGS:
                for model in DEVICE_CONFIGS[device_config_key]["models"]:
                    btn = QPushButton(model)
                    btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f8f9fa;
                            border: 1px solid #e9ecef;
                            padding: 12px;
                            text-align: left;
                            border-radius: 6px;
                            font-size: 14px;
                            color: #495057;
                        }
                        QPushButton:hover {
                            background-color: #e9ecef;
                            border-color: #00C957;
                        }
                        QPushButton:checked {
                            background-color: #00C957;
                            color: white;
                            border: none;
                        }
                    """)
                    btn.setCheckable(True)
                    button_group.addButton(btn)
                    device_buttons_layout.addWidget(btn)
                    btn.clicked.connect(lambda checked, b=btn: self.on_device_selected(b))
            
            left_layout.addWidget(device_frame)
            left_layout.addStretch()
            self.device_frames[device_type] = device_frame
            self.button_groups[device_type] = button_group
            
            # 右侧测试区域
            right_panel = QWidget()
            right_layout = QVBoxLayout(right_panel)
            right_layout.setContentsMargins(20, 20, 20, 20)
            right_layout.setSpacing(20)
            
            # 目标信息区域（靠上排列）
            target_info_layout = QHBoxLayout()
            
            # IP地址输入
            ip_group = QGroupBox("目标IP")
            ip_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
            """)
            ip_layout = QVBoxLayout(ip_group)
            self.ip_input = QLineEdit()
            self.ip_input.setPlaceholderText("输入目标IP地址")
            self.ip_input.setStyleSheet("""
                QLineEdit {
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: white;
                }
                QLineEdit:focus {
                    border-color: #00C957;
                }
            """)
            ip_layout.addWidget(self.ip_input)
            target_info_layout.addWidget(ip_group)
            
            # 端口设置
            port_group = QGroupBox("端口")
            port_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
            """)
            port_layout = QVBoxLayout(port_group)
            self.port_input = QSpinBox()
            self.port_input.setRange(1, 65535)
            self.port_input.setValue(502)
            self.port_input.setStyleSheet("""
                QSpinBox {
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: white;
                }
                QSpinBox:focus {
                    border-color: #00C957;
                }
            """)
            port_layout.addWidget(self.port_input)
            target_info_layout.addWidget(port_group)
            
            # 漏洞选择
            vuln_group = QGroupBox("漏洞选择")
            vuln_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
            """)
            vuln_layout = QVBoxLayout(vuln_group)
            self.vuln_combo = QComboBox()
            self.vuln_combo.setStyleSheet("""
                QComboBox {
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: white;
                    min-width: 300px;
                }
                QComboBox:focus {
                    border-color: #00C957;
                }
                QComboBox::drop-down {
                    border: none;
                    width: 20px;
                }
                QComboBox::down-arrow {
                    image: url(down_arrow.png);
                    width: 12px;
                    height: 12px;
                }
                QComboBox:disabled {
                    background: #f5f5f5;
                    color: #888;
                }
            """)
            self.vuln_combo.setEnabled(False)  # 初始状态禁用
            vuln_layout.addWidget(self.vuln_combo)
            target_info_layout.addWidget(vuln_group)
            
            # 存储漏洞选择下拉框的引用
            self.vuln_combos[device_type] = self.vuln_combo
            
            right_layout.addLayout(target_info_layout)
            
            # 设备信息显示区域
            device_info_group = QGroupBox("设备信息")
            device_info_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
            """)
            device_info_layout = QVBoxLayout(device_info_group)
            self.device_info_display = QTextEdit()
            self.device_info_display.setReadOnly(True)
            self.device_info_display.setStyleSheet("""
                QTextEdit {
                    border: none;
                    background: white;
                    font-family: Arial;
                    font-size: 13px;
                }
            """)
            device_info_layout.addWidget(self.device_info_display)
            right_layout.addWidget(device_info_group)
            
            # 测试日志区域
            log_group = QGroupBox("测试日志")
            log_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
            """)
            log_layout = QVBoxLayout(log_group)
            self.log_display = QTextEdit()
            self.log_display.setReadOnly(True)
            self.log_display.setStyleSheet("""
                QTextEdit {
                    border: none;
                    background: white;
                    font-family: Consolas, Monaco, monospace;
                    font-size: 13px;
                }
            """)
            log_layout.addWidget(self.log_display)
            right_layout.addWidget(log_group)
            
            # 添加左右面板到标签页
            tab_layout.addWidget(left_panel, 1)
            tab_layout.addWidget(right_panel, 2)
            
            self.tab_bar.addTab(tab, device_type)
        
        layout.addWidget(self.tab_bar)
        
        # 底部按钮
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("开始测试")
        self.stop_button = QPushButton("停止测试")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #00C957;
                color: white;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00A647;
            }
        """)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: white;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #CC3333;
            }
        """)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # 连接信号
        self.start_button.clicked.connect(self.start_test)
        self.stop_button.clicked.connect(self.stop_test)
        self.tab_bar.currentChanged.connect(self.on_tab_changed)
        
        self.worker = None

    def on_device_selected(self, button):
        """当设备被选中时更新设备信息"""
        if button.isChecked():
            device_type = self.get_current_device_type()
            device_config = DEVICE_CONFIGS[device_type]
            selected_model = button.text()
            
            # 更新设备信息显示
            info_text = f"设备型号: {selected_model}\n"
            info_text += f"支持的协议: {', '.join(device_config['protocols'])}\n"
            info_text += f"默认端口: {', '.join(map(str, device_config['ports']))}\n"
            info_text += f"可用漏洞:\n"
            for vuln in device_config['vulnerabilities'][selected_model]:
                info_text += f"- {vuln}\n"
            
            self.device_info_display.setText(info_text)
            
            # 获取当前标签页的漏洞选择下拉框
            current_tab_text = self.tab_bar.tabText(self.tab_bar.currentIndex())
            current_vuln_combo = self.vuln_combos[current_tab_text]
            
            if current_vuln_combo:
                current_vuln_combo.clear()
                if device_type == "火力发电机组" and selected_model == "西门子SGT-800":
                    # 添加漏洞列表
                    sgt800_vulns = [
                        "CVE-2020-15782 - 西门子S7通信协议漏洞",
                        "CVE-2021-27965 - SGT-800控制系统漏洞",
                        "CVE-2021-37195 - 西门子工业自动化漏洞",
                        "CVE-2022-38465 - SGT系列认证绕过漏洞"
                    ]
                    current_vuln_combo.addItems(sgt800_vulns)
                    current_vuln_combo.setEnabled(True)
                    current_vuln_combo.setCurrentIndex(0)  # 默认选择第一个漏洞
                    
                    # 更新提示信息
                    self.log_display.append("已启用漏洞利用功能，请选择要测试的漏洞")
                else:
                    current_vuln_combo.addItem("当前漏洞匹配仅支持西门子SGT-800机组")
                    current_vuln_combo.setEnabled(False)

    def on_tab_changed(self, index):
        """当标签页切换时清除其他标签页的选择并重置漏洞选择"""
        current_type = self.tab_bar.tabText(index)
        
        # 清除其他标签页的选择
        for device_type, button_group in self.button_groups.items():
            if device_type != current_type:
                button_group.setExclusive(False)
                for button in button_group.buttons():
                    button.setChecked(False)
                button_group.setExclusive(True)
        
        # 重置当前标签页的漏洞选择
        current_vuln_combo = self.vuln_combos[current_type]
        if current_vuln_combo:
            current_vuln_combo.clear()
            current_vuln_combo.addItem("当前漏洞匹配仅支持西门子SGT-800机组")
            current_vuln_combo.setEnabled(False)

    def get_current_device_type(self):
        """获取当前选中的设备类型"""
        current_tab_text = self.tab_bar.tabText(self.tab_bar.currentIndex())
        return f"{current_tab_text}机组"

    def start_test(self):
        if not self.ip_input.text():
            QMessageBox.warning(self, "警告", "请输入目标IP地址")
            return
        
        # 获取当前设备类型
        device_type = self.get_current_device_type()
        
        # 获取选中的设备型号
        current_button_group = self.button_groups[self.tab_bar.tabText(self.tab_bar.currentIndex())]
        selected_button = current_button_group.checkedButton()
        
        if not selected_button:
            QMessageBox.warning(self, "警告", "请选择设备型号")
            return
        
        # 获取当前标签页的漏洞选择下拉框
        current_vuln_combo = self.vuln_combos[self.tab_bar.tabText(self.tab_bar.currentIndex())]
        
        # 确定测试类型和漏洞
        test_type = "漏洞扫描"  # 默认使用漏洞扫描模式
        selected_vuln = None
        
        if (device_type == "火力发电机组" and 
            selected_button.text() == "西门子SGT-800" and 
            current_vuln_combo.isEnabled()):
            test_type = "漏洞利用"
            selected_vuln = current_vuln_combo.currentText()
            if not selected_vuln or selected_vuln == "当前漏洞匹配仅支持西门子SGT-800机组":
                QMessageBox.warning(self, "警告", "请选择要测试的漏洞")
                return
            
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_display.clear()
        
        # 开始测试
        self.worker = TestWorker(
            device_type,
            selected_button.text(),
            test_type,
            self.ip_input.text(),
            self.port_input.value(),
            3  # 默认线程数
        )
        
        # 添加测试开始提示信息
        if test_type == "漏洞利用":
            self.log_display.append(f"开始漏洞利用测试: {selected_vuln}")
        else:
            self.log_display.append(f"开始漏洞扫描测试: {selected_button.text()}")
        
        self.worker.progress.connect(self.update_log)
        self.worker.finished.connect(self.test_finished)
        self.worker.error.connect(self.handle_error)
        
        self.worker.start()

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.worker = None
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        self.log_display.append("测试已停止")

    def update_log(self, message):
        self.log_display.append(message)
        self.log_display.verticalScrollBar().setValue(
            self.log_display.verticalScrollBar().maximum()
        )

    def test_finished(self):
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        self.log_display.append("测试完成")

    def handle_error(self, error_message):
        QMessageBox.critical(self, "错误", error_message)
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # 设置应用程序样式
    app.setStyle("Fusion")
    
    # 创建自定义调色板
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 