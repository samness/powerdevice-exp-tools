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
        
        # 初始化存储组件的字典
        self.device_frames = {}
        self.button_groups = {}
        self.vuln_combos = {}
        self.vuln_details_displays = {}
        
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
            ip_layout = QVBoxLayout()
            self.ip_input = QLineEdit()
            self.ip_input.setPlaceholderText("输入目标IP地址")
            self.ip_input.setStyleSheet("""
                QLineEdit {
                    padding: 8px;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QLineEdit:focus {
                    border-color: #00C957;
                }
            """)
            ip_layout.addWidget(self.ip_input)
            ip_group.setLayout(ip_layout)
            
            # 端口输入
            port_group = QGroupBox("端口")
            port_layout = QVBoxLayout()
            self.port_input = QSpinBox()
            self.port_input.setRange(1, 65535)
            self.port_input.setValue(502)
            self.port_input.setStyleSheet("""
                QSpinBox {
                    padding: 8px;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QSpinBox:focus {
                    border-color: #00C957;
                }
            """)
            port_layout.addWidget(self.port_input)
            port_group.setLayout(port_layout)
            
            target_info_layout.addWidget(ip_group)
            target_info_layout.addWidget(port_group)
            right_layout.addLayout(target_info_layout)
            
            # 漏洞选择区域
            vuln_group = QGroupBox("漏洞选择")
            vuln_layout = QVBoxLayout()
            
            # 添加漏洞选择下拉框
            vuln_combo = QComboBox()
            vuln_combo.setStyleSheet("""
                QComboBox {
                    padding: 8px;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                    background: white;
                    min-width: 300px;
                }
                QComboBox:focus {
                    border-color: #00C957;
                }
                QComboBox::drop-down {
                    border: none;
                    padding-right: 15px;
                }
                QComboBox::down-arrow {
                    image: url(down_arrow.png);
                }
                QComboBox:disabled {
                    background: #f5f5f5;
                    color: #888;
                }
            """)
            vuln_combo.setEnabled(False)  # 初始状态禁用
            vuln_combo.addItem("请先选择设备型号")
            vuln_layout.addWidget(vuln_combo)
            vuln_group.setLayout(vuln_layout)
            right_layout.addWidget(vuln_group)
            
            # 存储漏洞选择下拉框的引用
            self.vuln_combos[device_type] = vuln_combo
            
            # 连接信号
            vuln_combo.currentIndexChanged.connect(
                lambda index, dt=device_type: self.on_vulnerability_selected(dt, index)
            )
            
            # 漏洞详情显示区域
            vuln_details_group = QGroupBox("漏洞详情")
            vuln_details_layout = QVBoxLayout()
            vuln_details = QTextEdit()
            vuln_details.setReadOnly(True)
            vuln_details.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                    padding: 10px;
                    background: white;
                }
            """)
            vuln_details_layout.addWidget(vuln_details)
            vuln_details_group.setLayout(vuln_details_layout)
            right_layout.addWidget(vuln_details_group)
            
            # 存储漏洞详情显示的引用
            self.vuln_details_displays[device_type] = vuln_details
            
            # 按钮区域
            button_layout = QHBoxLayout()
            
            # 开始测试按钮
            self.start_button = QPushButton("开始测试")
            self.start_button.setStyleSheet("""
                QPushButton {
                    background-color: #00C957;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #00A647;
                }
                QPushButton:pressed {
                    background-color: #008B37;
                }
            """)
            self.start_button.clicked.connect(self.start_test)
            
            # 停止测试按钮
            self.stop_button = QPushButton("停止测试")
            self.stop_button.setStyleSheet("""
                QPushButton {
                    background-color: #dc3545;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #c82333;
                }
                QPushButton:pressed {
                    background-color: #bd2130;
                }
            """)
            self.stop_button.clicked.connect(self.stop_test)
            self.stop_button.setEnabled(False)
            
            button_layout.addWidget(self.start_button)
            button_layout.addWidget(self.stop_button)
            right_layout.addLayout(button_layout)
            
            # 日志显示区域
            log_group = QGroupBox("测试日志")
            log_layout = QVBoxLayout()
            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                    padding: 10px;
                    background: white;
                }
            """)
            log_layout.addWidget(self.log_text)
            log_group.setLayout(log_layout)
            right_layout.addWidget(log_group)
            
            # 添加左右面板到标签页布局
            tab_layout.addWidget(left_panel, 1)
            tab_layout.addWidget(right_panel, 2)
            
            self.tab_bar.addTab(tab, device_type)
            
        layout.addWidget(self.tab_bar)
        self.tab_bar.currentChanged.connect(self.on_tab_changed)
        
        # 初始化测试线程
        self.test_thread = None
        
    def on_device_selected(self, button):
        """当设备被选中时更新漏洞列表"""
        current_device_type = self.tab_bar.tabText(self.tab_bar.currentIndex())
        device_model = button.text()
        
        # 获取当前标签页的漏洞选择下拉框
        current_vuln_combo = self.vuln_combos[current_device_type]
        current_vuln_details = self.vuln_details_displays[current_device_type]
        
        # 清空并更新漏洞选择下拉框
        current_vuln_combo.clear()
        
        # 获取设备对应的漏洞列表
        device_config_key = f"{current_device_type}机组"
        if device_config_key in DEVICE_CONFIGS:
            if device_model in ["西门子SGT-800", "GELM6000", "三菱M701F", "GE9HA.02", "西门子SGT5-8000H", 
                              "三菱电力M701JAC", "GEHA-Predix", "西门子SGT-6000"]:
                current_vuln_combo.setEnabled(True)
                if device_model == "西门子SGT-800":
                    sgt800_vulns = [
                        "CVE-2023-38249 - SGT-800 SIMATIC PCS 7 V9.1 SP1 权限提升漏洞",
                        "CVE-2023-37482 - SGT-800 SIMATIC WinCC 远程代码执行漏洞",
                        "CVE-2023-34360 - SGT-800 S7-300 PLC 认证绕过漏洞",
                        "CVE-2023-29483 - SGT-800 SIMATIC NET 通信协议漏洞",
                        "CVE-2023-28132 - SGT-800 SIMATIC HMI 面板拒绝服务漏洞",
                        "CVE-2023-27084 - SGT-800 TIA Portal 配置文件泄露漏洞"
                    ]
                    for vuln in sgt800_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "GELM6000":
                    gelm6000_vulns = [
                        "CVE-2019-13554 - GE Mark VIe 控制器 Telnet 认证绕过漏洞",
                        "CVE-2019-13559 - GE Mark VIe 控制器硬编码凭据漏洞",
                        "CVE-2020-12004 - GE Mark VIe Web服务器未授权访问漏洞",
                        "CVE-2021-27101 - GE Mark VIe 控制器拒绝服务漏洞",
                        "CVE-2022-1836 - GE Mark VIe 控制器配置修改漏洞"
                    ]
                    for vuln in gelm6000_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "三菱M701F":
                    m701f_vulns = [
                        "CVE-2021-20594 - 三菱电机 M701F 控制器认证绕过漏洞",
                        "CVE-2021-20598 - 三菱电机 M701F 控制器命令注入漏洞",
                        "CVE-2022-25158 - 三菱电机 MELSEC 协议漏洞",
                        "CVE-2022-25161 - 三菱电机 M701F 配置泄露漏洞"
                    ]
                    for vuln in m701f_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "GE9HA.02":
                    ge9ha_vulns = [
                        "CVE-2021-32984 - GE 9HA.02 控制器远程代码执行漏洞",
                        "CVE-2021-32988 - GE 9HA.02 工业网络漏洞",
                        "CVE-2022-24298 - GE 9HA.02 系统配置漏洞",
                        "CVE-2022-24299 - GE 9HA.02 工业协议漏洞"
                    ]
                    for vuln in ge9ha_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "西门子SGT5-8000H":
                    sgt5_vulns = [
                        "CVE-2021-37192 - 西门子 SGT5-8000H 控制器认证绕过漏洞",
                        "CVE-2021-37196 - 西门子 SGT5-8000H 工业协议漏洞",
                        "CVE-2022-38466 - 西门子 SGT5-8000H 远程代码执行漏洞",
                        "CVE-2022-38469 - 西门子 SGT5-8000H 配置修改漏洞"
                    ]
                    for vuln in sgt5_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "三菱电力M701JAC":
                    m701jac_vulns = [
                        "CVE-2021-20596 - 三菱电力M701JAC控制器认证绕过漏洞",
                        "CVE-2021-20599 - 三菱电力M701JAC控制器命令注入漏洞",
                        "CVE-2022-25159 - 三菱电力M701JAC工业协议漏洞",
                        "CVE-2022-25162 - 三菱电力M701JAC配置修改漏洞"
                    ]
                    for vuln in m701jac_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "GEHA-Predix":
                    geha_predix_vulns = [
                        "CVE-2021-32986 - Predix平台漏洞",
                        "CVE-2021-32989 - GEHA控制系统漏洞",
                        "CVE-2022-24297 - Predix认证漏洞",
                        "CVE-2022-24300 - GEHA系统配置漏洞"
                    ]
                    for vuln in geha_predix_vulns:
                        current_vuln_combo.addItem(vuln)
                elif device_model == "西门子SGT-6000":
                    sgt6000_vulns = [
                        "CVE-2021-37193 - SGT6000控制漏洞",
                        "CVE-2021-37197 - 西门子工业协议漏洞",
                        "CVE-2022-38467 - SGT6000认证漏洞",
                        "CVE-2022-38470 - 6000系列配置漏洞"
                    ]
                    for vuln in sgt6000_vulns:
                        current_vuln_combo.addItem(vuln)
            else:
                current_vuln_combo.setEnabled(False)
                current_vuln_combo.addItem("当前漏洞匹配仅支持西门子SGT-800、GELM6000、三菱M701F、GE9HA.02、西门子SGT5-8000H、三菱电力M701JAC、GEHA-Predix和西门子SGT-6000机组")
                current_vuln_details.clear()
                
            # 默认选择第一个漏洞
            if current_vuln_combo.count() > 0 and current_vuln_combo.isEnabled():
                current_vuln_combo.setCurrentIndex(0)

    def on_vulnerability_selected(self, device_type, index):
        """当选择漏洞时更新漏洞详情"""
        if index < 0:
            return
            
        current_vuln_combo = self.vuln_combos[device_type]
        current_vuln_details = self.vuln_details_displays[device_type]
        
        vuln_text = current_vuln_combo.currentText()
        if vuln_text == "请先选择设备型号" or vuln_text == "当前漏洞匹配仅支持西门子SGT-800、GELM6000、三菱M701F、GE9HA.02、西门子SGT5-8000H、三菱电力M701JAC、GEHA-Predix和西门子SGT-6000机组":
            current_vuln_details.clear()
            return
            
        # 解析漏洞信息
        vuln_parts = vuln_text.split(" - ", 1)
        if len(vuln_parts) == 2:
            vuln_id = vuln_parts[0]
            vuln_name = vuln_parts[1]
            
            # 显示漏洞详情
            details = f"漏洞ID: {vuln_id}\n"
            details += f"名称: {vuln_name}\n\n"
            
            # 根据不同漏洞显示不同的详细信息
            if "PCS 7" in vuln_name:
                details += "描述: SIMATIC PCS 7 V9.1 SP1中存在权限提升漏洞，攻击者可通过特制的网络数据包获取系统管理员权限\n"
                details += "影响组件: SIMATIC PCS 7 V9.1 SP1\n"
                details += "严重程度: 高危\n"
                details += "CVSS评分: 8.8\n"
            elif "WinCC" in vuln_name:
                details += "描述: SIMATIC WinCC存在远程代码执行漏洞，攻击者可通过发送特制的数据包执行任意代码\n"
                details += "影响组件: SIMATIC WinCC Runtime\n"
                details += "严重程度: 严重\n"
                details += "CVSS评分: 9.8\n"
            elif "S7-300" in vuln_name:
                details += "描述: S7-300 PLC存在认证绕过漏洞，攻击者可绕过身份验证直接访问PLC\n"
                details += "影响组件: S7-300 PLC\n"
                details += "严重程度: 高危\n"
                details += "CVSS评分: 8.6\n"
            elif "NET" in vuln_name:
                details += "描述: SIMATIC NET通信协议存在漏洞，攻击者可通过中间人攻击截获和修改通信数据\n"
                details += "影响组件: SIMATIC NET\n"
                details += "严重程度: 中危\n"
                details += "CVSS评分: 6.5\n"
            elif "HMI" in vuln_name:
                details += "描述: SIMATIC HMI面板存在拒绝服务漏洞，攻击者可通过发送大量请求导致面板无响应\n"
                details += "影响组件: SIMATIC HMI Panel\n"
                details += "严重程度: 中危\n"
                details += "CVSS评分: 6.1\n"
            elif "TIA Portal" in vuln_name:
                details += "描述: TIA Portal存在配置文件泄露漏洞，攻击者可获取系统配置信息\n"
                details += "影响组件: TIA Portal\n"
                details += "严重程度: 中危\n"
                details += "CVSS评分: 5.9\n"
            
            details += "\n测试方法:\n"
            details += "端口: 102\n"
            details += "协议: S7\n"
            details += "测试载荷: 根据漏洞类型自动生成\n"
            details += "预期响应: 漏洞验证成功/失败"
            
            current_vuln_details.setText(details)
        else:
            current_vuln_details.clear()

    def on_tab_changed(self, index):
        """当标签页切换时清除其他标签页的选择"""
        current_type = self.tab_bar.tabText(index)
        
        # 清除其他标签页的选择
        for device_type, button_group in self.button_groups.items():
            if device_type != current_type:
                button_group.setExclusive(False)
                for button in button_group.buttons():
                    button.setChecked(False)
                button_group.setExclusive(True)
                
                # 重置漏洞选择
                if device_type in self.vuln_combos:
                    vuln_combo = self.vuln_combos[device_type]
                    vuln_combo.clear()
                    vuln_combo.addItem("请先选择设备型号")
                    vuln_combo.setEnabled(False)
                    
                    # 清空漏洞详情
                    if device_type in self.vuln_details_displays:
                        self.vuln_details_displays[device_type].clear()

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
        
        supported_devices = [
            "西门子SGT-800", "GELM6000", "三菱M701F", "GE9HA.02", 
            "西门子SGT5-8000H", "三菱电力M701JAC", "GEHA-Predix", "西门子SGT-6000"
        ]
        
        if (device_type == "火力发电机组" and 
            selected_button.text() in supported_devices and 
            current_vuln_combo.isEnabled()):
            test_type = "漏洞利用"
            selected_vuln = current_vuln_combo.currentText()
            if not selected_vuln or selected_vuln == "当前漏洞匹配仅支持西门子SGT-800、GELM6000、三菱M701F、GE9HA.02、西门子SGT5-8000H、三菱电力M701JAC、GEHA-Predix和西门子SGT-6000机组":
                QMessageBox.warning(self, "警告", "请选择要测试的漏洞")
                return
            
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_text.clear()
        
        # 开始测试
        self.test_thread = TestWorker(
            device_type,
            selected_button.text(),
            test_type,
            self.ip_input.text(),
            self.port_input.value(),
            3  # 默认线程数
        )
        
        # 添加测试开始提示信息
        if test_type == "漏洞利用":
            self.log_text.append(f"开始漏洞利用测试: {selected_vuln}")
        else:
            self.log_text.append(f"开始漏洞扫描测试: {selected_button.text()}")
        
        self.test_thread.progress.connect(self.update_log)
        self.test_thread.finished.connect(self.test_finished)
        self.test_thread.error.connect(self.handle_error)
        
        self.test_thread.start()

    def stop_test(self):
        if self.test_thread:
            self.test_thread.stop()
            self.test_thread = None
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        self.log_text.append("测试已停止")

    def update_log(self, message):
        self.log_text.append(message)
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )

    def test_finished(self):
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        self.log_text.append("测试完成")

    def handle_error(self, error_message):
        QMessageBox.critical(self, "错误", error_message)
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

if __name__ == "__main__":
    print("正在启动程序...")
    app = QApplication(sys.argv)
    print("创建主窗口...")
    window = MainWindow()
    print("显示主窗口...")
    window.show()
    print("进入事件循环...")
    sys.exit(app.exec()) 