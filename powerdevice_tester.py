import sys
import socket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QComboBox, QLineEdit, 
                           QPushButton, QTextEdit, QSpinBox, QGroupBox,
                           QTabWidget, QFormLayout, QSplitter, QFrame)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon
import logging
from pymodbus.client import ModbusTcpClient
import nmap
import scapy.all as scapy
import paramiko
import requests

class PowerDeviceTester(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("发电设备测试工具 v0.1.3bea")
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(main_widget)
        
        # 创建顶部发电类型标签页
        power_type_tabs = QTabWidget()
        
        # 火力发电标签页
        thermal_tab = self.create_device_tab([
            "西门子 SGT-800",
            "GE LM6000",
            "三菱 M701F",
            "GE 9HA.02",
            "西门子 SGT5-8000H",
            "三菱 M701JAC",
            "GE HA-Predix",
            "西门子 SGT-6000"
        ])
        power_type_tabs.addTab(thermal_tab, "火力发电")
        
        # 水利发电标签页
        hydro_tab = self.create_device_tab([
            "VH喷嘴冲击式机组",
            "AHM调速系统",
            "GEHydro数字水轮机",
            "ABB水电站控制系统"
        ])
        power_type_tabs.addTab(hydro_tab, "水利发电")
        
        # 光伏发电标签页
        solar_tab = self.create_device_tab([
            "FSS7薄膜组件",
            "SPMa6",
            "FusionSolar",
            "NeNXH-XTR"
        ])
        power_type_tabs.addTab(solar_tab, "光伏发电")
        
        # 风力发电标签页
        wind_tab = self.create_device_tab([
            "VV236",
            "SGSG14-222",
            "GEC数字风机",
            "金风科技智能机组",
            "ABB Ability™ SXcelerator",
            "GEDWF"
        ])
        power_type_tabs.addTab(wind_tab, "风力发电")
        
        main_layout.addWidget(power_type_tabs)
        
        # 设置样式
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid gray;
                border-radius: 6px;
                margin-top: 6px;
                padding-top: 6px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 7px;
                padding: 0px 5px 0px 5px;
            }
            QPushButton {
                min-height: 30px;
                font-weight: bold;
            }
            QTextEdit {
                font-family: 'Courier New';
                font-size: 12px;
            }
            QTabWidget::pane {
                border: 1px solid #C4C4C4;
                top: -1px;
            }
            QTabBar::tab {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #E1E1E1, stop: 0.4 #DDDDDD,
                                          stop: 0.5 #D8D8D8, stop: 1.0 #D3D3D3);
                border: 1px solid #C4C4C4;
                border-bottom-color: #C2C7CB;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 8ex;
                padding: 8px;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #fafafa, stop: 0.4 #f4f4f4,
                                          stop: 0.5 #e7e7e7, stop: 1.0 #fafafa);
            }
        """)
        
        # 设置日志
        self.setup_logging()
    
    def create_device_tab(self, device_list):
        """创建设备测试标签页"""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # 创建左侧控制面板
        left_panel = QWidget()
        left_panel.setMaximumWidth(400)
        left_layout = QVBoxLayout(left_panel)
        
        # 设备信息组
        device_group = QGroupBox("设备信息")
        device_layout = QFormLayout()
        self.device_combo = QComboBox()
        self.device_combo.addItems(device_list)
        device_layout.addRow("设备类型:", self.device_combo)
        device_group.setLayout(device_layout)
        left_layout.addWidget(device_group)
        
        # 目标信息组
        target_group = QGroupBox("目标信息")
        target_layout = QFormLayout()
        self.ip_input = QLineEdit()
        self.port_input = QLineEdit("502")
        target_layout.addRow("目标IP:", self.ip_input)
        target_layout.addRow("端口:", self.port_input)
        target_group.setLayout(target_layout)
        left_layout.addWidget(target_group)
        
        # 测试配置组
        config_group = QGroupBox("测试配置")
        config_layout = QFormLayout()
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 10)
        self.thread_spin.setValue(1)
        self.test_combo = QComboBox()
        self.test_combo.addItems([
            "Modbus协议测试",
            "网络扫描",
            "漏洞评估",
            "认证测试"
        ])
        config_layout.addRow("并发线程:", self.thread_spin)
        config_layout.addRow("测试类型:", self.test_combo)
        config_group.setLayout(config_layout)
        left_layout.addWidget(config_group)
        
        # 控制按钮组
        button_group = QGroupBox("控制")
        button_layout = QVBoxLayout()
        self.start_button = QPushButton("开始测试")
        self.stop_button = QPushButton("停止测试")
        self.stop_button.setEnabled(False)
        self.start_button.setMinimumHeight(40)
        self.stop_button.setMinimumHeight(40)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_group.setLayout(button_layout)
        left_layout.addWidget(button_group)
        
        # 添加弹性空间
        left_layout.addStretch()
        
        # 创建右侧面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 创建标签页
        tab_widget = QTabWidget()
        
        # 实时日志标签页
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        tab_widget.addTab(log_tab, "实时日志")
        
        # 测试结果标签页
        result_tab = QWidget()
        result_layout = QVBoxLayout(result_tab)
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        result_layout.addWidget(self.result_display)
        tab_widget.addTab(result_tab, "测试结果")
        
        # 漏洞详情标签页
        vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(vuln_tab)
        self.vuln_display = QTextEdit()
        self.vuln_display.setReadOnly(True)
        vuln_layout.addWidget(self.vuln_display)
        tab_widget.addTab(vuln_tab, "漏洞详情")
        
        right_layout.addWidget(tab_widget)
        
        # 添加分割器
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        
        layout.addWidget(splitter)
        
        # 连接信号
        self.start_button.clicked.connect(self.start_test)
        self.stop_button.clicked.connect(self.stop_test)
        
        return tab
    
    def setup_logging(self):
        logging.basicConfig(level=logging.INFO)
        self.log_handler = logging.StreamHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_handler)
    
    def start_test(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_display.clear()
        
        target_ip = self.ip_input.text()
        target_port = int(self.port_input.text())
        test_type = self.test_combo.currentText()
        
        self.log_display.append(f"Starting {test_type} on {target_ip}:{target_port}")
        
        try:
            if test_type == "Modbus Protocol Test":
                self.modbus_test(target_ip, target_port)
            elif test_type == "Network Scan":
                self.network_scan(target_ip)
            elif test_type == "Vulnerability Assessment":
                self.vulnerability_assessment(target_ip)
            elif test_type == "Authentication Test":
                self.authentication_test(target_ip)
        except Exception as e:
            self.log_display.append(f"Error: {str(e)}")
    
    def stop_test(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_display.append("Test stopped by user")
    
    def modbus_test(self, ip, port):
        try:
            client = ModbusTcpClient(ip, port)
            client.connect()
            self.log_display.append("Connected to Modbus device")
            
            # Test read holding registers
            result = client.read_holding_registers(0, 10)
            if not result.isError():
                self.log_display.append("Successfully read holding registers")
            else:
                self.log_display.append("Failed to read holding registers")
            
            client.close()
        except Exception as e:
            self.log_display.append(f"Modbus test error: {str(e)}")
    
    def network_scan(self, ip):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sV')
            self.log_display.append(f"Scan results for {ip}:")
            for host in nm.all_hosts():
                self.log_display.append(f"Host: {host}")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        self.log_display.append(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
        except Exception as e:
            self.log_display.append(f"Network scan error: {str(e)}")
    
    def vulnerability_assessment(self, ip):
        try:
            # Basic vulnerability checks
            self.log_display.append("Starting vulnerability assessment...")
            
            # Check for common open ports
            common_ports = [21, 22, 23, 80, 443, 502, 102]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.log_display.append(f"Port {port} is open - Potential vulnerability")
                sock.close()
        except Exception as e:
            self.log_display.append(f"Vulnerability assessment error: {str(e)}")
    
    def authentication_test(self, ip):
        try:
            self.log_display.append("Starting authentication test...")
            # Test common default credentials
            common_credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "root"),
                ("root", "password")
            ]
            
            for username, password in common_credentials:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password, timeout=5)
                    self.log_display.append(f"WARNING: Default credentials found - {username}:{password}")
                    ssh.close()
                except:
                    pass
        except Exception as e:
            self.log_display.append(f"Authentication test error: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PowerDeviceTester()
    window.show()
    sys.exit(app.exec_()) 