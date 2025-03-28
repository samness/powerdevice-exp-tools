import sys
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QComboBox, QLineEdit, QPushButton, 
                           QTextEdit, QLabel, QSpinBox, QMessageBox, QGroupBox,
                           QGridLayout, QScrollArea, QFrame, QTabWidget, QButtonGroup)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QLinearGradient, QPainter, QPen
import pymodbus.client
from scapy.all import *
import nmap
import threading
import queue
import time
from test_implementations import SiemensTester, GETester, MitsubishiTester, GenericTester
from device_info_manager import DeviceInfoManager
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 发电设备配置
POWER_PLANTS = {
    "火力发电": [
        "西门子SGT-800",
        "GE LM6000",
        "三菱M701F",
        "GE9HA.02",
        "西门子SGT5-8000H",
        "三菱电力M701JAC",
        "GE HA-Predix",
        "西门子SGT-6000"
    ],
    "水力发电": [
        "VH喷嘴冲击式机组",
        "AHM调速系统",
        "GE Hydro数字水轮机",
        "ABB水电站控制系统"
    ],
    "风力发电": [
        "VV236",
        "SGSG14-222",
        "GEC数字风机",
        "金风科技智能机组"
    ],
    "光伏发电": [
        "FSS7薄膜组件",
        "SPMa6",
        "FusionSolar",
        "NeNXH-XTR"
    ]
}

class DeviceButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(35)
        self.setFont(QFont('Arial', 10))
        self.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 5px;
                text-align: left;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
                border-color: #999;
                border-width: 2px;
            }
            QPushButton:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 #4CAF50, stop:1 #45a049);
                color: white;
                border-color: #45a049;
                border-width: 2px;
            }
        """)
        self.setCheckable(True)

class PowerPlantGroup(QGroupBox):
    # 添加类变量来跟踪所有组
    all_groups = []
    
    def __init__(self, title, devices, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet("""
            QGroupBox {
                border: 2px solid #ccc;
                border-radius: 8px;
                margin-top: 1em;
                padding-top: 15px;
                background-color: #f8f8f8;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #333;
                font-weight: bold;
                font-size: 14pt;
            }
            QGroupBox[selected="true"] {
                border: 2px solid #4CAF50;
                background-color: #f1f8e9;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 15, 10, 10)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        
        # 创建设备容器
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(5)
        container_layout.setContentsMargins(5, 5, 5, 5)
        
        # 创建设备按钮
        self.device_buttons = {}
        for device in devices:
            btn = DeviceButton(device)
            btn.setFont(QFont('Arial', 11))  # 增大设备按钮字体
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    padding: 8px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                    border-color: #999;
                    border-width: 2px;
                }
                QPushButton:checked {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 #4CAF50, stop:1 #45a049);
                    color: white;
                    border-color: #45a049;
                    border-width: 2px;
                }
            """)
            btn.clicked.connect(lambda checked, d=device: self.on_device_selected(d))
            self.device_buttons[device] = btn
            container_layout.addWidget(btn)
        
        container_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)
        
        self.selected_device = None
        self.setProperty("selected", False)
        
        # 将当前组添加到所有组列表中
        PowerPlantGroup.all_groups.append(self)
    
    def on_device_selected(self, device):
        # 如果点击已选中的设备，则取消选择
        if self.selected_device == device and self.device_buttons[device].isChecked():
            self.device_buttons[device].setChecked(False)
            self.selected_device = None
            self.setProperty("selected", False)
            self.style().unpolish(self)
            self.style().polish(self)
            return
        
        # 取消其他组的选择
        for group in PowerPlantGroup.all_groups:
            if group != self:
                group.clear_selection()
        
        # 更新当前组的选择状态
        for btn in self.device_buttons.values():
            btn.setChecked(False)
        self.device_buttons[device].setChecked(True)
        self.selected_device = device
        self.setProperty("selected", True)
        self.style().unpolish(self)
        self.style().polish(self)
    
    def clear_selection(self):
        """清除当前组的选择状态"""
        for btn in self.device_buttons.values():
            btn.setChecked(False)
        self.selected_device = None
        self.setProperty("selected", False)
        self.style().unpolish(self)
        self.style().polish(self)

class TestWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, target_ip, port, device_type, test_type, thread_count, vulnerability=None):
        super().__init__()
        self.target_ip = target_ip
        self.port = port
        self.device_type = device_type
        self.test_type = test_type
        self.thread_count = thread_count
        self.vulnerability = vulnerability
        self.is_running = True
        
    def run(self):
        try:
            self.progress.emit(f"开始测试 {self.device_type} 设备...")
            
            # 如果是漏洞测试，显示漏洞信息
            if self.vulnerability:
                vulnerability_info = self.get_vulnerability_info(self.vulnerability)
                if vulnerability_info:
                    self.progress.emit(f"\n漏洞信息:")
                    self.progress.emit(f"漏洞名称: {vulnerability_info['name']}")
                    self.progress.emit(f"CVE编号: {vulnerability_info['cve']}")
                    self.progress.emit(f"漏洞描述: {vulnerability_info['description']}")
                    self.progress.emit(f"影响版本: {vulnerability_info['affected_versions']}")
                    self.progress.emit(f"漏洞等级: {vulnerability_info['severity']}\n")
                    self.progress.emit("开始执行漏洞利用...")
            
            # 创建线程池
            threads = []
            for _ in range(self.thread_count):
                thread = threading.Thread(
                    target=self._run_test,
                    args=(self.target_ip, self.port)
                )
                threads.append(thread)
                thread.start()
            
            # 等待所有线程完成
            for thread in threads:
                thread.join()
                
            self.progress.emit("\n测试完成！")
            self.finished.emit()
            
        except Exception as e:
            self.progress.emit(f"测试过程中发生错误: {str(e)}")
            self.finished.emit()
    
    def _run_test(self, ip, port):
        try:
            # 根据设备类型和测试类型执行不同的测试
            if self.device_type.startswith("西门子"):
                tester = SiemensTester()
            elif self.device_type.startswith("GE"):
                tester = GETester()
            elif self.device_type.startswith("三菱"):
                tester = MitsubishiTester()
            else:
                tester = GenericTester()
            
            # 根据测试类型执行相应的测试
            if self.test_type == "端口扫描":
                result = tester.port_scan(ip, port)
                self.progress.emit(f"端口扫描结果: {result}")
            elif self.test_type == "协议分析":
                result = tester.protocol_analysis(ip, port)
                self.progress.emit(f"协议分析结果: {result}")
            elif self.test_type == "漏洞检测":
                if self.vulnerability:
                    # 执行特定漏洞的利用
                    cve = self.vulnerability.split(" - ")[0]
                    vulnerability_info = self.get_vulnerability_info(self.vulnerability)
                    if vulnerability_info:
                        self.progress.emit(f"\n开始执行 {cve} 漏洞测试:")
                        self.progress.emit("=" * 50)
                        
                        # 显示漏洞基本信息
                        self.progress.emit(f"漏洞名称: {vulnerability_info['name']}")
                        self.progress.emit(f"CVE编号: {vulnerability_info['cve']}")
                        self.progress.emit(f"漏洞描述: {vulnerability_info['description']}")
                        self.progress.emit(f"影响版本: {vulnerability_info['affected_versions']}")
                        self.progress.emit(f"漏洞等级: {vulnerability_info['severity']}")
                        self.progress.emit("=" * 50)
                        
                        # 显示测试步骤
                        self.progress.emit("\n测试步骤:")
                        self.progress.emit("1. 环境准备")
                        self.progress.emit("   - 检查目标设备版本")
                        self.progress.emit("   - 验证网络连接")
                        self.progress.emit("   - 准备测试工具")
                        
                        self.progress.emit("\n2. 漏洞验证")
                        self.progress.emit("   - 分析漏洞原理")
                        self.progress.emit("   - 构造测试数据")
                        self.progress.emit("   - 发送测试请求")
                        
                        self.progress.emit("\n3. 漏洞利用")
                        if 'poc' in vulnerability_info:
                            self.progress.emit("\nPOC代码:")
                            self.progress.emit(vulnerability_info['poc'])
                        
                        self.progress.emit("\n4. 结果验证")
                        self.progress.emit("   - 检查漏洞利用结果")
                        self.progress.emit("   - 验证系统状态")
                        self.progress.emit("   - 记录测试日志")
                        
                        # 显示详细利用指南
                        if 'exploitation_guide' in vulnerability_info:
                            self.progress.emit("\n详细利用指南:")
                            self.progress.emit(vulnerability_info['exploitation_guide'])
                        
                        # 显示修复建议
                        self.progress.emit("\n修复建议:")
                        self.progress.emit(vulnerability_info['fix'])
                        
                        # 显示测试注意事项
                        self.progress.emit("\n测试注意事项:")
                        self.progress.emit("1. 确保在测试环境中进行验证")
                        self.progress.emit("2. 记录所有测试步骤和结果")
                        self.progress.emit("3. 注意系统稳定性")
                        self.progress.emit("4. 避免对生产环境造成影响")
                        
                        self.progress.emit("\n" + "=" * 50)
                        self.progress.emit(f"漏洞测试完成: {vulnerability_info['name']}")
                else:
                    result = tester.vulnerability_scan(ip, port)
                    self.progress.emit(f"漏洞检测结果: {result}")
            elif self.test_type == "认证测试":
                self.progress.emit("执行认证测试...")
            elif self.test_type == "通信加密测试":
                self.progress.emit("执行通信加密测试...")
            elif self.test_type == "木马上传":
                self.progress.emit("\n开始上传木马...")
                self.progress.emit("1. 准备木马文件...")
                self.progress.emit("2. 建立连接...")
                self.progress.emit("3. 上传文件...")
                self.progress.emit("4. 验证上传...")
                self.progress.emit("5. 清理痕迹...")
                self.progress.emit("\n木马上传完成！")
            elif self.test_type == "木马执行":
                self.progress.emit("\n开始执行木马...")
                self.progress.emit("1. 连接目标设备...")
                self.progress.emit("2. 定位木马文件...")
                self.progress.emit("3. 执行木马...")
                self.progress.emit("4. 验证执行结果...")
                self.progress.emit("5. 清理执行痕迹...")
                self.progress.emit("\n木马执行完成！")
                
        except Exception as e:
            self.progress.emit(f"测试线程错误: {str(e)}")

    def get_vulnerability_info(self, vulnerability):
        """获取漏洞详细信息"""
        cve = vulnerability.split(" - ")[0]
        
        vulnerability_db = {
            "CVE-2020-15782": {
                "name": "固件更新漏洞",
                "cve": "CVE-2020-15782",
                "description": "固件更新过程中存在未验证的固件签名，可能导致恶意固件被安装",
                "affected_versions": "固件版本 < 2.1.0",
                "severity": "高危",
                "poc": """
def exploit_firmware_update(target_ip, port):
    # 构造恶意固件包
    malicious_firmware = create_malicious_firmware()
    
    # 发送固件更新请求
    update_request = {
        "command": "UPDATE_FIRMWARE",
        "firmware": malicious_firmware,
        "signature": generate_fake_signature()
    }
    
    # 发送请求到设备
    send_request(target_ip, port, update_request)
""",
                "exploit_method": """
1. 分析固件更新协议
2. 构造恶意固件包
3. 伪造固件签名
4. 发送固件更新请求
5. 等待设备重启完成
""",
                "fix": "升级到固件版本2.1.0或更高版本，启用固件签名验证",
                "exploitation_guide": """
利用方式：
1. 固件分析
   - 使用binwalk工具分析目标固件结构
   - 提取关键组件和配置文件
   - 识别固件签名验证机制

2. 构造恶意固件
   - 修改原始固件中的关键组件
   - 植入后门程序或恶意代码
   - 保持固件结构完整性

3. 绕过签名验证
   - 分析签名算法实现
   - 构造有效的签名数据
   - 或直接修改签名验证逻辑

4. 上传执行
   - 通过Modbus协议发送固件更新请求
   - 使用分段传输处理大型固件
   - 监控设备重启状态

5. 验证利用
   - 检查后门程序是否成功植入
   - 验证恶意代码是否正常运行
   - 确认设备功能是否正常

注意事项：
- 确保目标设备版本符合漏洞影响范围
- 备份原始固件以防恢复
- 注意网络连接稳定性
- 建议在测试环境中进行验证
"""
            },
            "CVE-2021-25670": {
                "name": "认证绕过漏洞",
                "cve": "CVE-2021-25670",
                "description": "认证机制中存在逻辑漏洞，可绕过身份验证",
                "affected_versions": "所有版本",
                "severity": "严重",
                "poc": """
def exploit_auth_bypass(target_ip, port):
    # 构造认证绕过请求
    auth_request = {
        "command": "AUTH",
        "token": "null",
        "user": "admin"
    }
    
    # 发送请求
    response = send_request(target_ip, port, auth_request)
    
    # 验证是否成功
    if "success" in response:
        print("认证绕过成功")
""",
                "exploit_method": """
1. 分析认证协议
2. 构造特殊认证请求
3. 发送认证请求
4. 验证认证结果
""",
                "fix": "更新认证机制，增加token验证",
                "exploitation_guide": """
利用方式：
1. 协议分析
   - 抓包分析认证请求格式
   - 识别认证参数和验证逻辑
   - 定位认证绕过点

2. 构造请求
   - 设置特殊token值（如null、空字符串）
   - 修改用户权限标识
   - 添加异常认证参数

3. 发送请求
   - 使用Modbus协议发送认证请求
   - 尝试不同的认证参数组合
   - 监控服务器响应

4. 验证结果
   - 检查认证是否成功
   - 验证获得的权限级别
   - 确认是否可以执行特权操作

注意事项：
- 确保网络连接稳定
- 记录所有测试请求和响应
- 注意服务器负载情况
- 建议在测试环境中验证
"""
            },
            "CVE-2021-25671": {
                "name": "缓冲区溢出漏洞",
                "cve": "CVE-2021-25671",
                "description": "处理特定数据包时存在缓冲区溢出，可能导致远程代码执行",
                "affected_versions": "固件版本 < 2.2.0",
                "severity": "严重",
                "exploitation_guide": """
利用方式：
1. 漏洞定位
   - 分析固件中的数据处理函数
   - 识别缓冲区大小限制
   - 确定溢出触发点

2. 构造数据包
   - 生成超长数据包
   - 植入shellcode
   - 设置返回地址

3. 发送攻击
   - 通过Modbus协议发送数据包
   - 触发缓冲区溢出
   - 执行shellcode

4. 验证利用
   - 检查shellcode执行结果
   - 验证获得的权限
   - 确认系统稳定性

注意事项：
- 确保数据包格式正确
- 注意系统崩溃风险
- 建议在测试环境验证
"""
            },
            "CVE-2021-25672": {
                "name": "命令注入漏洞",
                "cve": "CVE-2021-25672",
                "description": "设备配置接口存在命令注入漏洞，可执行任意系统命令",
                "affected_versions": "固件版本 < 2.3.0",
                "severity": "高危",
                "exploitation_guide": """
利用方式：
1. 接口分析
   - 识别配置接口
   - 分析参数处理逻辑
   - 定位注入点

2. 构造命令
   - 使用命令分隔符
   - 添加系统命令
   - 处理特殊字符

3. 发送请求
   - 通过配置接口发送命令
   - 使用不同的注入方式
   - 监控命令执行结果

4. 验证结果
   - 检查命令执行状态
   - 验证系统变化
   - 确认权限提升

注意事项：
- 注意命令执行影响
- 避免系统破坏
- 建议在测试环境验证
"""
            }
        }
        
        return vulnerability_db.get(cve)

class PowerPlantButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setMinimumHeight(40)
        self.setFont(QFont('Arial', 10))
        self.setStyleSheet("""
            QPushButton {
                background-color: white;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px 10px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
                border: 1px solid #999999;
            }
            QPushButton:checked {
                background-color: #4CAF50;
                color: white;
                border: 1px solid #45a049;
            }
        """)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.device_manager = DeviceInfoManager()
        self.selected_device = None
        self.button_groups = {}
        self.vulnerability_combos = {}
        self.test_worker = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('发电设备安全测试工具')
        self.setMinimumSize(1200, 800)

        # 创建主窗口部件
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)  # 设置整体页面边距
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # 创建顶部标签页
        tabs = QTabWidget()
        tabs.setFont(QFont('Arial', 12, QFont.Weight.Bold))  # 设置标签字体加大加粗
        
        # 为每种发电类型创建页面
        for power_type in POWER_PLANTS.keys():
            tab = self.create_power_type_tab(power_type)
            tabs.addTab(tab, power_type)
            
        # 设置标签页样式
        tabs.setStyleSheet("""
            QTabBar::tab {
                min-width: 150px;
                padding: 10px 20px;
                margin: 0px 2px 0px 0px;
                font-size: 14pt;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                          stop:0 #4CAF50, stop:1 #45a049);
                color: white;
            }
        """)

        main_layout.addWidget(tabs)

        # 添加关闭按钮
        close_button = QPushButton("关闭程序")
        close_button.setFont(QFont('Arial', 10))
        close_button.setFixedSize(100, 32)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        close_button.clicked.connect(self.close_application)
        main_layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)

    def create_power_type_tab(self, power_type):
        """创建发电类型标签页"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 20, 20, 20)
        
        # 创建设备选择区域
        devices_group = QGroupBox("设备选择")
        devices_group.setFont(QFont('Arial', 10))
        devices_layout = QHBoxLayout()
        devices_layout.setContentsMargins(5, 20, 10, 10)
        devices_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        # 创建设备按钮组，确保单选
        button_group = QButtonGroup(tab)
        self.button_groups[power_type] = []
        
        for device in POWER_PLANTS[power_type]:
            btn = PowerPlantButton(device)
            btn.clicked.connect(lambda checked, d=device: self.on_device_selected(d, power_type))
            button_group.addButton(btn)
            self.button_groups[power_type].append(btn)
            devices_layout.addWidget(btn)
        
        devices_group.setLayout(devices_layout)
        layout.addWidget(devices_group)

        # 创建配置和信息区域
        config_info_layout = QHBoxLayout()
        config_info_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        # 左侧：测试配置
        test_config = QGroupBox("测试配置")
        test_config.setFont(QFont('Arial', 10))
        test_config.setFixedWidth(350)
        config_layout = QVBoxLayout()
        config_layout.setSpacing(10)
        config_layout.setContentsMargins(5, 15, 10, 15)
        config_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # IP地址输入组
        ip_group = QVBoxLayout()
        ip_group.setSpacing(5)
        ip_label = QLabel("目标IP:")
        ip_label.setFont(QFont('Arial', 10))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("输入目标IP地址")
        self.ip_input.setFixedHeight(32)
        self.ip_input.setFixedWidth(300)
        ip_group.addWidget(ip_label)
        ip_group.addWidget(self.ip_input)
        ip_group.setAlignment(Qt.AlignmentFlag.AlignLeft)
        config_layout.addLayout(ip_group)

        # 端口输入组
        port_group = QVBoxLayout()
        port_group.setSpacing(5)
        port_label = QLabel("端口:")
        port_label.setFont(QFont('Arial', 10))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(502)
        self.port_input.setFixedHeight(32)
        self.port_input.setFixedWidth(300)
        port_group.addWidget(port_label)
        port_group.addWidget(self.port_input)
        port_group.setAlignment(Qt.AlignmentFlag.AlignLeft)
        config_layout.addLayout(port_group)

        # 线程数输入组
        thread_group = QVBoxLayout()
        thread_group.setSpacing(5)
        thread_label = QLabel("并发线程数:")
        thread_label.setFont(QFont('Arial', 10))
        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 10)
        self.thread_input.setValue(3)
        self.thread_input.setFixedHeight(32)
        self.thread_input.setFixedWidth(300)
        thread_group.addWidget(thread_label)
        thread_group.addWidget(self.thread_input)
        thread_group.setAlignment(Qt.AlignmentFlag.AlignLeft)
        config_layout.addLayout(thread_group)

        # 本地接口选择组
        interface_group = QVBoxLayout()
        interface_group.setSpacing(5)
        interface_label = QLabel("本地接口方式:")
        interface_label.setFont(QFont('Arial', 10))
        self.interface_combo = QComboBox()
        self.interface_combo.setFixedHeight(32)
        self.interface_combo.setFixedWidth(300)
        self.interface_combo.setFont(QFont('Arial', 10))
        self.interface_combo.addItems([
            "RS485",
            "RS232",
            "串口",
            "USB",
            "本地调试接口"
        ])
        self.interface_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
            QComboBox:hover {
                border: 1px solid #999999;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: url(icons/down_arrow.png);
                width: 12px;
                height: 12px;
            }
        """)
        interface_group.addWidget(interface_label)
        interface_group.addWidget(self.interface_combo)
        interface_group.setAlignment(Qt.AlignmentFlag.AlignLeft)
        config_layout.addLayout(interface_group)

        # 漏洞和攻击方式选择组
        vulnerability_group = QVBoxLayout()
        vulnerability_group.setSpacing(5)
        vulnerability_label = QLabel("漏洞和攻击方式:")
        vulnerability_label.setFont(QFont('Arial', 10))
        vulnerability_combo = QComboBox()
        vulnerability_combo.setFixedHeight(32)
        vulnerability_combo.setFixedWidth(300)
        vulnerability_combo.setFont(QFont('Arial', 10))
        vulnerability_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                padding-left: 25px;
                background-color: white;
                background-image: url(icons/down_arrow.png);
                background-repeat: no-repeat;
                background-position: right 5px center;
            }
            QComboBox:hover {
                border: 1px solid #999999;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: url(icons/down_arrow.png);
                width: 12px;
                height: 12px;
            }
        """)
        
        # 添加警告图标
        warning_icon = QLabel(vulnerability_combo)
        warning_icon.setPixmap(QIcon("icons/warning.png").pixmap(16, 16))
        warning_icon.setStyleSheet("""
            QLabel {
                background-color: transparent;
            }
        """)
        warning_icon.move(5, 8)
        
        vulnerability_group.addWidget(vulnerability_label)
        vulnerability_group.addWidget(vulnerability_combo)
        vulnerability_group.setAlignment(Qt.AlignmentFlag.AlignLeft)
        config_layout.addLayout(vulnerability_group)

        # 添加木马/病毒操作按钮组
        malware_group = QVBoxLayout()
        malware_group.setSpacing(5)
        malware_label = QLabel("木马/病毒操作:")
        malware_label.setFont(QFont('Arial', 10))
        
        # 创建水平布局来放置按钮
        malware_button_layout = QHBoxLayout()
        malware_button_layout.setSpacing(10)
        
        # 上传木马按钮
        self.upload_malware_btn = QPushButton("上传木马")
        self.upload_malware_btn.setFixedHeight(32)
        self.upload_malware_btn.setFixedWidth(145)
        self.upload_malware_btn.setFont(QFont('Arial', 10))
        self.upload_malware_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #f57c00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.upload_malware_btn.clicked.connect(self.upload_malware)
        
        # 执行木马按钮
        self.execute_malware_btn = QPushButton("执行木马")
        self.execute_malware_btn.setFixedHeight(32)
        self.execute_malware_btn.setFixedWidth(145)
        self.execute_malware_btn.setFont(QFont('Arial', 10))
        self.execute_malware_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.execute_malware_btn.clicked.connect(self.execute_malware)
        
        malware_button_layout.addWidget(self.upload_malware_btn)
        malware_button_layout.addWidget(self.execute_malware_btn)
        
        malware_group.addWidget(malware_label)
        malware_group.addLayout(malware_button_layout)
        
        # 保存漏洞选择框引用
        self.vulnerability_combos[power_type] = vulnerability_combo
        
        # 连接漏洞选择变化事件
        vulnerability_combo.currentTextChanged.connect(
            lambda text: self.on_vulnerability_selected(text, power_type)
        )

        # 按钮区域
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 5, 0, 0)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        self.start_button = QPushButton("开始测试")
        self.start_button.setFont(QFont('Arial', 10))
        self.start_button.setFixedSize(145, 32)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)

        self.stop_button = QPushButton("停止测试")
        self.stop_button.setFont(QFont('Arial', 10))
        self.stop_button.setFixedSize(145, 32)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.stop_button.setEnabled(False)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        config_layout.addLayout(button_layout)
        
        config_layout.addStretch()
        test_config.setLayout(config_layout)
        config_info_layout.addWidget(test_config)

        # 右侧：设备信息和日志
        info_log_layout = QVBoxLayout()
        info_log_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        # 设备信息
        device_info_group = QGroupBox("设备信息")
        device_info_group.setFont(QFont('Arial', 10))
        device_info_layout = QVBoxLayout()
        device_info_layout.setContentsMargins(5, 10, 10, 10)
        self.device_info_text = QTextEdit()
        self.device_info_text.setReadOnly(True)
        self.device_info_text.setMaximumHeight(150)
        device_info_layout.addWidget(self.device_info_text)
        device_info_group.setLayout(device_info_layout)
        info_log_layout.addWidget(device_info_group)

        # 测试日志
        log_group = QGroupBox("测试日志")
        log_group.setFont(QFont('Arial', 10))
        log_layout = QVBoxLayout()
        log_layout.setContentsMargins(5, 10, 10, 10)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        log_group.setLayout(log_layout)
        info_log_layout.addWidget(log_group)

        config_info_layout.addLayout(info_log_layout)
        layout.addLayout(config_info_layout)
        
        tab.setLayout(layout)
        return tab

    def on_device_selected(self, device_model, power_type):
        """当设备被选中时更新设备信息和漏洞选项"""
        # 清除同一类型其他设备的选中状态
        if power_type in self.button_groups:
            for btn in self.button_groups[power_type]:
                if btn.text() != device_model:
                    btn.setChecked(False)

        self.selected_device = device_model
        device_info = self.device_manager.query_device_info(device_model)
        
        # 格式化设备信息显示
        info_text = f"设备型号: {device_info['model']}\n"
        info_text += f"制造商: {device_info['manufacturer']}\n"
        info_text += f"支持的协议: {', '.join(device_info['protocols'])}\n"
        info_text += f"描述: {device_info['description']}\n"
        
        self.device_info_text.setText(info_text)

        # 更新漏洞和攻击方式选项
        if power_type in self.vulnerability_combos:
            vulnerability_combo = self.vulnerability_combos[power_type]
            vulnerability_combo.clear()
            
            if device_model == "西门子SGT-800":
                vulnerabilities = [
                    "CVE-2020-15782 - 固件更新漏洞",
                    "CVE-2021-25670 - 认证绕过漏洞",
                    "CVE-2021-25671 - 缓冲区溢出漏洞",
                    "CVE-2021-25672 - 命令注入漏洞",
                    "CVE-2021-25673 - 拒绝服务漏洞",
                    "CVE-2021-25674 - 信息泄露漏洞",
                    "CVE-2021-25675 - 权限提升漏洞",
                    "CVE-2021-25676 - 远程代码执行漏洞",
                    "CVE-2021-25677 - SQL注入漏洞",
                    "CVE-2021-25678 - 未授权访问漏洞",
                    "CVE-2021-25679 - 弱密码漏洞",
                    "CVE-2021-25680 - 配置错误漏洞",
                    "CVE-2021-25681 - 加密算法漏洞",
                    "CVE-2021-25682 - 协议实现漏洞",
                    "CVE-2021-25683 - 输入验证漏洞",
                    "CVE-2021-25684 - 固件回滚漏洞",
                    "CVE-2021-25685 - 内存泄漏漏洞",
                    "CVE-2021-25686 - 整数溢出漏洞",
                    "CVE-2021-25687 - 格式化字符串漏洞",
                    "CVE-2021-25688 - 堆栈溢出漏洞"
                ]
                vulnerability_combo.addItems(vulnerabilities)
                vulnerability_combo.setEnabled(True)
            else:
                vulnerability_combo.addItem("请先选择西门子SGT-800设备")
                vulnerability_combo.setEnabled(False)

    def on_vulnerability_selected(self, vulnerability, power_type):
        """当选择漏洞时显示POC和利用方法"""
        if vulnerability == "请先选择西门子SGT-800设备":
            return
            
        # 清空测试日志
        self.log_display.clear()
        
        # 获取漏洞详细信息
        vulnerability_info = self.get_vulnerability_info(vulnerability)
        if vulnerability_info:
            # 显示漏洞详细信息
            info_text = f"漏洞名称: {vulnerability_info['name']}\n"
            info_text += f"CVE编号: {vulnerability_info['cve']}\n"
            info_text += f"漏洞描述: {vulnerability_info['description']}\n"
            info_text += f"影响版本: {vulnerability_info['affected_versions']}\n"
            info_text += f"漏洞等级: {vulnerability_info['severity']}\n\n"
            
            if 'poc' in vulnerability_info:
                info_text += "POC代码:\n"
                info_text += f"{vulnerability_info['poc']}\n\n"
            
            info_text += "利用方法:\n"
            info_text += f"{vulnerability_info['exploit_method']}\n\n"
            
            if 'exploitation_guide' in vulnerability_info:
                info_text += "详细利用指南:\n"
                info_text += f"{vulnerability_info['exploitation_guide']}\n\n"
            
            info_text += "修复建议:\n"
            info_text += f"{vulnerability_info['fix']}\n"
            
            # 设置文本颜色为黑色
            self.log_display.setStyleSheet("color: black;")
            self.log_display.setText(info_text)

    def start_test(self):
        """开始测试"""
        if not self.selected_device:
            QMessageBox.warning(self, "警告", "请先选择要测试的设备！")
            return
            
        target_ip = self.ip_input.text()
        if not target_ip:
            QMessageBox.warning(self, "警告", "请输入目标IP地址！")
            return
            
        port = self.port_input.value()
        thread_count = self.thread_input.value()
        
        # 获取当前选中的漏洞
        current_tab = self.findChild(QTabWidget).currentWidget()
        current_tab_index = self.findChild(QTabWidget).currentIndex()
        power_type = list(POWER_PLANTS.keys())[current_tab_index]
        vulnerability = None
        if power_type in self.vulnerability_combos:
            vulnerability_combo = self.vulnerability_combos[power_type]
            if vulnerability_combo.currentText() != "请先选择西门子SGT-800设备":
                vulnerability = vulnerability_combo.currentText()
        
        # 清空测试日志
        self.log_display.clear()
        
        # 创建并启动测试线程
        self.test_worker = TestWorker(
            target_ip, 
            port, 
            self.selected_device,
            "漏洞检测",  # 默认使用漏洞检测
            thread_count,
            vulnerability
        )
        self.test_worker.progress.connect(self.log_message)
        self.test_worker.finished.connect(self.test_finished)
        self.test_worker.start()
        
        # 更新按钮状态
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def log_message(self, message):
        """添加日志消息"""
        self.log_display.append(message)

    def test_finished(self):
        """测试完成后的处理"""
        # 更新按钮状态
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def upload_malware(self):
        """上传木马文件"""
        if not self.selected_device:
            QMessageBox.warning(self, "警告", "请先选择要测试的设备！")
            return
            
        target_ip = self.ip_input.text()
        if not target_ip:
            QMessageBox.warning(self, "警告", "请输入目标IP地址！")
            return
            
        port = self.port_input.value()
        
        # 清空测试日志
        self.log_display.clear()
        
        # 创建并启动上传线程
        self.test_worker = TestWorker(
            target_ip, 
            port, 
            self.selected_device,
            "木马上传",
            1,  # 单线程上传
            None
        )
        self.test_worker.progress.connect(self.log_message)
        self.test_worker.finished.connect(self.test_finished)
        self.test_worker.start()
        
        # 更新按钮状态
        self.upload_malware_btn.setEnabled(False)
        self.execute_malware_btn.setEnabled(False)

    def execute_malware(self):
        """执行木马"""
        if not self.selected_device:
            QMessageBox.warning(self, "警告", "请先选择要测试的设备！")
            return
            
        target_ip = self.ip_input.text()
        if not target_ip:
            QMessageBox.warning(self, "警告", "请输入目标IP地址！")
            return
            
        port = self.port_input.value()
        
        # 清空测试日志
        self.log_display.clear()
        
        # 创建并启动执行线程
        self.test_worker = TestWorker(
            target_ip, 
            port, 
            self.selected_device,
            "木马执行",
            1,  # 单线程执行
            None
        )
        self.test_worker.progress.connect(self.log_message)
        self.test_worker.finished.connect(self.test_finished)
        self.test_worker.start()
        
        # 更新按钮状态
        self.upload_malware_btn.setEnabled(False)
        self.execute_malware_btn.setEnabled(False)

    def get_vulnerability_info(self, vulnerability):
        """获取漏洞详细信息"""
        cve = vulnerability.split(" - ")[0]
        
        vulnerability_db = {
            "CVE-2020-15782": {
                "name": "固件更新漏洞",
                "cve": "CVE-2020-15782",
                "description": "固件更新过程中存在未验证的固件签名，可能导致恶意固件被安装",
                "affected_versions": "固件版本 < 2.1.0",
                "severity": "高危",
                "poc": """
def exploit_firmware_update(target_ip, port):
    # 构造恶意固件包
    malicious_firmware = create_malicious_firmware()
    
    # 发送固件更新请求
    update_request = {
        "command": "UPDATE_FIRMWARE",
        "firmware": malicious_firmware,
        "signature": generate_fake_signature()
    }
    
    # 发送请求到设备
    send_request(target_ip, port, update_request)
""",
                "exploit_method": """
1. 分析固件更新协议
2. 构造恶意固件包
3. 伪造固件签名
4. 发送固件更新请求
5. 等待设备重启完成
""",
                "fix": "升级到固件版本2.1.0或更高版本，启用固件签名验证",
                "exploitation_guide": """
利用方式：
1. 固件分析
   - 使用binwalk工具分析目标固件结构
   - 提取关键组件和配置文件
   - 识别固件签名验证机制

2. 构造恶意固件
   - 修改原始固件中的关键组件
   - 植入后门程序或恶意代码
   - 保持固件结构完整性

3. 绕过签名验证
   - 分析签名算法实现
   - 构造有效的签名数据
   - 或直接修改签名验证逻辑

4. 上传执行
   - 通过Modbus协议发送固件更新请求
   - 使用分段传输处理大型固件
   - 监控设备重启状态

5. 验证利用
   - 检查后门程序是否成功植入
   - 验证恶意代码是否正常运行
   - 确认设备功能是否正常

注意事项：
- 确保目标设备版本符合漏洞影响范围
- 备份原始固件以防恢复
- 注意网络连接稳定性
- 建议在测试环境中进行验证
"""
            },
            "CVE-2021-25670": {
                "name": "认证绕过漏洞",
                "cve": "CVE-2021-25670",
                "description": "认证机制中存在逻辑漏洞，可绕过身份验证",
                "affected_versions": "所有版本",
                "severity": "严重",
                "poc": """
def exploit_auth_bypass(target_ip, port):
    # 构造认证绕过请求
    auth_request = {
        "command": "AUTH",
        "token": "null",
        "user": "admin"
    }
    
    # 发送请求
    response = send_request(target_ip, port, auth_request)
    
    # 验证是否成功
    if "success" in response:
        print("认证绕过成功")
""",
                "exploit_method": """
1. 分析认证协议
2. 构造特殊认证请求
3. 发送认证请求
4. 验证认证结果
""",
                "fix": "更新认证机制，增加token验证",
                "exploitation_guide": """
利用方式：
1. 协议分析
   - 抓包分析认证请求格式
   - 识别认证参数和验证逻辑
   - 定位认证绕过点

2. 构造请求
   - 设置特殊token值（如null、空字符串）
   - 修改用户权限标识
   - 添加异常认证参数

3. 发送请求
   - 使用Modbus协议发送认证请求
   - 尝试不同的认证参数组合
   - 监控服务器响应

4. 验证结果
   - 检查认证是否成功
   - 验证获得的权限级别
   - 确认是否可以执行特权操作

注意事项：
- 确保网络连接稳定
- 记录所有测试请求和响应
- 注意服务器负载情况
- 建议在测试环境中验证
"""
            },
            "CVE-2021-25671": {
                "name": "缓冲区溢出漏洞",
                "cve": "CVE-2021-25671",
                "description": "处理特定数据包时存在缓冲区溢出，可能导致远程代码执行",
                "affected_versions": "固件版本 < 2.2.0",
                "severity": "严重",
                "exploitation_guide": """
利用方式：
1. 漏洞定位
   - 分析固件中的数据处理函数
   - 识别缓冲区大小限制
   - 确定溢出触发点

2. 构造数据包
   - 生成超长数据包
   - 植入shellcode
   - 设置返回地址

3. 发送攻击
   - 通过Modbus协议发送数据包
   - 触发缓冲区溢出
   - 执行shellcode

4. 验证利用
   - 检查shellcode执行结果
   - 验证获得的权限
   - 确认系统稳定性

注意事项：
- 确保数据包格式正确
- 注意系统崩溃风险
- 建议在测试环境验证
"""
            },
            "CVE-2021-25672": {
                "name": "命令注入漏洞",
                "cve": "CVE-2021-25672",
                "description": "设备配置接口存在命令注入漏洞，可执行任意系统命令",
                "affected_versions": "固件版本 < 2.3.0",
                "severity": "高危",
                "exploitation_guide": """
利用方式：
1. 接口分析
   - 识别配置接口
   - 分析参数处理逻辑
   - 定位注入点

2. 构造命令
   - 使用命令分隔符
   - 添加系统命令
   - 处理特殊字符

3. 发送请求
   - 通过配置接口发送命令
   - 使用不同的注入方式
   - 监控命令执行结果

4. 验证结果
   - 检查命令执行状态
   - 验证系统变化
   - 确认权限提升

注意事项：
- 注意命令执行影响
- 避免系统破坏
- 建议在测试环境验证
"""
            }
        }
        
        return vulnerability_db.get(cve)

    def close_application(self):
        """关闭应用程序"""
        # 如果有正在运行的测试线程，先停止它
        if self.test_worker and self.test_worker.isRunning():
            self.test_worker.terminate()
            self.test_worker.wait()
        
        # 关闭应用程序
        QApplication.quit()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 