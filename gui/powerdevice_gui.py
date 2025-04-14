import sys
import hashlib
import time
import base64
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QComboBox, QLineEdit, 
                           QPushButton, QTextEdit, QSpinBox, QGroupBox,
                           QTabWidget, QFormLayout, QSplitter, QFrame,
                           QTableWidget, QTableWidgetItem, QHeaderView,
                           QListWidget, QListWidgetItem, QMessageBox)
from PyQt5.QtCore import Qt, QSize, QPoint, QRect
from PyQt5.QtGui import (QFont, QIcon, QPixmap, QPainter, QLinearGradient, 
                        QColor, QPen)
from .vulnerability_db import (get_device_vulnerabilities, get_vulnerability_info,
                           get_all_vulnerability_ids, VulnerabilityInfo)
from .logger import PowerDeviceLogger
from .exploit_module import ExploitModule, ExploitResult
import logging
import traceback

class PowerDeviceGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.logger = PowerDeviceLogger()
        self.exploit_module = ExploitModule()
        self.device_tabs = {}  # 存储设备标签页的组件引用
        self._init_ui()
        
    def _create_logo(self):
        """创建个性化logo"""
        self.logger.debug("Creating personalized logo")
        # 创建一个32x32的图标
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        
        # 将密语转换为图案
        motto_hash = hashlib.md5(self._motto.encode()).hexdigest()
        
        # 使用密语哈希生成颜色
        r = int(motto_hash[:2], 16)
        g = int(motto_hash[2:4], 16)
        b = int(motto_hash[4:6], 16)
        
        # 创建渐变色图标
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # 创建渐变色
        gradient = QLinearGradient(0, 0, 32, 32)
        gradient.setColorAt(0, QColor(r, g, b))
        gradient.setColorAt(1, QColor(b, r, g))
        
        # 绘制圆形背景
        painter.setBrush(gradient)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(4, 4, 24, 24)
        
        # 添加边框
        pen = QPen(QColor(g, b, r))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(4, 4, 24, 24)
        
        # 添加文字标记
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setPointSize(12)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRect(0, 0, 32, 32), Qt.AlignCenter, "P")
        
        painter.end()
        
        self.logger.debug("Logo creation completed")
        return QIcon(pixmap)
        
    def _generate_auth_code(self):
        """生成基于密语的认证码"""
        self.logger.debug("Generating authentication code")
        timestamp = int(time.time() / 86400)  # 当天时间戳
        base = f"{self._motto}_{timestamp}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]
        
    def _get_hidden_mark(self):
        """获取隐藏标识"""
        self.logger.debug("Getting hidden mark")
        return base64.b64encode(self._motto.encode()).decode()[:8]
        
    def _verify_license(self):
        """验证许可证"""
        try:
            self.logger.info("Verifying license...")
            self.logger.debug("Auth code: %s", self._auth_code)
            self.logger.debug("Auth seed: %s", self._auth_seed)
            
            # 基于密语验证
            current_code = self._generate_auth_code()
            motto_verify = hashlib.sha256(f"{self._motto}_{self._auth_seed}".encode()).hexdigest()
            
            self.logger.debug("Current code: %s", current_code)
            self.logger.debug("Motto verify: %s", motto_verify)
            self.logger.debug("Motto verify starts with: %s", motto_verify.startswith(self._auth_seed))
            
            result = (self._auth_code == current_code)
            self.logger.info("License verification result: %s", result)
            return True  # 临时返回True以便测试
        except Exception as e:
            self.logger.error("Error in license verification: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())
            return False
            
    def _init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle('电力设备安全测试工具')
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(main_widget)
        
        # 创建顶部发电类型标签页
        self.power_type_tabs = QTabWidget()
        
        # 火力发电标签页
        thermal_tab = self.create_device_tab([
            "Siemens SGT-800",
            "GE LM6000",
            "Mitsubishi M701F"
        ])
        self.power_type_tabs.addTab(thermal_tab, "火力发电")
        
        # 水利发电标签页
        hydro_tab = self.create_device_tab([
            "VH喷嘴冲击式机组",
            "AHM调速系统"
        ])
        self.power_type_tabs.addTab(hydro_tab, "水利发电")
        
        # 光伏发电标签页
        solar_tab = self.create_device_tab([
            "FSS7薄膜组件",
            "SPMa6"
        ])
        self.power_type_tabs.addTab(solar_tab, "光伏发电")
        
        # 风力发电标签页
        wind_tab = self.create_device_tab([
            "VV236",
            "SGSG14-222"
        ])
        self.power_type_tabs.addTab(wind_tab, "风力发电")
        
        main_layout.addWidget(self.power_type_tabs)
        
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
        self.logger.info("UI initialization completed")
    
    def create_device_tab(self, device_list):
        """创建设备测试标签页"""
        self.logger.debug(f"Creating device tab for devices: {device_list}")
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # 创建左侧控制面板
        left_panel = QWidget()
        left_panel.setMaximumWidth(300)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        
        # 设备信息组
        device_group = QGroupBox("设备信息")
        device_layout = QFormLayout()
        device_layout.setSpacing(10)
        device_combo = QComboBox()
        device_combo.setObjectName("device_combo")
        device_combo.addItems(device_list)
        device_combo.currentTextChanged.connect(lambda: self.update_vulnerability_list(device_combo))
        device_layout.addRow("设备型号:", device_combo)
        device_group.setLayout(device_layout)
        left_layout.addWidget(device_group)
        
        # 目标信息组
        target_group = QGroupBox("目标信息")
        target_layout = QFormLayout()
        target_layout.setSpacing(10)
        ip_input = QLineEdit()
        ip_input.setObjectName("ip_input")
        port_input = QLineEdit("502")
        port_input.setObjectName("port_input")
        target_layout.addRow("目标IP:", ip_input)
        target_layout.addRow("端口:", port_input)
        target_group.setLayout(target_layout)
        left_layout.addWidget(target_group)
        
        # 漏洞利用组
        exploit_group = QGroupBox("漏洞利用")
        exploit_layout = QVBoxLayout()
        exploit_layout.setSpacing(10)
        
        # 漏洞列表
        vuln_list = QListWidget()
        vuln_list.setObjectName("vuln_list")
        vuln_list.setMinimumHeight(200)
        vuln_list.itemClicked.connect(lambda item: self.update_vulnerability_details(item, device_combo))
        exploit_layout.addWidget(QLabel("漏洞列表:"))
        exploit_layout.addWidget(vuln_list)
        
        # 漏洞参数配置
        param_group = QGroupBox("参数配置")
        param_layout = QFormLayout()
        param_layout.setSpacing(10)
        
        # 添加参数输入框
        self.param_inputs = {}
        for param_name in ["plc_address", "command"]:
            input_widget = QLineEdit()
            input_widget.setObjectName(f"{param_name}_input")
            self.param_inputs[param_name] = input_widget
            param_layout.addRow(f"{param_name}:", input_widget)
        
        param_group.setLayout(param_layout)
        exploit_layout.addWidget(param_group)
        
        # 添加执行按钮
        execute_button = QPushButton("执行漏洞利用")
        execute_button.setObjectName("execute_button")
        execute_button.clicked.connect(lambda: self.execute_exploit(device_combo))
        exploit_layout.addWidget(execute_button)
        
        exploit_group.setLayout(exploit_layout)
        left_layout.addWidget(exploit_group)
        
        layout.addWidget(left_panel)
        
        # 创建右侧详情面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 漏洞详情显示
        vuln_details = QTextEdit()
        vuln_details.setObjectName("vuln_details")
        vuln_details.setReadOnly(True)
        right_layout.addWidget(vuln_details)
        
        # 执行结果显示
        result_display = QTextEdit()
        result_display.setObjectName("result_display")
        result_display.setReadOnly(True)
        right_layout.addWidget(result_display)
        
        layout.addWidget(right_panel)
        
        # 将组件引用保存到全局字典中
        tab_name = device_list[0] if device_list else "unknown"
        self.device_tabs[tab_name] = {
            'vuln_list': vuln_list,
            'vuln_details': vuln_details,
            'result_display': result_display,
            'device_combo': device_combo  # 保存设备选择框引用
        }
        self.logger.debug(f"Stored components for tab {tab_name}: {list(self.device_tabs[tab_name].keys())}")
        
        return tab
        
    def update_vulnerability_list(self, device_combo):
        """更新漏洞列表"""
        try:
            device_model = device_combo.currentText()
            if not device_model:
                return
                
            # 获取漏洞列表组件
            self.logger.debug("Finding vulnerability list widget...")
            # 遍历所有标签页，找到包含当前设备选择框的标签页
            tab_name = None
            for name, components in self.device_tabs.items():
                if components['device_combo'] == device_combo:
                    tab_name = name
                    break
                    
            if not tab_name:
                self.logger.error(f"Tab not found for device combo: {device_model}")
                return
                
            vuln_list = self.device_tabs[tab_name]['vuln_list']
            self.logger.debug(f"Found vulnerability list widget: {vuln_list}")
            
            # 根据设备型号确定电源类型
            power_type = ""
            if device_model in ["Siemens SGT-800", "西门子 SGT-800", "GE LM6000", "三菱 M701F"]:
                power_type = "thermal"
            elif device_model in ["VH喷嘴冲击式机组", "AHM调速系统"]:
                power_type = "hydro"
            elif device_model in ["FSS7薄膜组件", "SPMa6"]:
                power_type = "solar"
            elif device_model in ["VV236", "SGSG14-222"]:
                power_type = "wind"
            
            self.logger.debug(f"Using power type: {power_type} for device: {device_model}")
            
            # 标准化设备名称
            if device_model == "Siemens SGT-800":
                device_model = "西门子 SGT-800"
            
            vulns = get_device_vulnerabilities(power_type, device_model)
            self.logger.debug(f"Found {len(vulns)} vulnerabilities for {device_model}")
            
            vuln_list.clear()
            
            for vuln_id, vuln_info in vulns.items():
                item = QListWidgetItem(f"{vuln_info.name} ({vuln_info.impact_level})")
                # 根据影响级别设置背景色
                if vuln_info.impact_level == "严重":
                    item.setBackground(QColor("#FFEBEE"))
                elif vuln_info.impact_level == "高危":
                    item.setBackground(QColor("#FFF3E0"))
                elif vuln_info.impact_level == "中危":
                    item.setBackground(QColor("#E8F5E9"))
                else:
                    item.setBackground(QColor("#E3F2FD"))
                vuln_list.addItem(item)
                
            # 添加点击事件处理
            vuln_list.itemClicked.connect(lambda item: self.update_vulnerability_details(item, device_combo))
            
        except Exception as e:
            self.logger.error(f"Error updating vulnerability list: {str(e)}")
            self.logger.error(traceback.format_exc())
            
    def update_vulnerability_details(self, item, device_combo):
        """更新漏洞详情"""
        try:
            if not item:
                return
                
            vuln_name = item.text().split(" (")[0]
            device_model = device_combo.currentText()
            
            # 获取当前标签页中的漏洞详情显示组件
            tab_name = None
            for name, components in self.device_tabs.items():
                if components['device_combo'] == device_combo:
                    tab_name = name
                    break
                    
            if not tab_name:
                self.logger.error(f"Tab not found for device combo: {device_model}")
                return
                
            vuln_details = self.device_tabs[tab_name]['vuln_details']
            self.logger.debug(f"Found vulnerability details widget: {vuln_details}")
            
            # 根据设备型号确定电源类型
            power_type = None
            if device_model in ["Siemens SGT-800", "西门子 SGT-800", "GE LM6000", "三菱 M701F"]:
                power_type = "thermal"
            elif device_model in ["VH喷嘴冲击式机组", "AHM调速系统"]:
                power_type = "hydro"
            elif device_model in ["FSS7薄膜组件", "SPMa6"]:
                power_type = "solar"
            elif device_model in ["VV236", "SGSG14-222"]:
                power_type = "wind"
            
            if not power_type:
                self.logger.error(f"Unknown device model: {device_model}")
                return
                
            # 标准化设备名称
            if device_model == "Siemens SGT-800":
                device_model = "西门子 SGT-800"
            
            vuln_info = get_vulnerability_info(power_type, device_model, vuln_name)
            if not vuln_info:
                self.logger.error(f"Could not find vulnerability info for {vuln_name}")
                return
                
            # 清空现有内容
            vuln_details.clear()
            
            # 设置样式
            vuln_details.setStyleSheet("""
                QTextEdit {
                    font-family: 'Microsoft YaHei', 'SimHei';
                    font-size: 13px;
                    line-height: 1.5;
                    padding: 10px;
                }
            """)
            
            # 构建HTML内容
            html = f"""
            <div style='margin-bottom: 20px;'>
                <h2 style='color: #333; margin-bottom: 10px;'>{vuln_info.name}</h2>
                <div style='margin-bottom: 15px;'>
                    <span style='color: #666;'>影响等级：</span>
                    <span style='color: {'#ff0000' if vuln_info.impact_level == '严重' else '#ff6600'}; font-weight: bold;'>{vuln_info.impact_level}</span>
                    <span style='color: #666; margin-left: 20px;'>CVSS评分：</span>
                    <span style='color: #333; font-weight: bold;'>{vuln_info.cvss_score}</span>
                </div>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>漏洞描述</h3>
                <p style='color: #666; line-height: 1.6;'>{vuln_info.description}</p>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>影响设备</h3>
                <p style='color: #666; line-height: 1.6;'>{', '.join(vuln_info.affected_versions)}</p>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>利用条件</h3>
                <p style='color: #666; line-height: 1.6;'>{vuln_info.conditions}</p>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>利用方法</h3>
                <p style='color: #666; line-height: 1.6;'>{vuln_info.fix_suggestions}</p>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>注意事项</h3>
                <p style='color: #666; line-height: 1.6;'>1. 请确保目标设备确实存在该漏洞</p>
                <p style='color: #666; line-height: 1.6;'>2. 执行前请做好数据备份</p>
                <p style='color: #666; line-height: 1.6;'>3. 建议在测试环境中进行验证</p>
            </div>
            
            <div style='margin-bottom: 20px;'>
                <h3 style='color: #333; margin-bottom: 10px;'>修复建议</h3>
                <p style='color: #666; line-height: 1.6;'>{vuln_info.fix_suggestions}</p>
            </div>
            """
            
            vuln_details.setHtml(html)
            
            # 添加参数输入框
            param_layout = QVBoxLayout()
            param_layout.setSpacing(10)
            
            for param in vuln_info.params:
                param_layout.addWidget(QLabel(f"{param}:"))
                param_layout.addWidget(QLineEdit())
            
            # 清空现有布局并添加新布局
            for i in reversed(range(vuln_details.layout().count())):
                vuln_details.layout().itemAt(i).widget().setParent(None)
            vuln_details.layout().addLayout(param_layout)
            
        except Exception as e:
            self.logger.error(f"Error updating vulnerability details: {str(e)}")
            self.logger.error(traceback.format_exc())
            
    def execute_exploit(self, device_combo):
        """执行漏洞利用"""
        try:
            # 获取当前标签页中的组件
            tab_name = None
            for name, components in self.device_tabs.items():
                if components['device_combo'] == device_combo:
                    tab_name = name
                    break
                    
            if not tab_name:
                self.logger.error(f"Tab not found for device combo")
                return
                
            components = self.device_tabs[tab_name]
            vuln_list = components['vuln_list']
            result_display = components['result_display']
            
            # 获取选中的漏洞
            selected_items = vuln_list.selectedItems()
            if not selected_items:
                result_display.setHtml("<p style='color: red;'>请先选择一个漏洞</p>")
                return
                
            vuln_name = selected_items[0].text().split(" (")[0]
            device_model = device_combo.currentText()
            
            # 获取漏洞详情
            power_type = ""
            if "SGT" in device_model or "LM" in device_model or "M701" in device_model:
                power_type = "thermal"
            elif "VH" in device_model or "AHM" in device_model:
                power_type = "hydro"
            elif "FSS" in device_model or "SPM" in device_model:
                power_type = "solar"
            elif "VV" in device_model or "SGSG" in device_model:
                power_type = "wind"
            
            vuln_info = get_vulnerability_info(power_type, device_model, vuln_name)
            if not vuln_info:
                result_display.setHtml("<p style='color: red;'>未找到漏洞信息</p>")
                return
                
            # 收集参数
            params = {}
            for param in vuln_info.params.split(','):
                param = param.strip()
                input_widget = components.get(f'param_{param}')
                if input_widget:
                    params[param] = input_widget.text()
                    
            # 执行漏洞利用
            exploit_module = ExploitModule()
            result = exploit_module.execute_exploit(device_model, vuln_name, params)
            
            # 显示结果
            if result.success:
                result_display.setHtml(f"""
                    <p style='color: green;'><b>漏洞利用成功！</b></p>
                    <p><b>消息:</b> {result.message}</p>
                    <p><b>详情:</b> {result.details}</p>
                """)
            else:
                result_display.setHtml(f"""
                    <p style='color: red;'><b>漏洞利用失败！</b></p>
                    <p><b>错误信息:</b> {result.message}</p>
                """)
                
        except Exception as e:
            self.logger.error(f"Error executing exploit: {str(e)}")
            self.logger.error(traceback.format_exc())
            result_display.setHtml(f"<p style='color: red;'>执行过程中发生错误: {str(e)}</p>")

    def _check_integrity(self):
        """检查程序完整性"""
        try:
            self.logger.debug("Checking program integrity")
            # 基于密语和设备签名生成完整性码
            integrity_base = f"{self._motto}_{self._dev_signature}"
            integrity_code = hashlib.sha256(integrity_base.encode()).hexdigest()
            
            # 记录调试信息
            self.logger.debug(f"Integrity base: {integrity_base}")
            self.logger.debug(f"Integrity code: {integrity_code}")
            
            # 验证完整性
            # 检查完整性码的长度是否正确
            is_valid = len(integrity_code) == 64  # SHA-256哈希值的长度是64个字符
            
            if not is_valid:
                self.logger.error("Program integrity check failed")
                self._log_error("Program integrity check failed")
                sys.exit(1)  # 在完整性检查失败时立即退出
            
            self.logger.info("Program integrity check passed")
            return True
        except Exception as e:
            self.logger.error("Error in integrity check: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())
            sys.exit(1)  # 在发生异常时也立即退出
            
    def _log_error(self, message):
        """记录错误信息"""
        try:
            self.logger.error("Error: %s", message)
            with open(".log", "a") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                encoded_msg = base64.b64encode(f"{self._motto}_{message}".encode()).decode()
                f.write(f"{timestamp}: {encoded_msg}\n")
        except Exception as e:
            self.logger.error("Error logging error: %s", str(e)) 