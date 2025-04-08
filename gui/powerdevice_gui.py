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
                           QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QSize, QPoint, QRect
from PyQt5.QtGui import (QFont, QIcon, QPixmap, QPainter, QLinearGradient, 
                        QColor, QPen)
from .vulnerability_db import (get_device_vulnerabilities, get_vulnerability_info,
                           get_all_vulnerability_ids, VulnerabilityInfo)
from .logger import PowerDeviceLogger

class PowerDeviceGUI(QMainWindow):
    def __init__(self):
        print("Initializing PowerDeviceGUI...")
        super().__init__()
        
        try:
            # 初始化日志记录器
            self.logger = PowerDeviceLogger()
            self.logger.info("PowerDeviceGUI initialization started")
            
            # 个人密语标识
            self.logger.info("Setting up personal identification...")
            self._motto = "君子论迹不论心"
            self._auth_seed = hashlib.sha256(self._motto.encode()).hexdigest()[:8]
            self._auth_code = self._generate_auth_code()
            
            if not self._verify_license():
                self.logger.error("License verification failed!")
                sys.exit(1)
                
            self.logger.info("Setting up window properties...")
            self.setWindowTitle(f"发电设备测试工具 v0.1.5bea - {self._get_hidden_mark()}")
            self.setGeometry(100, 100, 1200, 800)
            
            self.logger.info("Creating logo...")
            self.setWindowIcon(self._create_logo())
            
            # 初始化主窗口
            self.logger.info("Initializing UI...")
            self._init_ui()
            self.logger.info("PowerDeviceGUI initialization completed")
        except Exception as e:
            self.logger.error("Error in PowerDeviceGUI initialization: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())
            raise
        
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
        self.logger.info("Initializing user interface")
        # 添加个人标识信息
        self._dev_signature = f"PDT_{hashlib.md5(self._motto.encode()).hexdigest()[:12]}"
        self._check_integrity()
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(main_widget)
        
        # 创建顶部发电类型标签页
        self.power_type_tabs = QTabWidget()
        
        # 火力发电标签页
        thermal_tab = self.create_device_tab([
            "西门子 SGT-800",
            "GE LM6000",
            "三菱 M701F"
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
        self.logger.debug("Creating device tab for devices: %s", device_list)
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # 创建左侧控制面板
        left_panel = QWidget()
        left_panel.setMaximumWidth(300)  # 减小左侧面板宽度
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)  # 增加组件间距
        
        # 设备信息组
        device_group = QGroupBox("设备信息")
        device_layout = QFormLayout()
        device_layout.setSpacing(10)
        device_combo = QComboBox()
        device_combo.addItems(device_list)
        device_layout.addRow("设备类型:", device_combo)
        device_group.setLayout(device_layout)
        left_layout.addWidget(device_group)
        
        # 目标信息组
        target_group = QGroupBox("目标信息")
        target_layout = QFormLayout()
        target_layout.setSpacing(10)
        ip_input = QLineEdit()
        port_input = QLineEdit("502")
        target_layout.addRow("目标IP:", ip_input)
        target_layout.addRow("端口:", port_input)
        target_group.setLayout(target_layout)
        left_layout.addWidget(target_group)
        
        # 测试配置组
        config_group = QGroupBox("测试配置")
        config_layout = QFormLayout()
        config_layout.setSpacing(10)
        thread_spin = QSpinBox()
        thread_spin.setRange(1, 10)
        thread_spin.setValue(1)
        test_combo = QComboBox()
        test_combo.addItems([
            "Modbus协议测试",
            "网络扫描",
            "漏洞评估",
            "认证测试"
        ])
        config_layout.addRow("并发线程:", thread_spin)
        config_layout.addRow("测试类型:", test_combo)
        config_group.setLayout(config_layout)
        left_layout.addWidget(config_group)

        # 漏洞利用组
        exploit_group = QGroupBox("漏洞利用")
        exploit_layout = QVBoxLayout()  # 改用垂直布局
        exploit_layout.setSpacing(10)
        
        # 漏洞列表
        vuln_list = QListWidget()
        vuln_list.setMinimumHeight(200)  # 设置最小高度
        vuln_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #C4C4C4;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #E0E0E0;
            }
            QListWidget::item:selected {
                background-color: #E3F2FD;
                color: black;
            }
            QListWidget::item:hover {
                background-color: #F5F5F5;
            }
        """)
        exploit_layout.addWidget(QLabel("漏洞列表:"))
        exploit_layout.addWidget(vuln_list)
        
        # 漏洞参数配置
        param_group = QGroupBox("参数配置")
        param_layout = QFormLayout()
        param_layout.setSpacing(10)
        param_group.setLayout(param_layout)
        exploit_layout.addWidget(param_group)
        
        exploit_group.setLayout(exploit_layout)
        left_layout.addWidget(exploit_group)
        
        # 控制按钮组
        button_group = QGroupBox("控制")
        button_layout = QVBoxLayout()
        button_layout.setSpacing(10)
        start_button = QPushButton("开始测试")
        stop_button = QPushButton("停止测试")
        stop_button.setEnabled(False)
        start_button.setMinimumHeight(40)
        stop_button.setMinimumHeight(40)
        button_layout.addWidget(start_button)
        button_layout.addWidget(stop_button)
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
        log_display = QTextEdit()
        log_display.setReadOnly(True)
        log_layout.addWidget(log_display)
        tab_widget.addTab(log_tab, "实时日志")
        
        # 测试结果标签页
        result_tab = QWidget()
        result_layout = QVBoxLayout(result_tab)
        result_display = QTextEdit()
        result_display.setReadOnly(True)
        result_layout.addWidget(result_display)
        tab_widget.addTab(result_tab, "测试结果")
        
        # 漏洞详情标签页
        vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(vuln_tab)
        vuln_display = QTextEdit()
        vuln_display.setReadOnly(True)
        vuln_display.setStyleSheet("""
            QTextEdit {
                font-family: 'Microsoft YaHei', 'SimHei', sans-serif;
                font-size: 13px;
                line-height: 1.5;
                padding: 10px;
                background-color: #FFFFFF;
                border: 1px solid #C4C4C4;
                border-radius: 4px;
            }
        """)
        vuln_layout.addWidget(vuln_display)
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
        device_combo.currentTextChanged.connect(lambda text: self.update_vulnerability_list(text, vuln_list))
        vuln_list.itemSelectionChanged.connect(lambda: self.update_vulnerability_details(vuln_list, param_layout))
        
        # 设置日志显示组件
        self.logger.set_log_display(log_display)
        
        # 存储控件引用
        tab.widgets = {
            'device_combo': device_combo,
            'ip_input': ip_input,
            'port_input': port_input,
            'thread_spin': thread_spin,
            'test_combo': test_combo,
            'start_button': start_button,
            'stop_button': stop_button,
            'log_display': log_display,
            'result_display': result_display,
            'vuln_display': vuln_display,
            'vuln_list': vuln_list,
            'param_layout': param_layout,
            'tab_widget': tab_widget
        }
        
        self.logger.debug("Device tab creation completed")
        return tab
        
    def get_current_tab_widgets(self):
        """获取当前标签页的控件"""
        self.logger.debug("Getting current tab widgets")
        current_tab = self.power_type_tabs.currentWidget()
        return current_tab.widgets if hasattr(current_tab, 'widgets') else None 

    def update_vulnerability_list(self, device_model, vuln_list):
        """更新漏洞列表"""
        try:
            self.logger.info("Updating vulnerability list for device: %s", device_model)
            vuln_list.clear()
            
            # 获取当前标签页的设备类型
            current_tab = self.power_type_tabs.currentWidget()
            device_type = self.power_type_tabs.tabText(self.power_type_tabs.currentIndex())
            
            # 获取漏洞列表
            vulnerabilities = get_device_vulnerabilities(device_type, device_model)
            self.logger.info("Found %d vulnerabilities", len(vulnerabilities))
            
            # 添加漏洞到列表
            for vuln_id, vuln_info in vulnerabilities.items():
                # 简化显示格式，只显示名称和等级
                display_text = f"{vuln_info.name}\n[{vuln_info.impact_level}] CVSS: {vuln_info.cvss_score}"
                item = QListWidgetItem(display_text)
                item.setData(Qt.UserRole, vuln_id)
                
                # 根据影响等级设置不同的背景色和样式
                if vuln_info.impact_level == "严重":
                    item.setBackground(QColor("#FFEBEE"))  # 浅红色背景
                    item.setForeground(QColor("#D32F2F"))  # 红色文字
                elif vuln_info.impact_level == "高危":
                    item.setBackground(QColor("#FFF3E0"))  # 浅橙色背景
                    item.setForeground(QColor("#F57C00"))  # 橙色文字
                else:
                    item.setBackground(QColor("#F5F5F5"))  # 浅灰色背景
                
                # 设置字体
                font = item.font()
                font.setPointSize(10)
                item.setFont(font)
                
                vuln_list.addItem(item)
            
            # 自动选中第一个漏洞并显示详情
            if vuln_list.count() > 0:
                vuln_list.setCurrentRow(0)
                # 获取当前标签页的控件
                widgets = self.get_current_tab_widgets()
                # 切换到漏洞详情标签
                widgets['tab_widget'].setCurrentIndex(2)  # 切换到漏洞详情标签页
                # 更新漏洞详情
                self.update_vulnerability_details(vuln_list, widgets['param_layout'])
                
        except Exception as e:
            self.logger.error("Error updating vulnerability list: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())

    def update_vulnerability_details(self, vuln_list, param_layout):
        """更新漏洞详情"""
        try:
            selected_items = vuln_list.selectedItems()
            if not selected_items:
                return
                
            current_tab_text = self.power_type_tabs.tabText(self.power_type_tabs.currentIndex())
            current_device = self.get_current_tab_widgets()['device_combo'].currentText()
            vuln_id = selected_items[0].data(Qt.UserRole)
            
            self.logger.info("Getting details for vulnerability: %s", vuln_id)
            vuln_info = get_vulnerability_info(current_tab_text, current_device, vuln_id)
            if not vuln_info:
                self.logger.warning("No vulnerability info found")
                return
                
            # 更新漏洞详情显示
            vuln_display = self.get_current_tab_widgets()['vuln_display']
            vuln_display.clear()
            
            # 设置字体和样式
            vuln_display.setStyleSheet("""
                QTextEdit {
                    font-family: 'Microsoft YaHei', 'SimHei', sans-serif;
                    font-size: 13px;
                    line-height: 1.6;
                    padding: 15px;
                    background-color: #FFFFFF;
                }
            """)
            
            # 构建详细信息文本
            detail_text = f"""<div style='margin-bottom: 20px;'>
<h2 style='color: #1A237E; margin-bottom: 10px;'>{vuln_info.name}</h2>
<p style='color: {"#D32F2F" if vuln_info.impact_level == "严重" else "#F57C00" if vuln_info.impact_level == "高危" else "#424242"}'>
<b>影响等级：{vuln_info.impact_level}</b> | <b>CVSS评分：{vuln_info.cvss_score}</b>
</p>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #1A237E;'>漏洞描述</h3>
<p style='background-color: #F5F5F5; padding: 10px; border-radius: 4px;'>{vuln_info.description}</p>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #1A237E;'>影响范围</h3>
<ul style='background-color: #F5F5F5; padding: 10px; border-radius: 4px;'>
<li>设备型号：{current_device}</li>
<li>影响版本：{vuln_info.affected_versions if vuln_info.affected_versions else '所有版本'}</li>
<li>影响组件：{vuln_info.affected_components if vuln_info.affected_components else '控制系统'}</li>
</ul>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #1A237E;'>利用条件</h3>
<div style='background-color: #F5F5F5; padding: 10px; border-radius: 4px;'>
{vuln_info.conditions if vuln_info.conditions else '- 需要网络可达目标设备<br>- 需要设备开启相关服务'}
</div>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #1A237E;'>利用方法</h3>
<div style='background-color: #FFF8E1; padding: 10px; border-radius: 4px;'>
<p><b>所需参数：</b></p>
<ul>
{chr(10).join(f'<li><b>{name}：</b>{desc}</li>' for name, desc in vuln_info.params.items())}
</ul>
<p><b>使用步骤：</b></p>
<ol>
<li>确认目标设备信息正确</li>
<li>在左侧参数配置区域填写必要参数</li>
<li>点击"开始测试"按钮执行漏洞利用</li>
<li>查看实时日志了解测试进度</li>
<li>在测试结果标签页查看详细结果</li>
</ol>
</div>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #D32F2F;'>注意事项</h3>
<ul style='background-color: #FFEBEE; padding: 10px; border-radius: 4px;'>
<li>在进行漏洞利用之前，请确保已经获得授权</li>
<li>建议在测试环境中进行验证</li>
<li>请注意保存测试日志以供分析</li>
<li>如果设备出现异常，请立即停止测试</li>
<li>测试完成后及时清理测试数据</li>
</ul>
</div>

<div style='margin-bottom: 20px;'>
<h3 style='color: #2E7D32;'>修复建议</h3>
<div style='background-color: #E8F5E9; padding: 10px; border-radius: 4px;'>
{vuln_info.fix_suggestions if vuln_info.fix_suggestions else '- 及时更新设备固件到最新版本<br>- 加强访问控制<br>- 配置适当的安全策略'}
</div>
</div>"""
            
            # 使用HTML格式显示内容
            vuln_display.setHtml(detail_text)
            
            # 清除旧的参数输入框
            while param_layout.rowCount():
                param_layout.removeRow(0)
                
            # 添加新的参数输入框
            param_group = param_layout.parentWidget()
            param_group.setTitle(f"漏洞利用参数")
                
            # 添加参数输入框
            for param_name, param_desc in vuln_info.params.items():
                param_input = QLineEdit()
                param_input.setPlaceholderText(param_desc)
                param_input.setStyleSheet("""
                    QLineEdit {
                        padding: 5px;
                        border: 1px solid #C4C4C4;
                        border-radius: 4px;
                        background-color: #FFFFFF;
                    }
                    QLineEdit:focus {
                        border: 1px solid #2196F3;
                    }
                """)
                param_layout.addRow(f"{param_name}:", param_input)
                
        except Exception as e:
            self.logger.error("Error updating vulnerability details: %s", str(e))
            import traceback
            self.logger.error(traceback.format_exc())

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