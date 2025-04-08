import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QComboBox, QLineEdit, 
                           QPushButton, QTextEdit, QSpinBox, QGroupBox,
                           QTabWidget, QFormLayout, QSplitter, QFrame,
                           QTableWidget, QTableWidgetItem, QHeaderView,
                           QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon
from vulnerability_db import (get_device_vulnerabilities, get_vulnerability_info,
                          get_all_vulnerability_ids, VulnerabilityInfo)

class PowerDeviceGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("发电设备测试工具 v0.1.4bea")
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
            "西门子 SGT-800",
            "GE LM6000",
            "三菱 M701F",
            "GE 9HA.02",
            "西门子 SGT5-8000H",
            "三菱 M701JAC",
            "GE HA-Predix",
            "西门子 SGT-6000"
        ])
        self.power_type_tabs.addTab(thermal_tab, "火力发电")
        
        # 水利发电标签页
        hydro_tab = self.create_device_tab([
            "VH喷嘴冲击式机组",
            "AHM调速系统",
            "GEHydro数字水轮机",
            "ABB水电站控制系统"
        ])
        self.power_type_tabs.addTab(hydro_tab, "水利发电")
        
        # 光伏发电标签页
        solar_tab = self.create_device_tab([
            "FSS7薄膜组件",
            "SPMa6",
            "FusionSolar",
            "NeNXH-XTR"
        ])
        self.power_type_tabs.addTab(solar_tab, "光伏发电")
        
        # 风力发电标签页
        wind_tab = self.create_device_tab([
            "VV236",
            "SGSG14-222",
            "GEC数字风机",
            "金风科技智能机组",
            "ABB Ability™ SXcelerator",
            "GEDWF"
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
    
    def create_device_tab(self, device_list):
        """创建设备测试标签页"""
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
            'param_layout': param_layout
        }
        
        return tab
    
    def get_current_tab_widgets(self):
        """获取当前标签页的控件"""
        current_tab = self.power_type_tabs.currentWidget()
        return current_tab.widgets if hasattr(current_tab, 'widgets') else None 

    def update_vulnerability_list(self, device_model, vuln_list):
        """更新漏洞列表"""
        vuln_list.clear()
        current_tab_text = self.power_type_tabs.tabText(self.power_type_tabs.currentIndex())
        vulns = get_device_vulnerabilities(current_tab_text, device_model)
        
        for vuln_id, vuln_info in vulns.items():
            item = QListWidgetItem(vuln_info.name)
            item.setData(Qt.UserRole, vuln_id)
            item.setToolTip(f"漏洞ID: {vuln_id}\n影响等级: {vuln_info.impact_level}\nCVSS评分: {vuln_info.cvss_score}")
            vuln_list.addItem(item)
    
    def update_vulnerability_details(self, vuln_list, param_layout):
        """更新漏洞详情"""
        selected_items = vuln_list.selectedItems()
        if not selected_items:
            return
            
        current_tab_text = self.power_type_tabs.tabText(self.power_type_tabs.currentIndex())
        current_device = self.get_current_tab_widgets()['device_combo'].currentText()
        vuln_id = selected_items[0].data(Qt.UserRole)
        
        vuln_info = get_vulnerability_info(current_tab_text, current_device, vuln_id)
        if not vuln_info:
            return

        # 更新漏洞详情显示
        vuln_display = self.get_current_tab_widgets()['vuln_display']
        vuln_display.clear()
        
        # 设置红色文本颜色
        vuln_display.setTextColor(Qt.red)
        
        # 构建详细信息文本
        detail_text = f"""漏洞名称：{vuln_info.name}
漏洞ID：{vuln_id}
影响等级：{vuln_info.impact_level}
CVSS评分：{vuln_info.cvss_score}

详细描述：
{vuln_info.description}

利用条件：
{vuln_info.conditions if hasattr(vuln_info, 'conditions') else '- 需要网络可达目标设备\n- 需要设备开启相关服务'}

利用注意事项：
- 在进行漏洞利用之前，请确保已经获得授权
- 建议在测试环境中进行验证
- 请注意保存测试日志以供分析
- 如果设备出现异常，请立即停止测试
- 测试完成后及时清理测试数据

影响范围：
- 设备型号：{current_device}
- 影响版本：{vuln_info.affected_versions if hasattr(vuln_info, 'affected_versions') else '所有版本'}
- 影响组件：{vuln_info.affected_components if hasattr(vuln_info, 'affected_components') else '控制系统'}

修复建议：
{vuln_info.fix_suggestions if hasattr(vuln_info, 'fix_suggestions') else '- 及时更新设备固件到最新版本\n- 加强访问控制\n- 配置适当的安全策略'}
"""
        vuln_display.append(detail_text)
        
        # 清除旧的参数输入框
        while param_layout.rowCount():
            param_layout.removeRow(0)
            
        # 添加新的参数输入框
        param_group = param_layout.parentWidget()
        param_group.setTitle(f"漏洞利用参数 - {vuln_info.name}")
        
        for param_name, param_desc in vuln_info.params.items():
            param_input = QLineEdit()
            param_input.setPlaceholderText(param_desc)
            param_layout.addRow(f"{param_name}:", param_input) 