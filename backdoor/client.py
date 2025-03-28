import sys
import socket
import json
import base64
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                           QLineEdit, QTextEdit, QMessageBox, QTabWidget,
                           QTableWidget, QTableWidgetItem, QTreeWidget,
                           QTreeWidgetItem, QHeaderView, QStyle, QGroupBox,
                           QComboBox, QSpinBox, QCheckBox, QFormLayout,
                           QDialog, QInputDialog)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QImage, QPixmap, QIcon
import os
from datetime import datetime
import platform
import logging
from PIL import Image
import io
import subprocess
import psutil
from PIL import ImageGrab
import tempfile

# 配置日志
def setup_logger(name):
    # 创建日志目录
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log')
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建日志文件名（包含时间戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f'{name}_{timestamp}.log')
    
    # 配置日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # 创建文件处理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    # 创建格式化器
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 创建客户端日志记录器
logger = setup_logger('client')

class RemoteClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.socket = None
        self.connected = False
        self.current_path = os.path.expanduser("~")
        self.is_windows = platform.system() == 'Windows'
        self.base_font_size = 12  # 基础字体大小
        self.initUI()
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.update_processes)
        self.process_timer.setInterval(5000)  # Update every 5 seconds
        
        # 添加窗口大小变化事件处理
        self.resizeEvent = self.on_resize
        logger.info("客户端初始化完成")

    def on_resize(self, event):
        # 计算缩放因子
        width = self.width()
        height = self.height()
        base_width = 1400
        base_height = 900
        width_scale = width / base_width
        height_scale = height / base_height
        scale_factor = min(width_scale, height_scale)
        
        # 计算新的字体大小
        new_font_size = int(self.base_font_size * scale_factor)
        new_font_size = max(8, min(16, new_font_size))  # 限制字体大小范围
        
        # 更新样式表
        self.update_style_sheet(new_font_size)
        
        # 更新标题字体大小
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            for child in tab.findChildren(QLabel):
                if child.text() in ["远程屏幕", "文件管理器", "进程管理器", "命令提示符", "控制端生成器"]:
                    child.setStyleSheet(f"font-size: {new_font_size + 2}px; font-weight: bold;")
        
        # 更新组框标题字体大小
        for group in self.findChildren(QGroupBox):
            group.setStyleSheet(f"""
                QGroupBox {{
                    font-size: {new_font_size + 2}px;
                    font-weight: bold;
                }}
            """)
        
        super().resizeEvent(event)

    def update_style_sheet(self, font_size):
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: #FFFFFF;
                color: #000000;
            }}
            QPushButton {{
                background-color: #007ACC;
                color: white;
                border: none;
                padding: {max(6, int(font_size * 0.8))}px {max(12, int(font_size * 1.5))}px;
                border-radius: 4px;
                font-weight: bold;
                font-size: {font_size}px;
                min-width: {max(80, int(font_size * 8))}px;
            }}
            QPushButton:hover {{
                background-color: #1A8CD8;
            }}
            QPushButton:pressed {{
                background-color: #2D9CDB;
            }}
            QPushButton:disabled {{
                background-color: #CCCCCC;
            }}
            QLineEdit {{
                padding: {max(6, int(font_size * 0.8))}px;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                color: #000000;
                font-size: {font_size}px;
            }}
            QLineEdit:focus {{
                border-color: #007ACC;
            }}
            QLabel {{
                color: #000000;
                font-size: {font_size}px;
            }}
            QTabWidget::pane {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
            }}
            QTabBar::tab {{
                background-color: #F0F0F0;
                padding: {max(6, int(font_size * 0.8))}px {max(12, int(font_size * 1.5))}px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: bold;
                font-size: {font_size}px;
                color: #000000;
            }}
            QTabBar::tab:selected {{
                background-color: #007ACC;
                color: white;
            }}
            QTableWidget {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                gridline-color: #CCCCCC;
                color: #000000;
                font-size: {font_size}px;
            }}
            QTableWidget::item {{
                padding: {max(4, int(font_size * 0.5))}px;
                border-bottom: 1px solid #CCCCCC;
            }}
            QTableWidget::item:selected {{
                background-color: #007ACC;
                color: white;
            }}
            QHeaderView::section {{
                background-color: #F0F0F0;
                padding: {max(6, int(font_size * 0.8))}px;
                border: none;
                font-weight: bold;
                font-size: {font_size}px;
                color: #000000;
            }}
            QTextEdit {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                color: #000000;
                font-size: {font_size}px;
                padding: {max(6, int(font_size * 0.8))}px;
            }}
            QTextEdit:focus {{
                border-color: #007ACC;
            }}
            QTreeWidget {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                color: #000000;
                font-size: {font_size}px;
            }}
            QTreeWidget::item {{
                padding: {max(4, int(font_size * 0.5))}px;
                border-bottom: 1px solid #CCCCCC;
            }}
            QTreeWidget::item:selected {{
                background-color: #007ACC;
                color: white;
            }}
            QGroupBox {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                margin-top: {max(8, int(font_size * 1.2))}px;
                padding-top: {max(12, int(font_size * 1.8))}px;
                font-weight: bold;
                font-size: {font_size + 2}px;
                color: #000000;
                background-color: #FFFFFF;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: {max(8, int(font_size * 1.2))}px;
                padding: 0 {max(4, int(font_size * 0.5))}px;
            }}
            QComboBox {{
                padding: {max(6, int(font_size * 0.8))}px;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                color: #000000;
                font-size: {font_size}px;
                min-width: {max(120, int(font_size * 12))}px;
            }}
            QComboBox:focus {{
                border-color: #007ACC;
            }}
            QComboBox::drop-down {{
                border: none;
                width: {max(16, int(font_size * 1.5))}px;
            }}
            QComboBox::down-arrow {{
                image: url(down_arrow.png);
                width: {max(8, int(font_size * 0.8))}px;
                height: {max(8, int(font_size * 0.8))}px;
            }}
            QSpinBox {{
                padding: {max(6, int(font_size * 0.8))}px;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #FFFFFF;
                color: #000000;
                font-size: {font_size}px;
                min-width: {max(60, int(font_size * 6))}px;
            }}
            QSpinBox:focus {{
                border-color: #007ACC;
            }}
            QCheckBox {{
                font-size: {font_size}px;
                color: #000000;
            }}
            QCheckBox::indicator {{
                width: {max(12, int(font_size * 1.2))}px;
                height: {max(12, int(font_size * 1.2))}px;
            }}
            QStatusBar {{
                background-color: #F0F0F0;
                color: #000000;
                padding: {max(4, int(font_size * 0.5))}px;
                font-size: {font_size}px;
                border-top: 1px solid #CCCCCC;
            }}
        """)

    def initUI(self):
        self.setWindowTitle('远程桌面管理器')
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # Connection section with modern design
        conn_group = QGroupBox("连接设置")
        conn_layout = QHBoxLayout()
        conn_layout.setSpacing(10)
        
        # Host input with icon
        host_container = QWidget()
        host_layout = QHBoxLayout(host_container)
        host_icon = QLabel()
        host_icon.setPixmap(self.style().standardIcon(QStyle.SP_ComputerIcon).pixmap(24, 24))
        host_layout.addWidget(host_icon)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText('主机IP')
        self.host_input.setText('localhost')
        host_layout.addWidget(self.host_input)
        
        # Port input with icon
        port_container = QWidget()
        port_layout = QHBoxLayout(port_container)
        port_icon = QLabel()
        port_icon.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(24, 24))
        port_layout.addWidget(port_icon)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('端口')
        self.port_input.setText('5001')
        port_layout.addWidget(self.port_input)
        
        # Connect button with icon
        self.connect_btn = QPushButton('连接')
        self.connect_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.connect_btn.setIconSize(QSize(24, 24))
        self.connect_btn.clicked.connect(self.toggle_connection)
        
        conn_layout.addWidget(host_container)
        conn_layout.addWidget(port_container)
        conn_layout.addWidget(self.connect_btn)
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)

        # Create tab widget with modern design
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        layout.addWidget(self.tab_widget)

        # File manager tab with modern design
        file_tab = QWidget()
        file_layout = QVBoxLayout(file_tab)
        file_layout.setContentsMargins(10, 10, 10, 10)
        
        file_header = QHBoxLayout()
        file_title = QLabel("文件管理器")
        file_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        file_header.addWidget(file_title)
        file_layout.addLayout(file_header)
        
        # File operations buttons with modern design
        file_buttons = QHBoxLayout()
        self.upload_btn = QPushButton('上传文件')
        self.upload_btn.setIcon(self.style().standardIcon(QStyle.SP_ArrowUp))
        self.upload_btn.setIconSize(QSize(24, 24))
        self.upload_btn.clicked.connect(self.upload_file)
        
        self.download_btn = QPushButton('下载文件')
        self.download_btn.setIcon(self.style().standardIcon(QStyle.SP_ArrowDown))
        self.download_btn.setIconSize(QSize(24, 24))
        self.download_btn.clicked.connect(self.download_file)
        
        file_buttons.addWidget(self.upload_btn)
        file_buttons.addWidget(self.download_btn)
        file_buttons.addStretch()
        file_layout.addLayout(file_buttons)

        # File browser with modern design
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(['名称', '类型', '大小', '修改时间'])
        self.file_tree.itemDoubleClicked.connect(self.navigate_directory)
        self.file_tree.setColumnWidth(0, 300)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.setColumnWidth(2, 100)
        self.file_tree.setColumnWidth(3, 150)
        file_layout.addWidget(self.file_tree)
        self.tab_widget.addTab(file_tab, "文件管理器")

        # Process manager tab with modern design
        process_tab = QWidget()
        process_layout = QVBoxLayout(process_tab)
        process_layout.setContentsMargins(10, 10, 10, 10)
        
        process_header = QHBoxLayout()
        process_title = QLabel("进程管理器")
        process_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        process_header.addWidget(process_title)
        process_layout.addLayout(process_header)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(['进程ID', '名称', 'CPU使用率', '内存使用率'])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        process_layout.addWidget(self.process_table)
        self.tab_widget.addTab(process_tab, "进程管理器")

        # Command execution tab with modern design
        cmd_tab = QWidget()
        cmd_layout = QVBoxLayout(cmd_tab)
        cmd_layout.setContentsMargins(10, 10, 10, 10)
        
        cmd_header = QHBoxLayout()
        cmd_title = QLabel("命令提示符")
        cmd_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        cmd_header.addWidget(cmd_title)
        cmd_layout.addLayout(cmd_header)
        
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText('输入命令...')
        self.cmd_input.returnPressed.connect(self.execute_command)
        cmd_layout.addWidget(self.cmd_input)
        
        self.cmd_output = QTextEdit()
        self.cmd_output.setReadOnly(True)
        self.cmd_output.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        cmd_layout.addWidget(self.cmd_output)
        self.tab_widget.addTab(cmd_tab, "命令提示符")

        # System info section with modern design
        info_group = QGroupBox("系统信息")
        info_layout = QVBoxLayout(info_group)
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(150)
        info_layout.addWidget(self.info_text)
        layout.addWidget(info_group)

        # Status bar with modern design
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background-color: #E0E0E0;
                color: #333333;
                padding: 5px;
            }
        """)
        self.statusBar().showMessage('未连接')

        # Initialize button states
        self.update_button_states(False)

        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        # Add Generator tab with modern design
        generator_tab = QWidget()
        generator_layout = QVBoxLayout(generator_tab)
        generator_layout.setContentsMargins(10, 10, 10, 10)
        
        generator_header = QHBoxLayout()
        generator_title = QLabel("控制端生成器")
        generator_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        generator_header.addWidget(generator_title)
        generator_layout.addLayout(generator_header)

        # Generator form
        form_group = QGroupBox("生成配置")
        form_layout = QFormLayout()

        # Platform selection
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(['Windows', 'macOS', 'Linux'])
        form_layout.addRow("目标平台:", self.platform_combo)

        # Connection settings
        self.host_config = QLineEdit()
        self.host_config.setText('localhost')
        form_layout.addRow("连接地址:", self.host_config)

        self.port_config = QSpinBox()
        self.port_config.setRange(1, 65535)
        self.port_config.setValue(5001)
        form_layout.addRow("连接端口:", self.port_config)

        # Features selection
        self.feature_file = QCheckBox("文件管理")
        self.feature_file.setChecked(True)
        form_layout.addRow("", self.feature_file)

        self.feature_process = QCheckBox("进程管理")
        self.feature_process.setChecked(True)
        form_layout.addRow("", self.feature_process)

        self.feature_cmd = QCheckBox("命令执行")
        self.feature_cmd.setChecked(True)
        form_layout.addRow("", self.feature_cmd)

        # Additional options
        self.option_startup = QCheckBox("开机自启动")
        form_layout.addRow("", self.option_startup)

        self.option_hide = QCheckBox("隐藏程序窗口")
        form_layout.addRow("", self.option_hide)

        form_group.setLayout(form_layout)
        generator_layout.addWidget(form_group)

        # Generate button
        generate_btn_container = QHBoxLayout()
        self.generate_btn = QPushButton('生成控制端程序')
        self.generate_btn.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.generate_btn.setIconSize(QSize(24, 24))
        self.generate_btn.clicked.connect(self.generate_control)
        generate_btn_container.addStretch()
        generate_btn_container.addWidget(self.generate_btn)
        generate_btn_container.addStretch()
        generator_layout.addLayout(generate_btn_container)

        # Status and output
        self.generator_output = QTextEdit()
        self.generator_output.setReadOnly(True)
        self.generator_output.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                padding: 10px;
            }
        """)
        self.generator_output.setMaximumHeight(150)
        generator_layout.addWidget(self.generator_output)

        self.tab_widget.addTab(generator_tab, "控制端生成器")

    def toggle_connection(self):
        try:
            if not self.connected:
                # 获取连接信息
                host = self.host_input.text()
                port = int(self.port_input.text())
                
                # 创建新的socket连接
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(5)  # 设置连接超时
                
                # 尝试连接
                self.socket.connect((host, port))
                self.connected = True
                
                # 更新UI
                self.update_button_states(True)
                self.connect_btn.setText("断开连接")
                self.connect_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogCloseButton))
                
                # 启动进程更新定时器
                self.process_timer.start()
                
                # 获取系统信息
                self.get_system_info()
                
                # 刷新文件浏览器
                self.refresh_file_browser()
                
                logger.info(f"成功连接到服务器 {host}:{port}")
            else:
                self.disconnect()
                
        except socket.timeout:
            logger.error("连接超时")
            QMessageBox.warning(self, "连接错误", "连接超时，请检查服务器地址和端口是否正确")
            self.disconnect()
        except ConnectionRefusedError:
            logger.error("连接被拒绝")
            QMessageBox.warning(self, "连接错误", "连接被拒绝，请确保服务器正在运行")
            self.disconnect()
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            QMessageBox.warning(self, "连接错误", f"连接失败: {str(e)}")
            self.disconnect()

    def disconnect(self):
        try:
            # 停止进程更新定时器
            if hasattr(self, 'process_timer'):
                self.process_timer.stop()
                
            # 关闭socket连接
            if hasattr(self, 'socket') and self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                self.socket.close()
                self.socket = None
                
            self.connected = False
            self.connect_btn.setText('连接')
            self.connect_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
            self.statusBar().showMessage('未连接')
            self.update_button_states(False)
            
            # 清空UI
            self.info_text.clear()
            self.file_tree.clear()
            self.process_table.setRowCount(0)
            self.cmd_output.clear()
            
            logger.info("已断开与服务器的连接")
        except Exception as e:
            logger.error(f"断开连接时发生错误: {str(e)}")

    def update_button_states(self, connected):
        self.upload_btn.setEnabled(connected)
        self.download_btn.setEnabled(connected)
        self.cmd_input.setEnabled(connected)

    def update_processes(self):
        if not self.connected:
            return

        try:
            command = {'type': 'list_processes'}
            self.socket.send(json.dumps(command).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['status'] == 'success':
                self.process_table.setRowCount(len(response['data']))
                for i, proc in enumerate(response['data']):
                    self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
                    self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
                    self.process_table.setItem(i, 2, QTableWidgetItem(f"{proc['cpu_percent']:.1f}%"))
                    self.process_table.setItem(i, 3, QTableWidgetItem(f"{proc['memory_percent']:.1f}%"))
            else:
                logger.error(f"刷新进程列表失败: {response['message']}")
        except Exception as e:
            logger.error(f"刷新进程列表失败: {e}")

    def execute_command(self):
        if not self.connected:
            return

        command_text = self.cmd_input.text()
        if not command_text:
            return

        try:
            command = {'type': 'execute_command', 'command': command_text}
            self.socket.send(json.dumps(command).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['status'] == 'success':
                output = f"$ {command_text}\n"
                if response['stdout']:
                    output += response['stdout']
                if response['stderr']:
                    output += f"Error: {response['stderr']}\n"
                self.cmd_output.append(output)
                self.cmd_input.clear()
            else:
                self.cmd_output.append(f"Error: {response['message']}\n")
        except Exception as e:
            self.cmd_output.append(f"Error: {str(e)}\n")

    def generate_control(self):
        """生成控制端程序"""
        try:
            if not self.connected:
                logger.warning("未连接到服务器，请先连接服务器")
                QMessageBox.warning(self, "警告", "未连接到服务器，请先连接服务器")
                return

            # 获取平台选择
            platform = self.platform_combo.currentText()
            if not platform:
                logger.warning("请选择目标平台")
                QMessageBox.warning(self, "警告", "请选择目标平台")
                return

            # 获取服务器地址和端口
            server_address = self.host_config.text()
            server_port = self.port_config.value()  # 使用 value() 获取 QSpinBox 的值

            # 构建功能列表
            features = {
                'file_transfer': self.feature_file.isChecked(),
                'process_control': self.feature_process.isChecked(),
                'command_execution': self.feature_cmd.isChecked(),
                'system_info': True
            }

            # 构建请求数据
            request_data = {
                'type': 'generate_control',
                'data': {
                    'platform': platform,
                    'host': server_address,
                    'port': server_port,
                    'features': features
                }
            }

            logger.info(f"发送生成控制端请求: {request_data}")
            
            # 发送请求
            self.socket.send(json.dumps(request_data).encode())
            
            # 接收响应
            response = self.socket.recv(4096)
            logger.info(f"收到服务器响应: {response}")
            
            try:
                response_data = json.loads(response.decode())
                logger.info(f"解析后的响应数据: {response_data}")
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析错误: {e}")
                QMessageBox.critical(self, "错误", "服务器响应格式错误")
                return

            if response_data['status'] == 'success':
                # 解码并保存可执行文件
                try:
                    exe_data = base64.b64decode(response_data['data'])
                    save_path, _ = QFileDialog.getSaveFileName(
                        self,
                        "保存控制端程序",
                        os.path.expanduser("~/Desktop/RemoteControl"),
                        "可执行文件 (*.exe)" if platform == "Windows" else "可执行文件 (*)"
                    )
                    
                    if save_path:
                        with open(save_path, 'wb') as f:
                            f.write(exe_data)
                        logger.info(f"控制端程序已生成并保存到：\n{save_path}")
                        QMessageBox.information(self, "成功", f"控制端程序已生成并保存到：\n{save_path}")
                except Exception as e:
                    logger.error(f"保存文件错误: {e}")
                    QMessageBox.critical(self, "错误", f"保存文件失败：{str(e)}")
            else:
                error_msg = response_data.get('message', '未知错误')
                logger.error(f"生成失败: {error_msg}")
                QMessageBox.critical(self, "错误", f"生成控制端程序失败：{error_msg}")

        except Exception as e:
            logger.error(f"生成控制端程序时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"生成控制端程序时发生错误：{str(e)}")

    def get_system_info(self):
        if not self.connected:
            return

        try:
            command = {'type': 'system_info'}
            self.socket.send(json.dumps(command).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['status'] == 'success':
                info = response['data']
                info_text = f"计算机名称: {info['computer_name']}\n"
                info_text += f"用户名: {info['user_name']}\n"
                info_text += f"操作系统版本: {info['os_version']}\n"
                info_text += f"系统目录: {info['system_directory']}\n"
                info_text += f"用户目录: {info['home_directory']}"
                self.info_text.setText(info_text)
            else:
                logger.error(f"获取系统信息失败: {response['message']}")
        except Exception as e:
            logger.error(f"获取系统信息错误: {e}")

    def refresh_file_browser(self):
        if not self.connected:
            return

        try:
            command = {'type': 'list_directory', 'path': self.current_path}
            self.socket.send(json.dumps(command).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response['status'] == 'success':
                self.file_tree.clear()
                for item in response['data']:
                    tree_item = QTreeWidgetItem([
                        item['name'],
                        item['type'],
                        str(item['size']),
                        datetime.fromtimestamp(item['modified']).strftime('%Y-%m-%d %H:%M:%S')
                    ])
                    self.file_tree.addTopLevelItem(tree_item)
            else:
                logger.error(f"刷新文件浏览器失败: {response['message']}")
        except Exception as e:
            logger.error(f"刷新文件浏览器失败: {e}")

    def navigate_directory(self, item):
        if not self.connected:
            return

        try:
            new_path = os.path.join(self.current_path, item.text(0))
            if item.text(1) == 'directory':
                self.current_path = new_path
                self.refresh_file_browser()
        except Exception as e:
            logger.error(f"导航目录失败: {e}")

    def upload_file(self):
        if not self.connected:
            return

        file_path, _ = QFileDialog.getOpenFileName(self, '选择要上传的文件')
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                command = {
                    'type': 'file_upload',
                    'data': {
                        'filename': os.path.basename(file_path),
                        'content': base64.b64encode(file_content).decode()
                    }
                }
                self.socket.send(json.dumps(command).encode('utf-8'))
                response = json.loads(self.socket.recv(4096).decode('utf-8'))
                
                if response['status'] == 'success':
                    logger.info(f"文件上传成功: {file_path}")
                    QMessageBox.information(self, '成功', '文件上传成功')
                    self.refresh_file_browser()
                else:
                    logger.error(f"文件上传失败: {response['message']}")
                    QMessageBox.warning(self, '错误', response['message'])
            except Exception as e:
                logger.error(f"文件上传过程发生错误: {str(e)}")
                QMessageBox.critical(self, '上传错误', str(e))

    def download_file(self):
        if not self.connected:
            return

        file_path, _ = QFileDialog.getSaveFileName(self, '保存文件')
        if file_path:
            try:
                command = {
                    'type': 'file_download',
                    'path': file_path
                }
                self.socket.send(json.dumps(command).encode('utf-8'))
                response = json.loads(self.socket.recv(4096).decode('utf-8'))
                
                if response['status'] == 'success':
                    with open(file_path, 'wb') as f:
                        f.write(base64.b64decode(response['data']))
                    logger.info(f"文件下载成功: {file_path}")
                    QMessageBox.information(self, '成功', '文件下载成功')
                else:
                    logger.error(f"文件下载失败: {response['message']}")
                    QMessageBox.warning(self, '错误', response['message'])
            except Exception as e:
                logger.error(f"文件下载过程发生错误: {str(e)}")
                QMessageBox.critical(self, '下载错误', str(e))

    def closeEvent(self, event):
        self.disconnect()
        event.accept()

if __name__ == '__main__':
    try:
        logger.info("启动客户端程序")
        app = QApplication(sys.argv)
        client = RemoteClient()
        client.show()
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f"客户端程序运行错误: {str(e)}")
        sys.exit(1) 