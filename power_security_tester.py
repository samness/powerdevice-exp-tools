# -*- coding: utf-8 -*-
import sys
import logging
import os
from datetime import datetime
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
import socket
import traceback
import requests

# 配置日志
logger = logging.getLogger('power_security_tester')
logger.setLevel(logging.DEBUG)

# 创建logs目录（如果不存在）
if not os.path.exists('logs'):
    os.makedirs('logs')

# 创建文件处理器
log_file = os.path.join('logs', f'power_security_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 创建格式化器 - 更详细的格式
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# 禁用其他库的日志
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('scapy').setLevel(logging.WARNING)
logging.getLogger('pymodbus').setLevel(logging.WARNING)

# 测试日志功能
logger.info("程序启动")
logger.debug("调试信息")
logger.warning("警告信息")
logger.error("错误信息")

class SecurityTester(QMainWindow):
    def __init__(self):
        super().__init__()
        logger.info("初始化SecurityTester主窗口")
        self.setWindowTitle("电力设备安全测试工具")
        self.setGeometry(100, 100, 1200, 800)
        self.init_ui()
        logger.info("SecurityTester主窗口初始化完成")

    def init_ui(self):
        logger.info("开始初始化UI界面")
        try:
            # 创建主窗口部件
            main_widget = QWidget()
            self.setCentralWidget(main_widget)
            
            # 创建主布局
            main_layout = QVBoxLayout()
            main_widget.setLayout(main_layout)
            
            # 创建设备选择区域
            device_group = QGroupBox("设备选择")
            device_layout = QHBoxLayout()
            
            # 设备类型选择
            device_type_label = QLabel("设备类型:")
            self.device_type_combo = QComboBox()
            self.device_type_combo.addItems(DEVICE_CONFIGS.keys())
            self.device_type_combo.currentTextChanged.connect(self.on_device_type_changed)
            
            # 设备型号选择
            device_model_label = QLabel("设备型号:")
            self.device_model_combo = QComboBox()
            
            # 目标IP输入
            target_ip_label = QLabel("目标IP:")
            self.target_ip_input = QLineEdit()
            self.target_ip_input.setPlaceholderText("请输入目标IP地址")
            self.target_ip_input.textChanged.connect(self.on_target_ip_changed)
            
            # 添加部件到设备布局
            device_layout.addWidget(device_type_label)
            device_layout.addWidget(self.device_type_combo)
            device_layout.addWidget(device_model_label)
            device_layout.addWidget(self.device_model_combo)
            device_layout.addWidget(target_ip_label)
            device_layout.addWidget(self.target_ip_input)
            
            device_group.setLayout(device_layout)
            main_layout.addWidget(device_group)
            
            # 创建测试选项区域
            test_group = QGroupBox("测试选项")
            test_layout = QVBoxLayout()
            
            # 测试类型选择
            test_type_label = QLabel("测试类型:")
            self.test_type_combo = QComboBox()
            self.test_type_combo.addItems(TEST_TYPES)
            self.test_type_combo.currentTextChanged.connect(self.on_test_type_changed)
            
            # 测试参数设置
            param_layout = QHBoxLayout()
            self.param_widgets = {}
            
            for param in TEST_CONFIG:
                label = QLabel(f"{param}:")
                if param == "port":
                    widget = QSpinBox()
                    widget.setRange(1, 65535)
                    widget.setValue(TEST_CONFIG[param])
                else:
                    widget = QLineEdit()
                    widget.setText(str(TEST_CONFIG[param]))
                self.param_widgets[param] = widget
                param_layout.addWidget(label)
                param_layout.addWidget(widget)
            
            # 添加测试按钮
            self.start_test_button = QPushButton("开始测试")
            self.start_test_button.clicked.connect(self.start_test)
            self.start_test_button.setEnabled(False)
            
            # 添加部件到测试布局
            test_layout.addWidget(test_type_label)
            test_layout.addWidget(self.test_type_combo)
            test_layout.addLayout(param_layout)
            test_layout.addWidget(self.start_test_button)
            
            test_group.setLayout(test_layout)
            main_layout.addWidget(test_group)
            
            # 创建结果显示区域
            result_group = QGroupBox("测试结果")
            result_layout = QVBoxLayout()
            
            # 创建结果表格
            self.result_table = QTableWidget()
            self.result_table.setColumnCount(4)
            self.result_table.setHorizontalHeaderLabels(["测试项", "状态", "详情", "时间"])
            self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            
            # 创建日志显示区域
            self.log_display = QTextEdit()
            self.log_display.setReadOnly(True)
            
            # 添加部件到结果布局
            result_layout.addWidget(self.result_table)
            result_layout.addWidget(self.log_display)
            
            result_group.setLayout(result_layout)
            main_layout.addWidget(result_group)
            
            # 初始化设备型号列表
            self.on_device_type_changed(self.device_type_combo.currentText())
            
            logger.info("UI界面初始化完成")
        except Exception as e:
            logger.error(f"初始化UI时发生错误: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def on_device_type_changed(self, device_type):
        logger.info(f"设备类型更改为: {device_type}")
        try:
            self.device_model_combo.clear()
            if device_type in DEVICE_CONFIGS:
                self.device_model_combo.addItems(DEVICE_CONFIGS[device_type].keys())
            logger.debug(f"更新后的设备型号列表: {list(DEVICE_CONFIGS[device_type].keys())}")
        except Exception as e:
            logger.error(f"更新设备型号列表时发生错误: {str(e)}")
            logger.error(traceback.format_exc())

    def on_test_type_changed(self, test_type):
        logger.info(f"测试类型更改为: {test_type}")
        try:
            # 根据测试类型更新参数界面
            for param, widget in self.param_widgets.items():
                widget.setVisible(param in TEST_CONFIG)
            logger.debug(f"测试类型 {test_type} 的参数配置已更新")
        except Exception as e:
            logger.error(f"更新测试类型参数时发生错误: {str(e)}")
            logger.error(traceback.format_exc())

    def on_target_ip_changed(self, ip):
        logger.info(f"目标IP输入: {ip}")
        try:
            # 验证IP地址格式
            try:
                socket.inet_aton(ip)
                self.start_test_button.setEnabled(True)
                logger.info(f"IP地址 {ip} 格式正确")
            except socket.error:
                self.start_test_button.setEnabled(False)
                logger.warning(f"IP地址 {ip} 格式不正确")
        except Exception as e:
            logger.error(f"验证IP地址时发生错误: {str(e)}")
            logger.error(traceback.format_exc())

    def start_test(self):
        logger.info("开始执行测试")
        try:
            # 获取测试参数
            device_type = self.device_type_combo.currentText()
            device_model = self.device_model_combo.currentText()
            target_ip = self.target_ip_input.text()
            test_type = self.test_type_combo.currentText()
            
            logger.info(f"测试参数: 设备类型={device_type}, 设备型号={device_model}, 目标IP={target_ip}, 测试类型={test_type}")
            
            # 创建测试线程
            self.test_thread = TestThread(
                target_ip,
                device_type,
                device_model,
                test_type
            )
            
            # 连接信号
            self.test_thread.update_signal.connect(self.update_test_result)
            self.test_thread.log_signal.connect(self.update_log)
            
            # 启动测试线程
            self.test_thread.start()
            logger.info("测试线程已启动")
            
        except Exception as e:
            logger.error(f"启动测试时发生错误: {str(e)}")
            logger.error(traceback.format_exc())
            self.update_log(f"错误: {str(e)}")

    def update_test_result(self, test_item, status, details):
        logger.info(f"更新测试结果: {test_item}, 状态={status}, 详情={details}")
        try:
            row = self.result_table.rowCount()
            self.result_table.insertRow(row)
            self.result_table.setItem(row, 0, QTableWidgetItem(test_item))
            self.result_table.setItem(row, 1, QTableWidgetItem(status))
            self.result_table.setItem(row, 2, QTableWidgetItem(details))
            self.result_table.setItem(row, 3, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            logger.debug(f"测试结果已更新到表格第 {row+1} 行")
        except Exception as e:
            logger.error(f"更新测试结果时发生错误: {str(e)}")
            logger.error(traceback.format_exc())

    def update_log(self, message):
        logger.info(f"更新日志: {message}")
        try:
            self.log_display.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")
            logger.debug("日志已更新到显示区域")
        except Exception as e:
            logger.error(f"更新日志时发生错误: {str(e)}")
            logger.error(traceback.format_exc())

class TestThread(QThread):
    update_signal = pyqtSignal(str, str, str)
    log_signal = pyqtSignal(str)
    
    def __init__(self, target_ip, device_type, device_model, test_type):
        super().__init__()
        self.target_ip = target_ip
        self.device_type = device_type
        self.device_model = device_model
        self.test_type = test_type
        self.logger = logging.getLogger('power_security_tester')
        self.exploit_module = ExploitModule(target_ip, 502, device_type, device_model)  # 使用默认Modbus端口502
        self.logger.info("测试线程初始化完成")

    def run(self):
        try:
            self.logger.info(f"开始执行{self.test_type}测试")
            self.log_signal.emit(f"开始执行{self.test_type}测试...")
            
            if self.test_type == "漏洞扫描":
                self.perform_vulnerability_scan()
            elif self.test_type == "协议测试":
                self.perform_protocol_test()
            elif self.test_type == "配置检查":
                self.perform_config_check()
            elif self.test_type == "漏洞利用":
                self.perform_exploit_test()
            
            self.logger.info(f"{self.test_type}测试完成")
            self.log_signal.emit(f"{self.test_type}测试完成")
            
        except Exception as e:
            self.logger.error(f"测试执行过程中发生错误: {str(e)}")
            self.logger.error(traceback.format_exc())
            self.log_signal.emit(f"错误: {str(e)}")
            self.update_signal.emit("测试执行", "失败", str(e))

    def perform_vulnerability_scan(self):
        """执行漏洞扫描"""
        try:
            self.logger.info("开始执行漏洞扫描")
            self.log_signal.emit("正在执行漏洞扫描...")
            
            # 扫描常见端口
            try:
                nm = nmap.PortScanner()
                self.log_signal.emit("正在扫描端口...")
                nm.scan(self.target_ip, arguments='-sT -p 21,22,23,80,102,443,502,1089,1090,1091,2404,20000')
                
                for port in nm[self.target_ip].all_tcp():
                    state = nm[self.target_ip]['tcp'][port]['state']
                    if state == 'open':
                        self.logger.info(f"发现开放端口: {port}")
                        self.log_signal.emit(f"发现开放端口: {port}")
                        self.update_signal.emit("端口扫描", "发现", f"端口 {port} 开放")
            except Exception as e:
                self.logger.error(f"端口扫描失败: {str(e)}")
                self.log_signal.emit(f"端口扫描失败: {str(e)}")
            
            # 加载设备对应的漏洞配置
            try:
                from config import DEVICE_CONFIGS
                device_config = DEVICE_CONFIGS.get(self.device_type, {})
                vulnerabilities = device_config.get("vulnerabilities", {}).get(self.device_model, [])
                
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities:
                        if isinstance(vuln, dict):  # 处理详细配置的漏洞
                            self.log_signal.emit(f"正在测试漏洞: {vuln['name']}")
                            if self.exploit_module.test_vulnerability(vuln):
                                self.update_signal.emit(
                                    vuln['name'],
                                    "发现",
                                    f"{vuln['description']}\n严重程度: {vuln['severity']}"
                                )
                        else:  # 处理简单的CVE编号
                            self.log_signal.emit(f"正在测试漏洞: {vuln}")
                            self.update_signal.emit("漏洞扫描", "发现", vuln)
            except Exception as e:
                self.logger.error(f"漏洞测试失败: {str(e)}")
                self.log_signal.emit(f"漏洞测试失败: {str(e)}")
            
            self.logger.info("漏洞扫描完成")
            
        except Exception as e:
            self.logger.error(f"漏洞扫描时发生错误: {str(e)}")
            self.log_signal.emit(f"漏洞扫描错误: {str(e)}")
            raise

    def perform_protocol_test(self):
        """执行协议测试"""
        try:
            self.logger.info("开始执行协议测试")
            self.log_signal.emit("正在执行协议测试...")
            
            # 测试Modbus协议
            self.log_signal.emit("正在测试Modbus协议...")
            client = pymodbus.client.ModbusTcpClient(self.target_ip, port=502)
            if client.connect():
                self.logger.info("Modbus连接成功")
                self.log_signal.emit("Modbus连接成功")
                self.update_signal.emit("Modbus协议", "支持", "设备支持Modbus协议")
                client.close()
            
            # 测试S7协议
            self.log_signal.emit("正在测试S7协议...")
            sock = socket.socket()
            sock.settimeout(2)
            try:
                sock.connect((self.target_ip, 102))
                self.logger.info("S7连接成功")
                self.log_signal.emit("S7连接成功")
                self.update_signal.emit("S7协议", "支持", "设备支持S7协议")
            except:
                self.logger.info("设备不支持S7协议")
            finally:
                sock.close()
            
            self.logger.info("协议测试完成")
            
        except Exception as e:
            self.logger.error(f"协议测试时发生错误: {str(e)}")
            self.log_signal.emit(f"协议测试错误: {str(e)}")
            raise

    def perform_config_check(self):
        """执行配置检查"""
        try:
            self.logger.info("开始执行配置检查")
            self.log_signal.emit("正在执行配置检查...")
            
            # 检查Web服务配置
            self.log_signal.emit("正在检查Web服务配置...")
            try:
                response = requests.get(f"http://{self.target_ip}", timeout=5)
                if response.status_code == 200:
                    self.logger.info("发现Web服务")
                    self.log_signal.emit("发现Web服务")
                    self.update_signal.emit("Web服务", "发现", "设备开启了Web服务")
            except:
                self.logger.info("未发现Web服务")
            
            # 检查Telnet配置
            self.log_signal.emit("正在检查Telnet配置...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((self.target_ip, 23))
                self.logger.info("发现Telnet服务")
                self.log_signal.emit("发现Telnet服务")
                self.update_signal.emit("Telnet服务", "发现", "设备开启了Telnet服务")
            except:
                self.logger.info("未发现Telnet服务")
            finally:
                sock.close()
            
            self.logger.info("配置检查完成")
            
        except Exception as e:
            self.logger.error(f"配置检查时发生错误: {str(e)}")
            self.log_signal.emit(f"配置检查错误: {str(e)}")
            raise

    def perform_exploit_test(self):
        """执行漏洞利用测试"""
        try:
            self.logger.info("开始执行漏洞利用测试")
            self.log_signal.emit("正在执行漏洞利用测试...")
            
            # 测试弱密码漏洞
            self.log_signal.emit("正在测试弱密码漏洞...")
            self.exploit_module.exploit_modbus_weak_password()
            
            # 测试缓冲区溢出漏洞
            self.log_signal.emit("正在测试缓冲区溢出漏洞...")
            self.exploit_module.exploit_buffer_overflow()
            
            # 测试命令注入漏洞
            self.log_signal.emit("正在测试命令注入漏洞...")
            self.exploit_module.exploit_command_injection()
            
            # 测试Web接口漏洞
            self.log_signal.emit("正在测试Web接口漏洞...")
            self.exploit_module.exploit_web_interface()
            
            # 测试协议漏洞
            self.log_signal.emit("正在测试协议漏洞...")
            self.exploit_module.exploit_protocol_vulnerabilities()
            
            # 更新测试结果
            for result in self.exploit_module.results:
                self.update_signal.emit(
                    result["type"],
                    "发现" if result["severity"] in ["高", "严重"] else "警告",
                    f"{result['description']}\n详情: {result['details']}"
                )
            
            self.logger.info("漏洞利用测试完成")
            
        except Exception as e:
            self.logger.error(f"漏洞利用测试时发生错误: {str(e)}")
            self.log_signal.emit(f"漏洞利用测试错误: {str(e)}")
            raise

if __name__ == "__main__":
    logger.info("程序主入口开始执行")
    try:
        app = QApplication(sys.argv)
        window = SecurityTester()
        window.show()
        logger.info("主窗口已显示")
        sys.exit(app.exec())
    except Exception as e:
        logger.error(f"程序执行过程中发生错误: {str(e)}")
        logger.error(traceback.format_exc())
        raise 