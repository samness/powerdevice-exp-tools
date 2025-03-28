import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import socket
import threading
import time
from datetime import datetime
import random
import struct
import logging
import os
from logging.handlers import RotatingFileHandler
import binascii

class PLCSecurityTester:
    def __init__(self):
        # 设置日志系统
        self.setup_logging()
        
        self.root = tk.Tk()
        self.root.title("PLC 安全测试工具")
        self.root.geometry("1000x800")
        
        # 记录程序启动
        self.logger.info("PLC Security Testing Tool started")
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 创建左右分栏
        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # === 左侧配置区域 ===
        
        # PLC品牌选择框架
        plc_frame = ttk.LabelFrame(self.left_frame, text="PLC 品牌选择", padding="5")
        plc_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # PLC品牌按钮
        self.plc_brands = {
            "西门子 S7-300/400": "Siemens S7-300/400",
            "西门子 S7-1200/1500": "Siemens S7-1200/1500",
            "罗克韦尔 ControlLogix": "Allen Bradley ControlLogix",
            "罗克韦尔 CompactLogix": "Allen Bradley CompactLogix",
            "施耐德 M340": "Modicon M340",
            "施耐德 M580": "Modicon M580",
            "欧姆龙 CJ2": "Omron CJ2",
            "欧姆龙 CS1": "Omron CS1",
            "三菱 Q系列": "Mitsubishi Q Series",
            "三菱 FX系列": "Mitsubishi FX Series",
            "倍福 TwinCAT": "Beckhoff TwinCAT",
            "ABB AC500": "ABB AC500"
        }
        
        self.selected_brand = tk.StringVar(value="西门子 S7-300/400")
        
        # 创建按钮网格
        row = 0
        col = 0
        for brand_name in self.plc_brands.keys():
            btn = ttk.Radiobutton(plc_frame, text=brand_name, value=brand_name, 
                                variable=self.selected_brand, command=self.on_plc_brand_change)
            btn.grid(row=row, column=col, padx=5, pady=2, sticky=tk.W)
            col += 1
            if col > 1:
                col = 0
                row += 1
        
        # IP地址输入
        ttk.Label(self.left_frame, text="目标 IP:").grid(row=1, column=0, sticky=tk.W)
        self.target_ip = ttk.Entry(self.left_frame, width=40)
        self.target_ip.grid(row=1, column=1, sticky=(tk.W, tk.E))
        self.target_ip.insert(0, "192.168.1.100")
        
        # 端口输入
        ttk.Label(self.left_frame, text="端口:").grid(row=2, column=0, sticky=tk.W)
        self.port = ttk.Entry(self.left_frame, width=40)
        self.port.grid(row=2, column=1, sticky=(tk.W, tk.E))
        self.port.insert(0, "102")
        
        # 测试类型选择
        ttk.Label(self.left_frame, text="测试类型:").grid(row=3, column=0, sticky=tk.W)
        self.test_types = [
            "DDoS 攻击",
            "协议洪水",
            "网络扫描",
            "漏洞扫描",
            "性能测试",
            "安全评估",
            "协议分析",
            "模糊测试",
            "IEC 62351 测试",
            "IEC 60870-5-104 测试",
            "IEC 61850 测试",
            "Modbus 协议测试",
            "OPC UA 测试",
            "S7 协议测试",
            "CIP 协议测试",
            "通信报文漏洞挖掘",
            "S7 协议漏洞测试",
            "Modbus 协议漏洞测试",
            "DNP3 协议漏洞测试",
            "BACnet 协议漏洞测试",
            "EtherNet/IP 漏洞测试",
            "FINS 协议漏洞测试"
        ]
        self.test_type = ttk.Combobox(self.left_frame, values=self.test_types, width=30)
        self.test_type.grid(row=3, column=1, sticky=(tk.W, tk.E))
        self.test_type.set("DDoS 攻击")
        self.test_type.bind('<<ComboboxSelected>>', self.on_test_type_change)
        
        # 测试参数
        ttk.Label(self.left_frame, text="持续时间(秒):").grid(row=4, column=0, sticky=tk.W)
        self.duration = ttk.Entry(self.left_frame, width=40)
        self.duration.grid(row=4, column=1, sticky=(tk.W, tk.E))
        self.duration.insert(0, "60")
        
        # 协议参数
        self.protocol_frame = ttk.LabelFrame(self.left_frame, text="协议参数", padding="5")
        self.protocol_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 数据块大小
        ttk.Label(self.protocol_frame, text="数据块大小:").grid(row=0, column=0, sticky=tk.W)
        self.block_size = ttk.Entry(self.protocol_frame, width=20)
        self.block_size.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.block_size.insert(0, "1024")
        
        # 数据块数量
        ttk.Label(self.protocol_frame, text="数据块数量:").grid(row=1, column=0, sticky=tk.W)
        self.block_count = ttk.Entry(self.protocol_frame, width=20)
        self.block_count.grid(row=1, column=1, sticky=(tk.W, tk.E))
        self.block_count.insert(0, "100")
        
        # 开始按钮
        self.start_button = ttk.Button(self.left_frame, text="开始测试", command=self.start_test)
        self.start_button.grid(row=6, column=0, columnspan=2, pady=10)
        
        # 停止按钮
        self.stop_button = ttk.Button(self.left_frame, text="停止测试", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.grid(row=7, column=0, columnspan=2, pady=5)
        
        # === 右侧结果显示区域 ===
        
        # 创建notebook用于分页显示
        self.notebook = ttk.Notebook(self.right_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置right_frame的grid权重
        self.right_frame.grid_rowconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)
        
        # 测试结果页
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="测试结果")
        
        # 配置results_frame的grid权重
        self.results_frame.grid_rowconfigure(0, weight=1)
        self.results_frame.grid_columnconfigure(0, weight=1)
        
        # 结果显示区域
        self.result_text = tk.Text(self.results_frame, height=20, width=60, 
                                 bg='black', fg='green', insertbackground='green')
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # 添加滚动条
        result_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        result_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        
        # 协议分析页
        self.protocol_analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.protocol_analysis_frame, text="协议分析")
        
        # 配置protocol_analysis_frame的grid权重
        self.protocol_analysis_frame.grid_rowconfigure(0, weight=1)
        self.protocol_analysis_frame.grid_columnconfigure(0, weight=1)
        
        # 协议分析结果显示
        self.protocol_text = tk.Text(self.protocol_analysis_frame, height=20, width=60,
                                   bg='black', fg='green', insertbackground='green')
        self.protocol_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # 添加滚动条
        protocol_scrollbar = ttk.Scrollbar(self.protocol_analysis_frame, orient=tk.VERTICAL, command=self.protocol_text.yview)
        protocol_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.protocol_text.configure(yscrollcommand=protocol_scrollbar.set)
        
        # 底部按钮区域
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        # 保存结果按钮
        self.save_button = ttk.Button(self.button_frame, text="保存结果", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # 加载结果按钮
        self.load_button = ttk.Button(self.button_frame, text="加载结果", command=self.load_results)
        self.load_button.pack(side=tk.LEFT, padx=5)
        
        # 查看日志按钮
        self.view_log_button = ttk.Button(self.button_frame, text="查看日志", command=self.view_logs)
        self.view_log_button.pack(side=tk.LEFT, padx=5)
        
        # 清除结果按钮
        self.clear_button = ttk.Button(self.button_frame, text="清除结果", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
        self.status_label.grid(row=2, column=0, columnspan=2, sticky=tk.W)
        
        self.running = False
        self.test_thread = None
        self.results = []
        
        # 配置grid权重
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        
    def on_plc_brand_change(self):
        brand = self.selected_brand.get()
        self.logger.info(f"PLC brand changed to: {brand}")
        
        # 根据品牌设置默认端口
        if "西门子" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "102")
        elif "罗克韦尔" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "44818")
        elif "施耐德" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "502")
        elif "欧姆龙" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "9600")
        elif "三菱" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "5007")
        elif "倍福" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "851")
        elif "ABB" in brand:
            self.port.delete(0, tk.END)
            self.port.insert(0, "102")
            
    def on_test_type_change(self, event=None):
        test_type = self.test_type.get()
        self.logger.info(f"Test type changed to: {test_type}")
        
        # 根据测试类型启用/禁用相关参数
        if test_type in ["协议洪水", "协议分析", "模糊测试"]:
            self.protocol_frame.grid()
        else:
            self.protocol_frame.grid_remove()
            
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.protocol_text.delete(1.0, tk.END)
        self.results = []
        self.logger.info("Results cleared")
        
    def setup_logging(self):
        # 创建logs目录
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        # 设置日志文件名
        log_file = os.path.join('logs', f'plc_security_test_{datetime.now().strftime("%Y%m%d")}.log')
        
        # 配置日志记录器
        self.logger = logging.getLogger('PLCSecurityTester')
        self.logger.setLevel(logging.INFO)
        
        # 创建文件处理器（使用轮转文件处理器）
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # 添加处理器到日志记录器
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
    def start_test(self):
        if not self.validate_inputs():
            return
            
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Test in progress...")
        
        # 记录测试开始
        self.logger.info(f"Starting test - Brand: {self.selected_brand.get()}, IP: {self.target_ip.get()}, "
                        f"Port: {self.port.get()}, Type: {self.test_type.get()}, Duration: {self.duration.get()}s")
        
        self.test_thread = threading.Thread(target=self.run_test)
        self.test_thread.daemon = True
        self.test_thread.start()
        
    def stop_test(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Test stopped")
        
        # 记录测试停止
        self.logger.info("Test stopped by user")
        
    def validate_inputs(self):
        try:
            ip = self.target_ip.get()
            socket.inet_aton(ip)
        except socket.error:
            self.logger.error("Invalid IP address entered")
            messagebox.showerror("Error", "Invalid IP address")
            return False
            
        try:
            port = int(self.port.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self.logger.error("Invalid port number entered")
            messagebox.showerror("Error", "Invalid port number")
            return False
            
        try:
            duration = int(self.duration.get())
            if duration <= 0:
                raise ValueError
        except ValueError:
            self.logger.error("Invalid duration entered")
            messagebox.showerror("Error", "Invalid duration")
            return False
            
        return True
        
    def run_test(self):
        """运行测试线程"""
        start_time = time.time()
        test_type = self.test_type.get()
        brand = self.selected_brand.get()
        
        while self.running and (time.time() - start_time) < int(self.duration.get()):
            try:
                if test_type == "DDoS 攻击":
                    self.ddos_attack()
                elif test_type == "协议洪水":
                    self.protocol_flooding()
                elif test_type == "网络扫描":
                    self.network_scan()
                elif test_type == "漏洞扫描":
                    self.vulnerability_scan()
                elif test_type == "性能测试":
                    self.performance_test()
                elif test_type == "安全评估":
                    self.security_assessment()
                elif test_type == "协议分析":
                    self.protocol_analysis()
                elif test_type == "模糊测试":
                    self.fuzzing_test()
                elif test_type == "IEC 62351 测试":
                    self.iec_62351_test()
                elif test_type == "IEC 60870-5-104 测试":
                    self.iec_60870_test()
                elif test_type == "IEC 61850 测试":
                    self.iec_61850_test()
                elif test_type == "Modbus 协议测试":
                    self.modbus_test()
                elif test_type == "OPC UA 测试":
                    self.opc_ua_test()
                elif test_type == "S7 协议测试":
                    self.s7_protocol_test()
                elif test_type == "CIP 协议测试":
                    self.cip_protocol_test()
                elif test_type == "通信报文漏洞挖掘":
                    self.message_vulnerability_test()
                elif test_type == "S7 协议漏洞测试":
                    self.s7_vulnerability_test()
                elif test_type == "Modbus 协议漏洞测试":
                    self.modbus_vulnerability_test()
                elif test_type == "DNP3 协议漏洞测试":
                    self.dnp3_vulnerability_test()
                elif test_type == "BACnet 协议漏洞测试":
                    self.bacnet_vulnerability_test()
                elif test_type == "EtherNet/IP 漏洞测试":
                    self.ethernet_ip_vulnerability_test()
                elif test_type == "FINS 协议漏洞测试":
                    self.fins_vulnerability_test()
                    
                time.sleep(0.1)  # 避免CPU占用过高
            except Exception as e:
                self.logger.error(f"Test error: {str(e)}")
                self.update_result(f"测试错误: {str(e)}")
                time.sleep(1)  # 发生错误时等待较长时间
                
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("测试完成")
        self.logger.info("Test completed")
        self.update_result("测试完成")

    def iec_62351_test(self):
        """IEC 62351 安全测试"""
        try:
            # IEC 62351 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送IEC 62351测试数据包
            test_data = self.generate_iec_62351_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"IEC 62351 测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"IEC 62351 test error: {str(e)}")
            self.update_result(f"IEC 62351 测试错误: {str(e)}")

    def iec_60870_test(self):
        """IEC 60870-5-104 协议测试"""
        try:
            # IEC 60870-5-104 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送IEC 60870-5-104测试数据包
            test_data = self.generate_iec_60870_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"IEC 60870-5-104 测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"IEC 60870 test error: {str(e)}")
            self.update_result(f"IEC 60870-5-104 测试错误: {str(e)}")

    def iec_61850_test(self):
        """IEC 61850 协议测试"""
        try:
            # IEC 61850 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送IEC 61850测试数据包
            test_data = self.generate_iec_61850_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"IEC 61850 测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"IEC 61850 test error: {str(e)}")
            self.update_result(f"IEC 61850 测试错误: {str(e)}")

    def modbus_test(self):
        """Modbus 协议测试"""
        try:
            # Modbus 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送Modbus测试数据包
            test_data = self.generate_modbus_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"Modbus 测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"Modbus test error: {str(e)}")
            self.update_result(f"Modbus 测试错误: {str(e)}")

    def opc_ua_test(self):
        """OPC UA 协议测试"""
        try:
            # OPC UA 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送OPC UA测试数据包
            test_data = self.generate_opc_ua_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"OPC UA 测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"OPC UA test error: {str(e)}")
            self.update_result(f"OPC UA 测试错误: {str(e)}")

    def s7_protocol_test(self):
        """S7 协议测试"""
        try:
            # S7 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送S7测试数据包
            test_data = self.generate_s7_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"S7 协议测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"S7 protocol test error: {str(e)}")
            self.update_result(f"S7 协议测试错误: {str(e)}")

    def cip_protocol_test(self):
        """CIP 协议测试"""
        try:
            # CIP 协议测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 发送CIP测试数据包
            test_data = self.generate_cip_packet()
            sock.send(test_data)
            
            # 接收响应
            response = sock.recv(1024)
            self.update_result(f"CIP 协议测试响应: {binascii.hexlify(response).decode()}")
            
            sock.close()
        except Exception as e:
            self.logger.error(f"CIP protocol test error: {str(e)}")
            self.update_result(f"CIP 协议测试错误: {str(e)}")

    def message_vulnerability_test(self):
        """通信报文漏洞挖掘测试"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # 测试不同类型的漏洞
            vulnerabilities = [
                ("缓冲区溢出", self.generate_buffer_overflow_packet()),
                ("整数溢出", self.generate_integer_overflow_packet()),
                ("格式字符串", self.generate_format_string_packet()),
                ("SQL注入", self.generate_sql_injection_packet()),
                ("命令注入", self.generate_command_injection_packet()),
                ("XSS攻击", self.generate_xss_packet()),
                ("CSRF攻击", self.generate_csrf_packet()),
                ("重放攻击", self.generate_replay_packet()),
                ("中间人攻击", self.generate_mitm_packet()),
                ("协议降级", self.generate_protocol_downgrade_packet())
            ]
            
            for vuln_name, packet in vulnerabilities:
                try:
                    sock.send(packet)
                    response = sock.recv(1024)
                    self.update_result(f"漏洞测试: {vuln_name}")
                    self.update_result(f"响应数据: {binascii.hexlify(response).decode()}")
                except Exception as e:
                    self.update_result(f"漏洞测试 {vuln_name} 失败: {str(e)}")
                    
            sock.close()
        except Exception as e:
            self.logger.error(f"Message vulnerability test error: {str(e)}")
            self.update_result(f"通信报文漏洞挖掘测试错误: {str(e)}")

    def s7_vulnerability_test(self):
        """S7 协议漏洞测试"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # S7 协议漏洞测试
            vulnerabilities = [
                ("S7 协议栈溢出", self.generate_s7_stack_overflow()),
                ("S7 认证绕过", self.generate_s7_auth_bypass()),
                ("S7 拒绝服务", self.generate_s7_dos()),
                ("S7 命令注入", self.generate_s7_command_injection()),
                ("S7 缓冲区溢出", self.generate_s7_buffer_overflow())
            ]
            
            for vuln_name, packet in vulnerabilities:
                try:
                    sock.send(packet)
                    response = sock.recv(1024)
                    self.update_result(f"S7 漏洞测试: {vuln_name}")
                    self.update_result(f"响应数据: {binascii.hexlify(response).decode()}")
                except Exception as e:
                    self.update_result(f"S7 漏洞测试 {vuln_name} 失败: {str(e)}")
                    
            sock.close()
        except Exception as e:
            self.logger.error(f"S7 vulnerability test error: {str(e)}")
            self.update_result(f"S7 协议漏洞测试错误: {str(e)}")

    def modbus_vulnerability_test(self):
        """Modbus 协议漏洞测试"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip.get(), int(self.port.get())))
            
            # Modbus 协议漏洞测试
            vulnerabilities = [
                ("Modbus 功能码溢出", self.generate_modbus_function_overflow()),
                ("Modbus 寄存器溢出", self.generate_modbus_register_overflow()),
                ("Modbus 认证绕过", self.generate_modbus_auth_bypass()),
                ("Modbus 命令注入", self.generate_modbus_command_injection()),
                ("Modbus 缓冲区溢出", self.generate_modbus_buffer_overflow())
            ]
            
            for vuln_name, packet in vulnerabilities:
                try:
                    sock.send(packet)
                    response = sock.recv(1024)
                    self.update_result(f"Modbus 漏洞测试: {vuln_name}")
                    self.update_result(f"响应数据: {binascii.hexlify(response).decode()}")
                except Exception as e:
                    self.update_result(f"Modbus 漏洞测试 {vuln_name} 失败: {str(e)}")
                    
            sock.close()
        except Exception as e:
            self.logger.error(f"Modbus vulnerability test error: {str(e)}")
            self.update_result(f"Modbus 协议漏洞测试错误: {str(e)}")

    def generate_buffer_overflow_packet(self):
        """生成缓冲区溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x00] * 2048)  # 大尺寸数据包
        return bytes(packet)

    def generate_integer_overflow_packet(self):
        """生成整数溢出测试数据包"""
        packet = bytearray()
        packet.extend([0xFF, 0xFF, 0xFF, 0xFF])  # 最大整数值
        return bytes(packet)

    def generate_format_string_packet(self):
        """生成格式字符串测试数据包"""
        packet = bytearray()
        packet.extend(b"%x" * 100)  # 格式字符串
        return bytes(packet)

    def generate_sql_injection_packet(self):
        """生成SQL注入测试数据包"""
        packet = bytearray()
        packet.extend(b"'; DROP TABLE users; --")  # SQL注入
        return bytes(packet)

    def generate_command_injection_packet(self):
        """生成命令注入测试数据包"""
        packet = bytearray()
        packet.extend(b"| dir")  # 命令注入
        return bytes(packet)

    def generate_xss_packet(self):
        """生成XSS攻击测试数据包"""
        packet = bytearray()
        packet.extend(b"<script>alert('xss')</script>")  # XSS
        return bytes(packet)

    def generate_csrf_packet(self):
        """生成CSRF攻击测试数据包"""
        packet = bytearray()
        packet.extend(b"POST /admin HTTP/1.1\r\n")  # CSRF
        return bytes(packet)

    def generate_replay_packet(self):
        """生成重放攻击测试数据包"""
        packet = bytearray()
        packet.extend([0x00] * 100)  # 重放数据
        return bytes(packet)

    def generate_mitm_packet(self):
        """生成中间人攻击测试数据包"""
        packet = bytearray()
        packet.extend([0x00] * 100)  # 中间人数据
        return bytes(packet)

    def generate_protocol_downgrade_packet(self):
        """生成协议降级攻击测试数据包"""
        packet = bytearray()
        packet.extend([0x00] * 100)  # 协议降级数据
        return bytes(packet)

    def generate_s7_stack_overflow(self):
        """生成S7协议栈溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x03, 0x00, 0x00, 0x16])  # 头部
        packet.extend([0x11, 0xE0])  # 连接请求
        packet.extend([0x00] * 2048)  # 溢出数据
        return bytes(packet)

    def generate_s7_auth_bypass(self):
        """生成S7认证绕过测试数据包"""
        packet = bytearray()
        packet.extend([0x03, 0x00, 0x00, 0x16])  # 头部
        packet.extend([0x11, 0xE0])  # 连接请求
        packet.extend([0x00, 0x00])  # 认证数据
        return bytes(packet)

    def generate_s7_dos(self):
        """生成S7拒绝服务测试数据包"""
        packet = bytearray()
        packet.extend([0x03, 0x00, 0x00, 0x16])  # 头部
        packet.extend([0x11, 0xE0])  # 连接请求
        packet.extend([0xFF] * 100)  # DOS数据
        return bytes(packet)

    def generate_s7_command_injection(self):
        """生成S7命令注入测试数据包"""
        packet = bytearray()
        packet.extend([0x03, 0x00, 0x00, 0x16])  # 头部
        packet.extend([0x11, 0xE0])  # 连接请求
        packet.extend(b"| dir")  # 命令注入
        return bytes(packet)

    def generate_s7_buffer_overflow(self):
        """生成S7缓冲区溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x03, 0x00, 0x00, 0x16])  # 头部
        packet.extend([0x11, 0xE0])  # 连接请求
        packet.extend([0x00] * 2048)  # 溢出数据
        return bytes(packet)

    def generate_modbus_function_overflow(self):
        """生成Modbus功能码溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x00, 0x01])  # 事务标识符
        packet.extend([0x00, 0x00])  # 协议标识符
        packet.extend([0x00, 0x06])  # 长度
        packet.extend([0x01])  # 单元标识符
        packet.extend([0xFF])  # 溢出功能码
        packet.extend([0x00, 0x00])  # 起始地址
        packet.extend([0x00, 0x01])  # 寄存器数量
        return bytes(packet)

    def generate_modbus_register_overflow(self):
        """生成Modbus寄存器溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x00, 0x01])  # 事务标识符
        packet.extend([0x00, 0x00])  # 协议标识符
        packet.extend([0x00, 0x06])  # 长度
        packet.extend([0x01])  # 单元标识符
        packet.extend([0x03])  # 功能码
        packet.extend([0xFF, 0xFF])  # 溢出起始地址
        packet.extend([0xFF, 0xFF])  # 溢出寄存器数量
        return bytes(packet)

    def generate_modbus_auth_bypass(self):
        """生成Modbus认证绕过测试数据包"""
        packet = bytearray()
        packet.extend([0x00, 0x01])  # 事务标识符
        packet.extend([0x00, 0x00])  # 协议标识符
        packet.extend([0x00, 0x06])  # 长度
        packet.extend([0x00])  # 绕过认证
        packet.extend([0x03])  # 功能码
        packet.extend([0x00, 0x00])  # 起始地址
        packet.extend([0x00, 0x01])  # 寄存器数量
        return bytes(packet)

    def generate_modbus_command_injection(self):
        """生成Modbus命令注入测试数据包"""
        packet = bytearray()
        packet.extend([0x00, 0x01])  # 事务标识符
        packet.extend([0x00, 0x00])  # 协议标识符
        packet.extend([0x00, 0x06])  # 长度
        packet.extend([0x01])  # 单元标识符
        packet.extend([0x03])  # 功能码
        packet.extend(b"| dir")  # 命令注入
        return bytes(packet)

    def generate_modbus_buffer_overflow(self):
        """生成Modbus缓冲区溢出测试数据包"""
        packet = bytearray()
        packet.extend([0x00, 0x01])  # 事务标识符
        packet.extend([0x00, 0x00])  # 协议标识符
        packet.extend([0x00, 0x06])  # 长度
        packet.extend([0x01])  # 单元标识符
        packet.extend([0x03])  # 功能码
        packet.extend([0x00] * 2048)  # 溢出数据
        return bytes(packet)

    def update_result(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = f"[{timestamp}] {message}"
        self.results.append(result)
        self.root.after(0, lambda: self.result_text.insert(tk.END, result + "\n"))
        
    def save_results(self):
        if not self.results:
            self.logger.warning("Attempted to save empty results")
            messagebox.showwarning("Warning", "No results to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save Test Results"
        )
        
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.results, f, indent=2)
                self.logger.info(f"Results saved to {file_path}")
                messagebox.showinfo("Success", "Results saved successfully")
            except Exception as e:
                self.logger.error(f"Failed to save results: {str(e)}", exc_info=True)
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")
                
    def load_results(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")],
            title="Load Test Results"
        )
        
        if file_path:
            try:
                with open(file_path, "r") as f:
                    self.results = json.load(f)
                self.result_text.delete(1.0, tk.END)
                for result in self.results:
                    self.result_text.insert(tk.END, result + "\n")
                self.logger.info(f"Results loaded from {file_path}")
                messagebox.showinfo("Success", "Results loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load results: {str(e)}", exc_info=True)
                messagebox.showerror("Error", f"Failed to load results: {str(e)}")
                
    def view_logs(self):
        try:
            # 获取最新的日志文件
            log_files = sorted([f for f in os.listdir('logs') if f.endswith('.log')])
            if not log_files:
                messagebox.showinfo("Info", "No log files found")
                return
                
            latest_log = os.path.join('logs', log_files[-1])
            
            # 创建日志查看窗口
            log_window = tk.Toplevel(self.root)
            log_window.title("View Logs")
            log_window.geometry("800x600")
            
            # 创建文本区域
            log_text = tk.Text(log_window, wrap=tk.WORD)
            log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # 添加滚动条
            scrollbar = ttk.Scrollbar(log_window, orient=tk.VERTICAL, command=log_text.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            log_text.configure(yscrollcommand=scrollbar.set)
            
            # 读取并显示日志内容
            with open(latest_log, 'r', encoding='utf-8') as f:
                log_text.insert(tk.END, f.read())
                log_text.see(tk.END)
                
            # 禁用编辑
            log_text.configure(state=tk.DISABLED)
            
            self.logger.info("Logs viewed by user")
            
        except Exception as e:
            self.logger.error(f"Failed to view logs: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to view logs: {str(e)}")
                
    def run(self):
        self.root.mainloop()
        # 记录程序退出
        self.logger.info("PLC Security Testing Tool closed")

if __name__ == "__main__":
    app = PLCSecurityTester()
    app.run() 