import socket
import struct
import time
import binascii
from scapy.all import *
import nmap
import pymodbus.client
import sqlite3
import subprocess
import os
import hashlib
import requests
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class BaseTester:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 443, 445, 502, 102, 502, 1024, 1025, 1026, 1027, 1028, 1029]
        self.modbus_ports = [502, 102]
        self.industrial_protocols = {
            'Modbus': 502,
            'S7': 102,
            'DNP3': 20000,
            'BACnet': 47808,
            'EtherNet/IP': 44818,
            'IEC 104': 2404,
            'IEC 101': 2404,
            'IEC 103': 2404,
            'IEC 61850': 102,
            'MMS': 102,
            'GOOSE': 102,
            'SV': 102,
            'OPC UA': 4840,
            'MQTT': 1883,
            'CoAP': 5683
        }
        
    def run_tests(self, ip: str, port: int, test_types: Dict[str, str]) -> Dict[str, Any]:
        """执行所有选择的测试"""
        results = {}
        
        try:
            # 扫描测试
            if test_types.get("扫描测试"):
                results["扫描测试"] = self._run_scan_test(ip, port, test_types["扫描测试"])
            
            # 协议分析
            if test_types.get("协议分析"):
                results["协议分析"] = self._run_protocol_test(ip, port, test_types["协议分析"])
            
            # 硬件分析
            if test_types.get("硬件分析"):
                results["硬件分析"] = self._run_hardware_test(ip, port, test_types["硬件分析"])
            
            # 漏洞利用
            if test_types.get("漏洞利用"):
                results["漏洞利用"] = self._run_exploit_test(ip, port, test_types["漏洞利用"])
            
            # 恶意代码分析
            if test_types.get("恶意代码分析"):
                results["恶意代码分析"] = self._run_malware_test(ip, port, test_types["恶意代码分析"])
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_scan_test(self, ip: str, port: int, scan_type: str) -> Dict[str, Any]:
        """执行扫描测试"""
        results = {}
        
        try:
            if scan_type == "端口扫描":
                results = self.port_scan(ip, port)
            elif scan_type == "服务识别":
                results = self._identify_services(ip, port)
            elif scan_type == "操作系统识别":
                results = self._identify_os(ip)
            elif scan_type == "网络拓扑扫描":
                results = self._scan_network_topology(ip)
            elif scan_type == "资产发现":
                results = self._discover_assets(ip)
            elif scan_type == "弱密码扫描":
                results = self._scan_weak_passwords(ip, port)
            elif scan_type == "配置审计扫描":
                results = self._audit_configuration(ip, port)
            elif scan_type == "漏洞扫描":
                results = self._scan_vulnerabilities(ip, port)
                
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_protocol_test(self, ip: str, port: int, protocol_type: str) -> Dict[str, Any]:
        """执行协议分析测试"""
        results = {}
        
        try:
            if protocol_type == "Modbus协议分析":
                results = self._analyze_modbus(ip, port)
            elif protocol_type == "S7协议分析":
                results = self._analyze_s7(ip, port)
            elif protocol_type == "DNP3协议分析":
                results = self._analyze_dnp3(ip, port)
            elif protocol_type == "IEC 104协议分析":
                results = self._analyze_iec104(ip, port)
            elif protocol_type == "IEC 61850协议分析":
                results = self._analyze_iec61850(ip, port)
            elif protocol_type == "BACnet协议分析":
                results = self._analyze_bacnet(ip, port)
            elif protocol_type == "EtherNet/IP协议分析":
                results = self._analyze_ethernet_ip(ip, port)
            elif protocol_type == "OPC UA协议分析":
                results = self._analyze_opc_ua(ip, port)
            elif protocol_type == "MQTT协议分析":
                results = self._analyze_mqtt(ip, port)
            elif protocol_type == "CoAP协议分析":
                results = self._analyze_coap(ip, port)
                
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_hardware_test(self, ip: str, port: int, hardware_type: str) -> Dict[str, Any]:
        """执行硬件分析测试"""
        results = {}
        
        try:
            if hardware_type == "固件分析":
                results = self._analyze_firmware(ip, port)
            elif hardware_type == "硬件指纹识别":
                results = self._identify_hardware_fingerprint(ip, port)
            elif hardware_type == "硬件漏洞扫描":
                results = self._scan_hardware_vulnerabilities(ip, port)
            elif hardware_type == "硬件后门检测":
                results = self._detect_hardware_backdoors(ip, port)
            elif hardware_type == "硬件完整性验证":
                results = self._verify_hardware_integrity(ip, port)
            elif hardware_type == "硬件配置审计":
                results = self._audit_hardware_configuration(ip, port)
            elif hardware_type == "硬件通信接口分析":
                results = self._analyze_hardware_interfaces(ip, port)
            elif hardware_type == "硬件加密模块分析":
                results = self._analyze_hardware_encryption(ip, port)
                
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_exploit_test(self, ip: str, port: int, exploit_type: str) -> Dict[str, Any]:
        """执行漏洞利用测试"""
        results = {}
        
        try:
            if exploit_type == "缓冲区溢出利用":
                results = self._exploit_buffer_overflow(ip, port)
            elif exploit_type == "命令注入利用":
                results = self._exploit_command_injection(ip, port)
            elif exploit_type == "SQL注入利用":
                results = self._exploit_sql_injection(ip, port)
            elif exploit_type == "权限提升利用":
                results = self._exploit_privilege_escalation(ip, port)
            elif exploit_type == "拒绝服务攻击":
                results = self._exploit_dos(ip, port)
            elif exploit_type == "协议漏洞利用":
                results = self._exploit_protocol_vulnerabilities(ip, port)
            elif exploit_type == "固件漏洞利用":
                results = self._exploit_firmware_vulnerabilities(ip, port)
            elif exploit_type == "硬件漏洞利用":
                results = self._exploit_hardware_vulnerabilities(ip, port)
            elif exploit_type == "认证绕过利用":
                results = self._exploit_auth_bypass(ip, port)
            elif exploit_type == "加密算法漏洞利用":
                results = self._exploit_crypto_vulnerabilities(ip, port)
                
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_malware_test(self, ip: str, port: int, malware_type: str) -> Dict[str, Any]:
        """执行恶意代码分析测试"""
        results = {}
        
        try:
            if malware_type == "木马检测":
                results = self._detect_trojans(ip, port)
            elif malware_type == "病毒检测":
                results = self._detect_viruses(ip, port)
            elif malware_type == "后门程序检测":
                results = self._detect_backdoors(ip, port)
            elif malware_type == "勒索软件检测":
                results = self._detect_ransomware(ip, port)
            elif malware_type == "挖矿程序检测":
                results = self._detect_miners(ip, port)
            elif malware_type == "恶意固件检测":
                results = self._detect_malicious_firmware(ip, port)
            elif malware_type == "恶意协议检测":
                results = self._detect_malicious_protocols(ip, port)
            elif malware_type == "异常行为检测":
                results = self._detect_anomalies(ip, port)
            elif malware_type == "网络流量分析":
                results = self._analyze_network_traffic(ip, port)
            elif malware_type == "系统日志分析":
                results = self._analyze_system_logs(ip, port)
                
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def port_scan(self, ip: str, port: int = None) -> Dict[str, Any]:
        """执行端口扫描"""
        try:
            if port:
                self.nm.scan(ip, str(port))
            else:
                self.nm.scan(ip, ','.join(map(str, self.common_ports)))
            
            results = {
                'open_ports': [],
                'services': {},
                'vulnerabilities': []
            }
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        if state == 'open':
                            results['open_ports'].append(port)
                            results['services'][port] = self.nm[host][proto][port]['name']
                            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def protocol_analysis(self, ip: str, port: int) -> Dict[str, Any]:
        """分析工业协议"""
        results = {
            'protocols': [],
            'details': {},
            'vulnerabilities': []
        }
        
        try:
            # 检查常见工业协议
            for protocol, default_port in self.industrial_protocols.items():
                if port == default_port:
                    results['protocols'].append(protocol)
                    
                    # 协议特定分析
                    if protocol == 'Modbus':
                        results['details'][protocol] = self._analyze_modbus(ip, port)
                    elif protocol == 'S7':
                        results['details'][protocol] = self._analyze_s7(ip, port)
                    elif protocol == 'DNP3':
                        results['details'][protocol] = self._analyze_dnp3(ip, port)
                    elif protocol == 'BACnet':
                        results['details'][protocol] = self._analyze_bacnet(ip, port)
                    elif protocol == 'EtherNet/IP':
                        results['details'][protocol] = self._analyze_ethernet_ip(ip, port)
                    
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerability_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """执行漏洞扫描"""
        results = {
            'vulnerabilities': [],
            'risk_level': 'low',
            'recommendations': []
        }
        
        try:
            # 检查常见漏洞
            vulns = []
            
            # 1. 检查默认密码
            vulns.extend(self._check_default_passwords(ip, port))
            
            # 2. 检查缓冲区溢出漏洞
            vulns.extend(self._check_buffer_overflow(ip, port))
            
            # 3. 检查命令注入漏洞
            vulns.extend(self._check_command_injection(ip, port))
            
            # 4. 检查SQL注入漏洞
            vulns.extend(self._check_sql_injection(ip, port))
            
            # 5. 检查固件漏洞
            vulns.extend(self._check_firmware_vulnerabilities(ip, port))
            
            # 6. 检查拒绝服务漏洞
            vulns.extend(self._check_dos_vulnerabilities(ip, port))
            
            results['vulnerabilities'] = vulns
            
            # 评估风险等级
            if len(vulns) > 5:
                results['risk_level'] = 'high'
            elif len(vulns) > 2:
                results['risk_level'] = 'medium'
                
            # 生成建议
            results['recommendations'] = self._generate_recommendations(vulns)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_modbus(self, ip: str, port: int) -> Dict[str, Any]:
        """分析Modbus协议"""
        try:
            client = pymodbus.client.ModbusTcpClient(ip, port)
            client.connect()
            
            results = {
                'unit_id': None,
                'function_codes': [],
                'coils': [],
                'registers': []
            }
            
            # 尝试不同的单元ID
            for unit_id in range(1, 248):
                try:
                    response = client.read_coils(0, 1, slave=unit_id)
                    if not response.isError():
                        results['unit_id'] = unit_id
                        break
                except:
                    continue
            
            if results['unit_id']:
                # 测试功能码
                for fc in [1, 2, 3, 4, 5, 6, 15, 16]:
                    try:
                        if fc in [1, 2]:
                            response = client.read_coils(0, 1, slave=results['unit_id'])
                        elif fc in [3, 4]:
                            response = client.read_holding_registers(0, 1, slave=results['unit_id'])
                        if not response.isError():
                            results['function_codes'].append(fc)
                    except:
                        continue
            
            client.close()
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_s7(self, ip: str, port: int) -> Dict[str, Any]:
        """分析S7协议"""
        try:
            # 创建S7通信数据包
            s7_packet = (
                IP(dst=ip)/
                TCP(dport=port)/
                Raw(load=binascii.unhexlify('0300001611e00000000100c1020100c2020102'))
            )
            
            # 发送数据包并分析响应
            response = sr1(s7_packet, timeout=2, verbose=0)
            
            results = {
                'rack': None,
                'slot': None,
                'cpu_type': None,
                'firmware_version': None
            }
            
            if response and response.haslayer(Raw):
                # 解析S7响应
                data = response[Raw].load
                if len(data) >= 27:
                    results['rack'] = data[21]
                    results['slot'] = data[22]
                    results['cpu_type'] = data[23:25].hex()
                    results['firmware_version'] = data[25:27].hex()
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_dnp3(self, ip: str, port: int) -> Dict[str, Any]:
        """分析DNP3协议"""
        try:
            # 创建DNP3请求数据包
            dnp3_packet = (
                IP(dst=ip)/
                TCP(dport=port)/
                Raw(load=binascii.unhexlify('0564'))
            )
            
            # 发送数据包并分析响应
            response = sr1(dnp3_packet, timeout=2, verbose=0)
            
            results = {
                'source': None,
                'destination': None,
                'function_code': None,
                'internal_indications': None
            }
            
            if response and response.haslayer(Raw):
                # 解析DNP3响应
                data = response[Raw].load
                if len(data) >= 10:
                    results['source'] = int.from_bytes(data[0:2], byteorder='little')
                    results['destination'] = int.from_bytes(data[2:4], byteorder='little')
                    results['function_code'] = data[4]
                    results['internal_indications'] = int.from_bytes(data[5:7], byteorder='little')
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_bacnet(self, ip: str, port: int) -> Dict[str, Any]:
        """分析BACnet协议"""
        try:
            # 创建BACnet Who-Is请求
            bacnet_packet = (
                IP(dst=ip)/
                UDP(dport=port)/
                Raw(load=binascii.unhexlify('810b000c0120ffff00ff1008'))
            )
            
            # 发送数据包并分析响应
            response = sr1(bacnet_packet, timeout=2, verbose=0)
            
            results = {
                'device_id': None,
                'vendor_id': None,
                'firmware_version': None,
                'object_instances': []
            }
            
            if response and response.haslayer(Raw):
                # 解析BACnet响应
                data = response[Raw].load
                if len(data) >= 10:
                    results['device_id'] = int.from_bytes(data[2:4], byteorder='big')
                    results['vendor_id'] = int.from_bytes(data[4:6], byteorder='big')
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_ethernet_ip(self, ip: str, port: int) -> Dict[str, Any]:
        """分析EtherNet/IP协议"""
        try:
            # 创建EtherNet/IP List Identity请求
            ethernet_ip_packet = (
                IP(dst=ip)/
                TCP(dport=port)/
                Raw(load=binascii.unhexlify('6300000000000000000000000000000000000000000000000000000000000000'))
            )
            
            # 发送数据包并分析响应
            response = sr1(ethernet_ip_packet, timeout=2, verbose=0)
            
            results = {
                'device_type': None,
                'vendor_id': None,
                'product_code': None,
                'revision': None,
                'status': None
            }
            
            if response and response.haslayer(Raw):
                # 解析EtherNet/IP响应
                data = response[Raw].load
                if len(data) >= 24:
                    results['device_type'] = int.from_bytes(data[0:2], byteorder='little')
                    results['vendor_id'] = int.from_bytes(data[2:4], byteorder='little')
                    results['product_code'] = int.from_bytes(data[4:6], byteorder='little')
                    results['revision'] = f"{data[6]}.{data[7]}"
                    results['status'] = int.from_bytes(data[8:10], byteorder='little')
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_default_passwords(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查默认密码"""
        vulns = []
        default_credentials = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'root', 'password': 'root'},
            {'username': 'root', 'password': 'password'},
            {'username': 'admin', 'password': ''},
            {'username': 'root', 'password': ''}
        ]
        
        try:
            for cred in default_credentials:
                # 根据不同协议尝试认证
                if port == 502:  # Modbus
                    client = pymodbus.client.ModbusTcpClient(ip, port)
                    client.connect()
                    # 尝试认证
                    client.close()
                elif port == 102:  # S7
                    # 尝试S7认证
                    pass
                elif port == 80:  # Web界面
                    # 尝试Web认证
                    pass
                
        except Exception as e:
            vulns.append({
                'type': 'default_password',
                'description': f'发现默认密码漏洞: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _check_buffer_overflow(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查缓冲区溢出漏洞"""
        vulns = []
        
        try:
            # 创建超长数据包
            long_data = 'A' * 1000
            overflow_packet = (
                IP(dst=ip)/
                TCP(dport=port)/
                Raw(load=long_data)
            )
            
            # 发送数据包并观察响应
            response = sr1(overflow_packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP) and response[TCP].flags & 0x04:  # RST flag
                vulns.append({
                    'type': 'buffer_overflow',
                    'description': '可能存在缓冲区溢出漏洞',
                    'severity': 'high',
                    'port': port
                })
                
        except Exception as e:
            vulns.append({
                'type': 'buffer_overflow',
                'description': f'缓冲区溢出测试异常: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _check_command_injection(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查命令注入漏洞"""
        vulns = []
        
        try:
            # 测试命令注入
            injection_payloads = [
                '; ls',
                '| dir',
                '`whoami`',
                '$(cat /etc/passwd)',
                '; cat /etc/passwd',
                '| type c:\\windows\\system32\\drivers\\etc\\hosts'
            ]
            
            for payload in injection_payloads:
                injection_packet = (
                    IP(dst=ip)/
                    TCP(dport=port)/
                    Raw(load=payload)
                )
                
                response = sr1(injection_packet, timeout=2, verbose=0)
                
                if response and response.haslayer(Raw):
                    # 分析响应中是否包含命令执行结果
                    if any(marker in response[Raw].load.decode('utf-8', errors='ignore').lower() 
                          for marker in ['root:', 'administrator', 'system32', 'etc/passwd']):
                        vulns.append({
                            'type': 'command_injection',
                            'description': f'发现命令注入漏洞，成功执行: {payload}',
                            'severity': 'critical',
                            'port': port
                        })
                        break
                        
        except Exception as e:
            vulns.append({
                'type': 'command_injection',
                'description': f'命令注入测试异常: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _check_sql_injection(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查SQL注入漏洞"""
        vulns = []
        
        try:
            # SQL注入测试载荷
            sql_payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "' WAITFOR DELAY '0:0:5'--",
                "admin'--",
                "' OR 1=1--"
            ]
            
            for payload in sql_payloads:
                sql_packet = (
                    IP(dst=ip)/
                    TCP(dport=port)/
                    Raw(load=payload.encode())
                )
                
                start_time = time.time()
                response = sr1(sql_packet, timeout=2, verbose=0)
                end_time = time.time()
                
                # 检查时间延迟
                if end_time - start_time > 5:
                    vulns.append({
                        'type': 'sql_injection',
                        'description': f'发现SQL注入漏洞，成功执行: {payload}',
                        'severity': 'critical',
                        'port': port
                    })
                    break
                    
                # 检查错误信息
                if response and response.haslayer(Raw):
                    error_messages = [
                        'sql syntax',
                        'mysql_fetch_array()',
                        'sql error',
                        'oracle error',
                        'postgresql error',
                        'sql server error'
                    ]
                    
                    response_text = response[Raw].load.decode('utf-8', errors='ignore').lower()
                    if any(msg in response_text for msg in error_messages):
                        vulns.append({
                            'type': 'sql_injection',
                            'description': f'发现SQL注入漏洞，数据库错误信息泄露',
                            'severity': 'high',
                            'port': port
                        })
                        break
                        
        except Exception as e:
            vulns.append({
                'type': 'sql_injection',
                'description': f'SQL注入测试异常: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _check_firmware_vulnerabilities(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查固件漏洞"""
        vulns = []
        
        try:
            # 获取固件信息
            firmware_info = self._get_firmware_info(ip, port)
            
            if firmware_info:
                # 检查已知漏洞
                known_vulns = self._check_known_vulnerabilities(firmware_info)
                vulns.extend(known_vulns)
                
                # 检查固件完整性
                if not self._verify_firmware_integrity(firmware_info):
                    vulns.append({
                        'type': 'firmware_integrity',
                        'description': '固件完整性验证失败',
                        'severity': 'high',
                        'port': port
                    })
                
                # 检查固件更新机制
                if not self._check_firmware_update_mechanism(firmware_info):
                    vulns.append({
                        'type': 'firmware_update',
                        'description': '固件更新机制存在安全隐患',
                        'severity': 'medium',
                        'port': port
                    })
                    
        except Exception as e:
            vulns.append({
                'type': 'firmware_vulnerability',
                'description': f'固件漏洞检查异常: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _check_dos_vulnerabilities(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """检查拒绝服务漏洞"""
        vulns = []
        
        try:
            # 创建大量连接
            connections = []
            for _ in range(100):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((ip, port))
                    connections.append(sock)
                except:
                    break
            
            # 检查服务是否受到影响
            if len(connections) < 100:
                vulns.append({
                    'type': 'dos_vulnerability',
                    'description': '存在拒绝服务漏洞',
                    'severity': 'high',
                    'port': port
                })
            
            # 清理连接
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
                    
        except Exception as e:
            vulns.append({
                'type': 'dos_vulnerability',
                'description': f'拒绝服务测试异常: {str(e)}',
                'severity': 'high',
                'port': port
            })
        
        return vulns
    
    def _get_firmware_info(self, ip: str, port: int) -> Dict[str, Any]:
        """获取固件信息"""
        try:
            # 根据不同协议获取固件信息
            if port == 502:  # Modbus
                client = pymodbus.client.ModbusTcpClient(ip, port)
                client.connect()
                # 读取固件信息寄存器
                response = client.read_holding_registers(0, 10)
                client.close()
                return {
                    'protocol': 'Modbus',
                    'version': response.registers[0:2],
                    'device_type': response.registers[2:4],
                    'serial_number': response.registers[4:6]
                }
            elif port == 102:  # S7
                # 获取S7固件信息
                pass
            return None
            
        except Exception as e:
            return None
    
    def _check_known_vulnerabilities(self, firmware_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检查已知漏洞"""
        vulns = []
        
        try:
            # 这里应该维护一个已知漏洞数据库
            # 示例检查
            if firmware_info['protocol'] == 'Modbus':
                version = firmware_info['version']
                if version[0] < 2 or (version[0] == 2 and version[1] < 5):
                    vulns.append({
                        'type': 'known_vulnerability',
                        'description': '固件版本过低，存在已知漏洞',
                        'severity': 'high',
                        'details': '建议升级到最新版本'
                    })
                    
        except Exception as e:
            pass
        
        return vulns
    
    def _verify_firmware_integrity(self, firmware_info: Dict[str, Any]) -> bool:
        """验证固件完整性"""
        try:
            # 这里应该实现固件完整性验证
            # 示例实现
            return True
            
        except Exception as e:
            return False
    
    def _check_firmware_update_mechanism(self, firmware_info: Dict[str, Any]) -> bool:
        """检查固件更新机制"""
        try:
            # 这里应该检查固件更新机制的安全性
            # 示例实现
            return True
            
        except Exception as e:
            return False
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'default_password':
                recommendations.append('修改默认密码，使用强密码策略')
            elif vuln['type'] == 'buffer_overflow':
                recommendations.append('更新固件到最新版本，修复缓冲区溢出漏洞')
            elif vuln['type'] == 'command_injection':
                recommendations.append('实施输入验证和过滤，防止命令注入')
            elif vuln['type'] == 'sql_injection':
                recommendations.append('使用参数化查询，防止SQL注入')
            elif vuln['type'] == 'firmware_integrity':
                recommendations.append('实施固件签名验证机制')
            elif vuln['type'] == 'firmware_update':
                recommendations.append('加强固件更新过程的安全性')
            elif vuln['type'] == 'dos_vulnerability':
                recommendations.append('实施连接限制和流量控制机制')
        
        return recommendations

class SiemensTester(BaseTester):
    def __init__(self):
        super().__init__()
        self.siemens_ports = [102, 502, 1024, 1025, 1026, 1027, 1028, 1029]
    
    def port_scan(self, ip: str, port: int = None) -> Dict[str, Any]:
        """西门子设备端口扫描"""
        if port:
            ports = [port]
        else:
            ports = self.siemens_ports
            
        return super().port_scan(ip, ports)

class GETester(BaseTester):
    def __init__(self):
        super().__init__()
        self.ge_ports = [502, 1024, 1025, 1026, 1027, 1028, 1029]
    
    def port_scan(self, ip: str, port: int = None) -> Dict[str, Any]:
        """GE设备端口扫描"""
        if port:
            ports = [port]
        else:
            ports = self.ge_ports
            
        return super().port_scan(ip, ports)

class MitsubishiTester(BaseTester):
    def __init__(self):
        super().__init__()
        self.mitsubishi_ports = [502, 1024, 1025, 1026, 1027, 1028, 1029]
    
    def port_scan(self, ip: str, port: int = None) -> Dict[str, Any]:
        """三菱设备端口扫描"""
        if port:
            ports = [port]
        else:
            ports = self.mitsubishi_ports
            
        return super().port_scan(ip, ports)

class GenericTester(BaseTester):
    def __init__(self):
        super().__init__()
        self.generic_ports = [502, 1024, 1025, 1026, 1027, 1028, 1029]
    
    def port_scan(self, ip: str, port: int = None) -> Dict[str, Any]:
        """通用设备端口扫描"""
        if port:
            ports = [port]
        else:
            ports = self.generic_ports
            
        return super().port_scan(ip, ports) 