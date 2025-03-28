import requests
from bs4 import BeautifulSoup
import nmap
import socket
import json
import os
from typing import Dict, List, Tuple

class DeviceInfoManager:
    def __init__(self):
        self.device_info_cache = {}
        self.load_local_device_database()

    def load_local_device_database(self):
        """加载本地设备数据库"""
        database_path = "device_database.json"
        if os.path.exists(database_path):
            with open(database_path, 'r', encoding='utf-8') as f:
                self.local_database = json.load(f)
        else:
            self.local_database = {}

    def query_device_info(self, model: str) -> Dict:
        """查询设备信息（在线和本地结合）"""
        if model in self.device_info_cache:
            return self.device_info_cache[model]

        device_info = {
            'model': model,
            'manufacturer': '',
            'debug_ports': [],
            'maintenance_ports': [],
            'protocols': [],
            'description': ''
        }

        # 首先检查本地数据库
        if model in self.local_database:
            device_info.update(self.local_database[model])
        
        # 在线查询补充信息
        try:
            online_info = self._query_online_device_info(model)
            device_info.update(online_info)
        except Exception as e:
            print(f"在线查询设备信息失败: {str(e)}")

        self.device_info_cache[model] = device_info
        return device_info

    def _query_online_device_info(self, model: str) -> Dict:
        """从互联网查询设备信息"""
        # 使用多个数据源进行查询
        sources = [
            self._query_ics_cert_database,
            self._query_manufacturer_database,
            self._query_security_database
        ]

        combined_info = {
            'debug_ports': [],
            'maintenance_ports': [],
            'protocols': []
        }

        for source in sources:
            try:
                info = source(model)
                if info:
                    for key in combined_info:
                        if key in info:
                            combined_info[key].extend(info[key])
            except Exception as e:
                print(f"数据源查询失败: {str(e)}")

        # 去重
        for key in combined_info:
            combined_info[key] = list(set(combined_info[key]))

        return combined_info

    def _query_ics_cert_database(self, model: str) -> Dict:
        """查询工控设备认证数据库"""
        # 这里实现具体的查询逻辑
        # 示例实现
        return {
            'debug_ports': [],
            'maintenance_ports': [],
            'protocols': []
        }

    def _query_manufacturer_database(self, model: str) -> Dict:
        """查询制造商数据库"""
        # 这里实现具体的查询逻辑
        return {}

    def _query_security_database(self, model: str) -> Dict:
        """查询安全漏洞数据库"""
        # 这里实现具体的查询逻辑
        return {}

    def scan_local_ports(self, ip: str, port_range: Tuple[int, int] = (1, 65535)) -> Dict:
        """本地端口扫描"""
        results = {
            'debug_ports': [],
            'maintenance_ports': [],
            'unknown_ports': []
        }

        nm = nmap.PortScanner()
        nm.scan(ip, f"{port_range[0]}-{port_range[1]}", arguments='-sS -sV -Pn')

        if ip in nm.all_hosts():
            for port in nm[ip]['tcp']:
                service = nm[ip]['tcp'][port]
                port_info = {
                    'port': port,
                    'service': service.get('name', ''),
                    'version': service.get('version', ''),
                    'product': service.get('product', '')
                }

                # 根据服务特征分类端口
                if self._is_debug_port(service):
                    results['debug_ports'].append(port_info)
                elif self._is_maintenance_port(service):
                    results['maintenance_ports'].append(port_info)
                else:
                    results['unknown_ports'].append(port_info)

        return results

    def scan_remote_ports(self, ip: str, port_range: Tuple[int, int] = (1, 65535)) -> Dict:
        """远程端口扫描"""
        results = {
            'debug_ports': [],
            'maintenance_ports': [],
            'unknown_ports': []
        }

        for port in range(port_range[0], port_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        # 端口开放，尝试识别服务
                        service_info = self._identify_service(ip, port)
                        if self._is_debug_port(service_info):
                            results['debug_ports'].append({'port': port, **service_info})
                        elif self._is_maintenance_port(service_info):
                            results['maintenance_ports'].append({'port': port, **service_info})
                        else:
                            results['unknown_ports'].append({'port': port, **service_info})
            except Exception as e:
                print(f"扫描端口 {port} 时出错: {str(e)}")

        return results

    def _identify_service(self, ip: str, port: int) -> Dict:
        """识别服务类型和版本"""
        service_info = {
            'service': '',
            'version': '',
            'product': ''
        }

        try:
            # 尝试获取banner信息
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                s.send(b'')
                banner = s.recv(1024)
                service_info.update(self._parse_banner(banner))
        except Exception:
            pass

        return service_info

    def _parse_banner(self, banner: bytes) -> Dict:
        """解析banner信息"""
        try:
            banner_str = banner.decode('utf-8', errors='ignore')
            # 实现banner解析逻辑
            return {
                'service': '',
                'version': '',
                'product': ''
            }
        except Exception:
            return {}

    def _is_debug_port(self, service_info: Dict) -> bool:
        """判断是否为调试端口"""
        debug_services = {
            'telnet', 'ssh', 'debug', 'gdbserver',
            'jdwp', 'rdb', 'dap', 'lldb'
        }
        service_name = service_info.get('service', '').lower()
        return any(debug in service_name for debug in debug_services)

    def _is_maintenance_port(self, service_info: Dict) -> bool:
        """判断是否为维护端口"""
        maintenance_services = {
            'http', 'https', 'ftp', 'sftp', 'snmp',
            'modbus', 's7comm', 'bacnet', 'dnp3',
            'ethernet-ip', 'opcua', 'iec-104'
        }
        service_name = service_info.get('service', '').lower()
        return any(maint in service_name for maint in maintenance_services) 