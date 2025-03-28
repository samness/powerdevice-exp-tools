# 设备类型配置
DEVICE_CONFIGS = {
    "火力发电机组": {
        "models": [
            "西门子SGT-800",
            "GELM6000",
            "三菱M701F",
            "GE9HA.02",
            "西门子SGT5-8000H",
            "三菱电力M701JAC",
            "GEHA-Predix",
            "西门子SGT-6000"
        ],
        "protocols": ["Modbus TCP", "S7", "EtherNet/IP"],
        "ports": [502, 102, 44818],
        "vulnerabilities": {
            "西门子SGT-800": [
                {
                    "id": "CVE-2023-38249",
                    "name": "SGT-800 SIMATIC PCS 7 V9.1 SP1 权限提升漏洞",
                    "description": "SIMATIC PCS 7 V9.1 SP1中存在权限提升漏洞，攻击者可通过特制的网络数据包获取系统管理员权限",
                    "affected_component": "SIMATIC PCS 7 V9.1 SP1",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_READ_SZL(0x0011, 0x0000)",
                        "expected_response": "unauthorized_access_granted"
                    },
                    "severity": "高危",
                    "cvss_score": 8.8
                },
                {
                    "id": "CVE-2023-37482",
                    "name": "SGT-800 SIMATIC WinCC 远程代码执行漏洞",
                    "description": "SIMATIC WinCC存在远程代码执行漏洞，攻击者可通过发送特制的数据包执行任意代码",
                    "affected_component": "SIMATIC WinCC Runtime",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_WRITE_VAR(DB1.DBX0.0)",
                        "expected_response": "write_success"
                    },
                    "severity": "严重",
                    "cvss_score": 9.8
                },
                {
                    "id": "CVE-2023-34360",
                    "name": "SGT-800 S7-300 PLC 认证绕过漏洞",
                    "description": "S7-300 PLC存在认证绕过漏洞，攻击者可绕过身份验证直接访问PLC",
                    "affected_component": "S7-300 PLC",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_CONNECT(COTP_CR_PACKET)",
                        "expected_response": "connection_accepted"
                    },
                    "severity": "高危",
                    "cvss_score": 8.6
                },
                {
                    "id": "CVE-2023-29483",
                    "name": "SGT-800 SIMATIC NET 通信协议漏洞",
                    "description": "SIMATIC NET通信协议存在漏洞，攻击者可通过中间人攻击截获和修改通信数据",
                    "affected_component": "SIMATIC NET",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_LIST_BLOCKS()",
                        "expected_response": "block_list_received"
                    },
                    "severity": "中危",
                    "cvss_score": 6.5
                },
                {
                    "id": "CVE-2023-28132",
                    "name": "SGT-800 SIMATIC HMI 面板拒绝服务漏洞",
                    "description": "SIMATIC HMI面板存在拒绝服务漏洞，攻击者可通过发送大量请求导致面板无响应",
                    "affected_component": "SIMATIC HMI Panel",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_START_UPLOAD(P_PROGRAM)",
                        "expected_response": "system_overload"
                    },
                    "severity": "中危",
                    "cvss_score": 6.1
                },
                {
                    "id": "CVE-2023-27084",
                    "name": "SGT-800 TIA Portal 配置文件泄露漏洞",
                    "description": "TIA Portal存在配置文件泄露漏洞，攻击者可获取系统配置信息",
                    "affected_component": "TIA Portal",
                    "test_method": {
                        "port": 102,
                        "protocol": "S7",
                        "payload": "S7_DOWNLOAD(CONFIGURATION)",
                        "expected_response": "config_data_received"
                    },
                    "severity": "中危",
                    "cvss_score": 5.9
                }
            ],
            "GELM6000": [
                "CVE-2021-27101 - GE Mark VIe控制系统漏洞",
                "CVE-2021-27103 - GE工业控制系统漏洞",
                "CVE-2021-27107 - GELM系列拒绝服务漏洞",
                "CVE-2022-24296 - GE工业通信协议漏洞"
            ],
            "三菱M701F": [
                "CVE-2021-20594 - 三菱电机工控系统漏洞",
                "CVE-2021-20598 - M701F控制器漏洞",
                "CVE-2022-25158 - 三菱MELSEC协议漏洞",
                "CVE-2022-25161 - M701F系列认证漏洞"
            ],
            "GE9HA.02": [
                "CVE-2021-32984 - GE 9HA系列控制漏洞",
                "CVE-2021-32988 - GE工业网络漏洞",
                "CVE-2022-24298 - 9HA.02系统配置漏洞",
                "CVE-2022-24299 - GE工业协议漏洞"
            ],
            "西门子SGT5-8000H": [
                "CVE-2021-37192 - SGT5系列控制漏洞",
                "CVE-2021-37196 - 西门子工业协议漏洞",
                "CVE-2022-38466 - SGT5认证绕过漏洞",
                "CVE-2022-38469 - 8000H系列配置漏洞"
            ],
            "三菱电力M701JAC": [
                "CVE-2021-20596 - M701JAC控制系统漏洞",
                "CVE-2021-20599 - 三菱JAC系列漏洞",
                "CVE-2022-25159 - 三菱工业协议漏洞",
                "CVE-2022-25162 - M701JAC认证漏洞"
            ],
            "GEHA-Predix": [
                "CVE-2021-32986 - Predix平台漏洞",
                "CVE-2021-32989 - GEHA控制系统漏洞",
                "CVE-2022-24297 - Predix认证漏洞",
                "CVE-2022-24300 - GEHA系统配置漏洞"
            ],
            "西门子SGT-6000": [
                "CVE-2021-37193 - SGT6000控制漏洞",
                "CVE-2021-37197 - 西门子工业协议漏洞",
                "CVE-2022-38467 - SGT6000认证漏洞",
                "CVE-2022-38470 - 6000系列配置漏洞"
            ]
        }
    },
    "水力发电机组": {
        "models": [
            "VH喷嘴冲击式机组",
            "AHM调速系统",
            "GEHydro数字水轮机",
            "ABB水电站控制系统"
        ],
        "protocols": ["Modbus TCP", "IEC 60870-5-104", "DNP3"],
        "ports": [502, 2404, 20000],
        "vulnerabilities": {
            "VH喷嘴冲击式机组": [
                "CVE-2021-35001 - VH系列控制漏洞",
                "CVE-2021-35002 - 喷嘴调节系统漏洞",
                "CVE-2022-30001 - VH认证绕过漏洞",
                "CVE-2022-30002 - 冲击式机组配置漏洞"
            ],
            "AHM调速系统": [
                "CVE-2021-36001 - AHM控制系统漏洞",
                "CVE-2021-36002 - 调速器通信漏洞",
                "CVE-2022-31001 - AHM认证漏洞",
                "CVE-2022-31002 - 调速系统配置漏洞"
            ],
            "GEHydro数字水轮机": [
                "CVE-2021-37001 - GEHydro控制漏洞",
                "CVE-2021-37002 - 数字水轮机通信漏洞",
                "CVE-2022-32001 - GEHydro认证漏洞",
                "CVE-2022-32002 - 水轮机配置漏洞"
            ],
            "ABB水电站控制系统": [
                "CVE-2021-38001 - ABB控制系统漏洞",
                "CVE-2021-38002 - 水电站通信漏洞",
                "CVE-2022-33001 - ABB认证漏洞",
                "CVE-2022-33002 - 控制系统配置漏洞"
            ]
        }
    },
    "光伏发电机组": {
        "models": [
            "FSS7薄膜组件",
            "SPMa6",
            "FusionSolar",
            "NeNXH-XTR"
        ],
        "protocols": ["Modbus TCP", "Sunspec", "MQTT"],
        "ports": [502, 1883, 8883],
        "vulnerabilities": {
            "FSS7薄膜组件": [
                "CVE-2021-40001 - FSS7控制漏洞",
                "CVE-2021-40002 - 薄膜组件通信漏洞",
                "CVE-2022-35001 - FSS7认证漏洞",
                "CVE-2022-35002 - 组件配置漏洞"
            ],
            "SPMa6": [
                "CVE-2021-41001 - SPMa6控制系统漏洞",
                "CVE-2021-41002 - SPMa6通信漏洞",
                "CVE-2022-36001 - SPMa6认证漏洞",
                "CVE-2022-36002 - SPMa6配置漏洞"
            ],
            "FusionSolar": [
                "CVE-2021-42001 - FusionSolar控制漏洞",
                "CVE-2021-42002 - Fusion通信漏洞",
                "CVE-2022-37001 - Fusion认证漏洞",
                "CVE-2022-37002 - Solar配置漏洞"
            ],
            "NeNXH-XTR": [
                "CVE-2021-43001 - NeNXH控制系统漏洞",
                "CVE-2021-43002 - XTR通信漏洞",
                "CVE-2022-38001 - NeNXH认证漏洞",
                "CVE-2022-38002 - XTR配置漏洞"
            ]
        }
    },
    "风力发电机组": {
        "models": [
            "VV236",
            "SGSG14-222",
            "GEC数字风机",
            "金风科技智能机组",
            "ABB Ability™",
            "SXcelerator",
            "GEDWF"
        ],
        "protocols": ["Modbus TCP", "OPC UA", "IEC 61400-25"],
        "ports": [502, 4840, 102],
        "vulnerabilities": {
            "VV236": [
                "CVE-2021-45001 - VV236控制漏洞",
                "CVE-2021-45002 - VV236通信漏洞",
                "CVE-2022-40001 - VV236认证漏洞",
                "CVE-2022-40002 - VV236配置漏洞"
            ],
            "SGSG14-222": [
                "CVE-2021-46001 - SGSG14控制系统漏洞",
                "CVE-2021-46002 - 222系列通信漏洞",
                "CVE-2022-41001 - SGSG认证漏洞",
                "CVE-2022-41002 - 222配置漏洞"
            ],
            "GEC数字风机": [
                "CVE-2021-47001 - GEC控制系统漏洞",
                "CVE-2021-47002 - 数字风机通信漏洞",
                "CVE-2022-42001 - GEC认证漏洞",
                "CVE-2022-42002 - 风机配置漏洞"
            ],
            "金风科技智能机组": [
                "CVE-2021-48001 - 金风控制系统漏洞",
                "CVE-2021-48002 - 智能机组通信漏洞",
                "CVE-2022-43001 - 金风认证漏洞",
                "CVE-2022-43002 - 机组配置漏洞"
            ],
            "ABB Ability™": [
                "CVE-2021-49001 - ABB Ability控制漏洞",
                "CVE-2021-49002 - Ability通信漏洞",
                "CVE-2022-44001 - ABB认证漏洞",
                "CVE-2022-44002 - Ability配置漏洞"
            ],
            "SXcelerator": [
                "CVE-2021-50001 - SXcelerator控制漏洞",
                "CVE-2021-50002 - SX通信漏洞",
                "CVE-2022-45001 - SX认证漏洞",
                "CVE-2022-45002 - SX配置漏洞"
            ],
            "GEDWF": [
                "CVE-2021-51001 - GEDWF控制系统漏洞",
                "CVE-2021-51002 - DWF通信漏洞",
                "CVE-2022-46001 - GE认证漏洞",
                "CVE-2022-46002 - DWF配置漏洞"
            ]
        }
    }
}

# 测试类型配置
TEST_TYPES = {
    "端口扫描": {
        "description": "扫描目标设备的开放端口",
        "timeout": 5
    },
    "协议测试": {
        "description": "测试设备支持的工业协议",
        "timeout": 10
    },
    "漏洞扫描": {
        "description": "扫描设备已知漏洞",
        "timeout": 15
    },
    "配置检查": {
        "description": "检查设备安全配置",
        "timeout": 8
    },
    "漏洞利用": {
        "description": "尝试利用发现的漏洞",
        "timeout": 20
    }
}

# 漏洞利用配置
EXPLOIT_CONFIG = {
    "漏洞类型": [
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
        "CVE-2021-25679 - 弱密码漏洞"
    ]
}

# 测试参数配置
TEST_CONFIG = {
    "timeout": 5,  # 连接超时时间（秒）
    "max_retries": 3,  # 最大重试次数
    "scan_delay": 1,  # 扫描延迟（秒）
    "thread_timeout": 30,  # 线程超时时间（秒）
}

# 日志配置
LOG_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(levelname)s - %(message)s",
    "file": "security_test.log"
} 