# PLC Security Testing Tool

这是一个用于PLC安全测试的Python工具，支持多种PLC品牌和测试方法。

## 功能特点

- 支持多种PLC品牌：
  - 西门子 (Siemens)
  - 罗克韦尔 (Rockwell)
  - 施耐德 (Schneider)
  - 欧姆龙 (Omron)
  - 三菱电机 (Mitsubishi)
  - 倍福 (Beckhoff)
  - ABB

- 测试方法：
  - DDoS攻击
  - 协议洪水攻击
  - 数据包注入

## 安装要求

- Python 3.8+
- PyQt6
- pymodbus
- python-nmap

## 安装步骤

1. 克隆或下载此仓库
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

## 使用方法

1. 运行程序：
   ```bash
   python plc_security_test.py
   ```

2. 在GUI界面中：
   - 选择目标PLC品牌
   - 选择测试类型
   - 输入目标IP地址
   - 设置端口号（默认502）
   - 设置并发线程数
   - 点击"Start Test"开始测试

3. 测试过程中可以：
   - 查看实时日志
   - 随时停止测试
   - 查看测试结果

## 注意事项

- 本工具仅用于授权的安全测试
- 使用前请确保获得测试目标系统的授权
- 建议在测试环境中使用
- 过度使用可能导致目标系统不稳定

## 免责声明

本工具仅供安全研究和授权的渗透测试使用。使用本工具进行未经授权的测试可能违反相关法律法规。使用者需自行承担使用本工具的所有风险和责任。 