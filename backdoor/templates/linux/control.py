import socket
import json
import base64
import os
import platform
import subprocess
import psutil
from PIL import ImageGrab
import tempfile
import logging
from datetime import datetime

# 配置日志
def setup_logger(name):
    # 创建日志目录
    log_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "RemoteControl", "log")
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建日志文件名（包含日期）
    log_file = os.path.join(log_dir, f'{name}_{datetime.now().strftime("%Y%m%d")}.log')
    
    # 配置日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # 创建文件处理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # 创建格式化器
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    logger.addHandler(file_handler)
    
    return logger

# 创建控制端日志记录器
logger = setup_logger('control')

class RemoteControl:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.current_path = os.path.expanduser("~")
        self.is_linux = platform.system() == 'Linux'
        logger.info("控制端初始化完成")

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            self.connected = True
            logger.info(f"已连接到服务器: {SERVER_HOST}:{SERVER_PORT}")
            return True
        except Exception as e:
            logger.error(f"连接服务器失败: {str(e)}")
            return False

    def disconnect(self):
        if self.socket:
            self.socket.close()
        self.connected = False
        logger.info("已断开与服务器的连接")

    def handle_command(self):
        try:
            while True:
                # 接收命令
                data = self.socket.recv(4096)
                if not data:
                    break
                
                try:
                    command = json.loads(data.decode('utf-8'))
                    logger.debug(f"收到命令: {command}")
                except json.JSONDecodeError as e:
                    logger.error(f"JSON解析错误: {e}")
                    self.send_response({'status': 'error', 'message': f'无效的JSON数据: {str(e)}'})
                    continue

                # 处理命令
                command_type = command.get('type')
                if command_type == 'screen_capture':
                    response = self.handle_screen_capture()
                elif command_type == 'file_upload':
                    response = self.handle_file_upload(command.get('data', {}))
                elif command_type == 'file_download':
                    response = self.handle_file_download(command.get('path', ''))
                elif command_type == 'list_directory':
                    response = self.handle_list_directory(command.get('path', ''))
                elif command_type == 'list_processes':
                    response = self.handle_list_processes()
                elif command_type == 'execute_command':
                    response = self.handle_execute_command(command.get('command', ''))
                elif command_type == 'system_info':
                    response = self.handle_system_info()
                else:
                    response = {'status': 'error', 'message': f'未知的命令类型: {command_type}'}

                # 发送响应
                self.send_response(response)

        except Exception as e:
            logger.error(f"处理命令时发生错误: {e}")
        finally:
            self.disconnect()

    def send_response(self, response):
        try:
            self.socket.send(json.dumps(response).encode('utf-8'))
            logger.debug(f"发送响应: {response}")
        except Exception as e:
            logger.error(f"发送响应错误: {e}")

    def handle_screen_capture(self):
        try:
            logger.info("开始截图")
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
                
                # 读取文件并编码
                with open(temp_file.name, 'rb') as f:
                    image_data = f.read()
                    image_base64 = base64.b64encode(image_data).decode()
                
                # 删除临时文件
                os.unlink(temp_file.name)
                
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

    def handle_file_upload(self, data):
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
                'system_directory': '/',
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

def main():
    try:
        logger.info("启动控制端程序")
        control = RemoteControl()
        if control.connect():
            control.handle_command()
    except Exception as e:
        logger.error(f"控制端程序运行错误: {str(e)}")
    finally:
        control.disconnect()

if __name__ == '__main__':
    main() 