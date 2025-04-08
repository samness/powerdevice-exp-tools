import os
import logging
from datetime import datetime
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTextEdit

class PowerDeviceLogger:
    def __init__(self):
        """初始化日志记录器"""
        # 创建日志目录
        self.log_dir = os.path.join(os.getcwd(), "logs")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"Created log directory: {self.log_dir}")
            
        # 设置日志文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_dir, f"powerdevice_{timestamp}.log")
        print(f"Log file created: {self.log_file}")
        
        # 配置日志记录器
        self.logger = logging.getLogger("PowerDevice")
        self.logger.setLevel(logging.DEBUG)
        
        # 文件处理器
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # 日志显示组件
        self.log_display = None
        
        # 记录初始化信息
        self.logger.info("Logger initialized")
        self.logger.info(f"Log directory: {self.log_dir}")
        self.logger.info(f"Log file: {self.log_file}")
        
    def set_log_display(self, display: QTextEdit):
        """设置日志显示组件"""
        self.log_display = display
        self.logger.info("Log display component set")
        
    def log(self, level: str, message: str, *args):
        """记录日志"""
        # 记录到文件和控制台
        if level == 'debug':
            self.logger.debug(message, *args)
        elif level == 'info':
            self.logger.info(message, *args)
        elif level == 'warning':
            self.logger.warning(message, *args)
        elif level == 'error':
            self.logger.error(message, *args)
        elif level == 'critical':
            self.logger.critical(message, *args)
            
        # 更新日志显示
        if self.log_display:
            # 设置文本颜色
            if level == 'error' or level == 'critical':
                self.log_display.setTextColor(Qt.red)
            elif level == 'warning':
                self.log_display.setTextColor(Qt.darkYellow)
            elif level == 'info':
                self.log_display.setTextColor(Qt.black)
            elif level == 'debug':
                self.log_display.setTextColor(Qt.darkGray)
                
            # 添加日志消息
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted_message = message % args if args else message
            log_entry = f"{timestamp} - {level.upper()} - {formatted_message}"
            self.log_display.append(log_entry)
            
            # 滚动到底部
            self.log_display.verticalScrollBar().setValue(
                self.log_display.verticalScrollBar().maximum()
            )
            
    def debug(self, message: str, *args):
        """记录调试信息"""
        self.log('debug', message, *args)
        
    def info(self, message: str, *args):
        """记录一般信息"""
        self.log('info', message, *args)
        
    def warning(self, message: str, *args):
        """记录警告信息"""
        self.log('warning', message, *args)
        
    def error(self, message: str, *args):
        """记录错误信息"""
        self.log('error', message, *args)
        
    def critical(self, message: str, *args):
        """记录严重错误信息"""
        self.log('critical', message, *args) 