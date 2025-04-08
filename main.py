import sys
import os
from PyQt5.QtWidgets import QApplication
from gui import PowerDeviceGUI

def main():
    # 打印当前工作目录和Python路径
    print(f"Current working directory: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    
    # 创建应用程序实例
    app = QApplication(sys.argv)
    
    try:
        # 创建并显示主窗口
        print("Creating main window...")
        window = PowerDeviceGUI()
        print("Showing main window...")
        window.show()
        
        # 运行应用程序
        print("Starting application...")
        return app.exec_()
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 