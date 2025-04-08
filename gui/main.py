import sys
from PyQt5.QtWidgets import QApplication
from gui.powerdevice_gui import PowerDeviceGUI

def main():
    # 创建应用程序实例
    app = QApplication(sys.argv)
    
    try:
        # 创建并显示主窗口
        window = PowerDeviceGUI()
        window.show()
        
        # 运行应用程序
        return app.exec_()
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 