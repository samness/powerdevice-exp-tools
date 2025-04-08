import sys
from PyQt5.QtWidgets import QApplication
from powerdevice_gui import PowerDeviceGUI

def main():
    app = QApplication(sys.argv)
    window = PowerDeviceGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main() 