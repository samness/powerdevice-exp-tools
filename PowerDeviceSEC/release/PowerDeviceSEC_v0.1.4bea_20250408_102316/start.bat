@echo off
echo 正在启动发电设备测试工具...
if not exist "venv" (
    echo 正在创建虚拟环境...
    python -m venv venv
    call venv\Scripts\activate
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate
)
set PYTHONPATH=.
python gui\main.py
pause
