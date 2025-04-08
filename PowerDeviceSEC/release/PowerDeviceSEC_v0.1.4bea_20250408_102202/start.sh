#!/bin/bash
echo "正在启动发电设备测试工具..."
if [ ! -d "venv" ]; then
    echo "正在创建虚拟环境..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi
export PYTHONPATH=.
python3 gui/main.py
