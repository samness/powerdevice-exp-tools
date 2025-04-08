import os
import shutil
import datetime
import zipfile

def create_release_package():
    # 版本信息
    version = "v0.1.4bea"
    
    # 创建发布目录
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    release_name = f"PowerDeviceSEC_{version}"
    release_dir = f"release/{release_name}_{timestamp}"
    os.makedirs(release_dir, exist_ok=True)
    
    # 需要复制的文件和目录
    files_to_copy = [
        "gui/main.py",
        "gui/powerdevice_gui.py",
        "gui/vulnerability_db.py",
        "requirements.txt",
        "README.md"
    ]
    
    # 复制文件
    for file_path in files_to_copy:
        if os.path.exists(file_path):
            target_path = os.path.join(release_dir, file_path)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            shutil.copy2(file_path, target_path)
            print(f"Copied: {file_path}")
    
    # 创建虚拟环境目录
    venv_dir = os.path.join(release_dir, "venv")
    os.makedirs(venv_dir, exist_ok=True)
    
    # 创建启动脚本
    create_launch_scripts(release_dir)
    
    # 创建ZIP压缩包
    zip_filename = f"{release_name}.zip"
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(release_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, release_dir)
                zipf.write(file_path, arcname)
                print(f"Added to zip: {arcname}")
    
    print(f"\n打包完成！")
    print(f"发布目录: {release_dir}")
    print(f"压缩包: {zip_filename}")
    
    return release_dir, zip_filename

def create_launch_scripts(release_dir):
    # Windows启动脚本
    with open(os.path.join(release_dir, "start.bat"), "w", encoding="utf-8") as f:
        f.write("""@echo off
echo 正在启动发电设备测试工具...
if not exist "venv" (
    echo 正在创建虚拟环境...
    python -m venv venv
    call venv\\Scripts\\activate
    pip install -r requirements.txt
) else (
    call venv\\Scripts\\activate
)
set PYTHONPATH=.
python gui\\main.py
pause
""")
    
    # Unix/Linux/macOS启动脚本
    with open(os.path.join(release_dir, "start.sh"), "w", encoding="utf-8") as f:
        f.write("""#!/bin/bash
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
""")
    
    # 设置Unix脚本可执行权限
    os.chmod(os.path.join(release_dir, "start.sh"), 0o755)

if __name__ == "__main__":
    create_release_package() 