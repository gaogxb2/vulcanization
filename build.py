#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
快速打包脚本：将 main.py 打包成 exe
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def main():
    """主函数"""
    # 获取项目根目录
    root_dir = Path(__file__).parent
    main_file = root_dir / "vulcanization" / "main.py"
    config_file = root_dir / "vulcanization" / "config.json"
    
    # 检查文件是否存在
    if not main_file.exists():
        print(f"错误：找不到主文件 {main_file}")
        return 1
    
    if not config_file.exists():
        print(f"错误：找不到配置文件 {config_file}")
        return 1
    
    # 清理旧的构建文件
    print("清理旧的构建文件...")
    for dir_name in ['build', 'dist']:
        dir_path = root_dir / dir_name
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"已删除 {dir_name}/")
    
    # 清理 spec 文件
    for spec_file in root_dir.glob("*.spec"):
        spec_file.unlink()
        print(f"已删除 {spec_file.name}")
    
    print("\n开始打包...")
    print("=" * 50)
    
    # 根据操作系统选择路径分隔符
    separator = ";" if sys.platform == "win32" else ":"
    
    # PyInstaller 命令
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=文件夹分析工具",
        "--onefile",
        "--noconsole",  # 不显示控制台（GUI应用）
        f"--add-data={config_file}{separator}vulcanization",
        "--hidden-import=pandas",
        "--hidden-import=openpyxl",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.filedialog",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=tkinter.ttk",
        "--clean",  # 清理临时文件
        str(main_file)
    ]
    
    try:
        subprocess.check_call(cmd)
        print("=" * 50)
        print("打包成功！")
        exe_path = root_dir / "dist" / "文件夹分析工具.exe" if sys.platform == "win32" else root_dir / "dist" / "文件夹分析工具"
        print(f"EXE 文件位置: {exe_path}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"打包失败: {e}")
        return 1
    except FileNotFoundError:
        print("错误：未找到 PyInstaller")
        print("请先安装: pip install pyinstaller")
        return 1

if __name__ == "__main__":
    sys.exit(main())

