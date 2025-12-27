#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
打包脚本：将项目打包为 EXE 文件
运行方式：python build.py [选项]
选项：
    --method 1 或 2：选择打包方式（1=spec文件，2=命令行）
    --auto：自动模式，不询问，使用默认方式
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def check_pyinstaller():
    """检查是否安装了 PyInstaller"""
    try:
        import PyInstaller
        return True
    except ImportError:
        return False

def install_pyinstaller():
    """安装 PyInstaller"""
    print("正在安装 PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("PyInstaller 安装成功！")
        return True
    except subprocess.CalledProcessError:
        print("PyInstaller 安装失败！")
        return False

def build_exe():
    """使用 spec 文件打包"""
    spec_file = Path(__file__).parent / "build_exe.spec"
    
    if not spec_file.exists():
        print(f"错误：找不到 spec 文件 {spec_file}")
        return False
    
    print(f"使用 spec 文件打包: {spec_file}")
    print("=" * 50)
    
    try:
        # 使用 PyInstaller 打包
        cmd = [sys.executable, "-m", "PyInstaller", str(spec_file)]
        subprocess.check_call(cmd)
        print("=" * 50)
        print("打包成功！")
        print(f"EXE 文件位置: {Path(__file__).parent / 'dist' / '文件夹分析工具.exe'}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"打包失败: {e}")
        return False

def build_exe_direct():
    """直接使用命令行打包（不使用 spec 文件）"""
    main_file = Path(__file__).parent / "vulcanization" / "main.py"
    config_file = Path(__file__).parent / "vulcanization" / "config.json"
    
    if not main_file.exists():
        print(f"错误：找不到主文件 {main_file}")
        return False
    
    if not config_file.exists():
        print(f"错误：找不到配置文件 {config_file}")
        return False
    
    print("使用命令行直接打包...")
    print("=" * 50)
    
    # 根据操作系统选择分隔符
    separator = ";" if sys.platform == "win32" else ":"
    
    try:
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name=文件夹分析工具",
            "--onefile",
            "--windowed",
            f"--add-data={config_file}{separator}vulcanization",
            "--hidden-import=pandas",
            "--hidden-import=openpyxl",
            "--hidden-import=tkinter",
            str(main_file)
        ]
        subprocess.check_call(cmd)
        print("=" * 50)
        print("打包成功！")
        print(f"EXE 文件位置: {Path(__file__).parent / 'dist' / '文件夹分析工具.exe'}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"打包失败: {e}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Vulcanization Analysis 打包工具')
    parser.add_argument('--method', type=int, choices=[1, 2], default=1,
                        help='打包方式：1=使用spec文件（推荐），2=直接使用命令行')
    parser.add_argument('--auto', action='store_true',
                        help='自动模式，不询问，直接执行')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("Vulcanization Analysis - 打包工具")
    print("=" * 50)
    
    # 检查 PyInstaller
    if not check_pyinstaller():
        if args.auto:
            print("未检测到 PyInstaller，正在自动安装...")
            if not install_pyinstaller():
                return
        else:
            print("未检测到 PyInstaller，需要先安装")
            try:
                choice = input("是否现在安装？(y/n): ").strip().lower()
                if choice == 'y':
                    if not install_pyinstaller():
                        return
                else:
                    print("请先安装 PyInstaller: pip install pyinstaller")
                    return
            except EOFError:
                print("非交互式环境，自动安装 PyInstaller...")
                if not install_pyinstaller():
                    return
    
    # 选择打包方式
    if args.auto:
        choice = str(args.method)
        print(f"\n使用自动模式，选择方式 {choice}")
    else:
        print("\n请选择打包方式：")
        print("1. 使用 spec 文件打包（推荐）")
        print("2. 直接使用命令行打包")
        try:
            choice = input("请输入选项 (1/2，默认1): ").strip() or str(args.method)
        except EOFError:
            choice = str(args.method)
            print(f"非交互式环境，使用默认方式 {choice}")
    
    if choice == "1":
        success = build_exe()
    elif choice == "2":
        success = build_exe_direct()
    else:
        print("无效选项，使用默认方式（spec 文件）")
        success = build_exe()
    
    if success:
        print("\n打包完成！可以在 dist 目录找到生成的 EXE 文件。")
    else:
        print("\n打包失败，请检查错误信息。")

if __name__ == "__main__":
    main()

