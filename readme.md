# Vulcanization Analysis

文件夹内容分析工具

## 打包为 EXE 文件

### 方法一：使用 build.py 脚本（推荐）

直接运行打包脚本：

```bash
python build.py
```

脚本会自动检查并安装 PyInstaller（如果需要），然后提供两种打包方式：
1. 使用 spec 文件打包（推荐）
2. 直接使用命令行打包

### 方法二：手动使用 PyInstaller

#### 1. 安装 PyInstaller

```bash
pip install pyinstaller
```

#### 2. 使用 spec 文件打包

```bash
pyinstaller build_exe.spec
```

打包完成后，exe 文件会在 `dist/` 目录下。

#### 3. 或者直接使用命令行打包

```bash
pyinstaller --name="文件夹分析工具" \
    --onefile \
    --windowed \
    --add-data "vulcanization/config.json:vulcanization" \
    --hidden-import=pandas \
    --hidden-import=openpyxl \
    --hidden-import=tkinter \
    vulcanization/main.py
```

### 注意事项

1. **配置文件**：确保 `config.json` 会被包含在打包文件中
2. **依赖库**：确保所有依赖都已安装（pandas, openpyxl）
3. **文件大小**：打包后的 exe 文件可能会比较大（因为包含了 Python 解释器和所有依赖）
4. **测试**：打包后建议在干净的 Windows 系统上测试

### 打包后的文件结构

```
dist/
  └── 文件夹分析工具.exe
```

exe 文件可以独立运行，不需要安装 Python。
