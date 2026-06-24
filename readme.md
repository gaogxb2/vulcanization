# Vulcanization Analysis

网络设备工程师报告批量解析工具。递归扫描文件夹中的 `.txt` 日志，按 `config.json` 配置的正则规则提取结构化数据，并导出为 Excel 表格。

## 功能概览

| 功能 | 说明 |
|------|------|
| 图形界面 | Tkinter GUI，选择文件夹与 Excel 输出路径，一键分析 |
| 文件筛选 | 按路径关键词过滤（默认：`工程师报告`、`.txt`） |
| 日志解析 | 从工程师报告中提取槽位、条码、版本、时间、温度、Serdes code 等 |
| Excel 导出 | 汇总为表格，支持 macro/lane/code 拆行与十六进制转十进制 |
| 去重 | 文件名与文件大小相同的记录只保留一条 |
| 自动解压 | 可选：递归解压 zip 并在解压后删除原压缩包 |
| 磁盘清理 | 可选：删除未匹配关键词的文件 |
| 打包 exe | 支持 PyInstaller 打包为独立可执行文件 |

## 项目结构

```
vulcanization/
├── main.py            # GUI 入口
├── data_processor.py  # 核心解析、数据处理、Excel 导出
├── config.json        # 路径关键词与正则匹配规则
├── build.py           # 打包脚本
└── readme.md
```

## 使用方式

### 安装依赖

```bash
pip install -r requirements.txt
```

依赖：`pandas`、`openpyxl`、`pyinstaller`（仅打包时需要）

### 启动程序

```bash
cd vulcanization
python main.py
```

### 操作步骤

1. 点击 **浏览**，选择要分析的文件夹
2. 选择 **Excel 输出位置**（选文件夹后会自动填充默认路径）
3. 按需勾选：
   - 自动解压并在解压后删除 zip 文件
   - 【磁盘清理】删除选中文件夹内未匹配到关键词的文件
4. 点击 **开始分析**，完成后会弹出提示并生成 Excel 文件

## 分析流程

```
选择文件夹
    ↓
[可选] 递归解压 zip 并删除原压缩包
    ↓
[可选] 删除路径未匹配关键词的文件
    ↓
递归遍历文件夹内所有文件
    ↓
按 path_keywords 筛选文件路径
    ↓
按 extract_patterns 正则规则解析文件内容
    ↓
提取槽位号，并对每个槽位进行二次/多次匹配
    ↓
组装行数据（条码、版本号、时间、温度、code 等）
    ↓
解析 code，生成 macro X lane Y 列
    ↓
导出 Excel 前：拆行、十六进制转十进制、去重
    ↓
输出 Excel 文件
```

## 数据提取说明

解析规则在 `config.json` 的 `extract_patterns` 中配置。当前默认规则针对华为设备工程师报告，主要提取以下字段：

| Excel 列 | 来源 | 说明 |
|----------|------|------|
| 文件路径 / 文件名 / 文件大小 / 修改时间 | 文件系统 | 文件基本信息 |
| 匹配项 / 匹配值 | 主匹配 | 槽位号（`display device` 段落中的数字） |
| 条码1 / 条码2 / 条码3 | secondary_match | `display elabel brief` 中 MPU 条码信息 |
| 版本号 | match_version | `display startup` 中的版本（如 R024） |
| 时间 | third_match 或 third_match_2 | 非 R024：板卡复位日期；R024：`display clock` 日期 |
| 温度 | sixth_match | `display temperature` 段落 |
| code_hex_check | 派生字段 | code 中是否含 0x1～0x16 范围内的值（1/0） |
| macro / lane / code | 派生字段 | 见下方 Serdes code 说明 |

### Serdes code 获取逻辑

code 值来源取决于 **版本号**：

**版本号 ≠ R024（fourth_match）**

1. 在 `{number} module cpu_serdes_info` 段落中匹配 `macroX,dsY` 与 `DS_TX:` 后第 27 个逗号分隔字段
2. 对十六进制值取 bit0～bit5（`& 0x3F`）
3. 格式化为 `macroX laneY 0xP`

**版本号 = R024（fifth_match）**

1. 在 `serdes slot {number}` 段落中直接匹配 `macro X lane Y: code-up:0xZ`
2. 多个匹配以 ` | ` 拼接

### Excel 导出时的 code 处理

1. 从 code 字符串解析所有 `macro X lane Y 0xZ` 组合
2. 每个 macro-lane 组合拆成独立一行，新增 `macro`、`lane`、`code` 三列
3. 十六进制 code（如 `0x11`）转换为十进制（如 `17`）
4. 按「文件名 + 文件大小(字节)」去重，相同文件只保留一条

**示例：**

原始一行：

| 文件名 | code |
|--------|------|
| 报告.txt | macro1 lane1 0x11 \| macro1 lane2 0x22 |

导出后拆成两行：

| 文件名 | macro | lane | code |
|--------|-------|------|------|
| 报告.txt | 1 | 1 | 17 |
| 报告.txt | 1 | 2 | 34 |

## 配置说明

`config.json` 主要包含两部分：

### path_keywords

控制哪些文件会被分析。路径须包含配置中所有关键词（默认：`工程师报告`、`.txt`）。

### extract_patterns

每条规则包含：

- `start_field` / `end_field`：匹配段落起止标记
- `regex`：主正则表达式
- `use_for_filter`：是否用于过滤（未匹配则跳过该文件）
- `secondary_match`、`third_match`、`fourth_match` 等：基于槽位号的二次匹配
- `{number}` 占位符：替换为当前槽位号
- `match_all`：是否匹配所有结果（默认只取第一个）

修改配置后重启程序即可生效，无需改代码。

## 打包为 EXE 文件

### 方法一：使用 build.py 脚本（推荐）

```bash
python build.py
```

脚本会自动检查并安装 PyInstaller（如需要），并提供两种打包方式：

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

打包完成后，exe 文件在 `dist/` 目录下。

#### 3. 或直接使用命令行打包

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
2. **依赖库**：确保已安装 pandas、openpyxl
3. **文件大小**：打包后的 exe 可能较大（含 Python 解释器与依赖）
4. **测试**：建议在干净的 Windows 系统上测试

### 打包后的文件结构

```
dist/
  └── 文件夹分析工具.exe
```

exe 可独立运行，无需安装 Python。
