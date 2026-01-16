import json
import os
import sys
import zipfile
import shutil
import pandas as pd
import re
from pathlib import Path
from typing import List, Dict, Any


class DataProcessor:
    def __init__(self, config_path: str = None):
        """
        初始化数据处理器
        
        Args:
            config_path: 配置文件路径，如果为None则使用默认路径
        """
        if config_path is None:
            # 默认配置文件路径（与data_processor.py同目录）
            # 支持 PyInstaller 打包后的路径
            if getattr(sys, 'frozen', False):
                # 如果是打包后的exe，使用sys._MEIPASS获取临时目录
                base_path = sys._MEIPASS
            else:
                # 如果是普通运行，使用__file__所在目录
                base_path = os.path.dirname(__file__)
            config_path = os.path.join(base_path, "vulcanization", "config.json")
            # 如果上面的路径不存在，尝试直接在同目录查找
            if not os.path.exists(config_path):
                config_path = os.path.join(base_path, "config.json")
        
        self.config_path = config_path
        self.config = self.load_config()
        # 用于缓存文件内容和匹配结果，避免重复读取和匹配
        self._file_cache = {}
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            # 如果配置文件不存在，返回默认配置
            return {"path_keywords": []}
        except json.JSONDecodeError as e:
            raise ValueError(f"配置文件格式错误: {e}")
    
    def _check_path_keywords_match(self, file_path: str) -> bool:
        """
        检查文件路径是否匹配到配置的关键词
        
        Args:
            file_path: 文件路径（相对路径或绝对路径）
            
        Returns:
            True表示匹配到关键词，False表示未匹配
        """
        path_keywords_config = self.config.get("path_keywords", {})
        
        # 检查路径关键词（只检查use_for_filter为true的关键词）
        # 支持两种格式：对象格式 {"keyword": [...], "use_for_filter": true} 和字符串数组（向后兼容）
        filter_keywords = []
        if isinstance(path_keywords_config, dict):
            # 对象格式：{"keyword": [...], "use_for_filter": true/false}
            if path_keywords_config.get("use_for_filter", False):
                keywords = path_keywords_config.get("keyword", [])
                if isinstance(keywords, list):
                    filter_keywords = [k for k in keywords if isinstance(k, str)]
        elif isinstance(path_keywords_config, list):
            # 字符串数组格式（向后兼容）：默认use_for_filter为true
            filter_keywords = [k for k in path_keywords_config if isinstance(k, str)]
        
        # 如果没有配置关键词，认为匹配（不删除）
        if not filter_keywords:
            return True
        
        # 检查路径中是否包含所有用于过滤的关键词
        file_path_lower = file_path.lower()
        for keyword in filter_keywords:
            if keyword and keyword.lower() not in file_path_lower:
                return False
        
        return True
    
    def should_analyze(self, file_path: str, file_item: Path = None) -> bool:
        """
        判断文件路径是否应该被分析
        只有当路径包含所有配置的关键词时才会被分析
        如果配置了用于过滤的匹配项，还需要检查文件内容是否匹配
        
        Args:
            file_path: 文件路径（相对路径或绝对路径）
            file_item: 文件Path对象，用于读取文件内容（可选）
            
        Returns:
            True表示应该分析，False表示跳过
        """
        # 检查路径关键词匹配
        if not self._check_path_keywords_match(file_path):
            return False
        
        # 检查用于过滤的匹配项
        extract_patterns = self.config.get("extract_patterns", [])
        filter_patterns = [p for p in extract_patterns if p.get("use_for_filter", False)]
        
        if filter_patterns and file_item and file_item.is_file():
            # 读取文件内容（使用缓存）
            content = self._read_file_content(file_item)
            if not content:
                # 如果无法读取文件，跳过
                return False
            
            # 检查每个用于过滤的匹配项
            for pattern_config in filter_patterns:
                found, matches = self._match_pattern(content, pattern_config)
                if not found or not matches:
                    # 没找到起始/结束字段，或者正则表达式没有匹配到任何内容，不分析
                    return False
        
        return True
    
    def _read_file_content(self, file_path: Path) -> str:
        """
        读取文件内容，使用缓存避免重复读取
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容字符串，如果读取失败返回空字符串
        """
        file_key = str(file_path)
        if file_key not in self._file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self._file_cache[file_key] = f.read()
            except Exception:
                self._file_cache[file_key] = ""
        return self._file_cache[file_key]
    
    def _match_pattern(self, content: str, pattern_config: Dict[str, Any]) -> tuple:
        """
        对单个匹配项进行匹配
        
        Args:
            content: 文件内容
            pattern_config: 匹配项配置
            
        Returns:
            (是否找到起始和结束字段, 匹配到的结果列表)
        """
        start_field = pattern_config.get("start_field", "")
        end_field = pattern_config.get("end_field", "")
        regex_pattern = pattern_config.get("regex", "")
        
        if not start_field or not end_field or not regex_pattern:
            return (False, [])
        
        # 查找第一个起始字段和第一个结束字段之间的内容
        start_idx = content.find(start_field)
        if start_idx == -1:
            return (False, [])
        
        # 从起始字段之后开始查找结束字段
        search_start = start_idx + len(start_field)
        end_idx = content.find(end_field, search_start)
        if end_idx == -1:
            return (False, [])
        
        # 提取起始字段和结束字段之间的内容
        extracted_content = content[search_start:end_idx]
        
        # 使用正则表达式提取匹配的数字
        matches = re.findall(regex_pattern, extracted_content)
        # re.findall返回的是捕获组的内容列表（如果只有一个捕获组，返回字符串列表）
        # 如果正则表达式有多个捕获组，返回元组列表；如果只有一个捕获组，返回字符串列表
        if matches and isinstance(matches[0], tuple):
            numbers = [str(match[0]) for match in matches]
        else:
            numbers = [str(match) for match in matches]
        print("numbers:",numbers)
        return (True, numbers)
    
    def _match_secondary_pattern(self, content: str, number: str, secondary_config: Dict[str, Any]) -> List[str]:
        """
        对每个数字进行二次匹配
        
        Args:
            content: 文件内容
            number: 要匹配的数字
            secondary_config: 二次匹配配置，包含start_field, end_field, regex
            
        Returns:
            匹配到的结果列表
        """
        if not secondary_config:
            return []
        
        start_field = secondary_config.get("start_field", "")
        end_field = secondary_config.get("end_field", "")
        regex_template = secondary_config.get("regex", "")
        
        if not start_field or not end_field or not regex_template:
            return []
        
        # 替换 start_field 和 end_field 中的 {number} 占位符
        start_field = start_field.replace("{number}", number)
        end_field = end_field.replace("{number}", number)
        
        # 找到段落
        print("start_field:",start_field)
        start_idx = content.find(start_field)
        print("start_idx:",start_idx)
        if start_idx == -1:
            return []
        
        # 从起始字段之后开始查找结束字段
        search_start = start_idx + len(start_field)
        print("search_start:",search_start)
        end_idx = content.find(end_field, search_start)
        print("end_idx:",end_idx)
        if end_idx == -1:
            return []
        
        # 提取段落内容
        paragraph_content = content[search_start:end_idx]
        
        # 将正则表达式模板中的 {number} 替换为实际数字（转义）
        regex_pattern = regex_template.replace("{number}", re.escape(number))
        print("regex_pattern:", regex_pattern)
        print("paragraph_content length:", len(paragraph_content))
        # 检查是否需要使用 DOTALL 标志（如果正则表达式中包含 .* 等需要匹配换行符的模式）
        use_dotall = secondary_config.get("use_dotall", False)
        if not use_dotall and ('.*' in regex_template or '.+?' in regex_template):
            use_dotall = True
        
        # 执行匹配
        if use_dotall:
            matches = re.findall(regex_pattern, paragraph_content, re.DOTALL)
        else:
            matches = re.findall(regex_pattern, paragraph_content)
        print("total matches found:", len(matches))

        # 返回匹配到的结果，如果没有匹配到则返回空列表
        if not matches:
            print("no matches")
            return []
        print("matches:",matches)
        
        # 检查是否只匹配第一个结果
        match_all = secondary_config.get("match_all", False)  # 默认只匹配第一个
        print("match_all setting:", match_all)
        
        # 处理多个捕获组的情况
        if isinstance(matches[0], tuple):
            # 如果有多个捕获组，将所有捕获组用空格连接
            results = [' '.join(str(m) for m in match) for match in matches]
        else:
            # 如果只有一个捕获组，直接返回
            results = [str(match) for match in matches]
        
        # 如果 match_all 为 False，只返回第一个结果
        if not match_all and results:
            return [results[0]]
        
        return results
    
    def _match_secondary_pattern_detailed(self, content: str, number: str, secondary_config: Dict[str, Any]) -> List[List[str]]:
        """
        对每个数字进行二次匹配，返回详细的匹配结果（保留多个捕获组）
        
        Args:
            content: 文件内容
            number: 要匹配的数字
            secondary_config: 二次匹配配置，包含start_field, end_field, regex
            
        Returns:
            匹配到的结果列表，每个结果是一个列表（多个捕获组）或字符串（单个捕获组）
        """
        if not secondary_config:
            return []
        
        start_field = secondary_config.get("start_field", "")
        end_field = secondary_config.get("end_field", "")
        regex_template = secondary_config.get("regex", "")
        
        if not start_field or not end_field or not regex_template:
            return []
        
        # 检查是否只替换 regex 中的 {number}（不替换 start_field 中的）
        only_replace_in_regex = secondary_config.get("only_replace_in_regex", False)
        
        # 替换 start_field 和 end_field 中的 {number} 占位符（除非配置了 only_replace_in_regex）
        if not only_replace_in_regex:
            start_field = start_field.replace("{number}", number)
            end_field = end_field.replace("{number}", number)
        
        # 找到段落
        start_idx = content.find(start_field)
        if start_idx == -1:
            return []
        
        # 从起始字段之后开始查找结束字段
        search_start = start_idx + len(start_field)
        end_idx = content.find(end_field, search_start)
        if end_idx == -1:
            return []
        
        # 提取段落内容
        paragraph_content = content[search_start:end_idx]
        
        # 将正则表达式模板中的 {number} 替换为实际数字（转义）
        regex_pattern = regex_template.replace("{number}", re.escape(number))
        
        # 检查是否需要使用 DOTALL 标志
        use_dotall = secondary_config.get("use_dotall", False)
        if not use_dotall and ('.*' in regex_template or '.+?' in regex_template):
            use_dotall = True
        
        # 执行匹配
        if use_dotall:
            matches = re.findall(regex_pattern, paragraph_content, re.DOTALL)
        else:
            matches = re.findall(regex_pattern, paragraph_content)
        
        if not matches:
            return []
        
        # 检查是否只匹配第一个结果
        match_all = secondary_config.get("match_all", False)
        
        # 处理多个捕获组的情况，保留原始结构
        if isinstance(matches[0], tuple):
            # 如果有多个捕获组，返回元组列表转换为列表列表
            results = [[str(m) for m in match] for match in matches]
        else:
            # 如果只有一个捕获组，每个结果包装成列表
            results = [[str(match)] for match in matches]
        
        # 如果 match_all 为 False，只返回第一个结果
        if not match_all and results:
            return [results[0]]
        
        return results
    
    def _format_fourth_match(self, fourth_match: List[str]) -> str:
        """
        格式化fourth_match的结果
        输入格式1（match_all=False）：["macroX,dsY", "0xZ"]
        输入格式2（match_all=True）：["macroX,dsY 0xZ | macroX2,dsY2 0xZ2 | ..."]
        输出格式：f"macroX laneY 0xP"，其中0xP是0xZ的bit0-5的值
        如果有多个匹配，用 " | " 连接
        
        Args:
            fourth_match: fourth_match的匹配结果列表
            
        Returns:
            格式化后的字符串
        """
        if not fourth_match:
            return ""
        
        # 如果只有一个元素且包含 " | "，说明是match_all=True的情况
        if len(fourth_match) == 1 and " | " in fourth_match[0]:
            # 分割多个匹配
            matches_str = fourth_match[0].split(" | ")
            formatted_matches = []
            for match_str in matches_str:
                # 每个匹配格式：macroX,dsY 0xZ
                parts = match_str.strip().split()
                if len(parts) >= 2:
                    macro_ds = parts[0]  # macroX,dsY
                    hex_str = parts[1]   # 0xZ
                    formatted = self._format_single_fourth_match(macro_ds, hex_str)
                    if formatted:
                        formatted_matches.append(formatted)
            return " | ".join(formatted_matches) if formatted_matches else ""
        
        # 如果是两个元素，说明是match_all=False的情况
        if len(fourth_match) >= 2:
            macro_ds = fourth_match[0]  # macroX,dsY
            hex_str = fourth_match[1]   # 0xZ
            return self._format_single_fourth_match(macro_ds, hex_str) or " ".join(fourth_match)
        
        return " ".join(fourth_match)
    
    def _parse_code_macro_lane(self, code: str) -> Dict[str, str]:
        """
        解析code值，提取所有 macro X lane Y 0xZ 格式的内容
        
        Args:
            code: code值字符串，可能包含多个用 | 分隔的项
            
        Returns:
            字典，键为 "macro X lane Y"，值为 "0xZ"
        """
        result = {}
        if not code:
            return result
        
        # 正则表达式匹配 "macro X lane Y 0xZ" 格式
        # 支持格式：
        # - macro 1 lane 1 0x11 (有空格)
        # - macro1 lane1 0x11 (macro和数字之间无空格，lane和数字之间无空格)
        # - macro1lane1 0x11 (macro和数字之间无空格，lane和数字之间无空格，macro和lane之间也无空格)
        # - macro1 lane 1 0x11 (macro和数字之间无空格，lane和数字之间有空格)
        # - macro 1lane1 0x11 (macro和数字之间有空格，lane和数字之间无空格)
        # 使用 \s* 允许0个或多个空白字符，确保完全支持无空格格式
        pattern = r'macro\s*(\d+)\s*lane\s*(\d+)\s+(0x[0-9A-Fa-f]+)'
        matches = re.findall(pattern, code)
        
        for match in matches:
            macro_num = match[0]
            lane_num = match[1]
            hex_value = match[2]
            column_name = f"macro {macro_num} lane {lane_num}"
            result[column_name] = hex_value
        
        return result
    
    def _add_dynamic_macro_lane_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        根据code列的值，动态添加 macro X lane Y 列
        
        Args:
            df: 原始DataFrame
            
        Returns:
            添加了动态列的DataFrame
        """
        if df.empty or 'code' not in df.columns:
            return df
        
        # 收集所有唯一的 macro X lane Y 组合
        all_macro_lane_columns = set()
        row_macro_lane_data = []
        
        for idx, row in df.iterrows():
            code_value = str(row.get('code', ''))
            parsed = self._parse_code_macro_lane(code_value)
            all_macro_lane_columns.update(parsed.keys())
            row_macro_lane_data.append(parsed)
        
        # 按macro和lane的数字排序（macro小的在左边，macro相同时lane小的在左边）
        sorted_columns = sorted(all_macro_lane_columns, key=lambda x: (
            int(re.search(r'macro\s*(\d+)', x).group(1)),
            int(re.search(r'lane\s*(\d+)', x).group(1))
        ))
        
        # 为每个列创建数据
        for col_name in sorted_columns:
            col_data = []
            for parsed in row_macro_lane_data:
                col_data.append(parsed.get(col_name, ''))
            df[col_name] = col_data
        
        # 重新调整列顺序：将动态列放在code列之后，按macro和lane排序
        if sorted_columns:
            # 获取当前所有列
            all_columns = list(df.columns)
            
            # 找到code列的位置
            if 'code' in all_columns:
                code_index = all_columns.index('code')
                # 分离动态列和其他列
                other_columns = [col for col in all_columns if col not in sorted_columns]
                # 重新排列：code列之前的列 + code列 + 动态列（已排序）+ code列之后的列
                new_column_order = other_columns[:code_index] + ['code'] + sorted_columns + other_columns[code_index+1:]
                # 重新排列DataFrame的列
                df = df[new_column_order]
        
        return df
    
    def _check_code_contains_hex_range(self, code: str) -> int:
        """
        检查 code 中是否包含 0x1 到 0x16 之间的任意值
        
        Args:
            code: code 字符串
            
        Returns:
            如果包含 0x1 到 0x16 之间的任意值返回 1，否则返回 0
        """
        if not code:
            return 0
        
        # 匹配 0x1 到 0x16 之间的十六进制值
        # 0x1, 0x2, ..., 0x9, 0xa, 0xb, ..., 0xf, 0x10, 0x11, ..., 0x16
        # 使用正则表达式匹配这些值（不区分大小写）
        # 使用负向前瞻确保后面不是十六进制字符，避免匹配 0x1a 中的 0x1
        pattern = r'0x(?:1[0-6]|[1-9a-fA-F])(?![\da-fA-F])'
        if re.search(pattern, code, re.IGNORECASE):
            return 1
        return 0
    
    def _format_single_fourth_match(self, macro_ds: str, hex_str: str) -> str:
        """
        格式化单个fourth_match结果
        
        Args:
            macro_ds: "macroX,dsY" 格式的字符串
            hex_str: "0xZ" 格式的十六进制字符串
            
        Returns:
            格式化后的字符串：f"macroX laneY 0xP"
        """
        # 解析macroX,dsY
        macro_match = re.search(r'macro(\d+)', macro_ds)
        ds_match = re.search(r'ds(\d+)', macro_ds)
        
        if not macro_match or not ds_match:
            return ""
        
        macro_num = macro_match.group(1)
        ds_num = ds_match.group(1)
        
        # 解析十六进制数
        try:
            # 转换为整数
            if hex_str.startswith('0x') or hex_str.startswith('0X'):
                hex_value = int(hex_str, 16)
            else:
                # 如果不是十六进制格式，尝试直接转换
                hex_value = int(hex_str, 16) if all(c in '0123456789ABCDEFabcdef' for c in hex_str) else int(hex_str)
            
            # 提取bit0-5（即对0x3F进行按位与操作）
            bit0_5_value = hex_value & 0x3F
            
            # 格式化输出：macroX laneY 0xP
            return f"macro{macro_num} lane{ds_num} 0x{bit0_5_value:X}"
        except (ValueError, TypeError):
            return ""
    
    def extract_pattern_from_file(self, file_path: Path) -> Dict[str, Any]:
        """
        从文件中提取匹配模式的内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            包含提取结果的字典，键为模式名称，值为包含详细匹配信息的列表
        """
        result = {}
        extract_patterns = self.config.get("extract_patterns", [])
        
        if not extract_patterns:
            return result
        
        # 读取文件内容（使用缓存，避免重复读取）
        content = self._read_file_content(file_path)
        if not content:
            # 如果无法读取文件，返回空结果
            return result
        
        # 处理每个提取模式
        for pattern_config in extract_patterns:
            start_field = pattern_config.get("start_field", "")
            end_field = pattern_config.get("end_field", "")
            
            found, numbers = self._match_pattern(content, pattern_config)
            if not found or not numbers:
                result[f"{start_field}_{end_field}"] = []
                continue
            
            # 对每个数字进行二次、三次、三次匹配2、四次、五次匹配、六次匹配、版本匹配（如果配置了）
            final_results = []
            secondary_config = pattern_config.get("secondary_match", None)
            third_config = pattern_config.get("third_match", None)
            third_config_2 = pattern_config.get("third_match_2", None)
            fourth_config = pattern_config.get("fourth_match", None)
            fifth_config = pattern_config.get("fifth_match", None)
            sixth_config = pattern_config.get("sixth_match", None)
            match_version_config = pattern_config.get("match_version", None)
            
            for number in numbers:
                # 存储每个匹配项的详细结果
                match_data = {
                    "number": number,
                    "secondary_match": [],
                    "match_version": [],
                    "third_match": [],
                    "third_match_2": [],
                    "fourth_match": [],
                    "fifth_match": [],
                    "sixth_match": []
                }
                
                # 进行二次匹配（保留多个捕获组）
                if secondary_config:
                    secondary_matches = self._match_secondary_pattern_detailed(content, number, secondary_config)
                    if secondary_matches:
                        # secondary_match可能有多个匹配，每个匹配可能有多个捕获组
                        # 取第一个匹配的所有捕获组
                        if secondary_matches and secondary_matches[0]:
                            match_data["secondary_match"] = secondary_matches[0]
                
                # 进行版本匹配
                if match_version_config:
                    version_matches = self._match_secondary_pattern_detailed(content, number, match_version_config)
                    if version_matches:
                        # 取第一个匹配的第一个捕获组
                        if version_matches and version_matches[0]:
                            match_data["match_version"] = version_matches[0]
                
                # 进行三次匹配
                if third_config:
                    third_matches = self._match_secondary_pattern_detailed(content, number, third_config)
                    if third_matches:
                        if third_matches and third_matches[0]:
                            match_data["third_match"] = third_matches[0]
                
                # 进行三次匹配2
                if third_config_2:
                    third_matches_2 = self._match_secondary_pattern_detailed(content, number, third_config_2)
                    if third_matches_2:
                        if third_matches_2 and third_matches_2[0]:
                            match_data["third_match_2"] = third_matches_2[0]
                
                # 进行四次匹配
                if fourth_config:
                    fourth_matches = self._match_secondary_pattern_detailed(content, number, fourth_config)
                    if fourth_matches:
                        # 如果match_all为True，保留所有匹配，否则只取第一个
                        if fourth_config.get("match_all", False):
                            match_data["fourth_match"] = [" | ".join(" ".join(str(m) for m in match) for match in fourth_matches)]
                        else:
                            if fourth_matches and fourth_matches[0]:
                                match_data["fourth_match"] = fourth_matches[0]
                
                # 进行五次匹配
                if fifth_config:
                    fifth_matches = self._match_secondary_pattern_detailed(content, number, fifth_config)
                    if fifth_matches:
                        # 如果match_all为True，保留所有匹配，否则只取第一个
                        if fifth_config.get("match_all", False):
                            match_data["fifth_match"] = [" | ".join(" ".join(str(m) for m in match) for match in fifth_matches)]
                        else:
                            if fifth_matches and fifth_matches[0]:
                                match_data["fifth_match"] = fifth_matches[0]
                
                # 进行六次匹配（温度匹配）
                if sixth_config:
                    sixth_matches = self._match_secondary_pattern_detailed(content, number, sixth_config)
                    if sixth_matches:
                        # 如果match_all为True，保留所有匹配，否则只取第一个
                        if sixth_config.get("match_all", False):
                            match_data["sixth_match"] = [" | ".join(" ".join(str(m) for m in match) for match in sixth_matches)]
                        else:
                            if sixth_matches and sixth_matches[0]:
                                match_data["sixth_match"] = sixth_matches[0]
                
                final_results.append(match_data)
            
            result[f"{start_field}_{end_field}"] = final_results
        
        return result
    
    def extract_zip_recursive(self, zip_path: Path, extract_to: Path):
        """
        递归解压zip文件（逐层解压，不需要额外创建新文件夹）
        
        Args:
            zip_path: zip文件路径
            extract_to: 解压目标路径（直接解压到此目录）
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            
            # 删除已解压的zip文件
            zip_path.unlink()
            
            # 收集解压后目录中的所有zip文件（避免在遍历时修改目录结构）
            zip_files = []
            for item in extract_to.rglob('*.zip'):
                if item.is_file():
                    zip_files.append(item)
            
            # 递归解压所有找到的zip文件
            for zip_file in zip_files:
                # 逐层解压：直接解压到zip文件所在目录，不创建新文件夹
                self.extract_zip_recursive(zip_file, zip_file.parent)
        except (zipfile.BadZipFile, PermissionError, OSError) as e:
            # 跳过损坏的zip文件或权限错误
            pass
    
    def process_zip_files(self, folder_path: str):
        """
        处理文件夹中的zip文件，进行解压
        
        Args:
            folder_path: 要处理的文件夹路径
        """
        folder = Path(folder_path)
        
        # 收集所有zip文件（避免在遍历时修改目录结构）
        zip_files = []
        for item in folder.rglob('*.zip'):
            if item.is_file():
                zip_files.append(item)
        
        # 解压每个zip文件
        for zip_file in zip_files:
            try:
                # 第一层解压：创建与压缩包同名的文件夹
                zip_name_without_ext = zip_file.stem
                extract_folder = zip_file.parent / zip_name_without_ext
                
                # 如果文件夹已存在，添加序号
                counter = 1
                original_extract_folder = extract_folder
                while extract_folder.exists():
                    extract_folder = original_extract_folder.parent / f"{zip_name_without_ext}_{counter}"
                    counter += 1
                
                extract_folder.mkdir(parents=True, exist_ok=True)
                
                # 第一层解压到新创建的文件夹
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(extract_folder)
                
                # 删除原始zip文件
                zip_file.unlink()
                
                # 检查解压后的文件夹中是否有zip文件，如果有则递归解压
                nested_zip_files = []
                for item in extract_folder.rglob('*.zip'):
                    if item.is_file():
                        nested_zip_files.append(item)
                
                # 递归解压所有嵌套的zip文件（逐层解压，不创建新文件夹）
                for nested_zip in nested_zip_files:
                    self.extract_zip_recursive(nested_zip, nested_zip.parent)
            except (PermissionError, OSError, zipfile.BadZipFile) as e:
                # 跳过无法处理的zip文件
                continue
    
    def analyze_folder(self, folder_path: str, extract_zip: bool = False, delete_unmatched: bool = None) -> pd.DataFrame:
        """
        分析文件夹内容
        
        Args:
            folder_path: 要分析的文件夹路径
            extract_zip: 是否解压zip文件
            delete_unmatched: 是否删除未匹配的文件，如果为None则从配置文件读取
            
        Returns:
            包含分析结果的DataFrame
        """
        # 清空缓存，开始新的分析
        self._file_cache.clear()
        
        # 如果需要解压zip文件，先处理zip文件
        if extract_zip:
            self.process_zip_files(folder_path)
        
        data = []
        folder = Path(folder_path)
        
        for item in folder.rglob('*'):
            try:
                # 获取相对路径用于关键词匹配
                relative_path = str(item.relative_to(folder))
                
                # 如果文件路径没匹配到keyword，且UI勾选了删除选项，则删除该文件
                # delete_unmatched参数由UI传入，如果为None则默认为False（不删除）
                delete_if_no_match = delete_unmatched if delete_unmatched is not None else False
                if item.is_file() and delete_if_no_match:
                    if not self._check_path_keywords_match(relative_path):
                        try:
                            item.unlink()
                            print(f"删除未匹配文件: {relative_path}")
                            continue
                        except (PermissionError, OSError) as e:
                            print(f"无法删除文件 {relative_path}: {e}")
                            continue
                
                # 检查是否应该分析此文件（传入Path对象以便检查文件内容）
                if not self.should_analyze(relative_path, item):
                    print(f"跳过文件: {relative_path}")
                    continue
                else:
                    print(f"分析文件: {relative_path}")
                
                if item.is_file():
                    stat = item.stat()
                    # 提取匹配模式的内容
                    extracted_data = self.extract_pattern_from_file(item)
                    
                    # 构建文件基本信息
                    base_file_data = {
                        '文件路径': relative_path,
                        '文件名': item.name,
                        '文件类型': item.suffix or '无扩展名',
                        '文件大小(字节)': stat.st_size,
                        '文件大小(MB)': round(stat.st_size / (1024 * 1024), 2),
                        '修改时间': pd.Timestamp.fromtimestamp(stat.st_mtime),
                        '是否文件': '是',
                        '是否目录': '否'
                    }
                    
                    # 如果没有任何匹配项，仍然添加一行（不包含匹配数据）
                    if not extracted_data:
                        data.append(base_file_data.copy())
                    else:
                        # 处理每个匹配模式的结果
                        has_match_data = False
                        for pattern_name, match_data_list in extracted_data.items():
                            if not match_data_list:  # 如果没有匹配到的数据
                                continue
                            
                            has_match_data = True
                            # 为每个匹配数据创建一行
                            for match_data in match_data_list:
                                row_data = base_file_data.copy()
                                row_data['匹配项'] = pattern_name
                                row_data['匹配值'] = match_data.get("number", "")
                                
                                # 处理secondary_match，分成三列：条码1、条码2、条码3
                                secondary_match = match_data.get("secondary_match", [])
                                row_data['条码1'] = secondary_match[0] if len(secondary_match) > 0 else ""
                                row_data['条码2'] = secondary_match[1] if len(secondary_match) > 1 else ""
                                row_data['条码3'] = secondary_match[2] if len(secondary_match) > 2 else ""
                                
                                # 处理match_version，列名叫版本号
                                match_version = match_data.get("match_version", [])
                                version_str = match_version[0] if len(match_version) > 0 else ""
                                row_data['版本号'] = version_str
                                
                                # 根据版本号决定时间列
                                if version_str == "R024":
                                    # 如果版本号是R024：
                                    # third_match_2的列名叫做时间
                                    third_match_2 = match_data.get("third_match_2", [])
                                    row_data['时间'] = " ".join(third_match_2) if third_match_2 else ""
                                    # 忽略third_match
                                else:
                                    # 如果版本号不为R024：
                                    # third_match的列名叫做时间
                                    third_match = match_data.get("third_match", [])
                                    row_data['时间'] = " ".join(third_match) if third_match else ""
                                
                                # 处理sixth_match（温度），单独列一列
                                sixth_match = match_data.get("sixth_match", [])
                                row_data['温度'] = " ".join(sixth_match) if sixth_match else ""
                                
                                # 根据版本号决定code值（先计算，不添加到字典）
                                if version_str == "R024":
                                    # fifth_match作为code
                                    fifth_match = match_data.get("fifth_match", [])
                                    code_value = " ".join(fifth_match) if fifth_match else ""
                                else:
                                    # fourth_match作为code，需要格式化
                                    fourth_match = match_data.get("fourth_match", [])
                                    code_value = self._format_fourth_match(fourth_match) if fourth_match else ""
                                
                                # 检查 code 中是否包含 0x1 到 0x16 之间的值（先添加code_hex_check）
                                row_data['code_hex_check'] = self._check_code_contains_hex_range(code_value)
                                # 然后添加code列
                                row_data['code'] = code_value
                                
                                data.append(row_data)
                        
                        # 如果没有任何匹配数据，添加一行基本信息
                        if not has_match_data:
                            data.append(base_file_data.copy())
                elif item.is_dir():
                    data.append({
                        '文件路径': relative_path,
                        '文件名': item.name,
                        '文件类型': '目录',
                        '文件大小(字节)': 0,
                        '文件大小(MB)': 0,
                        '修改时间': pd.Timestamp.fromtimestamp(item.stat().st_mtime),
                        '是否文件': '否',
                        '是否目录': '是'
                    })
            except (PermissionError, OSError):
                # 跳过无法访问的文件
                continue
        
        df = pd.DataFrame(data)
        
        # 根据code列动态添加 macro X lane Y 列
        df = self._add_dynamic_macro_lane_columns(df)
        
        return df
    
    def _convert_hex_to_decimal(self, value: str) -> int:
        """
        将十六进制字符串转换为十进制整数
        
        Args:
            value: 十六进制字符串（如 "0x11"）
            
        Returns:
            十进制整数，如果转换失败返回None
        """
        if not value or not isinstance(value, str):
            return None
        
        value = value.strip()
        # 检查是否是十六进制格式（0x开头）
        if value.startswith('0x') or value.startswith('0X'):
            try:
                return int(value, 16)
            except (ValueError, TypeError):
                return None
        return None
    
    def _process_macro_lane_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        处理macro x lane y列：
        1. 将十六进制值转换为十进制
        2. 将macro x lane y列的数据拆分成多行，每行包含macro、lane和code值
        
        Args:
            df: 原始DataFrame
            
        Returns:
            处理后的DataFrame
        """
        if df.empty:
            return df
        
        # 找到所有macro x lane y列（列名格式：macro X lane Y）
        macro_lane_pattern = re.compile(r'^macro\s+\d+\s+lane\s+\d+$')
        macro_lane_columns = [col for col in df.columns if macro_lane_pattern.match(str(col))]
        
        if not macro_lane_columns:
            return df
        
        # 收集所有非macro x lane y列（同时排除原来的code列，因为会被新的code列替代）
        non_macro_lane_columns = [col for col in df.columns if col not in macro_lane_columns and col != 'code']
        
        # 存储新的行数据
        new_rows = []
        
        # 遍历每一行
        for idx, row in df.iterrows():
            # 获取该行的所有macro x lane y数据
            macro_lane_data = []
            
            for col_name in macro_lane_columns:
                value = row[col_name]
                if value and str(value).strip():
                    # 解析macro和lane数字
                    macro_match = re.search(r'macro\s*(\d+)', col_name)
                    lane_match = re.search(r'lane\s*(\d+)', col_name)
                    
                    if macro_match and lane_match:
                        macro_num = int(macro_match.group(1))
                        lane_num = int(lane_match.group(1))
                        
                        # 将十六进制值转换为十进制，如果已经是数字则直接使用
                        decimal_val = self._convert_hex_to_decimal(str(value))
                        if decimal_val is None:
                            # 如果不是十六进制格式，尝试直接转换为数字
                            try:
                                if pd.notna(value):
                                    decimal_val = int(float(str(value)))
                            except (ValueError, TypeError):
                                # 如果转换失败，跳过这个值
                                continue
                        
                        if decimal_val is not None:
                            macro_lane_data.append({
                                'macro': macro_num,
                                'lane': lane_num,
                                'code': decimal_val
                            })
            
            # 如果有macro x lane y数据，为每个macro-lane组合创建一行
            if macro_lane_data:
                for ml_data in macro_lane_data:
                    new_row = {}
                    # 复制所有非macro x lane y列的数据
                    for col in non_macro_lane_columns:
                        new_row[col] = row[col]
                    # 添加macro、lane和code列
                    new_row['macro'] = ml_data['macro']
                    new_row['lane'] = ml_data['lane']
                    new_row['code'] = ml_data['code']
                    new_rows.append(new_row)
            else:
                # 如果没有macro x lane y数据，保留原行（不包含macro、lane、code列）
                new_row = {}
                for col in non_macro_lane_columns:
                    new_row[col] = row[col]
                new_rows.append(new_row)
        
        # 创建新的DataFrame
        new_df = pd.DataFrame(new_rows)
        
        # 重新排列列顺序：将macro、lane、code列放在一起
        all_columns = list(new_df.columns)
        
        # 找到原来的code列的位置（如果存在，这是旧的code列，现在可能已经不需要了）
        # 但我们主要关注新的macro、lane、code列的位置
        new_column_order = []
        
        # 先添加所有非macro/lane/code列
        for col in all_columns:
            if col not in ['macro', 'lane', 'code']:
                new_column_order.append(col)
        
        # 添加macro、lane、code列（如果存在）
        if 'macro' in all_columns:
            new_column_order.append('macro')
        if 'lane' in all_columns:
            new_column_order.append('lane')
        if 'code' in all_columns:
            new_column_order.append('code')
        
        new_df = new_df[new_column_order]
        return new_df
    
    def save_to_excel(self, df: pd.DataFrame, output_path: str) -> None:
        """
        将DataFrame保存为Excel文件
        
        Args:
            df: 要保存的DataFrame
            output_path: 输出文件路径
        """
        if df.empty:
            raise ValueError("数据为空，无法保存")
        
        # 在保存前处理macro x lane y列
        df = self._process_macro_lane_columns(df)
        
        # 去重：如果文件名和文件大小相同，只保留一条记录
        if '文件名' in df.columns and '文件大小(字节)' in df.columns:
            # 记录去重前的行数
            before_count = len(df)
            # 基于文件名和文件大小去重，保留第一条记录
            df = df.drop_duplicates(subset=['文件名', '文件大小(字节)'], keep='first')
            after_count = len(df)
            if before_count != after_count:
                print(f"去重完成：从 {before_count} 条记录减少到 {after_count} 条记录")
        
        df.to_excel(output_path, index=False, engine='openpyxl')


def main():
    """主函数：直接运行此文件时自动分析指定目录"""
    # 要分析的目录路径
    folder_path = "/Users/xianbo/vulcanization/vulcanization/logs/test"
    
    # 输出Excel文件路径（与分析目录同目录）
    output_path = os.path.join(folder_path, "分析结果.xlsx")
    
    print(f"开始分析目录: {folder_path}")
    
    try:
        # 创建数据处理器
        processor = DataProcessor()
        
        # 分析文件夹（不自动解压zip，如需解压可设置 extract_zip=True）
        df = processor.analyze_folder(folder_path, extract_zip=False)
        
        if df.empty:
            print("警告: 没有找到符合条件的文件！")
            print("请检查配置文件中的关键词设置。")
            return
        
        # 保存到Excel
        processor.save_to_excel(df, output_path)
        
        print(f"分析完成！共分析 {len(df)} 个项目")
        print(f"Excel文件已保存到: {output_path}")
        
    except Exception as e:
        print(f"分析过程中出现错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

