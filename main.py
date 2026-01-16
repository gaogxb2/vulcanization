import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading
from data_processor import DataProcessor


class FolderAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件夹分析工具")
        self.root.geometry("600x400")
        
        self.selected_folder = None
        self.output_path = None
        self.extract_zip_var = tk.BooleanVar(value=False)
        self.delete_unmatched_var = tk.BooleanVar(value=False)
        
        self.setup_ui()
    
    def setup_ui(self):
        # 标题
        title_label = tk.Label(self.root, text="文件夹内容分析工具", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # 文件夹选择区域
        folder_frame = tk.Frame(self.root)
        folder_frame.pack(pady=10, padx=20, fill=tk.X)
        
        tk.Label(folder_frame, text="选择文件夹:", font=("Arial", 10)).pack(anchor=tk.W)
        
        folder_select_frame = tk.Frame(folder_frame)
        folder_select_frame.pack(fill=tk.X, pady=5)
        
        self.folder_path_label = tk.Label(folder_select_frame, text="未选择文件夹", 
                                          bg="white", relief=tk.SUNKEN, anchor=tk.W,
                                          padx=5, pady=5)
        self.folder_path_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        select_btn = tk.Button(folder_select_frame, text="浏览", 
                              command=self.select_folder, width=10)
        select_btn.pack(side=tk.RIGHT)
        
        # 输出位置选择区域
        output_frame = tk.Frame(self.root)
        output_frame.pack(pady=10, padx=20, fill=tk.X)
        
        tk.Label(output_frame, text="Excel输出位置:", font=("Arial", 10)).pack(anchor=tk.W)
        
        output_select_frame = tk.Frame(output_frame)
        output_select_frame.pack(fill=tk.X, pady=5)
        
        self.output_path_label = tk.Label(output_select_frame, text="未选择输出位置", 
                                          bg="white", relief=tk.SUNKEN, anchor=tk.W,
                                          padx=5, pady=5)
        self.output_path_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        output_btn = tk.Button(output_select_frame, text="浏览", 
                               command=self.select_output_path, width=10)
        output_btn.pack(side=tk.RIGHT)
        
        # 选项区域
        option_frame = tk.Frame(self.root)
        option_frame.pack(pady=10, padx=20, fill=tk.X)
        
        extract_checkbox = tk.Checkbutton(option_frame, 
                                          text="自动解压并在解压后删除zip文件",
                                          variable=self.extract_zip_var,
                                          font=("Arial", 10))
        extract_checkbox.pack(anchor=tk.W)
        
        delete_checkbox = tk.Checkbutton(option_frame, 
                                         text="【磁盘清理】删除选中文件夹内未匹配到关键词的文件",
                                         variable=self.delete_unmatched_var,
                                         font=("Arial", 10))
        delete_checkbox.pack(anchor=tk.W, pady=(5, 0))
        
        # 分析按钮
        self.analyze_btn = tk.Button(self.root, text="开始分析", 
                                     command=self.start_analysis,
                                     font=("Arial", 12, "bold"),
                                     bg="#4CAF50", fg="white",
                                     width=20, height=2)
        self.analyze_btn.pack(pady=20)
        
        # 进度条
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=10, padx=20, fill=tk.X)
        
        # 状态显示
        self.status_label = tk.Label(self.root, text="就绪", 
                                     font=("Arial", 9), fg="gray")
        self.status_label.pack(pady=5)
    
    def select_folder(self):
        folder = filedialog.askdirectory(title="选择要分析的文件夹")
        if folder:
            self.selected_folder = folder
            self.folder_path_label.config(text=folder)
            self.status_label.config(text=f"已选择文件夹: {os.path.basename(folder)}")
            # 自动填充输出位置为相同路径
            folder_name = os.path.basename(folder) or "分析结果"
            default_output = os.path.join(folder, f"{folder_name}_分析结果.xlsx")
            self.output_path = default_output
            self.output_path_label.config(text=default_output)
    
    def select_output_path(self):
        file_path = filedialog.asksaveasfilename(
            title="保存Excel文件",
            defaultextension=".xlsx",
            filetypes=[("Excel文件", "*.xlsx"), ("所有文件", "*.*")]
        )
        if file_path:
            self.output_path = file_path
            self.output_path_label.config(text=file_path)
            self.status_label.config(text=f"输出位置: {os.path.basename(file_path)}")
    
    def analyze_folder(self):
        """分析文件夹内容"""
        if not self.selected_folder:
            messagebox.showwarning("警告", "请先选择要分析的文件夹！")
            return
        
        if not self.output_path:
            messagebox.showwarning("警告", "请先选择Excel输出位置！")
            return
        
        try:
            self.analyze_btn.config(state=tk.DISABLED)
            self.progress.start()
            self.status_label.config(text="正在分析...", fg="blue")
            
            # 使用DataProcessor进行数据处理
            processor = DataProcessor()
            extract_zip = self.extract_zip_var.get()
            delete_unmatched = self.delete_unmatched_var.get()
            df = processor.analyze_folder(self.selected_folder, extract_zip=extract_zip, delete_unmatched=delete_unmatched)
            
            # 如果数据为空
            if df.empty:
                messagebox.showinfo("提示", "没有找到符合条件的文件！\n请检查配置文件中的关键词设置。")
                return
            
            # 保存到Excel
            processor.save_to_excel(df, self.output_path)
            
            self.progress.stop()
            self.status_label.config(text=f"分析完成！共分析 {len(df)} 个项目", fg="green")
            messagebox.showinfo("成功", f"分析完成！\n共分析 {len(df)} 个项目\n\nExcel文件已保存到:\n{self.output_path}")
            
        except Exception as e:
            self.progress.stop()
            self.status_label.config(text=f"分析失败: {str(e)}", fg="red")
            messagebox.showerror("错误", f"分析过程中出现错误:\n{str(e)}")
        finally:
            self.analyze_btn.config(state=tk.NORMAL)
    
    def start_analysis(self):
        """在新线程中启动分析，避免界面卡顿"""
        thread = threading.Thread(target=self.analyze_folder)
        thread.daemon = True
        thread.start()


def main():
    root = tk.Tk()
    app = FolderAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

