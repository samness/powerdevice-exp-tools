#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import os
import platform
import sys

# 设置 matplotlib 后端
import matplotlib
matplotlib.use('TkAgg')  # 在导入 pyplot 之前设置后端

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    # 设置中文字体
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']  # macOS 系统字体
    plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
except ImportError as e:
    print(f"错误：无法导入 matplotlib: {str(e)}")
    print("请确保已正确安装 matplotlib:")
    print("1. pip install matplotlib")
    print("2. 如果使用虚拟环境，请确保在虚拟环境中安装")
    print("3. 如果使用系统 Python，可能需要使用 sudo pip install matplotlib")
    sys.exit(1)

class FinanceManager:
    def __init__(self):
        try:
            self.root = tk.Tk()
            self.root.title("家庭财务记账系统")
            
            # macOS 特定设置
            if platform.system() == 'Darwin':  # macOS
                self.root.tk.call('tk', 'scaling', 1.0)
                self.root.option_add('*Font', ('Helvetica', 12))
                
                # 设置 matplotlib 的 DPI 和字体
                matplotlib.rcParams['figure.dpi'] = 100
                matplotlib.rcParams['figure.figsize'] = [6, 8]
                matplotlib.rcParams['font.sans-serif'] = ['Arial Unicode MS']
                matplotlib.rcParams['axes.unicode_minus'] = False
            
            # 获取屏幕尺寸
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            
            # 设置窗口大小
            window_width = 1200  # 增加窗口宽度以容纳图表
            window_height = 700
            
            # 计算窗口居中位置
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2
            
            # 设置窗口位置和大小
            self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
            
            # 创建数据库连接
            self.init_database()
            
            # 创建界面
            self.create_widgets()
            
            # 更新图表
            self.update_charts()
            
        except Exception as e:
            messagebox.showerror("错误", f"程序初始化失败：{str(e)}")
            sys.exit(1)
        
    def init_database(self):
        try:
            # 获取用户主目录
            home_dir = os.path.expanduser('~')
            db_path = os.path.join(home_dir, 'finance.db')
            
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            
            # 创建交易记录表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    category TEXT NOT NULL,
                    amount REAL NOT NULL,
                    description TEXT,
                    type TEXT NOT NULL
                )
            ''')
            self.conn.commit()
            
        except Exception as e:
            messagebox.showerror("数据库错误", f"数据库初始化失败：{str(e)}")
            raise
        
    def create_widgets(self):
        try:
            # 创建主框架
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # 配置网格权重
            self.root.grid_rowconfigure(0, weight=1)
            self.root.grid_columnconfigure(0, weight=1)
            main_frame.grid_columnconfigure(1, weight=1)
            
            # 左侧面板（输入和列表）
            left_panel = ttk.Frame(main_frame)
            left_panel.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # 创建输入区域
            input_frame = ttk.LabelFrame(left_panel, text="添加新记录", padding="5")
            input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
            
            # 日期输入
            ttk.Label(input_frame, text="日期:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
            self.date_entry = ttk.Entry(input_frame)
            self.date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))
            self.date_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
            
            # 类别输入
            ttk.Label(input_frame, text="类别:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
            self.category_entry = ttk.Entry(input_frame)
            self.category_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
            
            # 金额输入
            ttk.Label(input_frame, text="金额:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
            self.amount_entry = ttk.Entry(input_frame)
            self.amount_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
            
            # 类型选择
            ttk.Label(input_frame, text="类型:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
            self.type_var = tk.StringVar(value="支出")
            ttk.Radiobutton(input_frame, text="支出", variable=self.type_var, value="支出").grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
            ttk.Radiobutton(input_frame, text="收入", variable=self.type_var, value="收入").grid(row=3, column=2, sticky=tk.W, padx=5, pady=2)
            
            # 描述输入
            ttk.Label(input_frame, text="描述:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
            self.description_entry = ttk.Entry(input_frame)
            self.description_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
            
            # 添加按钮框架
            button_frame = ttk.Frame(input_frame)
            button_frame.grid(row=5, column=0, columnspan=3, pady=10)
            
            # 添加按钮
            ttk.Button(button_frame, text="添加记录", command=self.add_record).grid(row=0, column=0, padx=5)
            ttk.Button(button_frame, text="修改记录", command=self.edit_record).grid(row=0, column=1, padx=5)
            ttk.Button(button_frame, text="删除记录", command=self.delete_record).grid(row=0, column=2, padx=5)
            
            # 创建记录显示区域
            self.tree = ttk.Treeview(left_panel, columns=("日期", "类别", "金额", "类型", "描述"), show="headings")
            self.tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
            
            # 设置列标题和宽度
            self.tree.heading("日期", text="日期")
            self.tree.heading("类别", text="类别")
            self.tree.heading("金额", text="金额")
            self.tree.heading("类型", text="类型")
            self.tree.heading("描述", text="描述")
            
            # 设置列宽
            self.tree.column("日期", width=100)
            self.tree.column("类别", width=100)
            self.tree.column("金额", width=100)
            self.tree.column("类型", width=80)
            self.tree.column("描述", width=200)
            
            # 添加滚动条
            scrollbar = ttk.Scrollbar(left_panel, orient=tk.VERTICAL, command=self.tree.yview)
            scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
            self.tree.configure(yscrollcommand=scrollbar.set)
            
            # 绑定双击事件
            self.tree.bind('<Double-1>', lambda e: self.edit_record())
            
            # 右侧图表面板
            right_panel = ttk.Frame(main_frame)
            right_panel.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10)
            
            # 创建图表区域
            self.fig = Figure(figsize=(6, 8))
            self.canvas = FigureCanvasTkAgg(self.fig, master=right_panel)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # 加载现有记录
            self.load_records()
            
        except Exception as e:
            messagebox.showerror("界面错误", f"界面创建失败：{str(e)}")
            raise
        
    def edit_record(self):
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请先选择要修改的记录")
                return
                
            # 获取选中的记录
            values = self.tree.item(selected_item[0])['values']
            
            # 创建编辑窗口
            edit_window = tk.Toplevel(self.root)
            edit_window.title("修改记录")
            edit_window.geometry("400x300")
            
            # 设置模态
            edit_window.transient(self.root)
            edit_window.grab_set()
            
            # 创建输入框
            ttk.Label(edit_window, text="日期:").grid(row=0, column=0, padx=5, pady=5)
            date_entry = ttk.Entry(edit_window)
            date_entry.insert(0, values[0])
            date_entry.grid(row=0, column=1, padx=5, pady=5)
            
            ttk.Label(edit_window, text="类别:").grid(row=1, column=0, padx=5, pady=5)
            category_entry = ttk.Entry(edit_window)
            category_entry.insert(0, values[1])
            category_entry.grid(row=1, column=1, padx=5, pady=5)
            
            ttk.Label(edit_window, text="金额:").grid(row=2, column=0, padx=5, pady=5)
            amount_entry = ttk.Entry(edit_window)
            amount_entry.insert(0, values[2])
            amount_entry.grid(row=2, column=1, padx=5, pady=5)
            
            ttk.Label(edit_window, text="类型:").grid(row=3, column=0, padx=5, pady=5)
            type_var = tk.StringVar(value=values[3])
            ttk.Radiobutton(edit_window, text="支出", variable=type_var, value="支出").grid(row=3, column=1, sticky=tk.W)
            ttk.Radiobutton(edit_window, text="收入", variable=type_var, value="收入").grid(row=3, column=1, sticky=tk.E)
            
            ttk.Label(edit_window, text="描述:").grid(row=4, column=0, padx=5, pady=5)
            description_entry = ttk.Entry(edit_window)
            description_entry.insert(0, values[4])
            description_entry.grid(row=4, column=1, padx=5, pady=5)
            
            # 保存按钮
            def save_changes():
                try:
                    # 更新数据库
                    self.cursor.execute('''
                        UPDATE transactions 
                        SET date=?, category=?, amount=?, type=?, description=?
                        WHERE date=? AND category=? AND amount=? AND type=? AND description=?
                    ''', (
                        date_entry.get(), category_entry.get(), float(amount_entry.get()),
                        type_var.get(), description_entry.get(),
                        values[0], values[1], float(values[2]), values[3], values[4]
                    ))
                    self.conn.commit()
                    
                    # 刷新显示
                    self.load_records()
                    self.update_charts()
                    
                    edit_window.destroy()
                    messagebox.showinfo("成功", "记录已更新！")
                except Exception as e:
                    messagebox.showerror("错误", f"更新失败：{str(e)}")
            
            ttk.Button(edit_window, text="保存", command=save_changes).grid(row=5, column=0, columnspan=2, pady=20)
            
        except Exception as e:
            messagebox.showerror("错误", f"修改记录失败：{str(e)}")

    def delete_record(self):
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请先选择要删除的记录")
                return
            
            if messagebox.askyesno("确认", "确定要删除选中的记录吗？"):
                values = self.tree.item(selected_item[0])['values']
                
                # 从数据库删除记录
                self.cursor.execute('''
                    DELETE FROM transactions 
                    WHERE date=? AND category=? AND amount=? AND type=? AND description=?
                ''', values)
                self.conn.commit()
                
                # 刷新显示
                self.load_records()
                self.update_charts()
                
                messagebox.showinfo("成功", "记录已删除！")
        except Exception as e:
            messagebox.showerror("错误", f"删除记录失败：{str(e)}")

    def update_charts(self):
        try:
            # 清除现有图表
            self.fig.clear()
            
            # 获取数据
            self.cursor.execute('''
                SELECT type, SUM(amount) as total
                FROM transactions
                GROUP BY type
            ''')
            type_data = self.cursor.fetchall()
            
            self.cursor.execute('''
                SELECT category, SUM(amount) as total
                FROM transactions
                WHERE type='支出'
                GROUP BY category
            ''')
            category_data = self.cursor.fetchall()
            
            # 创建支出收入对比图
            ax1 = self.fig.add_subplot(211)
            types = [x[0] for x in type_data]
            amounts = [x[1] for x in type_data]
            ax1.pie(amounts, labels=types, autopct='%1.1f%%', textprops={'fontsize': 10})
            ax1.set_title('收支比例', fontsize=12, pad=20)
            
            # 创建支出类别分布图
            ax2 = self.fig.add_subplot(212)
            categories = [x[0] for x in category_data]
            category_amounts = [x[1] for x in category_data]
            bars = ax2.bar(categories, category_amounts)
            ax2.set_title('支出类别分布', fontsize=12, pad=20)
            
            # 设置x轴标签旋转
            plt.xticks(rotation=45, ha='right')
            
            # 添加数值标签
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'¥{height:,.0f}',
                        ha='center', va='bottom', fontsize=8)
            
            # 调整布局
            self.fig.tight_layout()
            
            # 更新画布
            self.canvas.draw()
            
        except Exception as e:
            messagebox.showerror("错误", f"更新图表失败：{str(e)}")

    def add_record(self):
        try:
            date = self.date_entry.get()
            category = self.category_entry.get()
            amount = float(self.amount_entry.get())
            type_ = self.type_var.get()
            description = self.description_entry.get()
            
            # 保存到数据库
            self.cursor.execute('''
                INSERT INTO transactions (date, category, amount, type, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (date, category, amount, type_, description))
            self.conn.commit()
            
            # 清空输入框
            self.category_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)
            self.description_entry.delete(0, tk.END)
            
            # 刷新显示
            self.load_records()
            self.update_charts()
            
            messagebox.showinfo("成功", "记录添加成功！")
            
        except ValueError:
            messagebox.showerror("错误", "请输入有效的金额")
        except Exception as e:
            messagebox.showerror("错误", f"添加记录失败：{str(e)}")

    def load_records(self):
        try:
            # 清空现有显示
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            # 从数据库加载记录
            self.cursor.execute('SELECT date, category, amount, type, description FROM transactions ORDER BY date DESC')
            for record in self.cursor.fetchall():
                self.tree.insert("", "end", values=record)
                
        except Exception as e:
            messagebox.showerror("错误", f"加载记录失败：{str(e)}")
            
    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            messagebox.showerror("错误", f"程序运行失败：{str(e)}")
        finally:
            try:
                self.conn.close()
            except:
                pass

if __name__ == "__main__":
    try:
        app = FinanceManager()
        app.run()
    except Exception as e:
        messagebox.showerror("错误", f"程序启动失败：{str(e)}")
        sys.exit(1) 