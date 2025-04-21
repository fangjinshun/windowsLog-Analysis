import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import win32evtlog
import win32evtlogutil
import win32con
import os
from datetime import datetime
import csv
import re
from collections import defaultdict
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_record_xml_view

class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command=None, width=120, height=35, corner_radius=10, padding=2, bg="#f0f0f0", fg="#333333", hover_bg="#4a90e2", hover_fg="#ffffff"):
        tk.Canvas.__init__(self, parent, width=width, height=height, bg=bg, highlightthickness=0)
        self.command = command
        self.corner_radius = corner_radius
        self.padding = padding
        self.bg = bg
        self.fg = fg
        self.hover_bg = hover_bg
        self.hover_fg = hover_fg
        
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        
        self.draw_button(text)
        
    def draw_button(self, text):
        self.delete("all")
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        
        # 绘制圆角矩形
        self.create_roundrect(0, 0, width, height, self.corner_radius, fill=self.bg)
        
        # 添加文字
        self.create_text(width/2, height/2, text=text, fill=self.fg, font=('Microsoft YaHei UI', 10, 'bold'))
        
    def create_roundrect(self, x1, y1, x2, y2, radius, **kwargs):
        points = [x1+radius, y1,
                 x2-radius, y1,
                 x2, y1,
                 x2, y1+radius,
                 x2, y2-radius,
                 x2, y2,
                 x2-radius, y2,
                 x1+radius, y2,
                 x1, y2,
                 x1, y2-radius,
                 x1, y1+radius,
                 x1, y1]
        return self.create_polygon(points, smooth=True, **kwargs)
        
    def _on_enter(self, event):
        self.draw_button(self.find_withtag("text")[0])
        self.config(bg=self.hover_bg)
        self.itemconfig("all", fill=self.hover_fg)
        
    def _on_leave(self, event):
        self.draw_button(self.find_withtag("text")[0])
        self.config(bg=self.bg)
        self.itemconfig("all", fill=self.fg)
        
    def _on_click(self, event):
        if self.command:
            self.command()

class LogAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows日志分析工具")
        self.root.geometry("1200x800")
        
        # 设置蓝色主题
        self.setup_blue_theme()
        
        # 定义关注的事件ID和描述
        self.security_events = {
            4624: "登录成功",
            4625: "登录失败",
            4648: "明文登录",
            4672: "特权登录"
        }
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建标题
        self.create_title()
        
        # 创建工具栏
        self.create_toolbar()
        
        # 创建日志显示区域
        self.create_log_display()
        
        # 创建筛选区域
        self.create_filter_section()
        
        # 创建爆破检测区域
        self.create_brute_force_section()
        
        # 存储当前日志数据
        self.current_logs = []
        # 存储爆破检测结果
        self.brute_force_results = []
        
    def setup_blue_theme(self):
        """设置蓝色主题"""
        # 设置窗口背景色
        self.root.configure(bg='#f0f8ff')
        
        # 创建自定义样式
        style = ttk.Style()
        style.theme_use('default')
        
        # 配置主框架样式
        style.configure('Main.TFrame', background='#f0f8ff')
        
        # 配置标签样式
        style.configure('Blue.TLabel',
                      background='#f0f8ff',
                      foreground='#1e90ff',
                      font=('Microsoft YaHei UI', 10, 'bold'))
        
        # 配置Treeview样式
        style.configure('Blue.Treeview',
                      background='#ffffff',
                      foreground='#333333',
                      fieldbackground='#ffffff',
                      font=('Microsoft YaHei UI', 9))
        style.configure('Blue.Treeview.Heading',
                      background='#1e90ff',
                      foreground='#ffffff',
                      font=('Microsoft YaHei UI', 10, 'bold'))
        style.map('Blue.Treeview',
                 background=[('selected', '#4a90e2')],
                 foreground=[('selected', '#ffffff')])
        
        # 配置Entry样式
        style.configure('Blue.TEntry',
                      fieldbackground='#ffffff',
                      foreground='#333333',
                      insertcolor='#1e90ff',
                      font=('Microsoft YaHei UI', 9))
        
        # 配置LabelFrame样式
        style.configure('Blue.TLabelframe',
                      background='#f0f8ff',
                      foreground='#1e90ff',
                      font=('Microsoft YaHei UI', 10, 'bold'))
        style.configure('Blue.TLabelframe.Label',
                      background='#f0f8ff',
                      foreground='#1e90ff',
                      font=('Microsoft YaHei UI', 10, 'bold'))

    def create_title(self):
        """创建标题"""
        title_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(title_frame,
                              text="Windows日志分析工具",
                              style='Blue.TLabel',
                              font=('Microsoft YaHei UI', 16, 'bold'))
        title_label.pack(pady=5)
        
        subtitle_label = ttk.Label(title_frame,
                                 text="网络安全分析助手",
                                 style='Blue.TLabel',
                                 font=('Microsoft YaHei UI', 12))
        subtitle_label.pack()

    def create_toolbar(self):
        """创建工具栏"""
        toolbar = ttk.Frame(self.main_frame, style='Main.TFrame')
        toolbar.pack(fill=tk.X, pady=5)
        
        # 创建圆角按钮
        RoundedButton(toolbar, "分析本地日志", command=self.analyze_local_logs).pack(side=tk.LEFT, padx=5)
        RoundedButton(toolbar, "导入事件日志", command=self.import_evtx_file).pack(side=tk.LEFT, padx=5)
        RoundedButton(toolbar, "导出日志", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        RoundedButton(toolbar, "检测爆破", command=self.detect_brute_force).pack(side=tk.LEFT, padx=5)
        
        # 添加一键清空按钮（使用红色突出显示）
        clear_button = RoundedButton(toolbar, "一键清空", command=self.clear_all, 
                                   bg="#ff4d4d", fg="#ffffff", 
                                   hover_bg="#ff1a1a", hover_fg="#ffffff")
        clear_button.pack(side=tk.RIGHT, padx=5)

    def create_log_display(self):
        # 创建日志显示区域
        log_frame = ttk.LabelFrame(self.main_frame, text="日志内容", style='Blue.TLabelframe')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建Treeview
        columns = ("时间", "事件ID", "事件类型", "IP地址", "用户名", "登录结果", "详细信息")
        self.tree = ttk.Treeview(log_frame, columns=columns, show="headings", style='Blue.Treeview')
        
        # 设置列标题和固定宽度
        for col in columns:
            self.tree.heading(col, text=col, anchor=tk.W)
            self.tree.column(col, width=150, minwidth=150, stretch=tk.NO)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_brute_force_section(self):
        """创建爆破检测结果显示区域"""
        brute_frame = ttk.LabelFrame(self.main_frame, text="爆破检测结果", style='Blue.TLabelframe')
        brute_frame.pack(fill=tk.X, pady=5)
        
        # 创建Treeview
        columns = ("IP地址", "失败次数", "时间范围", "风险等级", "尝试的用户名", "目标用户名")
        self.brute_tree = ttk.Treeview(brute_frame, columns=columns, show="headings", style='Blue.Treeview')
        
        # 设置列标题和固定宽度
        for col in columns:
            self.brute_tree.heading(col, text=col, anchor=tk.W)
            self.brute_tree.column(col, width=150, minwidth=150, stretch=tk.NO)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(brute_frame, orient=tk.VERTICAL, command=self.brute_tree.yview)
        self.brute_tree.configure(yscrollcommand=scrollbar.set)
        
        self.brute_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 添加说明标签
        info_label = ttk.Label(brute_frame,
                             text="提示：系统会自动分析登录失败事件，识别可能的暴力破解攻击。\n"
                                  "风险等级说明：\n"
                                  "- 警告：5-9次失败登录\n"
                                  "- 可疑：10-19次失败登录\n"
                                  "- 高危：20次以上失败登录",
                             style='Blue.TLabel',
                             font=('Microsoft YaHei UI', 9))
        info_label.pack(pady=5)
        
    def extract_login_info(self, event_id, description):
        """从事件描述中提取登录信息"""
        # 初始化结果
        ip_address = "未知"
        username = "未知"
        login_result = "未知"
        details = ""
        
        # 将描述转换为字符串并打印用于调试
        if isinstance(description, tuple):
            print(f"\n原始事件数据: {description}")
            # 根据事件ID提取信息
            if event_id == 4624:  # 登录成功
                if len(description) >= 6:
                    username = description[5]  # 用户名在第6个位置
                    # 尝试从不同位置获取IP地址
                    if len(description) > 18 and description[18]:  # 源网络地址
                        ip_address = description[18]
                    elif len(description) > 1 and description[1]:  # 计算机名
                        ip_address = description[1]
                    logon_type = description[8] if len(description) > 8 else "未知"
                    logon_process = description[9] if len(description) > 9 else "未知"
                    details = f"登录类型: {logon_type}, 登录进程: {logon_process}"
                login_result = "成功"
            
            elif event_id == 4625:  # 登录失败
                if len(description) >= 6:
                    username = description[5]  # 用户名在第6个位置
                    # 尝试从不同位置获取IP地址
                    if len(description) > 19 and description[19]:  # 源网络地址
                        ip_address = description[19]
                    elif len(description) > 1 and description[1]:  # 计算机名
                        ip_address = description[1]
                    # 如果IP地址仍然是"未知"，尝试从其他位置获取
                    if ip_address == "未知":
                        # 检查是否有IP地址格式的字符串
                        for i, item in enumerate(description):
                            if isinstance(item, str):
                                # 检查是否是IP地址格式
                                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', item):
                                    ip_address = item
                                    print(f"在索引 {i} 找到IP地址: {ip_address}")
                                    break
                                # 检查是否包含IP地址
                                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', item)
                                if ip_match:
                                    ip_address = ip_match.group(0)
                                    print(f"在索引 {i} 找到IP地址: {ip_address}")
                                    break
                        # 如果仍然没有找到IP地址，尝试从工作站名获取
                        if ip_address == "未知" and len(description) > 11 and description[11]:
                            ip_address = description[11]  # 工作站名
                    failure_reason = description[7] if len(description) > 7 else "未知"
                    sub_status = description[8] if len(description) > 8 else "未知"
                    logon_type = description[8] if len(description) > 8 else "未知"
                    details = f"失败原因: {failure_reason}, 子状态: {sub_status}, 登录类型: {logon_type}"
                login_result = "失败"
            
            elif event_id == 4648:  # 明文凭据登录尝试
                if len(description) >= 6:
                    username = description[5]  # 用户名在第6个位置
                    # 尝试从不同位置获取IP地址
                    if len(description) > 8 and description[8]:  # 源工作站名
                        ip_address = description[8]
                    process_name = description[10] if len(description) > 10 else "未知"
                    details = f"进程名: {process_name}"
                login_result = "尝试"
            
            elif event_id == 4672:  # 特权登录
                if len(description) >= 2:
                    username = description[1]  # 用户名在第2个位置
                    # 尝试从不同位置获取IP地址
                    if len(description) > 2 and description[2]:  # 域
                        ip_address = description[2]
                    privileges = description[4] if len(description) > 4 else "未知"
                    details = f"特权: {privileges}"
                login_result = "特权"
        
        print(f"解析结果 - IP: {ip_address}, 用户名: {username}, 登录结果: {login_result}, 详情: {details}")
        return ip_address, username, login_result, details
        
    def analyze_local_logs(self):
        """分析本地Windows安全日志"""
        try:
            # 连接到本地安全日志
            log = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # 清空现有数据
            self.current_logs = []
            
            # 读取事件
            while True:
                events = win32evtlog.ReadEventLog(log, flags, 0)
                if not events:
                    break
                
                for event in events:
                    event_id = event.EventID
                    if event_id in self.security_events:
                        # 提取登录信息
                        ip_address, username, login_result, details = self.extract_login_info(event_id, event.StringInserts)
                        
                        # 添加日志条目
                        self.current_logs.append({
                            "时间": event.TimeGenerated.Format(),
                            "事件ID": event_id,
                            "事件类型": self.security_events[event_id],
                            "IP地址": ip_address,
                            "用户名": username,
                            "登录结果": login_result,
                            "详情": details
                        })
            
            # 关闭日志
            win32evtlog.CloseEventLog(log)
            
            # 更新显示
            self.update_log_display()
            
        except Exception as e:
            messagebox.showerror("错误", f"分析日志时出错: {str(e)}")
            
    def detect_brute_force(self):
        """检测可能的暴力破解攻击"""
        # 清空爆破检测结果
        for item in self.brute_tree.get_children():
            self.brute_tree.delete(item)
            
        # 统计每个IP的失败登录信息
        ip_failures = defaultdict(lambda: {
            'count': 0,
            'usernames': set(),
            'times': [],
            'last_time': None,
            'first_time': None,
            'target_usernames': set()
        })
        
        # 分析日志数据
        for log in self.current_logs:
            if log['事件ID'] == 4625:  # 失败登录
                ip = log['IP地址']
                username = log['用户名']
                time_str = log['时间']
                
                # 更新时间信息
                if ip_failures[ip]['first_time'] is None:
                    ip_failures[ip]['first_time'] = time_str
                ip_failures[ip]['last_time'] = time_str
                
                # 更新统计信息
                ip_failures[ip]['count'] += 1
                ip_failures[ip]['usernames'].add(username)
                
                # 记录目标用户名（如果用户名不是常见系统账户）
                if username.lower() not in ['system', 'administrator', 'guest', 'defaultaccount']:
                    ip_failures[ip]['target_usernames'].add(username)
        
        # 分析可能的爆破行为
        for ip, data in ip_failures.items():
            if data['count'] >= 5:  # 如果同一IP有5次或更多失败登录
                # 计算时间范围
                time_range = f"{data['first_time']} 至 {data['last_time']}"
                
                # 确定风险等级
                if data['count'] >= 20:
                    status = "高危"
                elif data['count'] >= 10:
                    status = "可疑"
                else:
                    status = "警告"
                
                # 获取尝试的用户名列表
                usernames = ", ".join(data['usernames'])
                target_usernames = ", ".join(data['target_usernames'])
                
                # 添加检测结果
                self.brute_tree.insert('', 'end', values=(
                    ip,
                    data['count'],
                    time_range,
                    status,
                    usernames,
                    target_usernames
                ))
                
        # 如果没有检测到爆破行为
        if not self.brute_tree.get_children():
            messagebox.showinfo("提示", "未检测到可能的暴力破解攻击")
            
    def import_evtx_file(self):
        """导入EVTX文件"""
        file_path = filedialog.askopenfilename(
            title="选择事件日志文件",
            filetypes=[
                ("事件日志文件", "*.evtx"),
                ("所有文件", "*.*")
            ]
        )
        
        if file_path:
            try:
                # 清空现有数据
                self.current_logs = []
                
                # 读取EVTX文件
                with Evtx(file_path) as log:
                    for record in log.records():
                        try:
                            # 解析XML内容
                            xml_content = record.xml()
                            event = ET.fromstring(xml_content)
                            
                            # 获取System节点
                            system = event.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
                            if system is None:
                                continue
                                
                            # 获取事件ID
                            event_id_elem = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                            if event_id_elem is None:
                                continue
                            
                            event_id = int(event_id_elem.text)
                            
                            # 只处理我们关注的事件ID
                            if event_id in self.security_events:
                                # 获取时间
                                time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
                                event_time = time_created.get('SystemTime') if time_created is not None else ''
                                
                                # 获取EventData节点
                                event_data = event.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                                if event_data is None:
                                    continue
                                
                                # 解析事件数据
                                data = {}
                                for data_item in event_data.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                                    name = data_item.get('Name')
                                    if name:
                                        data[name] = data_item.text if data_item.text else ''
                                
                                # 根据事件ID提取相关信息
                                if event_id == 4624:  # 登录成功
                                    ip_address = data.get('IpAddress', data.get('WorkstationName', '未知'))
                                    username = data.get('TargetUserName', '未知')
                                    logon_type = data.get('LogonType', '未知')
                                    details = f"登录类型: {logon_type}, 进程: {data.get('ProcessName', '未知')}"
                                    login_result = '成功'
                                    
                                elif event_id == 4625:  # 登录失败
                                    ip_address = data.get('IpAddress', data.get('WorkstationName', '未知'))
                                    username = data.get('TargetUserName', '未知')
                                    sub_status = data.get('SubStatus', '未知')
                                    details = f"失败原因: {sub_status}, 登录类型: {data.get('LogonType', '未知')}"
                                    login_result = '失败'
                                    
                                elif event_id == 4648:  # 使用明文凭据尝试登录
                                    ip_address = data.get('TargetServerName', '未知')
                                    username = data.get('TargetUserName', '未知')
                                    details = f"进程: {data.get('ProcessName', '未知')}"
                                    login_result = '明文尝试'
                                    
                                elif event_id == 4672:  # 特权登录
                                    ip_address = data.get('WorkstationName', '未知')
                                    username = data.get('SubjectUserName', '未知')
                                    details = f"特权: {data.get('PrivilegeList', '未知')}"
                                    login_result = '特权登录'
                                
                                # 添加日志条目
                                log_entry = {
                                    '时间': event_time,
                                    '事件ID': event_id,
                                    '事件类型': self.security_events[event_id],
                                    'IP地址': ip_address,
                                    '用户名': username,
                                    '登录结果': login_result,
                                    '详情': details
                                }
                                self.current_logs.append(log_entry)
                        
                        except Exception as e:
                            print(f"跳过无效记录: {e}")
                            continue
                
                # 更新显示
                self.update_log_display()
                
                if not self.current_logs:
                    messagebox.showwarning("警告", "未找到相关的登录事件记录")
                else:
                    messagebox.showinfo("成功", f"成功导入 {len(self.current_logs)} 条日志记录")
                
            except Exception as e:
                messagebox.showerror("错误", f"导入文件时发生错误:\n{str(e)}")

    def export_logs(self):
        if not self.current_logs:
            messagebox.showwarning("警告", "没有可导出的日志数据")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="导出日志",
            filetypes=[("CSV文件", "*.csv")],
            defaultextension=".csv"
        )
        
        if file_path:
            try:
                # 定义固定的字段列表
                fieldnames = ['时间', '事件ID', '事件类型', 'IP地址', '用户名', '登录结果', '详细信息']
                
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    # 确保每条记录只包含指定的字段
                    for log in self.current_logs:
                        filtered_log = {
                            '时间': log.get('时间', ''),
                            '事件ID': log.get('事件ID', ''),
                            '事件类型': log.get('事件类型', ''),
                            'IP地址': log.get('IP地址', ''),
                            '用户名': log.get('用户名', ''),
                            '登录结果': log.get('登录结果', ''),
                            '详细信息': log.get('详情', '')
                        }
                        writer.writerow(filtered_log)
                        
                messagebox.showinfo("成功", "日志导出成功")
            except Exception as e:
                messagebox.showerror("错误", f"导出日志时发生错误: {str(e)}")
                
    def clear_log_display(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
    def add_log_to_tree(self, log_entry):
        self.tree.insert('', 'end', values=(
            log_entry['时间'],
            log_entry['事件ID'],
            log_entry['事件类型'],
            log_entry['IP地址'],
            log_entry['用户名'],
            log_entry['登录结果'],
            log_entry['详细信息']
        ))
                
    def create_filter_section(self):
        """创建筛选条件区域"""
        filter_frame = ttk.LabelFrame(self.main_frame, text="筛选条件", style='Blue.TLabelframe')
        filter_frame.pack(fill=tk.X, pady=5)
        
        # 创建筛选条件输入框和操作按钮的框架
        input_and_actions_frame = ttk.Frame(filter_frame, style='Main.TFrame')
        input_and_actions_frame.pack(fill=tk.X, pady=5)
        
        # 创建左侧的筛选条件输入区域
        filter_inputs = ttk.Frame(input_and_actions_frame, style='Main.TFrame')
        filter_inputs.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 事件ID筛选
        id_frame = ttk.Frame(filter_inputs, style='Main.TFrame')
        id_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(id_frame, text="事件ID:", style='Blue.TLabel').pack(side=tk.LEFT)
        self.event_id_var = tk.StringVar()
        self.event_id_entry = ttk.Entry(id_frame, textvariable=self.event_id_var, 
                                      style='Blue.TEntry', width=10)
        self.event_id_entry.pack(side=tk.LEFT, padx=(2, 10))
        
        # IP地址筛选
        ip_frame = ttk.Frame(filter_inputs, style='Main.TFrame')
        ip_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(ip_frame, text="IP地址:", style='Blue.TLabel').pack(side=tk.LEFT)
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(ip_frame, textvariable=self.ip_var, 
                                style='Blue.TEntry', width=15)
        self.ip_entry.pack(side=tk.LEFT, padx=(2, 10))
        
        # 用户名筛选
        user_frame = ttk.Frame(filter_inputs, style='Main.TFrame')
        user_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(user_frame, text="用户名:", style='Blue.TLabel').pack(side=tk.LEFT)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(user_frame, textvariable=self.username_var, 
                                      style='Blue.TEntry', width=15)
        self.username_entry.pack(side=tk.LEFT, padx=(2, 10))
        
        # 创建右侧的操作按钮区域
        action_buttons = ttk.Frame(input_and_actions_frame, style='Main.TFrame')
        action_buttons.pack(side=tk.RIGHT, padx=5)
        
        # 应用筛选按钮
        RoundedButton(action_buttons, 
                     text="应用筛选",
                     width=80,
                     height=30,
                     command=self.apply_filters).pack(side=tk.LEFT, padx=5)
        
        # 重置筛选按钮
        RoundedButton(action_buttons,
                     text="重置筛选",
                     width=80,
                     height=30,
                     command=self.reset_filters).pack(side=tk.LEFT, padx=5)
        
        # 创建事件类型快速筛选区域
        event_filter_frame = ttk.Frame(filter_frame, style='Main.TFrame')
        event_filter_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 添加事件类型说明标签
        ttk.Label(event_filter_frame, 
                 text="快速筛选:", 
                 style='Blue.TLabel',
                 font=('Microsoft YaHei UI', 10)).pack(side=tk.LEFT, padx=(5, 10))
        
        # 快速筛选按钮
        event_buttons = {
            4624: "登录成功",
            4625: "登录失败",
            4648: "明文登录",
            4672: "特权登录"
        }
        
        for event_id, desc in event_buttons.items():
            btn = RoundedButton(event_filter_frame, 
                              text=f"{event_id}\n{desc}",
                              width=100,
                              height=45,
                              command=lambda eid=event_id: self.filter_by_event_id(eid))
            btn.pack(side=tk.LEFT, padx=5)

    def reset_filters(self):
        """重置所有筛选条件"""
        self.event_id_var.set("")
        self.ip_var.set("")
        self.username_var.set("")
        self.apply_filters()

    def filter_by_event_id(self, event_id):
        """快速筛选特定事件ID"""
        self.event_id_var.set(str(event_id))
        self.apply_filters()

    def apply_filters(self):
        """应用筛选条件"""
        # 获取筛选条件
        event_id = self.event_id_var.get().strip()
        ip_address = self.ip_var.get().strip()
        username = self.username_var.get().strip()
        
        # 清空现有显示
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 应用筛选条件
        filtered_logs = self.current_logs if hasattr(self, 'current_logs') else []
        
        if event_id:
            try:
                event_id = int(event_id)
                filtered_logs = [log for log in filtered_logs if log['事件ID'] == event_id]
            except ValueError:
                messagebox.showwarning("警告", "事件ID必须是数字")
                return
                
        if ip_address:
            filtered_logs = [log for log in filtered_logs if ip_address.lower() in log['IP地址'].lower()]
            
        if username:
            filtered_logs = [log for log in filtered_logs if username.lower() in log['用户名'].lower()]
        
        # 显示筛选后的日志
        for log in filtered_logs:
            self.tree.insert('', 'end', values=(
                log['时间'],
                log['事件ID'],
                log['事件类型'],
                log['IP地址'],
                log['用户名'],
                log['登录结果'],
                log['详情']
            ))
            
        # 如果没有匹配的日志，显示提示
        if not filtered_logs:
            messagebox.showinfo("提示", "没有找到匹配的日志记录")

    def update_log_display(self):
        """更新日志显示"""
        try:
            # 清空现有显示
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # 添加新的日志条目
            for log in self.current_logs:
                self.tree.insert('', 'end', values=(
                    log['时间'],
                    log['事件ID'],
                    log['事件类型'],
                    log['IP地址'],
                    log['用户名'],
                    log['登录结果'],
                    log['详情']
                ))
        except Exception as e:
            messagebox.showerror("错误", f"更新显示时发生错误:\n{str(e)}")

    def clear_all(self):
        """一键清空所有数据和显示"""
        try:
            # 清空日志显示
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # 清空爆破检测结果
            for item in self.brute_tree.get_children():
                self.brute_tree.delete(item)
            
            # 清空数据
            self.current_logs = []
            self.brute_force_results = []
            
            # 清空筛选条件
            self.event_id_var.set("")
            self.ip_var.set("")
            self.username_var.set("")
            
            messagebox.showinfo("成功", "已清空所有数据和显示")
            
        except Exception as e:
            messagebox.showerror("错误", f"清空数据时发生错误: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzer(root)
    root.mainloop() 