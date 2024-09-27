import sys
import os

# 添加当前目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# 添加 libs 目录到 Python 路径
libs_dir = os.path.join(current_dir, 'libs')
sys.path.insert(0, libs_dir)

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import pyperclip # type: ignore
import qrcode # type: ignore
from PIL import Image, ImageTk # type: ignore
import io
import urllib.parse
import base64
import hashlib
import re
import binascii
import socket
import struct

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("多功能加解密工具smartcrypto_v1.0 --by dreamblade")
        master.geometry("1200x800")
        master.configure(bg="#f0f0f0")
        
        self.create_styles()
        self.create_widgets()
        self.create_context_menus()
        
        # 读取关键词列表
        self.keywords = self.load_keywords()
        
    def create_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.element_create("Custom.Checkbutton.indicator", "from", "default")
        style.layout("Custom.TCheckbutton", [
            ('Custom.Checkbutton.indicator', {'side': 'left', 'sticky': ''}),
            ('Checkbutton.focus', {'side': 'left', 'sticky': '',
                                   'children': [('Checkbutton.label', {'sticky': ''})]})
        ])
        style.configure("Custom.TCheckbutton", 
                        indicatorcolor="#ffffff",
                        indicatorbackground="#ffffff",
                        font=("Helvetica", 10))
        style.map("Custom.TCheckbutton",
                  indicatorcolor=[("selected", "#00aa00")],
                  indicatorbackground=[("selected", "#ffffff")])
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_bar = ttk.Label(self.master, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 输入框
        input_frame = ttk.LabelFrame(main_frame, text="输入", padding="5")
        input_frame.pack(fill=tk.X, pady=5)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=5, font=("Consolas", 11))
        self.input_text.pack(fill=tk.X)
        
        # 输入操作按钮
        input_button_frame = ttk.Frame(main_frame)
        input_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(input_button_frame, text="粘贴", command=self.paste_input).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_button_frame, text="复制", command=self.copy_input).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_button_frame, text="从文件加载", command=self.load_from_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_button_frame, text="保存到文件", command=self.save_to_file).pack(side=tk.LEFT, padx=2)
        
        # 主要操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        self.encrypt_button = ttk.Button(button_frame, text="加密", command=self.encrypt)
        self.encrypt_button.pack(side=tk.LEFT, padx=5)
        self.decrypt_button = ttk.Button(button_frame, text="解密", command=self.decrypt)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = ttk.Button(button_frame, text="清空", command=self.clear)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        self.qr_button = ttk.Button(button_frame, text="生成二维码", command=self.generate_qr)
        self.qr_button.pack(side=tk.LEFT, padx=5)
        
        # 加解密方式选择
        methods_frame = ttk.LabelFrame(main_frame, text="加解密方式", padding="5")
        methods_frame.pack(fill=tk.X, pady=5)
        self.methods = ["URL", "Unicode/ASCII", "Unicode/中文", "UTF-8", "16进制", "8进制", "2进制", "BASE64", "URL安全Base64", "MD5", "Hex Dump"]
        self.method_vars = []
        for i, method in enumerate(self.methods):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(methods_frame, text=method, variable=var, style="Custom.TCheckbutton")
            chk.grid(row=i//5, column=i%5, sticky="w", padx=5, pady=2)
            self.method_vars.append(var)
        
        # Notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 输出页
        page1 = ttk.Frame(self.notebook)
        self.notebook.add(page1, text="输出")
        
        # 详细视图页
        page2 = ttk.Frame(self.notebook)
        self.notebook.add(page2, text="详细视图")
        self.detail_view = scrolledtext.ScrolledText(page2, height=20, font=("Consolas", 11))
        self.detail_view.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 输出框
        self.output_frames = {}
        for i, method in enumerate(self.methods):
            frame = ttk.LabelFrame(page1, text=method, padding="2")
            frame.grid(row=i//2, column=i%2, sticky="nsew", padx=5, pady=5)
            output = scrolledtext.ScrolledText(frame, height=5, font=("Consolas", 10))
            output.pack(fill=tk.BOTH, expand=True)
            output.bind("<Double-1>", lambda e, m=method: self.show_detail(m))
            self.output_frames[method] = output
        
        # 配置网格布局
        page1.grid_columnconfigure(0, weight=1)
        page1.grid_columnconfigure(1, weight=1)
        for i in range(6):
            page1.grid_rowconfigure(i, weight=1)

    def create_context_menus(self):
        self.input_menu = tk.Menu(self.master, tearoff=0)
        self.input_menu.add_command(label="复制", command=self.copy_selected)
        self.input_menu.add_command(label="粘贴", command=self.paste_selected)
        self.input_menu.add_command(label="剪切", command=self.cut_selected)
        self.input_menu.add_separator()
        self.input_menu.add_command(label="清空", command=self.clear_selected)

        self.output_menu = tk.Menu(self.master, tearoff=0)
        self.output_menu.add_command(label="复制", command=self.copy_selected)
        self.output_menu.add_separator()
        self.output_menu.add_command(label="清空", command=self.clear_selected)

        self.input_text.bind("<Button-3>", self.show_context_menu)
        self.detail_view.bind("<Button-3>", self.show_context_menu)
        for output in self.output_frames.values():
            output.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        widget = event.widget
        if widget == self.input_text:
            self.input_menu.tk_popup(event.x_root, event.y_root)
        else:
            self.output_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected(self):
        try:
            selected_text = self.master.focus_get().selection_get()
            pyperclip.copy(selected_text)
            self.status_bar.config(text="已复制选中内容")
        except:
            self.status_bar.config(text="无法复制：未选中内容")

    def paste_selected(self):
        try:
            self.master.focus_get().insert(tk.INSERT, pyperclip.paste())
            self.status_bar.config(text="已粘贴内容")
        except:
            self.status_bar.config(text="无法粘贴：不支持粘贴操作")

    def cut_selected(self):
        try:
            selected_text = self.master.focus_get().selection_get()
            pyperclip.copy(selected_text)
            self.master.focus_get().delete(tk.SEL_FIRST, tk.SEL_LAST)
            self.status_bar.config(text="已剪切选中内容")
        except:
            self.status_bar.config(text="无法剪切：未选中内容")

    def clear_selected(self):
        try:
            self.master.focus_get().delete('1.0', tk.END)
            self.status_bar.config(text="已清空内容")
        except:
            self.status_bar.config(text="无法清空：不支持清空操作")

    def show_detail(self, method):
        content = self.output_frames[method].get('1.0', tk.END)
        self.detail_view.delete('1.0', tk.END)
        self.detail_view.insert(tk.END, f"{method} 详细内容:\n\n")
        self.highlight_keywords(content, self.detail_view)
        self.notebook.select(1)  # 切换到第二页

    def load_keywords(self):
        keywords = []
        try:
            keywords_path = os.path.join(current_dir, 'value.txt')
            with open(keywords_path, 'r', encoding='utf-8') as f:
                keywords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("未找到 value.txt 文件，将创建一个空文件。")
            with open(keywords_path, 'w', encoding='utf-8') as f:
                pass
        return keywords

    def highlight_keywords(self, text, output_widget):
        output_widget.delete('1.0', tk.END)
        output_widget.insert(tk.END, text)
        for keyword in self.keywords:
            start = '1.0'
            while True:
                # 使用正则表达式进行不区分大小写的搜索
                match = output_widget.search(re.escape(keyword), start, stopindex=tk.END, regexp=True, nocase=True)
                if not match:
                    break
                end = output_widget.index(f"{match}+{len(keyword)}c")
                output_widget.tag_add('highlight', match, end)
                start = end
        output_widget.tag_config('highlight', background='yellow', foreground='red')

    def encrypt(self):
        input_text = self.input_text.get('1.0', tk.END).strip()
        if not input_text:
            messagebox.showwarning("警告", "请先输入文本")
            return
        
        for method, var in zip(self.methods, self.method_vars):
            if var.get():
                try:
                    if method == "URL":
                        result = urllib.parse.quote(input_text, safe='')
                    elif method == "Unicode/ASCII":
                        result = ' '.join([str(ord(c)) for c in input_text])
                    elif method == "Unicode/中文":
                        result = ''.join(f"\\u{ord(c):04x}" for c in input_text)
                    elif method == "UTF-8":
                        result = ''.join([f'\\x{b:02x}' for b in input_text.encode('utf-8')])
                    elif method == "16进制":
                        result = input_text.encode().hex()
                    elif method == "8进制":
                        result = ' '.join([f"{ord(c):03o}" for c in input_text])
                    elif method == "2进制":
                        result = ' '.join([f"{ord(c):08b}" for c in input_text])
                    elif method == "BASE64":
                        result = base64.b64encode(input_text.encode()).decode()
                    elif method == "URL安全Base64":
                        result = base64.urlsafe_b64encode(input_text.encode()).decode()
                    elif method == "MD5":
                        result = hashlib.md5(input_text.encode()).hexdigest()
                    elif method == "Hex Dump":
                        result = self.hex_dump(input_text.encode())
                    self.highlight_keywords(result, self.output_frames[method])
                except Exception as e:
                    self.output_frames[method].delete('1.0', tk.END)
                    self.output_frames[method].insert(tk.END, f"错误: {str(e)}")
        
        self.status_bar.config(text="加密完成")
        self.notebook.select(0)  # 切换到输出页面

    def decrypt(self):
        input_text = self.input_text.get('1.0', tk.END).strip()
        if not input_text:
            messagebox.showwarning("警告", "请先输入文本")
            return
        
        for method, var in zip(self.methods, self.method_vars):
            if var.get():
                try:
                    result = self.partial_decode(input_text, method)
                    if result == input_text and method != "MD5":
                        raise ValueError("无法解密")
                    self.highlight_keywords(result, self.output_frames[method])
                except Exception as e:
                    self.output_frames[method].delete('1.0', tk.END)
                    self.output_frames[method].insert(tk.END, f"错误: {str(e)}")
        
        self.status_bar.config(text="解密完成")
        self.notebook.select(0)  # 切换到输出页面

    def partial_decode(self, text, method):
        if method == "URL":
            return urllib.parse.unquote(text)
        elif method == "Unicode/ASCII":
            return ''.join([chr(int(c)) for c in text.split()])
        elif method == "Unicode/中文": 
            try:
                decoded = text.encode().decode('unicode_escape')
                return decoded
            except:
                raise ValueError("无法解密")
        elif method == "UTF-8":
            try:
                decoded_text = bytes(text, "utf-8").decode("unicode_escape").encode('latin1').decode('utf-8')
                return decoded_text
            except:
                raise ValueError("无法解码")
        elif method == "16进制":
            return bytes.fromhex(text).decode()
        elif method == "8进制":
            return ''.join([chr(int(c, 8)) for c in text.split()])
        elif method == "2进制":
            return ''.join([chr(int(c, 2)) for c in text.split()])
        elif method == "BASE64":
            try:
                pattern = r'[A-Za-z0-9+/]{4,}={0,2}'
                matches = re.findall(pattern, text)
                if not matches:
                    raise ValueError("未找到有效的Base64编码")
                decoded_parts = []
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode()
                        decoded_parts.append(decoded)
                    except:
                        decoded_parts.append(match)
                return re.sub(pattern, lambda m: decoded_parts.pop(0), text)
            except Exception as e:
                raise ValueError(f"Base64解码错误: {str(e)}")
        elif method == "URL安全Base64":
            try:
                pattern = r'[A-Za-z0-9_-]{4,}={0,2}'
                matches = re.findall(pattern, text)
                if not matches:
                    raise ValueError("未找到有效的URL安全Base64编码")
                decoded_parts = []
                for match in matches:
                    try:
                        decoded = base64.urlsafe_b64decode(match).decode()
                        decoded_parts.append(decoded)
                    except:
                        decoded_parts.append(match)
                return re.sub(pattern, lambda m: decoded_parts.pop(0), text)
            except Exception as e:
                raise ValueError(f"URL安全Base64解码错误: {str(e)}")
        elif method == "MD5":
            return "MD5 无法解密"
        elif method == "Hex Dump":
            return self.parse_hex_dump(text)
        else:
            raise ValueError("未知的解密方法")

    def hex_dump(self, data):
        def grouped(iterable, n):
            return zip(*[iter(iterable)]*n)

        result = []
        for i, chunk in enumerate(grouped(data, 16)):
            hexa = ' '.join([f'{x:02X}' for x in chunk])
            text = ''.join([chr(x) if 32 <= x < 127 else '.' for x in chunk])
            result.append(f'{i*16:08X}:  {hexa:<48}  {text}')
        return '\n'.join(result)

    def parse_hex_dump(self, hex_dump):
        lines = hex_dump.strip().split('\n')
        output = ""
        binary_data = b''

        for line in lines:
            match = re.match(r'([0-9A-Fa-f]+):\s+((?:[0-9A-Fa-f]{2}\s*){1,16})\s*(.{0,16})', line)
            if match:
                offset, hex_values, ascii_values = match.groups()
                hex_bytes = bytes.fromhex(hex_values.replace(' ', ''))
                binary_data += hex_bytes
                output += f"{line}\n"

        output += "-" * 60 + "\n"

        try:
            # 解析以太网头部
            if len(binary_data) >= 14:
                eth_header = struct.unpack('!6s6s2s', binary_data[:14])
                dst_mac = ':'.join([f'{b:02X}' for b in eth_header[0]])
                src_mac = ':'.join([f'{b:02X}' for b in eth_header[1]])
                eth_type = int.from_bytes(eth_header[2], 'big')
                
                output += "以太网头部：\n"
                output += f"目的MAC地址: {dst_mac}\n"
                output += f"源MAC地址: {src_mac}\n"
                output += f"以太网类型: 0x{eth_type:04X} ({self.get_ether_type(eth_type)})\n"
                output += "-" * 60 + "\n"

                # 解析IP头部
                if eth_type == 0x0800 and len(binary_data) >= 34:  # IPv4
                    ip_header = struct.unpack('!BBHHHBBH4s4s', binary_data[14:34])
                    
                    version = ip_header[0] >> 4
                    ihl = ip_header[0] & 0xF
                    tos = ip_header[1]
                    total_length = ip_header[2]
                    identification = ip_header[3]
                    flags_and_offset = ip_header[4]
                    flags = flags_and_offset >> 13
                    fragment_offset = flags_and_offset & 0x1FFF
                    ttl = ip_header[5]
                    protocol = ip_header[6]
                    header_checksum = ip_header[7]
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])

                    output += "IP头部：\n"
                    output += f"版本: IPv{version}\n"
                    output += f"头部长度: {ihl*4} 字节\n"
                    output += f"服务类型: 0x{tos:02X}\n"
                    output += f"总长度: {total_length} 字节\n"
                    output += f"标识: 0x{identification:04X}\n"
                    output += f"{self.get_ip_flags_and_offset(flags, fragment_offset)}\n"
                    output += f"生存时间: {ttl}\n"
                    output += f"协议: {self.get_protocol_name(protocol)} ({protocol})\n"
                    output += f"头部校验和: 0x{header_checksum:04X}\n"
                    output += f"源IP地址: {src_ip}\n"
                    output += f"目的IP地址: {dst_ip}\n"
                    output += "-" * 60 + "\n"

                    # 解析ICMP
                    if protocol == 1 and len(binary_data) >= 42:  # ICMP
                        icmp_header = struct.unpack('!BBHHH', binary_data[34:42])
                        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = icmp_header
                        
                        output += "ICMP头部：\n"
                        output += f"类型: {icmp_type} ({self.get_icmp_type(icmp_type, icmp_code)})\n"
                        output += f"代码: {icmp_code}\n"
                        output += f"校验和: 0x{icmp_checksum:04X}\n"
                        output += f"标识符: {icmp_id}\n"
                        output += f"序列号: {icmp_seq}\n"
                        output += "-" * 60 + "\n"

                        icmp_data = binary_data[42:]
                        output += "ICMP数据部分：\n"
                        for i in range(0, len(icmp_data), 16):
                            chunk = icmp_data[i:i+16]
                            output += f"{chunk.hex(' ').upper()}\n"
                        output += f"ASCII: {self.bytes_to_ascii(icmp_data)}\n"

                    # 解析UDP
                    elif protocol == 17 and len(binary_data) >= 42:  # UDP
                        udp_header = struct.unpack('!HHHH', binary_data[34:42])
                        src_port, dst_port, length, checksum = udp_header

                        output += "UDP头部：\n"
                        output += f"源端口: {src_port}\n"
                        output += f"目的端口: {dst_port}\n"
                        output += f"长度: {length}\n"
                        output += f"校验和: 0x{checksum:04X}\n"
                        output += "-" * 60 + "\n"

                        udp_data = binary_data[42:]
                        output += "UDP数据部分：\n"
                        for i in range(0, len(udp_data), 16):
                            chunk = udp_data[i:i+16]
                            output += f"{chunk.hex(' ').upper()}\n"
                        output += f"ASCII: {self.bytes_to_ascii(udp_data)}\n"

        except Exception as e:
            output += f"解析错误: {str(e)}\n"

        return output

    def get_ether_type(self, eth_type):
        ether_types = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
        return ether_types.get(eth_type, f"未知 (0x{eth_type:04X})")

    def get_ip_flags_and_offset(self, flags, offset):
        flag_str = ""
        if flags & 4:
            flag_str += "Reserved "
        if flags & 2:
            flag_str += "Don't Fragment "
        if flags & 1:
            flag_str += "More Fragments "
        return f"标志 = {flag_str.strip()}，片偏移 = {offset}"

    def get_protocol_name(self, protocol):
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(protocol, f"未知协议 ({protocol})")

    def get_icmp_type(self, icmp_type, icmp_code):
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
        }
        return icmp_types.get(icmp_type, f"未知ICMP类型 (类型: {icmp_type}, 代码: {icmp_code})")

    def bytes_to_ascii(self, data):
        return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

    def clear(self):
        self.input_text.delete('1.0', tk.END)
        for output in self.output_frames.values():
            output.delete('1.0', tk.END)
        self.detail_view.delete('1.0', tk.END)
        self.status_bar.config(text="已清空所有内容")

    def paste_input(self):
        self.input_text.delete('1.0', tk.END)
        self.input_text.insert(tk.END, pyperclip.paste())
        self.status_bar.config(text="已粘贴内容到输入框")

    def copy_input(self):
        pyperclip.copy(self.input_text.get('1.0', tk.END).strip())
        self.status_bar.config(text="已复制输入框内容")

    def load_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                self.input_text.delete('1.0', tk.END)
                self.input_text.insert(tk.END, content)
            self.status_bar.config(text=f"已从文件加载内容: {file_path}")

    def save_to_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as file:
                input_content = self.input_text.get('1.0', tk.END).strip()
                detail_content = self.detail_view.get('1.0', tk.END).strip()
                file.write(f"{input_content}\n\n{'='*50}\n\n{detail_content}")
            self.status_bar.config(text=f"已保存内容到文件: {file_path}")

    def generate_qr(self):
        input_text = self.input_text.get('1.0', tk.END).strip()
        if not input_text:
            messagebox.showwarning("警告", "请先输入文本")
            return
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(input_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        photo = ImageTk.PhotoImage(Image.open(buffer))
        
        top = tk.Toplevel(self.master)
        top.title("二维码")
        label = ttk.Label(top, image=photo)
        label.image = photo
        label.pack()
        self.status_bar.config(text="已生成二维码")

def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()