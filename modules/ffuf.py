# --------------------
# 文件: information/modules/ffuf.py (V2新增)
# --------------------
import os
import subprocess
import sys
from singscan.modules.publi import Initialization


class UseFfuf(Initialization):

    def __init__(self, target_domain):
        super().__init__(target_domain)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'ffuf', 'ffuf.exe')

        # ffuf字典位置
        self.wordlist_path = os.path.join(package_root, 'tool', 'ffuf', 'dicc.txt')

        # 在项目结果文件夹下为 ffuf 创建专门的报告子文件夹
        self.ffuf_save_dir = os.path.join(self.save_dir, "ffuf_reports")

    def use(self, target_url):
        """对单个URL执行ffuf扫描"""
        if not os.path.exists(self.wordlist_path):
            print(f"FFUF 字典文件未找到: {self.wordlist_path}, 跳过对 {target_url} 的扫描")
            return None

        if not os.path.exists(self.ffuf_save_dir):
            os.makedirs(self.ffuf_save_dir, exist_ok=True)

        # 根据URL生成安全的文件名
        safe_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        report_path = os.path.join(self.ffuf_save_dir, f"{safe_name}.json")

        # FUZZ参数为爆破字典
        url_with_fuzz = f"{target_url}/FUZZ"

        cmd = [
            self.tool_path,
            "-u", url_with_fuzz,
            "-w", self.wordlist_path,
            "-o", report_path,
            "-of", "json",
            "-t", "50",  # 线程数
            "-ac",  # 自动校准过滤
            "-timeout", "10",
            "-r",  # 跟随跳转
            "-s"  # 静默模式，不输出到控制台
        ]

        print(f"开始 FFUF 快速目录扫描: {target_url}")
        try:
            # 使用 DEVNULL 防止控制台挂起，并捕获输出
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, encoding='utf-8',
                                    errors='ignore')

            # 检查报告是否生成且非空
            if os.path.exists(report_path) and os.path.getsize(report_path) > 20:  # >20字节以确保不是空JSON
                return report_path
            else:
                if result.stderr:
                    print(f"FFUF 扫描 {target_url} 未发现有效目录或报错: {result.stderr.strip()}")
                return None

        except Exception as e:
            print(f"FFUF 执行出错 ({target_url}): {e}")
            return None
