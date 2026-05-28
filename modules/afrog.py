"""
afrog 漏洞扫描模块
"""
import os
import subprocess
from singscan.modules.publi import Initialization


class UseAfrog(Initialization):
    def __init__(self, target_domain):
        super().__init__(target_domain)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'afrog', 'afrog.exe')
        self.afrog_save_dir = os.path.join(self.save_dir, "afrog_reports")

    def use(self, target_list_path, search=None, report_suffix=None):
        """从目标文件批量进行漏洞扫描"""
        if not target_list_path or not os.path.exists(target_list_path):
            print("Afrog: 无效目标文件路径，取消扫描。")
            return None

        if not os.path.exists(self.afrog_save_dir):
            os.makedirs(self.afrog_save_dir, exist_ok=True)

        report_name = "afrog_result.html"
        if report_suffix:
            report_name = f"afrog_result_{report_suffix}.html"
        report_path = os.path.join(self.afrog_save_dir, report_name)
        cmd = [
            self.tool_path,
            "-T", target_list_path,
            "-o", report_path,
            "-silent",
            "-c", "25",
            "-rl", "120"
        ]

        if search:
            cmd.extend(["-s", search])

        print(f"Afrog 开始批量漏洞扫描，读取目标文件: {target_list_path}")
        try:
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0 and os.path.exists(report_path):
                print(f"Afrog 扫描完成，报告存放在: {report_path}")
                return report_path

            if result.returncode == 0:
                print("Afrog 扫描完成，未发现可输出的漏洞结果。")
                return "no-findings"

            print(f"Afrog 运行异常: {result.stderr}")
            return None
        except Exception as e:
            print(f"Afrog 运行出错: {e}")
            return None
