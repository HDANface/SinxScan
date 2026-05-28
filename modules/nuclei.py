"""
nuclei 漏洞扫描模块
"""
import os
import subprocess
from singscan.modules.publi import Initialization


class UseNuclei(Initialization):
    def __init__(self, target_domain):
        super().__init__(target_domain)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'Nuclei', 'nuclei.exe')
        self.nuclei_save_dir = os.path.join(self.save_dir, "nuclei_reports")

    def use(self, target_list_path, tags=None, report_suffix=None):
        """从目标文件批量进行漏洞扫描"""
        if not target_list_path or not os.path.exists(target_list_path):
            print("Nuclei: 无效目标文件路径，取消扫描。")
            return None

        if not os.path.exists(self.nuclei_save_dir):
            os.makedirs(self.nuclei_save_dir, exist_ok=True)

        report_name = "nuclei_result.jsonl"
        if report_suffix:
            report_name = f"nuclei_result_{report_suffix}.jsonl"
        report_path = os.path.join(self.nuclei_save_dir, report_name)
        cmd = [
            self.tool_path,
            "-l", target_list_path,
            "-jle", report_path,
            "-silent",
            "-nc",
            "-rl", "120",
            "-c", "25"
        ]

        if tags:
            cmd.extend(["-tags", tags])

        print(f"Nuclei 开始批量漏洞扫描，读取目标文件: {target_list_path}")
        try:
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0 and os.path.exists(report_path):
                print(f"Nuclei 扫描完成，报告存放在: {report_path}")
                return report_path
            else:
                print(f"Nuclei 运行异常: {result.stderr}")
                return None
        except Exception as e:
            print(f"Nuclei 运行出错: {e}")
            return None
