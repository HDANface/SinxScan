"""
ehole 指纹识别模块
"""
import json
import os
import re
import subprocess
from singscan.modules.publi import Initialization


class UseEhole(Initialization):
    def __init__(self, target_domain):
        super().__init__(target_domain)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'EHole_windows_amd64', 'EHole_windows_amd64.exe')
        self.ehole_save_dir = os.path.join(self.save_dir, "ehole_reports")

    def use(self, target_list_path):
        """从目标文件批量识别指纹"""
        if not target_list_path or not os.path.exists(target_list_path):
            print("EHole: 无效目标文件路径，取消扫描。")
            return None

        if not os.path.exists(self.ehole_save_dir):
            os.makedirs(self.ehole_save_dir, exist_ok=True)

        report_path = os.path.join(self.ehole_save_dir, "ehole_result.json")
        cmd = [
            self.tool_path,
            "finger",
            "-l", target_list_path,
            "-o", report_path,
            "-t", "100"
        ]

        print(f"EHole 开始批量指纹识别，读取目标文件: {target_list_path}")
        try:
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, encoding='utf-8', errors='ignore')

            # EHole 在部分场景可能返回非0但仍生成结果文件，以结果文件为准。
            if os.path.exists(report_path) and os.path.getsize(report_path) > 2:
                print(f"EHole 扫描完成，报告存放在: {report_path}")
                return report_path

            # 回退：从 stdout 提取结果并落盘，保证项目内有可消费结果文件。
            fallback_items = self._parse_stdout_to_items(result.stdout)
            if fallback_items:
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(fallback_items, f, ensure_ascii=False, indent=2)
                print(f"EHole 扫描完成（stdout回退），报告存放在: {report_path}")
                return report_path

            print(f"EHole 运行异常: {result.stderr}")
            return None
        except Exception as e:
            print(f"EHole 运行出错: {e}")
            return None

    def _parse_stdout_to_items(self, stdout_text):
        items = []
        if not stdout_text:
            return items

        # 解析形如: [ http://xx | cms | server | 200 | 123 | title ]
        pattern = re.compile(r"^\[\s*(https?://[^|\]]+)\s*\|\s*([^|\]]*)\s*\|\s*([^|\]]*)\s*\|\s*([^|\]]*)\s*\|\s*([^|\]]*)\s*\|\s*([^\]]*)\]$")
        for raw_line in stdout_text.splitlines():
            line = raw_line.strip()
            if not line.startswith("[") or "|" not in line:
                continue

            m = pattern.match(line)
            if not m:
                continue

            url = m.group(1).strip()
            cms = m.group(2).strip()
            server = m.group(3).strip()
            status_code = m.group(4).strip()
            content_length = m.group(5).strip()
            title = m.group(6).strip()

            item = {
                "url": url,
                "cms": cms,
                "server": server,
                "status_code": status_code,
                "content_length": content_length,
                "title": title
            }
            items.append(item)

        return items
