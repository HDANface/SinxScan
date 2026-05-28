"""
子域名扫描 subfinder
"""
import os
import subprocess
import sys
from singscan.modules.publi import Initialization


# 调用 Subfinder
class Subfinder(Initialization):
    def __init__(self, url):
        super().__init__(url)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool','subfinder','subfinder.exe')
        self.report_path = self.get_save_path("subfinder.json")

    def use(self):
        # 通过父类的方法获取存储路径
        report_path = self.report_path
        cmd = [
            self.tool_path,
            "-d",self.url,
            "-all",
            "-o",report_path,
            "-json"
        ]
        print("Subfinder 开始扫描...")
        try :
            result = subprocess.run(cmd, capture_output=True, text=True)
            # print(result.stdout)  //输出控制台信息
            if result.returncode != 0:
                print("Subfinder 执行失败 错误原因:")
                print(result.stderr)
                return None
            else:
                print(f"Subfinder 成功 存储位置:{report_path}")
                return self.report_path
        except Exception as e:
            print(f"Subfinder 执行过程中出现错误: {e}")
            return None




