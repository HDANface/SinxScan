"""
urlfinder
"""
import os
import subprocess
from singscan.modules.publi import Initialization

class UseUrlFinder(Initialization):
    def __init__(self, url):
        super().__init__(url)
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'urlfinder', 'URLFinder.exe')
        self.save_dir = os.path.join(self.get_save_path("urlfinder"))

    def use(self, txt_path):

        # -ff 读取文件，-o 指定输出目录 (URLFinder会在该目录下按域名自动建文件夹)
        cmd = [
            self.tool_path,
            "-ff",txt_path,
            "-o",self.save_dir,
            "-s","200,204,301,302,401,403,405,500,502,503",
            "-m","3" #深度抓取
        ]

        print(f"URLFinder 开始批量扫描，读取目标文件: {txt_path}")
        # print(f"URLFinder 命令: {cmd}")
        try:
            # 同样加入 utf-8 和 ignore 防止控制台乱码导致 Python 崩溃
            result = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='ignore')
            # print(f"URLFinder 运行结果: {result.stdout}")
            if result.returncode == 0:
                print(f"URLFinder 扫描完成，报告存放在: {self.save_dir}")
                return self.save_dir
            else:
                print(f"URLFinder 运行异常: {result.stderr}")
                return None
        except Exception as e:
            print(f"URLFinder 运行出错: {e}")
            return None