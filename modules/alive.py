import os
import subprocess
from singscan.modules.publi import Initialization

class UseHttpx(Initialization):
    def __init__(self, url):
        # 这里的 url 是为了让 Initialization 能够生成以域名命名的结果文件夹
        super().__init__(url) 
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'httpx', 'httpx.exe')
        self.report_path = self.get_save_path("httpx_result.json")

    def use(self, target_list_path):
        """
        接收一个包含多个域名的 txt 文件路径进行批量扫描
        """
        if not target_list_path or not os.path.exists(target_list_path):
            print("无效的目标文件路径，Httpx 取消扫描。")
            return None

        # -l 指定目标文件，-title 获取标题，-sc 获取状态码，-json 输出 JSONL
        cmd = [
            self.tool_path,
            "-l", target_list_path,
            "-o", self.report_path, "-json",
            "-sc",
            "-title",
            "-td",
            "-cdn",
            "-ip",
            "-cname",
            "-server",
            "-jarm",  #获取 JARM 指纹，后续可用于绕过 CDN 找真实 IP
            "-fr",  # Follow Redirects，跟随跳转。
            "-t", "100",
            "-timeout", "10"
        ]
        # print(f"实际执行的完整命令: {' '.join(cmd)}")
        print(f"Httpx 正在批量探测存活 ...")
        try:
            result = subprocess.run(cmd,stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8')
            # stdin=subprocess.DEVNULL解决等待卡死问题
            if result.returncode == 0:
                print(f"Httpx 成功 储存位置:{self.report_path}")
                return self.report_path
            else:
                print(f"Httpx 执行失败 错误原因:\n{result.stderr}")
                return None
        except Exception as e:
            print(f"Httpx 执行过程中出现错误: {e}")
            return None