import sys
import requests
import subprocess #控制台调用模块
import os
import json
from datetime import datetime
from urllib.parse import urlparse

"""
父类：负责处理一切公共逻辑（时间、路径创建、URL清洗）
"""
class Initialization:
    def __init__(self, url):
        self.url = url
        self.time_str = datetime.now().strftime("%Y%m%d")

        # 代码位于 singscan/ 下，但扫描结果仍然保留在仓库根目录。
        package_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        self.base_dir = os.path.dirname(package_root)

        # 特殊字符处理
        parsed_url = urlparse(url)
        self.domain = parsed_url.netloc or parsed_url.path
        self.domain = self.domain.replace(':', '_')
        self.domain = self.domain.replace('/', '')

        self.save_dir = os.path.join(self.base_dir, "result", f"{self.time_str}_{self.domain}")

        self._create_directory()

    def _create_directory(self):
        """内部方法：创建存放数据的文件夹"""
        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)
            print(f"收集信息储存位置: {self.save_dir}")

    def get_save_path(self, filename):
        """公共方法：给子类提供文件绝对路经"""
        return os.path.join(self.save_dir, filename)