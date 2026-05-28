"""
端口扫描 nmap
"""
import os
import subprocess
import json
import xml.etree.ElementTree as ET
from singscan.modules.publi import Initialization

class UseNmap(Initialization):
    def __init__(self, url):
        super().__init__(url)
        # 获取 nmap.exe 的路径
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool_path = os.path.join(package_root, 'tool', 'nmap', 'nmap.exe')
        self.xml_report = self.get_save_path("nmap_result.xml")
        self.json_report = self.get_save_path("nmap_result.json")

    def use(self, ip_list):
        """
        接收 IP 列表进行扫描并转换结果
        """
        if not ip_list:
            print("没有待扫描的 IP，Nmap 跳过。")
            return None

        # 将 IP 列表转换为 Nmap 接受的字符串
        targets = " ".join(ip_list)

        # -sV: 版本探测, -T4: 速度, -Pn: 跳过 Ping 扫描
        cmd = [
            self.tool_path,
            "-sV",
            "-Pn",
            "--open", "-T4",
            "-sC",  #开启默认脚本扫描。比如扫到 21 端口
            "-p", "21,22,80,443,445,3306,6379,1433,27017,9200",
            "-oX", self.xml_report, *ip_list
        ]

        print(f"Nmap 正在对 {len(ip_list)} 个唯一 IP 进行端口探测...")
        try:
            if os.path.exists(self.xml_report):
                os.remove(self.xml_report)
            if os.path.exists(self.json_report):
                os.remove(self.json_report)
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Nmap 扫描成功，开始转换结果...")
                return self._xml_to_json()
            else:
                print(f"Nmap 执行失败: {result.stderr}")
                return None
        except Exception as e:
            print(f"Nmap 执行过程中出现错误: {e}")
            return None

    def _xml_to_json(self):
        """内部方法：将 Nmap XML 转换为自定义的 JSON 格式"""
        if not os.path.exists(self.xml_report):
            return None

        results = []
        try:
            with open(self.xml_report, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()

            end_tag = "</nmaprun>"
            end_index = xml_text.find(end_tag)
            if end_index == -1:
                raise ValueError("nmap XML missing closing </nmaprun> tag")

            cleaned_xml = xml_text[:end_index + len(end_tag)]
            root = ET.fromstring(cleaned_xml)

            for host in root.findall('host'):
                ip = host.find("address[@addrtype='ipv4']").get('addr')
                port_list = []
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        p_id = port.get('portid')
                        state = port.find('state').get('state')
                        service = port.find('service').get('name') if port.find('service') is not None else "unknown"
                        if state == 'open':
                            port_list.append({"port": p_id, "service": service})

                results.append({"ip": ip, "ports": port_list})

            with open(self.json_report, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)

            return self.json_report
        except Exception as e:
            print(f"XML 转换 JSON 失败: {e}")
            return None