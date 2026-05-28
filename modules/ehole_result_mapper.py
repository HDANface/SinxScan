
# 负责把 EHole 输出映射成数据库可消费的子域名与技术指纹信息。
class EHoleResultMapper:
    """解析 EHole 结果并产出技术指纹合并所需的数据。"""

    def extract_subdomain(self, target):
        """从 URL、域名或 IP 文本中提取可用于匹配数据库记录的子域名。"""
        target = (target or "").strip()
        if not target:
            return ""
        target = target.replace("http://", "").replace("https://", "")
        return target.split("/")[0].split(":")[0].strip()

    def parse_csv_set(self, value):
        """把数据库中的逗号分隔技术栈字段归一化成小写集合。"""
        if not value:
            return set()
        return {item.strip().lower() for item in str(value).split(",") if item.strip()}

    def extract_ehole_technologies(self, item):
        """从 EHole 单条结果中提取并归一化技术指纹集合。"""
        techs = set()

        def add_text(v):
            text = str(v).strip().lower()
            if text and text not in ("none", "null"):
                techs.add(text)

        cms = item.get("cms")
        if isinstance(cms, list):
            for c in cms:
                add_text(c)
        elif cms:
            add_text(cms)

        app = item.get("app")
        if isinstance(app, list):
            for a in app:
                add_text(a)
        elif app:
            add_text(app)

        finger = item.get("finger")
        if isinstance(finger, list):
            for f in finger:
                if isinstance(f, dict):
                    if f.get("cms"):
                        add_text(f.get("cms"))
                    if f.get("app"):
                        add_text(f.get("app"))
                else:
                    add_text(f)

        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, list):
            for f in fingerprint:
                if isinstance(f, dict):
                    if f.get("cms"):
                        add_text(f.get("cms"))
                    if f.get("app"):
                        add_text(f.get("app"))
                else:
                    add_text(f)

        if not techs:
            if item.get("cms"):
                add_text(item.get("cms"))
            if item.get("server"):
                add_text(item.get("server"))

        return techs

    def merge_technologies(self, technologies_httpx, old_ehole, old_merged, ehole_techs):
        """把 httpx 与 EHole 的技术指纹合并成新的 ehole/总技术栈字段。"""
        merged_ehole_set = self.parse_csv_set(old_ehole) | ehole_techs
        merged_all_set = self.parse_csv_set(technologies_httpx) | merged_ehole_set
        if not merged_all_set and old_merged:
            merged_all_set = self.parse_csv_set(old_merged)

        return {
            "technologies_ehole": ",".join(sorted(list(merged_ehole_set))),
            "technologies": ",".join(sorted(list(merged_all_set)))
        }
