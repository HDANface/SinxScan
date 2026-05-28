"""
资产规则引擎（第一阶段）
规则1/2/3：
1) 高危技术一票保送
2) 3306 + 非CDN
3) 后台标题 + 200/302
"""


class RuleEngine:
    def __init__(self):
        # 高危技术指纹：命中后可直接提升为 critical。
        self.critical_tech = {"weblogic", "shiro", "log4j", "fastjson", "struts2","nginx"}

        # 管理后台关键词：用于识别高价值业务面。
        self.backend_keywords = ["后台", "系统", "管理", "admin", "login", "控制台", "dashboard"]

        # 高危数据库/中间件端口组（用于组合规则判断）。
        self.critical_ports = {
            "3306": "mysql",
            "6379": "redis",
            "1433": "mssql",
            "5432": "postgresql",
            "27017": "mongodb",
            "9200": "elasticsearch",
        }

    def evaluate_assets(self, assets, stage="full"):
        results = []
        for asset in assets:
            results.append(self._evaluate_single(asset, stage))
        return results

    def _evaluate_single(self, asset, stage="full"):
        subdomain = asset.get("subdomain", "")
        technologies = self._parse_technologies(asset.get("technologies", ""))
        ports = self._parse_ports(asset.get("ports", ""))
        is_cdn = self._to_bool(asset.get("is_cdn"))

        status_code = asset.get("status_code")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except Exception:
                status_code = None

        title = (asset.get("title") or "").strip()
        title_lower = title.lower()

        tags = []
        actions = []
        score = 0
        tier = "low"
        confidence = "low"

        # 规则1：高危技术一票保送
        hit_critical_tech = sorted(list(technologies & self.critical_tech))
        if hit_critical_tech:
            for tech in hit_critical_tech:
                tags.append(f"tech:{tech}")
            tags.append("tier:critical")
            actions.append("action:direct-poc")
            tier = "critical"
            confidence = "high"
            score += 80

        # 规则2：高危数据库/中间件端口 + 非CDN（弱口令/未授权优先验证）
        hit_critical_ports = sorted(list(ports & set(self.critical_ports.keys())))
        if hit_critical_ports and is_cdn is False:
            for port in hit_critical_ports:
                tags.append(f"net:port:{port}")
                tags.append(f"service:{self.critical_ports[port]}")
            tags.append("asset:cdn:false")
            actions.append("action:weakpass-db")
            score += 25
            if confidence == "low":
                confidence = "mid"

        # 规则3：200/302 + 后台标题
        has_backend_keyword = any(keyword in title_lower for keyword in self.backend_keywords)
        if status_code in (200, 302) and has_backend_keyword:
            tags.append("title:backend")
            tags.append(f"http:status:{status_code}")
            actions.append("action:ffuf-deep")
            actions.append("action:nuclei-focused")
            score += 30
            if tier != "critical":
                tier = "high"
            if confidence == "low":
                confidence = "mid"

        # 基础标签
        if status_code is not None:
            tags.append(f"http:status:{status_code}")
        if is_cdn is True:
            tags.append("asset:cdn:true")
        elif is_cdn is False:
            tags.append("asset:cdn:false")

        # 非命中情况下的基础分
        if score == 0 and status_code in (200, 302):
            score = 10

        tier = self._normalize_tier(tier, score)

        return {
            "subdomain": subdomain,
            "asset_score": score,
            "asset_tier": tier,
            "confidence": confidence,
            "tags": sorted(list(set(tags))),
            "actions": sorted(list(set(actions)))
        }

    def _parse_technologies(self, technologies):
        if not technologies:
            return set()
        return {item.strip().lower() for item in technologies.split(",") if item.strip()}

    def _parse_ports(self, ports):
        if not ports:
            return set()
        return {item.strip() for item in str(ports).split(",") if item.strip()}

    def _to_bool(self, value):
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        if isinstance(value, int):
            if value == 1:
                return True
            if value == 0:
                return False
        if isinstance(value, str):
            val = value.strip().lower()
            if val in ("1", "true", "yes"):
                return True
            if val in ("0", "false", "no"):
                return False
        return None

    def _normalize_tier(self, tier, score):
        if tier == "critical":
            return "critical"
        if tier == "high":
            return "high"
        if score >= 80:
            return "high"
        if score >= 50:
            return "mid"
        return "low"
