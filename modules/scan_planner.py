import json


class ScanPlanner:
    # 统一承接“下一步扫什么”的选择与分组规则，不处理文件写入或数据库访问。
    def build_httpx_targets(self, assets):
        """从资产快照中选出尚未做存活探测的子域名。"""
        targets = [asset.get("subdomain", "").strip() for asset in assets if asset.get("is_alive") is None]
        return sorted([target for target in targets if target])

    def build_nmap_ips(self, assets):
        """从资产快照中提取仍需做端口探测的唯一 IP。"""
        unique_ips = set()
        for asset in assets:
            if not self._to_bool(asset.get("is_alive")):
                continue
            if self._to_bool(asset.get("is_nmap_scanned")):
                continue
            raw_ip = str(asset.get("ip_address") or "").strip()
            if not raw_ip:
                continue
            for item in raw_ip.split(','):
                item = item.strip()
                if item:
                    unique_ips.add(item)
        return sorted(list(unique_ips))

    def build_ehole_targets(self, assets, fallback_target_domain=None):
        """为 EHole 生成指纹识别目标，并在没有资产时回退到当前目标域名。"""
        targets = set()
        for asset in assets:
            target = self._build_target_url(asset.get("subdomain"), asset.get("alive_url"))
            if target:
                targets.add(target)

        if not targets:
            base_target = str(fallback_target_domain or "").strip()
            if not base_target:
                return []
            if base_target.startswith("http://") or base_target.startswith("https://"):
                targets.add(base_target)
            else:
                targets.add(f"https://{base_target}")
        return sorted(list(targets))

    def build_urlfinder_targets(self, assets):
        """选出仍需做 URL 爬取的存活目标。"""
        targets = set()
        for asset in assets:
            if not self._to_bool(asset.get("is_alive")):
                continue
            if self._to_bool(asset.get("is_urlfinder_scanned")):
                continue
            target = self._build_target_url(asset.get("subdomain"), asset.get("alive_url"))
            if target:
                targets.add(target)
        return sorted(list(targets))

    def build_ffuf_targets(self, assets):
        """选出仍需做目录爆破的存活目标。"""
        targets = []
        for asset in assets:
            if not self._to_bool(asset.get("is_alive")):
                continue
            if self._to_bool(asset.get("is_ffuf_scanned")):
                continue
            target = self._build_target_url(asset.get("subdomain"), asset.get("alive_url"))
            if target:
                targets.append(target)
        return sorted(list(dict.fromkeys(targets)))

    def build_nuclei_plan(self, assets):
        """按资产动作建议、优先级和技术指纹生成 Nuclei 分组计划。"""
        grouped = {}
        for asset in assets:
            if not self._to_bool(asset.get("is_alive")):
                continue
            actions = self._parse_json_list(asset.get("actions"))
            tier = asset.get("asset_tier")
            if not ("action:nuclei-focused" in actions or "action:direct-poc" in actions or tier in ("critical", "high")):
                continue

            selector = self._build_nuclei_selector(
                self._collect_service_tokens(asset.get("technologies"), asset.get("web_server")),
                actions
            )
            target = self._build_target_url(asset.get("subdomain"), asset.get("alive_url"))
            if target:
                grouped.setdefault(selector, set()).add(target)

        plans = []
        for selector in sorted(grouped.keys()):
            targets = sorted(list(grouped[selector]))
            if targets:
                plans.append({"selector": selector, "targets": targets})
        return plans

    def build_afrog_plan(self, assets):
        """按资产动作建议、优先级和技术指纹生成 Afrog 分组计划。"""
        grouped = {}
        for asset in assets:
            if not self._to_bool(asset.get("is_alive")):
                continue
            actions = self._parse_json_list(asset.get("actions"))
            tier = asset.get("asset_tier")
            if not ("action:direct-poc" in actions or "action:weakpass-db" in actions or tier == "critical"):
                continue

            selector = self._build_afrog_selector(
                self._collect_service_tokens(asset.get("technologies"), asset.get("web_server")),
                actions
            )
            target = self._build_target_url(asset.get("subdomain"), asset.get("alive_url"))
            if target:
                grouped.setdefault(selector, set()).add(target)

        plans = []
        for selector in sorted(grouped.keys()):
            targets = sorted(list(grouped[selector]))
            if targets:
                plans.append({"selector": selector, "targets": targets})
        return plans

    def _normalize_alive_url(self, alive_url):
        text = str(alive_url or "").strip()
        if text.startswith("http://") or text.startswith("https://"):
            return text
        return ""

    def _build_target_url(self, subdomain, alive_url=None):
        normalized = self._normalize_alive_url(alive_url)
        if normalized:
            return normalized

        subdomain = str(subdomain or "").strip()
        if not subdomain:
            return ""
        if subdomain.startswith("http://") or subdomain.startswith("https://"):
            return subdomain
        return f"https://{subdomain}"

    def _parse_json_list(self, value):
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            return []
        except Exception:
            return []

    def _collect_service_tokens(self, technologies, web_server):
        tokens = set()
        for raw in [technologies, web_server]:
            text = str(raw or "").strip().lower()
            if not text:
                continue
            normalized = text.replace("|", ",").replace(";", ",").replace("/", ",")
            for part in normalized.split(','):
                part = part.strip()
                if not part:
                    continue
                for item in part.split():
                    item = item.strip()
                    if item:
                        tokens.add(item)
        return tokens

    def _build_nuclei_selector(self, service_tokens, actions):
        tags = set()
        mapping = {
            "weblogic": "weblogic",
            "shiro": "shiro",
            "struts": "struts",
            "fastjson": "fastjson",
            "log4j": "log4j",
            "nginx": "nginx",
            "apache": "apache",
            "iis": "iis",
            "tomcat": "tomcat",
            "spring": "spring",
            "php": "php",
            "redis": "redis",
            "mysql": "mysql",
            "mssql": "mssql",
            "postgres": "postgresql",
            "mongodb": "mongodb",
            "elastic": "elasticsearch"
        }
        for token in service_tokens:
            for key, tag in mapping.items():
                if key in token:
                    tags.add(tag)

        if "action:weakpass-db" in actions:
            tags.update(["mysql", "redis", "mssql", "postgresql", "mongodb", "elasticsearch"])

        if not tags and "action:direct-poc" in actions:
            tags.update(["weblogic", "shiro", "struts", "fastjson", "log4j"])

        if not tags:
            tags.add("http")
        return ",".join(sorted(list(tags)))

    def _build_afrog_selector(self, service_tokens, actions):
        selectors = set()
        mapping = {
            "weblogic": "weblogic",
            "shiro": "shiro",
            "struts": "struts",
            "fastjson": "fastjson",
            "log4j": "log4j",
            "nginx": "nginx",
            "apache": "apache",
            "iis": "iis",
            "tomcat": "tomcat",
            "spring": "spring",
            "php": "php",
            "redis": "redis",
            "mysql": "mysql",
            "mssql": "mssql",
            "postgres": "postgresql",
            "mongodb": "mongodb",
            "elastic": "elasticsearch"
        }
        for token in service_tokens:
            for key, selector in mapping.items():
                if key in token:
                    selectors.add(selector)

        if "action:weakpass-db" in actions:
            selectors.update(["mysql", "redis", "mssql", "postgresql", "mongodb", "elasticsearch"])

        if not selectors and "action:direct-poc" in actions:
            selectors.update(["weblogic", "shiro", "struts", "fastjson", "log4j"])

        if not selectors:
            selectors.add("http")
        return ",".join(sorted(list(selectors)))

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
