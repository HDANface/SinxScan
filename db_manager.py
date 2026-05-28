# --------------------
# 文件: information/db_manager.py (V2.1 线程安全修复版)
# --------------------
import sqlite3
import json
import os
from singscan.modules.ehole_result_mapper import EHoleResultMapper


class DatabaseManager:
    def __init__(self, db_path="assets.db"):
        # check_same_thread=False 解决多线程调用数据库
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.ehole_mapper = EHoleResultMapper()
        self.create_db()
        self.ensure_rule_columns()
        self.backfill_alive_url()
        self.rebuild_subdomains_table_remove_legacy_columns()
        self.ensure_directories_unique_index()

    # 表格创建
    def create_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS subdomains
                       (
                           id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                           target_domain        TEXT,
                           subdomain            TEXT UNIQUE,
                           source               TEXT,
                           is_alive             BOOLEAN DEFAULT NULL,
                           status_code          INTEGER DEFAULT NULL,
                           title                TEXT    DEFAULT NULL,
                           web_server           TEXT    DEFAULT NULL,
                           technologies         TEXT    DEFAULT NULL,
                           is_cdn               BOOLEAN DEFAULT NULL,
                           cdn_name             TEXT    DEFAULT NULL,
                           ip_address           TEXT    DEFAULT NULL,
                           cname                TEXT    DEFAULT NULL,
                           favicon_hash         TEXT    DEFAULT NULL,
                           redirect_location    TEXT    DEFAULT NULL,

                           -- V2新增: 任务状态标记 (0=未扫描, 1=已扫描)
                           is_nmap_scanned      INTEGER DEFAULT 0,
                           is_urlfinder_scanned INTEGER DEFAULT 0,
                           is_ffuf_scanned      INTEGER DEFAULT 0
                       )
                       ''')

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS directories
                       (
                           id             INTEGER PRIMARY KEY AUTOINCREMENT,
                           target_domain  TEXT,
                           url            TEXT,
                           status_code    INTEGER,
                           content_length INTEGER
                       )
                       ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_target ON subdomains(target_domain);')
        self.conn.commit()

    def ensure_rule_columns(self):
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(subdomains)")
        columns = {row[1] for row in cursor.fetchall()}

        alter_sqls = []
        if "ports" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN ports TEXT DEFAULT NULL")
        if "asset_score" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN asset_score INTEGER DEFAULT 0")
        if "asset_tier" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN asset_tier TEXT DEFAULT 'low'")
        if "confidence" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN confidence TEXT DEFAULT 'low'")
        if "tags" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN tags TEXT DEFAULT '[]'")
        if "actions" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN actions TEXT DEFAULT '[]'")
        if "technologies_httpx" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN technologies_httpx TEXT DEFAULT NULL")
        if "technologies_ehole" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN technologies_ehole TEXT DEFAULT NULL")
        if "alive_url" not in columns:
            alter_sqls.append("ALTER TABLE subdomains ADD COLUMN alive_url TEXT DEFAULT NULL")

        for sql in alter_sqls:
            cursor.execute(sql)

        if alter_sqls:
            self.conn.commit()
            print(f"规则字段初始化完成，新增 {len(alter_sqls)} 个字段。")

    # 通过重建 subdomains 表完成旧列删除，同时把 prot 的历史数据合并到规范字段 ports。
    def rebuild_subdomains_table_remove_legacy_columns(self):
        """重建 subdomains 表并移除旧的 prot 列。"""
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(subdomains)")
        columns = {row[1] for row in cursor.fetchall()}
        if "prot" not in columns:
            return

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS subdomains_new
                       (
                           id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                           target_domain        TEXT,
                           subdomain            TEXT UNIQUE,
                           source               TEXT,
                           is_alive             BOOLEAN DEFAULT NULL,
                           status_code          INTEGER DEFAULT NULL,
                           title                TEXT    DEFAULT NULL,
                           web_server           TEXT    DEFAULT NULL,
                           technologies         TEXT    DEFAULT NULL,
                           is_cdn               BOOLEAN DEFAULT NULL,
                           cdn_name             TEXT    DEFAULT NULL,
                           ip_address           TEXT    DEFAULT NULL,
                           cname                TEXT    DEFAULT NULL,
                           favicon_hash         TEXT    DEFAULT NULL,
                           redirect_location    TEXT    DEFAULT NULL,
                           is_nmap_scanned      INTEGER DEFAULT 0,
                           is_urlfinder_scanned INTEGER DEFAULT 0,
                           is_ffuf_scanned      INTEGER DEFAULT 0,
                           ports                TEXT    DEFAULT NULL,
                           asset_score          INTEGER DEFAULT 0,
                           asset_tier           TEXT    DEFAULT 'low',
                           confidence           TEXT    DEFAULT 'low',
                           tags                 TEXT    DEFAULT '[]',
                           actions              TEXT    DEFAULT '[]',
                           technologies_httpx   TEXT    DEFAULT NULL,
                           technologies_ehole   TEXT    DEFAULT NULL,
                           alive_url            TEXT    DEFAULT NULL
                       )
                       ''')

        cursor.execute('''
                       INSERT INTO subdomains_new (
                           id, target_domain, subdomain, source, is_alive, status_code, title, web_server,
                           technologies, is_cdn, cdn_name, ip_address, cname, favicon_hash, redirect_location,
                           is_nmap_scanned, is_urlfinder_scanned, is_ffuf_scanned, ports, asset_score,
                           asset_tier, confidence, tags, actions, technologies_httpx, technologies_ehole, alive_url
                       )
                       SELECT id, target_domain, subdomain, source, is_alive, status_code, title, web_server,
                              technologies, is_cdn, cdn_name, ip_address, cname, favicon_hash, redirect_location,
                              is_nmap_scanned, is_urlfinder_scanned, is_ffuf_scanned,
                              CASE
                                  WHEN ports IS NOT NULL AND ports != '' THEN ports
                                  WHEN prot IS NOT NULL AND prot != '' THEN prot
                                  ELSE NULL
                              END,
                              asset_score, asset_tier, confidence, tags, actions,
                              technologies_httpx, technologies_ehole, alive_url
                       FROM subdomains
                       ''')
        cursor.execute('DROP TABLE subdomains')
        cursor.execute('ALTER TABLE subdomains_new RENAME TO subdomains')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_target ON subdomains(target_domain)')
        self.conn.commit()

    def backfill_alive_url(self):
        cursor = self.conn.cursor()
        cursor.execute('''
                       UPDATE subdomains
                       SET alive_url = 'https://' || subdomain
                       WHERE is_alive = 1
                         AND subdomain IS NOT NULL
                         AND subdomain != ''
                         AND (alive_url IS NULL OR alive_url = '')
                       ''')
        updated = cursor.rowcount
        self.conn.commit()
        if updated > 0:
            print(f"存活URL字段回填完成，共更新 {updated} 条记录。")

    # directories 依赖唯一索引，才能让 INSERT OR IGNORE 真正承担去重职责。
    def ensure_directories_unique_index(self):
        """清理重复目录记录并补齐唯一索引。"""
        cursor = self.conn.cursor()
        cursor.execute('''
                       DELETE FROM directories
                       WHERE id NOT IN (
                           SELECT MIN(id)
                           FROM directories
                           GROUP BY target_domain, url
                       )
                       ''')
        cursor.execute('''
                       CREATE UNIQUE INDEX IF NOT EXISTS idx_directories_domain_url_unique
                       ON directories(target_domain, url)
                       ''')
        self.conn.commit()

    # --- 数据插入/更新 ---

    def insert_data(self, json_file_path, target_domain):
        if not os.path.exists(json_file_path):
            print(f"找不到 Subfinder 文件: {json_file_path}")
            return
        print(f"准备将 {target_domain} 的子域名入库...")
        cursor = self.conn.cursor()
        insert_count = 0
        with open(json_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    subdomain = data.get("host")
                    source = data.get("source", "unknown")
                    cursor.execute('''
                                   INSERT OR IGNORE INTO subdomains (target_domain, subdomain, source)
                                   VALUES (?, ?, ?)
                                   ''', (target_domain, subdomain, source))
                    if cursor.rowcount > 0:
                        insert_count += 1
                except:
                    continue
        self.conn.commit()
        if insert_count > 0:
            print(f"入库完毕，新增 {insert_count} 条资产。")

    def update_httpx_results(self, json_file_path, target_domain):
        if not os.path.exists(json_file_path): return
        print(f"正在将 Httpx 探测结果更新至数据库...")
        cursor = self.conn.cursor()
        update_count = 0
        with open(json_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())
                    subdomain = data.get("host", "") or (
                    data.get("url", "").replace("http://", "").replace("https://", "").split(":")[0])
                    if not subdomain: continue

                    tech_httpx = ",".join(data.get("tech", []))
                    alive_url = data.get("url", "")
                    cursor.execute('''
                                   UPDATE subdomains
                                   SET is_alive          = 1,
                                       alive_url         = ?,
                                       status_code       = ?,
                                       title             = ?,
                                       web_server        = ?,
                                       technologies_httpx= ?,
                                       technologies      = ?,
                                       is_cdn            = ?,
                                       cdn_name          = ?,
                                       ip_address        = ?,
                                       cname             = ?,
                                       favicon_hash      = ?,
                                       redirect_location = ?
                                   WHERE subdomain = ?
                                   ''', (alive_url, data.get("status_code"), data.get("title", ""), data.get("webserver", ""),
                                         tech_httpx, tech_httpx, data.get("cdn", False),
                                         data.get("cdn_name", ""),
                                         ",".join(data.get("a", [])), ",".join(data.get("cnames", [])),
                                         data.get("favicon", ""), data.get("location", ""), subdomain))
                    if cursor.rowcount > 0:
                        update_count += 1
                except Exception as e:
                    print(f"Httpx单条JSON解析失败: {e}, {line}")

        # 标记本次扫描中没有返回结果的为不存活
        cursor.execute('''
                       UPDATE subdomains
                       SET is_alive = 0
                       WHERE is_alive IS NULL
                         AND target_domain = ?
                       ''', (target_domain,))
        self.conn.commit()
        print(f"Httpx存活状态更新完成！本次确认存活资产: {update_count} 条。")

    def update_nmap_results(self, json_file_path, target_domain):
        if not os.path.exists(json_file_path): return
        with open(json_file_path, 'r', encoding='utf-8') as f:
            nmap_data = json.load(f)

        cursor = self.conn.cursor()
        update_count = 0
        scanned_ips = set()
        for item in nmap_data:
            ip = item.get("ip")
            if not ip: continue
            scanned_ips.add(ip)
            ports = item.get("ports", [])
            if not ports: continue
            port_str = ",".join([str(p['port']) for p in ports])
            cursor.execute('UPDATE subdomains SET ports = ? WHERE ip_address LIKE ? AND target_domain = ?',
                           (port_str, f"%{ip}%", target_domain))
            update_count += cursor.rowcount
        # 标记已扫描过的IP
        for ip in scanned_ips:
            cursor.execute('UPDATE subdomains SET is_nmap_scanned = 1 WHERE ip_address LIKE ? AND target_domain = ?',
                           (f"%{ip}%", target_domain))
        self.conn.commit()
        if update_count > 0:
            print(f"Nmap 端口信息更新完成，共影响 {update_count} 条记录。")

    def mark_urlfinder_scanned(self, export_path):
        if not os.path.exists(export_path): return
        cursor = self.conn.cursor()
        with open(export_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url: continue
                subdomain = url.replace("http://", "").replace("https://", "").split("/")[0]
                cursor.execute('UPDATE subdomains SET is_urlfinder_scanned = 1 WHERE subdomain = ?', (subdomain,))
        self.conn.commit()
        print(f"Urlfinder 任务状态标记完成。")

    def insert_ffuf_results(self, json_path, target_domain):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results = data.get("results", [])
            if not results: return

            cursor = self.conn.cursor()
            insert_count = 0
            # 从结果中推断出被扫描的基础URL，以标记状态
            scanned_url_base = results[0].get("input", {}).get("url", "").replace("/FUZZ", "")

            for item in results:
                cursor.execute('''
                               INSERT OR IGNORE INTO directories (target_domain, url, status_code, content_length)
                               VALUES (?, ?, ?, ?)
                               ''', (target_domain, item.get("url"), item.get("status"), item.get("length")))
                insert_count += 1

            # 标记该URL已完成FFUF扫描
            if scanned_url_base:
                subdomain = scanned_url_base.replace("http://", "").replace("https://", "").split("/")[0]
                cursor.execute("UPDATE subdomains SET is_ffuf_scanned = 1 WHERE subdomain = ?", (subdomain,))

            self.conn.commit()
            if insert_count > 0:
                print(f"FFUF 报告 {os.path.basename(json_path)} 入库，提取 {insert_count} 条有效目录。")
        except Exception as e:
            print(f"FFUF JSON ({os.path.basename(json_path)}) 解析或入库失败: {e}")

    def update_ehole_results(self, json_file_path, target_domain):
        if not os.path.exists(json_file_path):
            return 0

        try:
            with open(json_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
        except Exception as e:
            print(f"EHole 结果文件解析失败: {e}")
            return 0

        if not isinstance(data, list):
            print("EHole 结果为空或格式不匹配，跳过入库。")
            return 0

        cursor = self.conn.cursor()
        update_count = 0

        for item in data:
            if not isinstance(item, dict):
                continue

            target_value = item.get("url") or item.get("host") or item.get("domain") or item.get("ip") or ""
            subdomain = self.ehole_mapper.extract_subdomain(target_value)
            if not subdomain:
                continue

            ehole_techs = self.ehole_mapper.extract_ehole_technologies(item)
            if not ehole_techs:
                continue

            cursor.execute('''
                           SELECT technologies_httpx, technologies_ehole, technologies
                           FROM subdomains
                           WHERE target_domain = ?
                             AND subdomain = ?
                           ''', (target_domain, subdomain))
            row = cursor.fetchone()
            if not row:
                continue

            technologies_httpx = row[0] or ""
            old_ehole = row[1] or ""
            old_merged = row[2] or ""

            merged = self.ehole_mapper.merge_technologies(
                technologies_httpx,
                old_ehole,
                old_merged,
                ehole_techs
            )

            technologies_ehole = merged["technologies_ehole"]
            technologies_merged = merged["technologies"]

            cursor.execute('''
                           UPDATE subdomains
                           SET technologies_ehole = ?,
                               technologies = ?
                           WHERE target_domain = ?
                             AND subdomain = ?
                           ''', (technologies_ehole, technologies_merged, target_domain, subdomain))
            if cursor.rowcount > 0:
                update_count += 1

        self.conn.commit()
        print(f"EHole 指纹更新完成，共影响 {update_count} 条记录。")
        return update_count

    # --- ScanPlanner 只读快照 ---

    def get_assets_for_scan_planner(self, target_domain):
        cursor = self.conn.cursor()
        cursor.execute('''
                       SELECT subdomain,
                              alive_url,
                              is_alive,
                              is_urlfinder_scanned,
                              is_ffuf_scanned,
                              is_nmap_scanned,
                              ip_address,
                              actions,
                              asset_tier,
                              technologies,
                              web_server
                       FROM subdomains
                       WHERE target_domain = ?
                       ''', (target_domain,))
        rows = cursor.fetchall()
        assets = []
        for row in rows:
            assets.append({
                "subdomain": row[0],
                "alive_url": row[1] or "",
                "is_alive": row[2],
                "is_urlfinder_scanned": row[3],
                "is_ffuf_scanned": row[4],
                "is_nmap_scanned": row[5],
                "ip_address": row[6] or "",
                "actions": row[7] or "[]",
                "asset_tier": row[8] or "low",
                "technologies": row[9] or "",
                "web_server": row[10] or ""
            })
        return assets

    def get_assets_for_rule_eval(self, target_domain, stage="full"):
        cursor = self.conn.cursor()
        if stage == "httpx":
            cursor.execute('''
                           SELECT subdomain, technologies, status_code, title, COALESCE(ports, ''), is_cdn
                           FROM subdomains
                           WHERE target_domain = ?
                             AND is_alive = 1
                             AND (is_nmap_scanned = 0 OR COALESCE(ports, '') = '')
                           ''', (target_domain,))
        elif stage == "post_concurrent":
            cursor.execute('''
                           SELECT subdomain, technologies, status_code, title, COALESCE(ports, ''), is_cdn
                           FROM subdomains
                           WHERE target_domain = ?
                             AND is_alive = 1
                           ''', (target_domain,))
        else:
            cursor.execute('''
                           SELECT subdomain, technologies, status_code, title, COALESCE(ports, ''), is_cdn
                           FROM subdomains
                           WHERE target_domain = ?
                           ''', (target_domain,))

        rows = cursor.fetchall()
        assets = []
        for row in rows:
            assets.append({
                "subdomain": row[0],
                "technologies": row[1] or "",
                "status_code": row[2],
                "title": row[3] or "",
                "ports": row[4] or "",
                "is_cdn": row[5]
            })
        return assets

    def update_rule_results_batch(self, results, target_domain):
        if not results:
            return 0

        cursor = self.conn.cursor()
        update_count = 0
        for item in results:
            try:
                cursor.execute('''
                               UPDATE subdomains
                               SET asset_score = ?,
                                   asset_tier = ?,
                                   confidence = ?,
                                   tags = ?,
                                   actions = ?
                               WHERE target_domain = ?
                                 AND subdomain = ?
                               ''', (
                                   item.get("asset_score", 0),
                                   item.get("asset_tier", "low"),
                                   item.get("confidence", "low"),
                                   json.dumps(item.get("tags", []), ensure_ascii=False),
                                   json.dumps(item.get("actions", []), ensure_ascii=False),
                                   target_domain,
                                   item.get("subdomain", "")
                               ))
                if cursor.rowcount > 0:
                    update_count += 1
            except Exception as e:
                print(f"规则结果回写失败: {e}")

        self.conn.commit()
        print(f"规则引擎结果更新完成，共影响 {update_count} 条记录。")
        return update_count

    def close(self):
        self.conn.close()
