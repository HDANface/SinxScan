from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from singscan.db_manager import DatabaseManager
from singscan.modules.afrog import UseAfrog
from singscan.modules.alive import UseHttpx
from singscan.modules.ehole import UseEhole
from singscan.modules.ffuf import UseFfuf
from singscan.modules.nuclei import UseNuclei
from singscan.modules.portscan import UseNmap
from singscan.modules.rule_engine import RuleEngine
from singscan.modules.scan_planner import ScanPlanner
from singscan.modules.subdomain import Subfinder
from singscan.modules.target_file_writer import write_grouped_target_files, write_target_file
from singscan.modules.urlfinder import UseUrlFinder


# 负责串联扫描阶段，并在 planner、adapter 与持久化层之间协调数据流转。
class ScanOrchestrator:
    """组织 SingScan 的完整扫描工作流。"""

    def __init__(self, target_domain, db_path="assets.db"):
        self.target_domain = target_domain
        self.db = DatabaseManager(db_path)
        self.planner = ScanPlanner()
        self.init = UseFfuf(target_domain)

    # 执行 Nmap 阶段：从 planner 获取待扫 IP，再把扫描结果回写数据库。
    def run_nmap_task(self):
        """获取未扫描的 IP，运行 Nmap，并更新数据库。"""
        print("--- [Nmap 任务启动] ---")
        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        unique_ips = self.planner.build_nmap_ips(assets)
        if not unique_ips:
            print("Nmap: 未发现需要扫描的新 IP 地址。")
            return "Nmap 已跳过"

        print(f"Nmap: 发现 {len(unique_ips)} 个新IP需要扫描。")
        nmap_scanner = UseNmap(self.target_domain)
        nmap_report = nmap_scanner.use(unique_ips)
        if nmap_report:
            self.db.update_nmap_results(nmap_report, self.target_domain)
        print("--- [Nmap 任务完成] ---")
        return "Nmap 已完成"

    # 执行 URLFinder 阶段：把 planner 选出的目标写入文件后交给 URLFinder 处理。
    def run_urlfinder_task(self):
        """获取未爬取的目标，运行 URLFinder，并更新数据库。"""
        print("--- [URLFinder 任务启动] ---")
        urlfinder = UseUrlFinder(self.target_domain)
        urlfinder_target_txt = os.path.join(urlfinder.save_dir, "urlfinder_targets.txt")

        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        export_path = write_target_file(urlfinder_target_txt, self.planner.build_urlfinder_targets(assets))
        if not export_path:
            print("URLFinder: 未发现需要爬取的新存活目标。")
            return "URLFinder 已跳过"

        print(f"URLFinder: 发现新目标，已导出至 {export_path}")
        urlfinder_report_dir = urlfinder.use(export_path)
        if urlfinder_report_dir:
            print("URLFinder: 资产爬取完毕，更新数据库状态。")
            self.db.mark_urlfinder_scanned(export_path)

        if os.path.exists(export_path):
            os.remove(export_path)

        print("--- [URLFinder 任务完成] ---")
        return "URLFinder 已完成"

    # 执行 EHole 阶段：用 planner 产出的目标列表做指纹识别并回写识别结果。
    def run_ehole_task(self):
        """获取存活目标，运行 EHole 并将指纹入库。"""
        print("--- [EHole 任务启动] ---")
        ehole = UseEhole(self.target_domain)
        ehole_target_txt = os.path.join(ehole.save_dir, "ehole_targets.txt")

        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        export_path = write_target_file(
            ehole_target_txt,
            self.planner.build_ehole_targets(assets, fallback_target_domain=self.target_domain)
        )
        if not export_path:
            print("EHole: 未发现可识别指纹的存活目标。")
            return "EHole 已跳过"

        ehole_report = ehole.use(export_path)
        if ehole_report:
            self.db.update_ehole_results(ehole_report, self.target_domain)

        if os.path.exists(export_path):
            os.remove(export_path)

        print("--- [EHole 任务完成] ---")
        return "EHole 已完成"

    def run_ffuf_task(self, ffuf_scanner, url):
        """在单个 URL 上运行 FFUF 并将结果入库。"""
        report_path = ffuf_scanner.use(url)
        if report_path:
            self.db.insert_ffuf_results(report_path, self.target_domain)
        return f"FFUF on {url} 已完成"

    # 执行 Nuclei 阶段：消费 planner 的分组计划，并负责把计划转换成扫描器输入文件。
    def run_nuclei_task(self):
        """按 planner 生成的分组计划执行 Nuclei 漏洞验证。"""
        print("--- [Nuclei 任务启动] ---")
        nuclei = UseNuclei(self.target_domain)

        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        plan_items = self.planner.build_nuclei_plan(assets)
        if not plan_items:
            print("Nuclei: 未发现符合规则的目标，跳过。")
            return "Nuclei 已跳过"

        exports = write_grouped_target_files(plan_items, nuclei.save_dir, "nuclei")
        if not exports:
            print("Nuclei: 目标分组导出为空，跳过。")
            return "Nuclei 已跳过"

        success_count = 0
        for item in exports:
            report = nuclei.use(item["file_path"], tags=item.get("selector"), report_suffix=item.get("report_suffix"))
            if report:
                success_count += 1
            if os.path.exists(item["file_path"]):
                os.remove(item["file_path"])

        if success_count > 0:
            return f"Nuclei 已完成({success_count}/{len(exports)})"
        return "Nuclei 执行失败"

    # 执行 Afrog 阶段：消费 planner 的分组计划，并负责把计划转换成扫描器输入文件。
    def run_afrog_task(self):
        """按 planner 生成的分组计划执行 Afrog 漏洞验证。"""
        print("--- [Afrog 任务启动] ---")
        afrog = UseAfrog(self.target_domain)

        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        plan_items = self.planner.build_afrog_plan(assets)
        if not plan_items:
            print("Afrog: 未发现符合规则的目标，跳过。")
            return "Afrog 已跳过"

        exports = write_grouped_target_files(plan_items, afrog.save_dir, "afrog")
        if not exports:
            print("Afrog: 目标分组导出为空，跳过。")
            return "Afrog 已跳过"

        success_count = 0
        for item in exports:
            report = afrog.use(item["file_path"], search=item.get("selector"), report_suffix=item.get("report_suffix"))
            if report:
                success_count += 1
            if os.path.exists(item["file_path"]):
                os.remove(item["file_path"])

        if success_count > 0:
            return f"Afrog 已完成({success_count}/{len(exports)})"
        return "Afrog 执行失败"

    # 规则引擎阶段只关心资产评分与动作建议，不参与扫描计划文件的生成。
    def run_rule_engine_stage(self, stage):
        """运行指定阶段的 RuleEngine 评估并批量回写评分结果。"""
        print(f"--- [RuleEngine 任务启动: {stage}] ---")
        assets = self.db.get_assets_for_rule_eval(self.target_domain, stage)
        if not assets:
            print("RuleEngine: 未发现可评估资产，跳过。")
            return 0

        engine = RuleEngine()
        results = engine.evaluate_assets(assets, stage=stage)
        update_count = self.db.update_rule_results_batch(results, self.target_domain)

        print(f"--- [RuleEngine 任务完成: {stage}] 更新 {update_count} 条 ---")
        return update_count

    # 主流程负责串联各扫描阶段，并在 planner 与具体扫描器之间承担 adapter 角色。
    def run(self):
        """串联 SingScan 的完整扫描流程。"""
        print(f"====== 扫描器启动: {self.target_domain} ======")
        print(f"结果将保存在: {self.init.save_dir}")

        print("\n[阶段 1] 开始进行子域名收集")
        scanner = Subfinder(self.target_domain)
        sub_report = scanner.use()
        if sub_report:
            self.db.insert_data(sub_report, self.target_domain)
        else:
            print("Subfinder: 未发现新资产，或扫描失败。")

        print("\n[阶段 2] 开始进行存活探测")
        temp_target_txt = os.path.join(self.init.save_dir, "httpx_targets.txt")

        assets = self.db.get_assets_for_scan_planner(self.target_domain)
        targets_for_httpx_file = write_target_file(temp_target_txt, self.planner.build_httpx_targets(assets))

        if targets_for_httpx_file:
            httpx_scanner = UseHttpx(self.target_domain)
            httpx_report = httpx_scanner.use(targets_for_httpx_file)
            if httpx_report:
                self.db.update_httpx_results(httpx_report, self.target_domain)
                self.run_ehole_task()
                self.run_rule_engine_stage(stage="httpx")
            if os.path.exists(targets_for_httpx_file):
                os.remove(targets_for_httpx_file)
        else:
            print("Httpx: 所有已知子域名均已探测过存活状态，跳过。")

        print("\n[阶段 3] 开始并发执行深度扫描")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            futures.append(executor.submit(self.run_nmap_task))
            futures.append(executor.submit(self.run_urlfinder_task))

            # urls_to_ffuf = self.planner.build_ffuf_targets(self.db.get_assets_for_scan_planner(self.target_domain))
            # if urls_to_ffuf:
            #     print(f"FFUF: 发现 {len(urls_to_ffuf)} 个新存活URL需要进行目录扫描。")
            #     ffuf_scanner = UseFfuf(self.target_domain)
            #     for url in urls_to_ffuf:
            #         futures.append(executor.submit(self.run_ffuf_task, ffuf_scanner, url))
            # else:
            #     print("FFUF: 未发现需要进行目录扫描的新存活URL。")

            print(f"\n已提交 {len(futures)} 个并发任务，等待执行结果...")
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"一个并发任务在执行时发生异常: {exc}")

        self.run_rule_engine_stage(stage="post_concurrent")

        print("\n[阶段 4] 开始规则驱动漏洞验证")
        with ThreadPoolExecutor(max_workers=2) as executor:
            stage4_futures = [
                executor.submit(self.run_nuclei_task),
                executor.submit(self.run_afrog_task)
            ]
            for future in as_completed(stage4_futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"阶段4并发任务执行异常: {exc}")

        print(f"\n====== 描器运行完毕: {self.target_domain} ======")
        self.db.close()
