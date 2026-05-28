from singscan.modules.scan_orchestrator import ScanOrchestrator


# 包入口只负责接收目标并委派给 orchestration Module。
def main(target):
    """创建 orchestrator 并启动完整扫描流程。"""
    orchestrator = ScanOrchestrator(target, "assets.db")
    orchestrator.run()


if __name__ == "__main__":
    target = "cargosmart.com"
    main(target)
