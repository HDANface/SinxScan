import os


# 负责把 ScanPlanner 产出的目标列表落成扫描器可消费的 txt 文件。
def write_target_file(file_path, targets):
    """将一组扫描目标写入指定文件，供命令行扫描器批量读取。"""
    if not targets:
        return None
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        for target in targets:
            f.write(target + "\n")
    return file_path


# 负责把分组后的扫描计划转换为多个目标文件，并补齐执行阶段需要的元数据。
def write_grouped_target_files(plan_items, save_dir, prefix):
    """将分组计划写成多个目标文件，并返回带 selector/report_suffix 的执行清单。"""
    if not plan_items:
        return []

    os.makedirs(save_dir, exist_ok=True)
    exports = []
    index = 1
    for item in plan_items:
        targets = item.get("targets", [])
        if not targets:
            continue

        file_path = os.path.join(save_dir, f"{prefix}_targets_{index}.txt")
        write_target_file(file_path, targets)
        exports.append({
            "selector": item.get("selector", ""),
            "targets": targets,
            "file_path": file_path,
            "report_suffix": f"{prefix}_{index}"
        })
        index += 1

    return exports
