#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cda-core JSON CLI。所有输出为单行 JSON（stdout），供 Cyrene-Agent 工具层解析。

用法：
    python cda_cli.py datasets
    python cda_cli.py detect   --dataset karate --algorithm louvain --seed 42
    python cda_cli.py attack   --dataset karate --budget 8 --generations 30 \
                               --pop-size 20 --guide degree --seed 42
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from typing import Dict, List, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cda_core as core  # noqa: E402


def _emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def _load(name: str):
    g, gt, desc = core.load_dataset(name)
    return g, gt, desc


def cmd_datasets(_args: argparse.Namespace) -> None:
    items = [
        {"name": "karate", "description": "Zachary Karate Club（34 节点 / 78 边，自带真实社区）"},
        {"name": "planted", "description": "Planted Partition 网络（90 节点 / 4 社区，自带真实社区）"},
        {"name": "gnp", "description": "随机分块网络（75 节点 / 4 社区）"},
        {"name": "<边表文件路径>", "description": "自定义网络：每行两个整数表示一条边，# 开头为注释"},
    ]
    _emit({"ok": True, "datasets": items})


def cmd_detect(args: argparse.Namespace) -> None:
    try:
        g, gt, desc = _load(args.dataset)
        comms = core.detect_communities(g, args.algorithm, args.seed)
        labels = core.to_labels(comms, g.number_of_nodes())
        out = {
            "ok": True,
            "dataset": args.dataset,
            "description": desc,
            "nodes": g.number_of_nodes(),
            "edges": g.number_of_edges(),
            "algorithm": args.algorithm,
            "seed": args.seed,
            "n_communities": len(comms),
            "modularity": round(core.modularity(g, comms), 6),
            "community_sizes": sorted((len(c) for c in comms), reverse=True),
            "communities": [sorted(c) for c in comms],
        }
        if gt is not None:
            gt_labels = [gt[n] for n in sorted(g.nodes())]
            out["ground_truth"] = True
            out["nmi_vs_ground_truth"] = round(core.nmi_score(gt_labels, labels), 6)
            out["ari_vs_ground_truth"] = round(core.ari_score(gt_labels, labels), 6)
        _emit(out)
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def cmd_attack(args: argparse.Namespace) -> None:
    try:
        g, gt, desc = _load(args.dataset)
        attack = core.EvolutionaryAttack(
            g,
            budget=args.budget,
            generations=args.generations,
            pop_size=args.pop_size,
            guide=args.guide,
            detect_algorithm=args.algorithm,
            seed=args.seed,
            ground_truth=gt,
        )
        result = attack.run()
        result["dataset"] = args.dataset
        result["dataset_description"] = desc
        result["interpretation"] = (
            f"在预算 β={result['budget']}（共 {result['budget']} 次边修改）约束下，"
            f"进化攻击将社区检测的 NMI 从 1.0 降至 {result['best_nmi']}"
            f"（下降 {result['nmi_reduction']}），ARI={result['best_ari']}；"
            f"NMI/ARI 越低，社区结构隐私保护效果越好。"
        )
        _emit(result)
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


# ---------------------------------------------------------------------------
# batch：批量扫参数实验（多种子统计 + 预算曲线 + 基线对比）
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "dataset", "budget", "method", "seed", "best_nmi", "nmi_reduction",
    "best_ari", "budget_efficiency", "gt_nmi_before", "gt_nmi_after",
    "gt_nmi_reduction", "runtime_s",
]


def _parse_int_list(raw: str) -> List[int]:
    return [int(x) for x in re.split(r"[,\s]+", raw.strip()) if x]


def _mean_std(values: Sequence[float]) -> Tuple[float, float]:
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mean = sum(values) / n
    if n < 2:
        return round(mean, 6), 0.0
    var = sum((v - mean) ** 2 for v in values) / (n - 1)  # 样本标准差
    return round(mean, 6), round(math.sqrt(var), 6)


def cmd_batch(args: argparse.Namespace) -> None:
    """批量实验：数据集 × 预算 × 随机种子 × 方法。

    输出：
      * stdout 单行 JSON 汇总（每组 nmi_reduction 的 mean±std、gt 退化、胜率）
      * --csv  逐次运行的原始记录（可直接导入 Excel / pandas）
      * --md   Markdown 汇总表（直接粘进报告）
    """
    import csv
    import time

    try:
        t_start = time.time()
        datasets = re.split(r"[,\s]+", args.datasets.strip())
        budgets = _parse_int_list(args.budgets)
        methods = re.split(r"[,\s]+", args.methods.strip())
        for m in methods:
            if m not in ("evolutionary", "random", "heuristic"):
                raise ValueError(f"未知方法: {m}（可选 evolutionary / random / heuristic）")

        rows: List[Dict] = []
        for ds in datasets:
            g, gt, _desc = _load(ds)
            for budget in budgets:
                for method in methods:
                    for seed in range(args.seed_base, args.seed_base + args.runs):
                        res = _run_one(g, gt, ds, budget, method, seed, args)
                        if not res.get("ok"):
                            continue
                        rows.append({
                            "dataset": ds,
                            "budget": budget,
                            "method": method,
                            "seed": seed,
                            "best_nmi": res["best_nmi"],
                            "nmi_reduction": res["nmi_reduction"],
                            "best_ari": res["best_ari"],
                            "budget_efficiency": res["budget_efficiency"],
                            "gt_nmi_before": res.get("gt_nmi_before", ""),
                            "gt_nmi_after": res.get("gt_nmi_after", ""),
                            "gt_nmi_reduction": res.get("gt_nmi_reduction", ""),
                            "runtime_s": res["runtime_s"],
                        })

        if args.csv:
            with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)

        summary = _summarize(rows, budgets, methods)
        if args.md:
            _write_markdown(args.md, rows, budgets, methods, datasets, args)

        out = {
            "ok": True,
            "datasets": datasets,
            "budgets": budgets,
            "methods": methods,
            "runs_per_group": args.runs,
            "total_runs": len(rows),
            "csv_path": args.csv or None,
            "markdown_path": args.md or None,
            "runtime_s": round(time.time() - t_start, 3),
            "groups": summary,
        }
        _emit(out)
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def _run_one(g, gt, ds: str, budget: int, method: str, seed: int,
             args: argparse.Namespace) -> Dict:
    if method == "random":
        return core.random_attack(g, budget, args.algorithm, seed, gt)
    if method == "heuristic":
        return core.heuristic_attack(g, budget, args.algorithm, seed, gt)
    attack = core.EvolutionaryAttack(
        g,
        budget=budget,
        generations=args.generations,
        pop_size=args.pop_size,
        guide=args.guide,
        detect_algorithm=args.algorithm,
        seed=seed,
        ground_truth=gt,
    )
    res = attack.run()
    res["dataset"] = ds
    return res


def _summarize(rows: List[Dict], budgets: List[int], methods: List[str]) -> List[Dict]:
    """按 (dataset, budget, method) 聚合 mean±std；evolutionary 额外算对基线的胜率。"""
    grouped: Dict[Tuple[str, int, str], List[Dict]] = {}
    for r in rows:
        grouped.setdefault((r["dataset"], r["budget"], r["method"]), []).append(r)

    out = []
    for (ds, budget, method), items in sorted(grouped.items(), key=lambda kv: kv[0]):
        red = [float(i["nmi_reduction"]) for i in items]
        mean, std = _mean_std(red)
        eff_mean, _ = _mean_std([float(i["budget_efficiency"]) for i in items])
        rt_mean, _ = _mean_std([float(i["runtime_s"]) for i in items])
        entry = {
            "dataset": ds,
            "budget": budget,
            "method": method,
            "runs": len(items),
            "nmi_reduction_mean": mean,
            "nmi_reduction_std": std,
            "budget_efficiency_mean": eff_mean,
            "runtime_s_mean": rt_mean,
        }
        gt_after = [float(i["gt_nmi_after"]) for i in items if i["gt_nmi_after"] != ""]
        if gt_after:
            gmean, gstd = _mean_std(gt_after)
            before = float(items[0]["gt_nmi_before"])
            entry["gt_nmi_before"] = round(before, 6)
            entry["gt_nmi_after_mean"] = gmean
            entry["gt_nmi_after_std"] = gstd
            entry["gt_nmi_reduction_mean"] = round(before - gmean, 6)

        if method == "evolutionary":
            for ref in ("random", "heuristic"):
                ref_items = grouped.get((ds, budget, ref))
                if not ref_items:
                    continue
                # 逐 seed 配对比较（seed 序列相同才能对齐）
                ref_map = {i["seed"]: float(i["nmi_reduction"]) for i in ref_items}
                pairs = [(v, ref_map[i["seed"]]) for i, v in
                         ((i, float(i["nmi_reduction"])) for i in items)
                         if i["seed"] in ref_map]
                if pairs:
                    wins = sum(1 for a, b in pairs if a > b)
                    entry[f"win_rate_vs_{ref}"] = round(wins / len(pairs), 4)
                    entry[f"avg_gain_vs_{ref}"] = round(
                        sum(a - b for a, b in pairs) / len(pairs), 6)
        out.append(entry)
    return out


def _write_markdown(path: str, rows: List[Dict], budgets: List[int],
                    methods: List[str], datasets: List[str],
                    args: argparse.Namespace) -> None:
    """生成 Markdown 汇总表（每张表一个预算配置行 x 方法列，值=mean±std）。"""
    grouped: Dict[Tuple[str, int, str], List[Dict]] = {}
    for r in rows:
        grouped.setdefault((r["dataset"], r["budget"], r["method"]), []).append(r)

    lines = [
        "# CDA 攻击实验汇总",
        "",
        f"- 数据集：{', '.join(datasets)}",
        f"- 攻击预算 β：{', '.join(str(b) for b in budgets)}",
        f"- 每组重复次数：{args.runs}",
        f"- 社区检测算法：{args.algorithm}；进化参数：{args.generations} 代 / "
        f"种群 {args.pop_size} / guide={args.guide}",
        "",
        "表中数值为 NMI 下降量（相对攻击前检测结果的 mean±std），越大越好。",
        "",
    ]
    for ds in datasets:
        lines += [f"## {ds}", ""]
        header = "| β | " + " | ".join(methods) + " |"
        lines += [header, "|" + "---|" * (len(methods) + 1)]
        for budget in budgets:
            cells = []
            for m in methods:
                items = grouped.get((ds, budget, m))
                if not items:
                    cells.append("—")
                    continue
                mean, std = _mean_std([float(i["nmi_reduction"]) for i in items])
                cells.append(f"{mean:.4f}±{std:.4f}")
            lines.append(f"| {budget} | " + " | ".join(cells) + " |")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(prog="cda_cli", description="社区检测攻击 CDA 核心 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("datasets", help="列出内置数据集")

    p_detect = sub.add_parser("detect", help="社区检测")
    p_detect.add_argument("--dataset", required=True, help="数据集名或边表文件路径")
    p_detect.add_argument("--algorithm", default="louvain", choices=["louvain", "greedy"])
    p_detect.add_argument("--seed", type=int, default=42)

    p_attack = sub.add_parser("attack", help="进化社区检测攻击")
    p_attack.add_argument("--dataset", required=True, help="数据集名或边表文件路径")
    p_attack.add_argument("--budget", type=int, default=8, help="攻击预算 β（边修改总数）")
    p_attack.add_argument("--generations", type=int, default=30, help="进化代数")
    p_attack.add_argument("--pop-size", type=int, default=20, help="种群规模")
    p_attack.add_argument("--guide", default="degree", choices=["degree", "random"],
                          help="变异引导：degree=边强度偏向（论文 CDA-CAGRL 简化）")
    p_attack.add_argument("--algorithm", default="louvain", choices=["louvain", "greedy"],
                          help="个体评估所用社区检测算法")
    p_attack.add_argument("--seed", type=int, default=42)

    p_batch = sub.add_parser("batch", help="批量扫参实验：多种子统计 + 预算曲线 + 基线对比")
    p_batch.add_argument("--datasets", default="karate",
                         help="逗号分隔的数据集列表，如 karate,planted,gnp")
    p_batch.add_argument("--budgets", default="2,5,8,12,20",
                         help="逗号分隔的攻击预算列表，如 2,5,8,12,20")
    p_batch.add_argument("--methods", default="evolutionary,random",
                         help="逗号分隔的方法：evolutionary/random/heuristic")
    p_batch.add_argument("--runs", type=int, default=20, help="每组重复次数（不同随机种子）")
    p_batch.add_argument("--seed-base", type=int, default=0, help="随机种子起始值，默认 0")
    p_batch.add_argument("--generations", type=int, default=30, help="进化代数")
    p_batch.add_argument("--pop-size", type=int, default=20, help="种群规模")
    p_batch.add_argument("--guide", default="degree", choices=["degree", "random"])
    p_batch.add_argument("--algorithm", default="louvain", choices=["louvain", "greedy"])
    p_batch.add_argument("--csv", help="原始逐次结果 CSV 输出路径")
    p_batch.add_argument("--md", help="Markdown 汇总表输出路径")

    args = parser.parse_args()
    if args.command == "datasets":
        cmd_datasets(args)
    elif args.command == "detect":
        cmd_detect(args)
    elif args.command == "attack":
        cmd_attack(args)
    elif args.command == "batch":
        cmd_batch(args)


if __name__ == "__main__":
    main()
