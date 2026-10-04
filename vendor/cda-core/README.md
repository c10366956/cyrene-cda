# cda-core — 社区检测攻击（CDA）核心算法包

面向 Cyrene-Agent「大模型 + 社区检测攻击」方向的 Python 算法内核，
算法思路参考刘夫武硕士论文《面向复杂网络社区检测攻击的进化算法研究》
（CDA-CAGRL / CDA-MOEA 的简化单文件重写版）。

## 依赖

```
pip install networkx
```

（NMI / ARI 为纯 Python 实现，不依赖 sklearn / numpy。）

## CLI

```bash
# 列出内置数据集
python cda_cli.py datasets

# 社区检测
python cda_cli.py detect --dataset karate --algorithm louvain --seed 42

# 进化攻击（预算 β=8 条边改动，30 代，种群 20）
python cda_cli.py attack --dataset karate --budget 8 --generations 30 --pop-size 20 --guide degree --seed 42

# 批量扫参实验：2 数据集 × 5 预算 × 3 方法 × 20 个随机种子
python cda_cli.py batch \
  --datasets karate,planted \
  --budgets 2,5,8,12,20 \
  --methods evolutionary,random,heuristic \
  --runs 20 --generations 30 --pop-size 20 \
  --csv results/cda_batch_results.csv \
  --md  results/cda_batch_summary.md

# 从边表文件加载（每行 "u v"）
python cda_cli.py detect --dataset path/to/edges.txt
```

所有命令输出单行 JSON，`ok: true/false` 表示成败。

实测攻击效果（budget=15, 25 代, 种群 16）：
karate NMI 1.0→0.43、planted 1.0→0.78、gnp 1.0→0.35。

## 子命令

| 命令 | 参数 | 说明 |
|---|---|---|
| `datasets` | — | 列出内置数据集（karate / lfr / gnp） |
| `detect` | `--dataset`, `--algorithm`(louvain/greedy), `--seed` | 社区检测：返回分区、模块度 Q、规模 |
| `attack` | `--dataset`, `--budget`, `--generations`, `--pop-size`, `--guide`(degree/random), `--seed`, `--algorithm` | 进化攻击：预算约束下加/删边使 NMI 最小化 |
| `batch` | `--datasets`, `--budgets`, `--methods`, `--runs`, `--seed-base`, `--generations`, `--pop-size`, `--guide`, `--algorithm`, `--csv`, `--md` | 批量实验：多种子 mean±std、预算曲线、进化 vs 基线胜率 |

## 三种方法（batch 的 --methods）

| 方法 | 说明 |
|---|---|
| `evolutionary` | 本文算法：进化搜索（锦标赛选择 + 边集交叉 + 边强度偏向变异） |
| `random` | 基线 1：随机挑 β 条边改动，证明搜索确实有价值 |
| `heuristic` | 基线 2：贪心固定策略（删最强社区内部边 + 加最低相似度跨社区边），无搜索 |

## batch 输出

- stdout：单行 JSON，`groups[]` 每项含 `nmi_reduction_mean/std`、`gt_nmi_after_mean/std`、
  `budget_efficiency_mean`、`runtime_s_mean`；`evolutionary` 额外给出 `win_rate_vs_random`、
  `win_rate_vs_heuristic`（逐种子配对比较）与 `avg_gain_vs_*`
- `--csv`：逐次运行原始记录（dataset, budget, method, seed, best_nmi, nmi_reduction, best_ari,
  budget_efficiency, gt_nmi_before, gt_nmi_after, gt_nmi_reduction, runtime_s），UTF-8-BOM 可直接用 Excel 打开
- `--md`：Markdown 汇总表，每个数据集一张「β × 方法」的 mean±std 表，可直接粘进报告

## attack 输出字段

### 两套评估基准（不可混用）

| 字段 | 对比对象 | 含义 |
|---|---|---|
| `baseline_nmi`(恒 1.0) / `best_nmi` / `nmi_reduction` | 攻击**前**的检测结果 | 结构扰动强度 |
| `gt_nmi_before` / `gt_nmi_after` / `gt_nmi_reduction` | 数据集**自带真实社区** | 检测质量退化（`has_ground_truth: true` 时才有） |

- `best_nmi`：攻击后 NMI（越低攻击效果越好）
- `nmi_reduction`：下降幅度
- `budget_efficiency`：`nmi_reduction / β`，单位预算的攻击性价比
- `added_edges` / `removed_edges`：对抗网络的边修改方案
- `history`：每代最优 NMI 曲线（仅 `attack`，`batch` 不返回）
