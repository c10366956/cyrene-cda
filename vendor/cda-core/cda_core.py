#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cda-core: 社区检测攻击（Community Detection Attack, CDA）核心算法包。

算法思路参考刘夫武硕士论文《面向复杂网络社区检测攻击的进化算法研究》：
- 攻击建模：预算 β 约束下对网络加/删边得到对抗网络 G'，使社区检测算法
  在 G' 上的社区结构与原结构差异最大化（NMI/ARI 越低攻击效果越好）。
- 论文挑战1（个体评估昂贵）的简化应对：支持 fast 模式用贪心模块度替代
  Louvain 做个体评估。
- 论文挑战2（搜索空间组合爆炸）的简化应对：基于边强度的偏向变异
  （CDA-CAGRL 中"节点嵌入相似性 → 基因强度"思想的 common-neighbor
  相似度简化版）。

对外提供 JSON CLI（见 cda_cli.py），本模块只承载纯算法。
"""

from __future__ import annotations

import math
import random
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:
    import networkx as nx
except ImportError as _e:  # pragma: no cover
    raise SystemExit(
        "[cda-core] 缺少依赖 networkx，请先安装：pip install networkx"
    ) from _e

Edge = Tuple[int, int]

# ---------------------------------------------------------------------------
# 数据集
# ---------------------------------------------------------------------------

BUILTIN_DATASETS = ("karate", "lfr", "gnp")


def _norm_edge(u: int, v: int) -> Edge:
    return (u, v) if u <= v else (v, u)


def load_dataset(name: str) -> Tuple[nx.Graph, Dict[int, int] | None, str]:
    """加载数据集。返回 (图, 真实社区标签 ground_truth 或 None, 描述)。

    ground_truth: 节点 -> 社区编号；基准数据集自带，边表文件为 None。
    """
    if name == "karate":
        g = nx.karate_club_graph()
        gt = {n: (1 if g.nodes[n]["club"] == "Mr. Hi" else 0) for n in g.nodes}
        return g, gt, "Zachary Karate Club (34 节点 / 78 边, 自带真实社区)"

    if name == "planted":
        # planted partition 网络：社区内部连接强、社区之间稀疏，带真实社区标签。
        # 相比 LFR 基准，参数可控、生成无挂起风险。
        g = nx.random_partition_graph([30, 25, 20, 15], 0.35, 0.05, seed=42)
        gt = {}
        for i, block in enumerate(g.graph["partition"]):
            for n in block:
                gt[n] = i
        return nx.Graph(g), gt, "Planted Partition 网络 (90 节点 / 4 社区, p_in=0.35 / p_out=0.05)"

    if name == "gnp":
        sizes = [20, 20, 20, 15]
        p_in, p_out = 0.35, 0.08
        g = nx.random_partition_graph(sizes, p_in, p_out, seed=42)
        gt = {}
        for i, block in enumerate(g.graph["partition"]):
            for n in block:
                gt[n] = i
        return nx.Graph(g), gt, "随机分块网络 (75 节点, 4 社区, p_in=0.35 / p_out=0.08)"

    # 文件路径：每行 "u v"（# 开头为注释）
    edges: List[Edge] = []
    with open(name, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace(",", " ").split()
            if len(parts) < 2:
                continue
            edges.append((int(parts[0]), int(parts[1])))
    if not edges:
        raise ValueError(f"边表文件 {name} 中没有可解析的边")
    g = nx.Graph()
    g.add_edges_from(edges)
    g = nx.convert_node_labels_to_integers(g)
    return g, None, f"边表文件 ({g.number_of_nodes()} 节点 / {g.number_of_edges()} 边)"


# ---------------------------------------------------------------------------
# 社区检测
# ---------------------------------------------------------------------------

def detect_communities(g: nx.Graph, algorithm: str = "louvain",
                       seed: int = 42) -> List[Set[int]]:
    """社区检测。louvain = 论文中的 AD；greedy = 贪心模块度（fast 模式）。"""
    if algorithm == "greedy":
        return [set(c) for c in nx.community.greedy_modularity_communities(g)]
    if algorithm == "louvain":
        return [set(c) for c in nx.community.louvain_communities(g, seed=seed)]
    raise ValueError(f"未知社区检测算法: {algorithm}")


def to_labels(communities: Sequence[Set[int]], n_nodes: int) -> List[int]:
    labels = [-1] * n_nodes
    for cid, com in enumerate(communities):
        for n in com:
            labels[n] = cid
    return labels


def modularity(g: nx.Graph, communities: Sequence[Set[int]]) -> float:
    return float(nx.community.modularity(g, communities))


# ---------------------------------------------------------------------------
# NMI / ARI（纯 Python 实现，与 sklearn 默认口径一致）
# ---------------------------------------------------------------------------

def _contingency(a: Sequence[int], b: Sequence[int]) -> Tuple[List[List[int]], List[int], List[int]]:
    ka, kb = max(a) + 1, max(b) + 1
    m = [[0] * kb for _ in range(ka)]
    ca = [0] * ka
    cb = [0] * kb
    for x, y in zip(a, b):
        m[x][y] += 1
        ca[x] += 1
        cb[y] += 1
    return m, ca, cb


def nmi_score(a: Sequence[int], b: Sequence[int]) -> float:
    """标准化互信息（算术平均归一化，log 以 e 为底）。"""
    n = len(a)
    if n == 0:
        return 1.0
    m, ca, cb = _contingency(a, b)
    ka, kb = len(ca), len(cb)
    mi = 0.0
    for i in range(ka):
        for j in range(kb):
            if m[i][j] == 0:
                continue
            pij = m[i][j] / n
            pi = ca[i] / n
            pj = cb[j] / n
            mi += pij * math.log(pij / (pi * pj))
    ha = -sum((c / n) * math.log(c / n) for c in ca if c > 0)
    hb = -sum((c / n) * math.log(c / n) for c in cb if c > 0)
    denom = (ha + hb) / 2
    if denom <= 0:
        return 1.0
    return float(mi / denom)


def ari_score(a: Sequence[int], b: Sequence[int]) -> float:
    """调整兰德指数。"""
    n = len(a)
    m, ca, cb = _contingency(a, b)
    sum_comb_c = sum(c * (c - 1) // 2 for row in m for c in row)
    sum_comb_a = sum(c * (c - 1) // 2 for c in ca)
    sum_comb_b = sum(c * (c - 1) // 2 for c in cb)
    total = n * (n - 1) // 2
    if total == 0:
        return 1.0
    expected = sum_comb_a * sum_comb_b / total
    max_index = (sum_comb_a + sum_comb_b) / 2
    if max_index == expected:
        return 1.0
    return float((sum_comb_c - expected) / (max_index - expected))


# ---------------------------------------------------------------------------
# 进化攻击
# ---------------------------------------------------------------------------

def _edge_strength(g: nx.Graph, u: int, v: int) -> float:
    """边强度 = 端点 common-neighbor 相似度（CDA-CAGRL 基因强度思想的简化）。"""
    cn = len(set(g.neighbors(u)) & set(g.neighbors(v)))
    return 1.0 + cn


def evaluate_modification(g: nx.Graph, add: Sequence[Edge], remove: Sequence[Edge],
                          detect_algorithm: str = "louvain", seed: int = 42,
                          ground_truth: Optional[Dict[int, int]] = None) -> Dict:
    """给定一组边改动，评估其对社区检测的影响（两套基准）。

    ref 分区 = 改动前的检测结果；gt = 数据集自带真实社区（可为 None）。
    """
    import time
    t0 = time.time()
    n_nodes = g.number_of_nodes()
    ref_labels = to_labels(detect_communities(g, detect_algorithm, seed), n_nodes)
    g2 = _apply_edges(g, add, remove)
    labels = to_labels(detect_communities(g2, detect_algorithm, seed), n_nodes)

    best_nmi = nmi_score(ref_labels, labels)
    reduction = 1.0 - best_nmi
    out: Dict = {
        "ok": True,
        "dataset_nodes": n_nodes,
        "dataset_edges": g.number_of_edges(),
        "budget": len(add) + len(remove),
        "baseline_nmi": 1.0,
        "baseline_ari": 1.0,
        "best_nmi": round(best_nmi, 6),
        "best_ari": round(ari_score(ref_labels, labels), 6),
        "nmi_reduction": round(reduction, 6),
        "budget_efficiency": round(reduction / max(1, len(add) + len(remove)), 6),
        "added_edges": [list(e) for e in add],
        "removed_edges": [list(e) for e in remove],
        "runtime_s": round(time.time() - t0, 3),
    }
    _attach_gt(out, ground_truth, n_nodes, ref_labels, labels)
    return out


def _attach_gt(out: Dict, ground_truth: Optional[Dict[int, int]], n_nodes: int,
               ref_labels: Sequence[int], labels: Sequence[int]) -> None:
    """把「对比真实社区」的指标挂到结果字典上。"""
    gt_labels = None
    if ground_truth:
        try:
            gt_labels = [ground_truth[i] for i in range(n_nodes)]
        except KeyError:
            gt_labels = None
    if gt_labels is None:
        out["has_ground_truth"] = False
        return
    before = nmi_score(gt_labels, ref_labels)
    after = nmi_score(gt_labels, labels)
    out["has_ground_truth"] = True
    out["gt_nmi_before"] = round(before, 6)
    out["gt_nmi_after"] = round(after, 6)
    out["gt_nmi_reduction"] = round(before - after, 6)
    out["gt_ari_before"] = round(ari_score(gt_labels, ref_labels), 6)
    out["gt_ari_after"] = round(ari_score(gt_labels, labels), 6)


def random_attack(g: nx.Graph, budget: int = 8, detect_algorithm: str = "louvain",
                  seed: int = 42, ground_truth: Optional[Dict[int, int]] = None) -> Dict:
    """基线 1：随机攻击。随机挑 β 条改动（加/删混合），不做任何优化。

    用于证明进化搜索确实优于瞎改。
    """
    rng = random.Random(seed)
    nodes = sorted(g.nodes())
    edges = [_norm_edge(u, v) for u, v in g.edges()]
    edge_set = set(edges)
    non_edges = [
        _norm_edge(nodes[i], nodes[j])
        for i in range(len(nodes))
        for j in range(i + 1, len(nodes))
        if _norm_edge(nodes[i], nodes[j]) not in edge_set
    ]

    n_remove = rng.randint(0, budget)
    n_add = budget - n_remove
    n_remove = min(n_remove, len(edges))
    n_add = min(n_add, len(non_edges))
    if n_add + n_remove < budget:  # 候选池不够时尽量补满
        n_remove = min(len(edges), budget - n_add)

    remove = rng.sample(edges, n_remove) if n_remove else []
    add = rng.sample(non_edges, n_add) if n_add else []

    out = evaluate_modification(g, add, remove, detect_algorithm, seed, ground_truth)
    out["generations"] = 0
    out["pop_size"] = 0
    out["guide"] = "none"
    return out


def heuristic_attack(g: nx.Graph, budget: int = 8, detect_algorithm: str = "louvain",
                     seed: int = 42, ground_truth: Optional[Dict[int, int]] = None) -> Dict:
    """基线 2：贪心启发式攻击。按边强度降序删边 + 补低相似度跨社区边（无搜索）。

    代表"人工可设计的固定策略"，用于对照进化搜索的增益。
    """
    rng = random.Random(seed)
    nodes = sorted(g.nodes())
    edges = [_norm_edge(u, v) for u, v in g.edges()]
    edge_set = set(edges)
    non_edges = [
        _norm_edge(nodes[i], nodes[j])
        for i in range(len(nodes))
        for j in range(i + 1, len(nodes))
        if _norm_edge(nodes[i], nodes[j]) not in edge_set
    ]

    # 删：边强度（common neighbors）最高的预算条边 —— 最"结实"的社区内部边
    ranked_rm = sorted(edges, key=lambda e: -_edge_strength(g, e[0], e[1]))
    n_remove = min(budget, len(ranked_rm))
    n_add = budget - n_remove
    remove = ranked_rm[:n_remove]

    # 加：相似度最低的跨社区边
    ranked_add = sorted(non_edges, key=lambda e: _edge_strength(g, e[0], e[1]))
    add = ranked_add[: min(n_add, len(ranked_add))]

    out = evaluate_modification(g, add, remove, detect_algorithm, seed, ground_truth)
    out["generations"] = 0
    out["pop_size"] = 0
    out["guide"] = "heuristic"
    return out


def _apply_edges(g: nx.Graph, add: Sequence[Edge], remove: Sequence[Edge]) -> nx.Graph:
    h = g.copy()
    h.remove_edges_from(remove)
    h.add_edges_from(add)
    return h


class EvolutionaryAttack:
    """预算约束的社区检测攻击进化算法（全局攻击，单目标简化版）。

    个体 = (E+, E-)，|E+| + |E-| = β。
    适应度 = NMI(原网络分区, 对抗网络分区)，越小越优。
    """

    def __init__(self, g: nx.Graph, budget: int = 8, generations: int = 30,
                 pop_size: int = 20, guide: str = "degree",
                 detect_algorithm: str = "louvain", seed: int = 42,
                 ground_truth: Optional[Dict[int, int]] = None):
        if budget < 1:
            raise ValueError("budget 必须 >= 1")
        if pop_size < 4:
            raise ValueError("pop_size 必须 >= 4")
        self.g = g
        self.budget = min(budget, g.number_of_edges())  # 删边不能超过边数
        self.generations = generations
        self.pop_size = pop_size
        self.guide = guide
        self.detect_algorithm = detect_algorithm
        self.rng = random.Random(seed)
        self.seed = seed

        self.n_nodes = g.number_of_nodes()
        self.nodes = sorted(g.nodes())
        self.edges = [_norm_edge(u, v) for u, v in g.edges()]
        self.edge_set = set(self.edges)

        # 非边候选池（加边用），限制规模避免组合爆炸
        all_pairs = [
            _norm_edge(self.nodes[i], self.nodes[j])
            for i in range(self.n_nodes)
            for j in range(i + 1, self.n_nodes)
        ]
        self.non_edges = [e for e in all_pairs if e not in self.edge_set]

        # 参考分区：攻击前社区检测结果（固定的攻击目标）
        self.ref_communities = detect_communities(g, detect_algorithm, seed)
        self.ref_labels = to_labels(self.ref_communities, self.n_nodes)

        # 真实社区标签（数据集自带时才有）：用于第二套评估基准
        self.gt_raw = ground_truth

        # 边强度权重（guide=degree 时用于偏向变异）
        self._remove_weights = self._build_remove_weights()
        self._add_weights = self._build_add_weights()

    # ----- 权重 -----

    def _build_remove_weights(self) -> Dict[Edge, float]:
        if self.guide == "random":
            return {e: 1.0 for e in self.edges}
        # 偏向删除高强度边（社区内部边）：删掉后社区结构更模糊
        return {e: _edge_strength(self.g, e[0], e[1]) for e in self.edges}

    def _build_add_weights(self) -> Dict[Edge, float]:
        if self.guide == "random":
            return {e: 1.0 for e in self.non_edges[:5000]}
        # 偏向添加低相似度（跨社区）边
        return {
            e: 1.0 / _edge_strength(self.g, e[0], e[1]) for e in self.non_edges[:5000]
        }

    def _weighted_choice(self, weights: Dict[Edge, float], k: int,
                         exclude: Set[Edge]) -> List[Edge]:
        items = [e for e in weights if e not in exclude]
        if not items:
            return []
        ws = [weights[e] for e in items]
        chosen: List[Edge] = []
        pool = list(items)
        pool_w = list(ws)
        for _ in range(min(k, len(pool))):
            total = sum(pool_w)
            r = self.rng.random() * total
            acc = 0.0
            for idx, w in enumerate(pool_w):
                acc += w
                if acc >= r:
                    chosen.append(pool[idx])
                    pool.pop(idx)
                    pool_w.pop(idx)
                    break
        return chosen

    # ----- 个体操作 -----

    def random_individual(self) -> Tuple[List[Edge], List[Edge]]:
        n_add = self.rng.randint(0, self.budget)
        n_remove = self.budget - n_add
        add = self._weighted_choice(self._add_weights, n_add, set())
        remove = self._weighted_choice(self._remove_weights, n_remove, set())
        return add, remove

    def fitness(self, ind: Tuple[List[Edge], List[Edge]]) -> float:
        g2 = _apply_edges(self.g, ind[0], ind[1])
        comms = detect_communities(g2, self.detect_algorithm, self.seed)
        labels = to_labels(comms, self.n_nodes)
        return 1.0 - nmi_score(self.ref_labels, labels)  # 攻击增益，越大越好

    def crossover(self, p1: Tuple[List[Edge], List[Edge]],
                  p2: Tuple[List[Edge], List[Edge]]) -> Tuple[List[Edge], List[Edge]]:
        a1, r1 = p1
        a2, r2 = p2
        add = list(dict.fromkeys(a1 + a2))[: self.budget]
        remove = list(dict.fromkeys(r1 + r2))[: self.budget]
        # 保持总量 = budget：不够则随机补
        need = self.budget - len(add) - len(remove)
        if need > 0:
            used_add = set(add)
            used_rm = set(remove)
            for _ in range(need):
                if self.rng.random() < 0.5 and self._add_weights:
                    add += self._weighted_choice(self._add_weights, 1, used_add)
                    used_add = set(add)
                else:
                    remove += self._weighted_choice(self._remove_weights, 1, used_rm)
                    used_rm = set(remove)
        return add, remove

    def mutate(self, ind: Tuple[List[Edge], List[Edge]],
               rate: float = 0.3) -> Tuple[List[Edge], List[Edge]]:
        add, remove = ind
        if self.rng.random() > rate:
            return add, remove
        new_ind = [list(add), list(remove)]
        op = self.rng.random()
        if op < 0.5 and new_ind[1]:  # 换一条删的边
            used = set(new_ind[0]) | set(new_ind[1])
            new_ind[1].pop(self.rng.randrange(len(new_ind[1])))
            new_ind[1] += self._weighted_choice(self._remove_weights, 1, used)
        else:  # 换一条加的边
            used = set(new_ind[0]) | set(new_ind[1])
            if new_ind[0]:
                new_ind[0].pop(self.rng.randrange(len(new_ind[0])))
            new_ind[0] += self._weighted_choice(self._add_weights, 1, used)
        # 预算合法性
        total = len(new_ind[0]) + len(new_ind[1])
        if total > self.budget:
            while len(new_ind[0]) + len(new_ind[1]) > self.budget:
                if new_ind[0] and (not new_ind[1] or self.rng.random() < 0.5):
                    new_ind[0].pop()
                else:
                    new_ind[1].pop()
        return new_ind

    def repair(self, ind: Tuple[List[Edge], List[Edge]]) -> Tuple[List[Edge], List[Edge]]:
        """修复非法个体：加边必须是非边，删边必须是已有边，总量 = budget。"""
        add: List[Edge] = []
        seen: Set[Edge] = set()
        for e in ind[0]:
            if e not in self.edge_set and e not in seen:
                add.append(e)
                seen.add(e)
        remove: List[Edge] = []
        seen_rm: Set[Edge] = set()
        for e in ind[1]:
            e_n = _norm_edge(*e)
            if e_n in self.edge_set and e_n not in seen and e_n not in seen_rm:
                remove.append(e_n)
                seen_rm.add(e_n)
        total = len(add) + len(remove)
        if total > self.budget:
            while len(add) + len(remove) > self.budget:
                if add and (not remove or self.rng.random() < 0.5):
                    add.pop()
                else:
                    remove.pop()
        else:
            need = self.budget - total
            for _ in range(need):
                if self.rng.random() < 0.5:
                    add += self._weighted_choice(self._add_weights, 1, set(add))
                else:
                    remove += self._weighted_choice(self._remove_weights, 1, set(remove))
        return add, remove

    # ----- 主循环 -----

    def run(self) -> Dict:
        import time
        t0 = time.time()
        pop = [self.random_individual() for _ in range(self.pop_size)]
        pop = [self.repair(p) for p in pop]
        scores = [self.fitness(p) for p in pop]
        history = [1.0 - max(scores)]
        best_idx = max(range(len(pop)), key=lambda i: scores[i])
        best, best_score = pop[best_idx], scores[best_idx]

        for _ in range(self.generations):
            new_pop: List[Tuple[List[Edge], List[Edge]]] = [best]  # 精英保留
            while len(new_pop) < self.pop_size:
                cands = self.rng.sample(range(len(pop)), min(3, len(pop)))
                p1 = pop[max(cands, key=lambda i: scores[i])]
                cands = self.rng.sample(range(len(pop)), min(3, len(pop)))
                p2 = pop[max(cands, key=lambda i: scores[i])]
                child = self.crossover(p1, p2)
                child = self.mutate(child)
                child = self.repair(child)
                new_pop.append(child)
            pop = new_pop
            scores = [self.fitness(p) for p in pop]
            gen_best_idx = max(range(len(pop)), key=lambda i: scores[i])
            if scores[gen_best_idx] > best_score:
                best, best_score = pop[gen_best_idx], scores[gen_best_idx]
            history.append(1.0 - max(scores))

        g2 = _apply_edges(self.g, best[0], best[1])
        atk_comms = detect_communities(g2, self.detect_algorithm, self.seed)
        atk_labels = to_labels(atk_comms, self.n_nodes)

        best_nmi = nmi_score(self.ref_labels, atk_labels)
        reduction = 1.0 - best_nmi

        out = {
            "ok": True,
            "dataset_nodes": self.n_nodes,
            "dataset_edges": len(self.edges),
            "budget": self.budget,
            "generations": self.generations,
            "pop_size": self.pop_size,
            "guide": self.guide,
            "detect_algorithm": self.detect_algorithm,
            "seed": self.seed,
            # 基准 A：对比「攻击前的社区检测结果」（结构扰动强度，恒以 1.0 起步）
            "baseline_nmi": 1.0,
            "baseline_ari": 1.0,
            "best_nmi": round(best_nmi, 6),
            "best_ari": round(ari_score(self.ref_labels, atk_labels), 6),
            "nmi_reduction": round(reduction, 6),
            "budget_efficiency": round(reduction / self.budget, 6),
            "added_edges": [list(e) for e in best[0]],
            "removed_edges": [list(e) for e in best[1]],
            "communities_after": [sorted(c) for c in atk_comms],
            "history": [round(h, 6) for h in history],
            "runtime_s": round(time.time() - t0, 3),
        }

        _attach_gt(out, self.gt_raw, self.n_nodes, self.ref_labels, atk_labels)
        return out
