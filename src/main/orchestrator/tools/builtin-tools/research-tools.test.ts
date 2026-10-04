// CDA 科研工具组测试。
//
// 分两层：
//   1) 纯逻辑单测（必跑）：参数渲染、规模估算、超时降级、结果格式化 —— 不启动 Python。
//   2) 集成冒烟（默认跑，无 Python/networkx 时自动跳过）：真正调用 vendor/cda-core，
//      验证 TS 工具层与 Python CLI 的字段契约没有漂移。
//
// 单跑本文件：
//   node node_modules/vitest/vitest.mjs run src/main/orchestrator/tools/builtin-tools/research-tools.test.ts

import { describe, expect, it } from "vitest";
import {
  cdaBatchExperimentTool,
  cdaDetectCommunitiesTool,
  cdaListDatasetsTool,
  cdaRunAttackTool,
  degradeBatchPlan,
  describeDowngrade,
  estimateRuns,
  formatBatchOutput,
  parseBatchPlan,
  renderBatchArgs,
} from "./research-tools";

const FULL_ARGS = {
  datasets: "karate,planted",
  budgets: "2,5,8,12,20",
  methods: "evolutionary,random,heuristic",
  runs: 20,
  generations: 30,
  popSize: 20,
  timeoutSec: 900,
};

function planOf(args: Record<string, unknown>) {
  return parseBatchPlan(args);
}

describe("batch 参数渲染", () => {
  it("默认计划会被渲染成完整 argv", () => {
    const argv = renderBatchArgs(planOf({}));
    expect(argv[0]).toBe("batch");
    expect(argv).toContain("--datasets");
    expect(argv).toContain("karate");
    expect(argv).toContain("--budgets");
    expect(argv).toContain("2,5,8,12,20");
    expect(argv).toContain("--runs");
  });

  it("仅在给出时才追加 csv/md 落盘参数", () => {
    const noFile = renderBatchArgs(planOf({}));
    expect(noFile).not.toContain("--csv");
    expect(noFile).not.toContain("--md");

    const withFiles = renderBatchArgs(
      planOf({ csvPath: "results/a.csv", mdPath: "results/a.md" }),
    );
    expect(withFiles).toContain("--csv");
    expect(withFiles).toContain("results/a.csv");
    expect(withFiles).toContain("--md");
  });

  it("runs / generations / popSize 有下限保护", () => {
    const plan = planOf({ runs: 0, generations: 0, popSize: 1 });
    expect(plan.runs).toBeGreaterThanOrEqual(1);
    expect(plan.generations).toBeGreaterThanOrEqual(1);
    expect(plan.popSize).toBeGreaterThanOrEqual(4); // EvolutionaryAttack 要求 >= 4
  });
});

describe("batch 规模估算与降级", () => {
  it("规模 = 数据集 × 预算 × 方法 × 重复次数", () => {
    expect(estimateRuns(planOf({}))).toBe(1 * 5 * 2 * 20); // 默认两项方法
    expect(estimateRuns(planOf(FULL_ARGS))).toBe(2 * 5 * 3 * 20);
  });

  it("降级后规模显著变小，但保留 evolutionary 与首尾预算点", () => {
    const before = planOf(FULL_ARGS);
    const after = degradeBatchPlan(before)!;
    expect(after).not.toBeNull();
    expect(estimateRuns(after)).toBeLessThan(estimateRuns(before) / 4);

    expect(after.methods.split(",")).toContain("evolutionary");
    expect(after.methods.split(",")).toHaveLength(2); // 进化 + 一个对照

    const budgets = after.budgets.split(",");
    expect(budgets).toHaveLength(2);
    expect(budgets[0]).toBe("2"); // 首点
    expect(budgets[1]).toBe("20"); // 尾点：趋势曲线端点得以保留

    expect(after.runs).toBeLessThan(before.runs);
    expect(after.runs).toBeGreaterThanOrEqual(3);
    expect(after.generations).toBeLessThanOrEqual(before.generations / 2);
  });

  it("规模已经很小时不再降级（避免无意义的重试）", () => {
    const tiny = planOf({ datasets: "karate", budgets: "8", methods: "evolutionary", runs: 3 });
    expect(estimateRuns(tiny)).toBeLessThanOrEqual(12);
    expect(degradeBatchPlan(tiny)).toBeNull();
  });

  it("降级说明标注了新旧规模并提示显著性下降", () => {
    const text = describeDowngrade(planOf(FULL_ARGS), degradeBatchPlan(planOf(FULL_ARGS))!);
    expect(text).toContain("[降级重跑]");
    expect(text).toContain("显著性");
  });
});

/** 构造 batch 的正常输出（字段与 cda_cli.py batch 保持一致，防止契约漂移） */
function fakeBatchJson(): string {
  return JSON.stringify({
    ok: true,
    datasets: ["karate"],
    budgets: [2, 8],
    methods: ["evolutionary", "random"],
    runs_per_group: 5,
    total_runs: 20,
    csv_path: "results/x.csv",
    markdown_path: "results/x.md",
    runtime_s: 1.4,
    groups: [
      {
        dataset: "karate", budget: 2, method: "evolutionary", runs: 5,
        nmi_reduction_mean: 0.204449, nmi_reduction_std: 0.091191,
        budget_efficiency_mean: 0.102224, runtime_s_mean: 0.13,
        gt_nmi_before: 0.600011, gt_nmi_after_mean: 0.605309,
        gt_nmi_reduction_mean: -0.005298,
        win_rate_vs_random: 1.0, win_rate_vs_heuristic: 1.0,
      },
      {
        dataset: "karate", budget: 2, method: "random", runs: 5,
        nmi_reduction_mean: 0.0, nmi_reduction_std: 0.0,
      },
      {
        dataset: "karate", budget: 8, method: "evolutionary", runs: 5,
        nmi_reduction_mean: 0.3967, nmi_reduction_std: 0.0643,
        win_rate_vs_random: 1.0,
      },
      {
        dataset: "karate", budget: 8, method: "random", runs: 5,
        nmi_reduction_mean: 0.0555, nmi_reduction_std: 0.0548,
      },
    ],
  });
}

describe("batch 输出格式化", () => {
  it("压成 Markdown 表格并附带补充指标", () => {
    const out = formatBatchOutput({
      ok: true, stdout: fakeBatchJson(), stderr: "", exitCode: 0, timedOut: false,
    });
    expect(out).toContain("### karate");
    expect(out).toContain("| β |");
    expect(out).toContain("0.2044±0.0912");
    expect(out).toContain("0.3967±0.0643");
    expect(out).toContain("胜率 100%");
    expect(out).toContain("results/x.csv");
    // 提示模型两套基准不可混用
    expect(out).toContain("另一套基准");
  });

  it("Python 报错时透出错误原因", () => {
    const out = formatBatchOutput({
      ok: false,
      stdout: JSON.stringify({ ok: false, error: "ValueError: bad dataset" }),
      stderr: "", exitCode: 1, timedOut: false,
    });
    expect(out).toContain("[错误]");
    expect(out).toContain("ValueError: bad dataset");
  });

  it("输出非 JSON 时不抛异常，保留原始片段便于排查", () => {
    const out = formatBatchOutput({
      ok: false, stdout: "Traceback... not json", stderr: "", exitCode: 1, timedOut: false,
    });
    expect(out).toContain("不是合法 JSON");
  });
});

describe("工具元数据", () => {
  it("四个工具均为 work 模式下的安全只读工具", () => {
    for (const tool of [
      cdaListDatasetsTool,
      cdaDetectCommunitiesTool,
      cdaRunAttackTool,
      cdaBatchExperimentTool,
    ]) {
      expect(tool.modes).toContain("work");
      expect(tool.risk).toBe("safe");
      expect(tool.effectKind).toBe("read");
      expect(tool.id.startsWith("cda_")).toBe(true);
    }
  });

  it("attack 缺少 dataset 时给出引导而不是报错崩溃", async () => {
    const out = await cdaRunAttackTool.execute({}, {} as never);
    expect(typeof out).toBe("string");
    expect(out).toContain("dataset");
  });
});

// ---------------------------------------------------------------------------
// 集成冒烟：需要本机可用的 python + networkx（可用 CDA_PYTHON 指定解释器）。
// ---------------------------------------------------------------------------
/**
 * 判定失败是否属于"本机环境不具备"（而不是代码 bug）。
 * 两种情况都视为环境跳过：找不到 Python 解释器 / Python 缺 networkx。
 */
function isEnvironmentIssue(out: string): boolean {
  return out.startsWith("[错误]") && (out.includes("Python") || out.includes("networkx"));
}

/** 当前可用的 python 是否装了 networkx（决定集成用例能否真跑） */
let _cdaReady: boolean | undefined;
async function cdaEnvReady(): Promise<boolean> {
  if (_cdaReady === undefined) {
    const probe = await cdaListDatasetsTool.execute({}, {} as never);
    _cdaReady = probe.includes("karate");
  }
  return _cdaReady;
}

describe("集成冒烟（无 Python 环境自动跳过）", () => {
  it("cda_list_datasets 能列出 karate", async () => {
    const out = await cdaListDatasetsTool.execute({}, {} as never);
    if (isEnvironmentIssue(out)) {
      expect(out).toMatch(/Python|networkx/); // 无环境则跳过，不算失败
      return;
    }
    expect(out).toContain("karate");
  }, 120_000);

  it("cda_detect_communities 在 karate 上返回 34 节点", async () => {
    const out = await cdaDetectCommunitiesTool.execute({ dataset: "karate" }, {} as never);
    if (isEnvironmentIssue(out) || !(await cdaEnvReady())) return;
    const parsed = JSON.parse(out) as { nodes: number; ok: boolean };
    expect(parsed.nodes).toBe(34);
  }, 120_000);

  it("cda_run_attack 在 karate 上双基准字段齐备", async () => {
    const out = await cdaRunAttackTool.execute(
      { dataset: "karate", budget: 8, generations: 10, popSize: 10 },
      {} as never,
    );
    if (isEnvironmentIssue(out) || !(await cdaEnvReady())) return;
    const parsed = JSON.parse(out) as Record<string, unknown>;
    expect(parsed.ok).toBe(true);
    // 基准 A：结构扰动
    expect(parsed).toHaveProperty("best_nmi");
    expect(parsed).toHaveProperty("nmi_reduction");
    expect(parsed).toHaveProperty("budget_efficiency");
    // 基准 B：真实社区（karate 自带标签）
    expect(parsed.has_ground_truth).toBe(true);
    expect(parsed).toHaveProperty("gt_nmi_before");
    expect(parsed).toHaveProperty("gt_nmi_after");
  }, 120_000);
});
