import { spawn } from "child_process";
import { app } from "electron";
import fs from "node:fs";
import path from "node:path";
import type { ToolDefinition } from "../registry/tool-registry";
import { toolRegistry } from "../registry/tool-registry";

/**
 * CDA 科研工具组 —— 大模型 + 社区检测攻击（Community Detection Attack）。
 *
 * 算法内核：vendor/cda-core/（Python，networkx），思路参考
 * 刘夫武硕士论文《面向复杂网络社区检测攻击的进化算法研究》
 * （CDA-CAGRL / CDA-MOEA 的简化单目标重写）。
 *
 * 工具 execute 内通过受控 argv 调用 vendor/cda-core/cda_cli.py，
 * 不接受任何来自模型的任意命令字符串，效果类型为纯本地计算（read）。
 */

const CDA_TIMEOUT_MS_DEFAULT = 120_000;

/** 解析 Python 解释器：CDA_PYTHON 环境变量 → PATH 上的 python/python3。 */
function resolvePythonExe(): string {
  const fromEnv = process.env.CDA_PYTHON?.trim();
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  if (process.platform === "win32") return "python";
  return "python3";
}

/**
 * 解析 cda_cli.py 所在目录：
 * CDA_CORE_DIR 环境变量 → Electron appPath（仅主进程可用）→ process.cwd()。
 *
 * 三级回退让本模块在纯 Node 环境（vitest、脚本化调用）下也能定位算法目录，
 * 不会因为 electron 的 app 未初始化而直接抛错。
 */
function resolveCdaCoreDir(): string {
  const fromEnv = process.env.CDA_CORE_DIR?.trim();
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  try {
    const appPath = app?.getAppPath?.();
    if (appPath) return path.join(appPath, "vendor", "cda-core");
  } catch {
    /* 非 Electron 环境下忽略 */
  }
  return path.join(process.cwd(), "vendor", "cda-core");
}

export interface CdaRunOutcome {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

function runCdaCli(args: string[], timeoutMs: number): Promise<CdaRunOutcome> {
  const pythonExe = resolvePythonExe();
  const coreDir = resolveCdaCoreDir();
  const script = path.join(coreDir, "cda_cli.py");

  return new Promise((resolve) => {
    if (!fs.existsSync(script)) {
      resolve({
        ok: false,
        stdout: "",
        stderr: `[cda-core] 未找到算法脚本: ${script}（可用环境变量 CDA_CORE_DIR 指定目录）`,
        exitCode: null,
        timedOut: false,
      });
      return;
    }

    let child;
    try {
      child = spawn(pythonExe, [script, ...args], {
        cwd: coreDir,
        env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" },
        windowsHide: true,
      });
    } catch (err) {
      resolve({
        ok: false,
        stdout: "",
        stderr: `[cda-core] 无法启动 Python（${pythonExe}）：${String(err)}。请安装 Python 并 pip install networkx，或用环境变量 CDA_PYTHON 指定解释器。`,
        exitCode: null,
        timedOut: false,
      });
      return;
    }

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
    }, timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf-8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8");
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        ok: false,
        stdout,
        stderr: `${stderr}\n[cda-core] Python 启动失败（${pythonExe}）：${err.message}。请确认已安装 Python 与 networkx（pip install networkx），或设置 CDA_PYTHON 指向可用解释器。`,
        exitCode: null,
        timedOut,
      });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: code === 0 && !timedOut, stdout, stderr, exitCode: code, timedOut });
    });
  });
}

/** 把 CLI 输出整理成返回给模型的字符串（JSON 解析失败时附原始输出便于排查）。 */
function formatCliOutput(outcome: CdaRunOutcome): string {
  if (outcome.timedOut) {
    return "[错误] CDA 计算超时。建议减小 generations / pop-size，或换更小的数据集后重试。";
  }
  const raw = outcome.stdout.trim();
  if (!raw) {
    return `[错误] CDA CLI 无输出。stderr: ${outcome.stderr.slice(0, 800)}`;
  }
  // cda_cli.py 每次输出单行 JSON；容错取最后一行非空输出
  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const last = lines[lines.length - 1]!;
  try {
    const parsed = JSON.parse(last) as { ok?: boolean; error?: string };
    if (parsed.ok === false && parsed.error) {
      return `[错误] CDA 计算失败：${parsed.error}`;
    }
    return JSON.stringify(parsed, null, 1);
  } catch {
    return `[错误] CDA CLI 输出不是合法 JSON。原始输出: ${raw.slice(0, 800)} stderr: ${outcome.stderr.slice(0, 400)}`;
  }
}

function strArg(args: Record<string, unknown>, key: string, fallback: string): string {
  const v = args[key];
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : fallback;
}

function numArg(args: Record<string, unknown>, key: string, fallback: number): number {
  const v = args[key];
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return fallback;
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

export const cdaListDatasetsTool: ToolDefinition = {
  id: "cda_list_datasets",
  name: "CDA数据集列表",
  description:
    "列出社区检测攻击（CDA）研究可用的内置网络数据集。" +
    "包括 Zachary Karate Club 空手道俱乐部网络、Planted Partition 网络、" +
    "随机分块网络，以及自定义边表文件的支持说明。\n\n" +
    "何时用：用户想开始社区检测/社区检测攻击实验，但还没指定用哪个网络数据集时，" +
    "先调用本工具查看可用数据集再推荐。",
  enabled: true,
  risk: "safe",
  modes: ["work"],
  effectKind: "read",
  verificationPolicy: "none",
  inputSchema: { type: "object", properties: {}, required: [] },
  execute: async () => {
    const outcome = await runCdaCli(["datasets"], CDA_TIMEOUT_MS_DEFAULT);
    return formatCliOutput(outcome);
  },
};

export const cdaDetectCommunitiesTool: ToolDefinition = {
  id: "cda_detect_communities",
  name: "CDA社区检测",
  description:
    "在指定网络上运行社区检测算法（Louvain 或贪心模块度），返回社区划分、模块度 Q、" +
    "社区规模，以及与真实社区的 NMI/ARI（数据集自带真实社区时）。\n\n" +
    "何时用：攻击前的基线分析、攻击后验证对抗网络结构、或单纯想看网络社区结构。\n\n" +
    "参数：dataset（必填：karate / planted / gnp 或边表文件路径）、algorithm（可选）、seed（可选）。",
  enabled: true,
  risk: "safe",
  modes: ["work"],
  effectKind: "read",
  verificationPolicy: "none",
  inputSchema: {
    type: "object",
    properties: {
      dataset: {
        type: "string",
        description: "数据集名（karate / planted / gnp）或边表文件路径（每行 'u v'）",
      },
      algorithm: {
        type: "string",
        enum: ["louvain", "greedy"],
        description: "社区检测算法，默认 louvain",
      },
      seed: { type: "number", description: "随机种子，默认 42" },
    },
    required: ["dataset"],
  },
  execute: async (args) => {
    const dataset = strArg(args, "dataset", "");
    if (!dataset) return "[提示] 缺少 dataset 参数。可先调用 cda_list_datasets 查看可用数据集。";
    const cliArgs = [
      "detect",
      "--dataset",
      dataset,
      "--algorithm",
      strArg(args, "algorithm", "louvain"),
      "--seed",
      String(numArg(args, "seed", 42)),
    ];
    const outcome = await runCdaCli(cliArgs, CDA_TIMEOUT_MS_DEFAULT);
    return formatCliOutput(outcome);
  },
};

export const cdaRunAttackTool: ToolDefinition = {
  id: "cda_run_attack",
  name: "CDA进化攻击",
  description:
    "运行社区检测攻击进化算法：在攻击预算 β（边修改总数）约束下对网络加/删边，" +
    "使社区检测算法在对抗网络上的社区结构与原结构差异最大化。" +
    "返回两套评估指标，汇报时务必区分清楚：\n" +
    "1) best_nmi / best_ari / nmi_reduction：对比『攻击前的检测结果』，baseline_nmi 恒为 1.0，" +
    "衡量的是结构扰动强度；\n" +
    "2) has_ground_truth 为 true 时才有 gt_nmi_before / gt_nmi_after / gt_nmi_reduction：" +
    "对比『数据集自带真实社区』，衡量检测质量退化（如 karate 为 0.5942→更低）。\n" +
    "两套数值不可混用，也不要把 baseline 的 gt 值当成攻击前的 nmi。\n" +
    "另外 budget_efficiency = nmi_reduction / β，衡量单位预算的攻击性价比。\n\n" +
    "还返回边修改方案、每代最优 NMI 收敛曲线。\n\n" +
    "算法：进化算法（锦标赛选择 + 边集交叉 + 强度偏向变异），" +
    "参考 CDA-CAGRL 的'节点相似性引导变异'思想（guide=degree）。\n\n" +
    "何时用：用户想做社区检测攻击实验、评估隐私保护效果、比较不同预算/参数下的攻击效果。\n\n" +
    "建议流程：先用 cda_detect_communities 看基线，再调本工具攻击，最后再用 " +
    "cda_detect_communities 无法直接验证（对抗网络已包含在返回结果中）。\n" +
    "参数较小时计算很快（karate 30 代约 1 秒）；大规模网络请控制 generations/pop-size。",
  enabled: true,
  risk: "safe",
  modes: ["work"],
  effectKind: "read",
  verificationPolicy: "none",
  inputSchema: {
    type: "object",
    properties: {
      dataset: {
        type: "string",
        description: "数据集名（karate / planted / gnp）或边表文件路径（每行 'u v'）",
      },
      budget: { type: "number", description: "攻击预算 β：允许加/删边的总数，默认 8" },
      generations: { type: "number", description: "进化代数，默认 30" },
      popSize: { type: "number", description: "种群规模，默认 20" },
      guide: {
        type: "string",
        enum: ["degree", "random"],
        description: "变异引导：degree=边强度偏向（论文思想简化版，推荐），random=随机",
      },
      algorithm: {
        type: "string",
        enum: ["louvain", "greedy"],
        description: "个体评估所用社区检测算法，默认 louvain（greedy 更快但粗糙）",
      },
      seed: { type: "number", description: "随机种子，默认 42" },
      timeoutSec: { type: "number", description: "计算超时秒数，默认 120" },
    },
    required: ["dataset"],
  },
  execute: async (args) => {
    const dataset = strArg(args, "dataset", "");
    if (!dataset) return "[提示] 缺少 dataset 参数。可先调用 cda_list_datasets 查看可用数据集。";
    const cliArgs = [
      "attack",
      "--dataset",
      dataset,
      "--budget",
      String(Math.max(1, Math.floor(numArg(args, "budget", 8)))),
      "--generations",
      String(Math.max(1, Math.floor(numArg(args, "generations", 30)))),
      "--pop-size",
      String(Math.max(4, Math.floor(numArg(args, "popSize", 20)))),
      "--guide",
      strArg(args, "guide", "degree"),
      "--algorithm",
      strArg(args, "algorithm", "louvain"),
      "--seed",
      String(numArg(args, "seed", 42)),
    ];
    const timeoutMs = Math.max(5, numArg(args, "timeoutSec", 120)) * 1000;
    const outcome = await runCdaCli(cliArgs, timeoutMs);
    return formatCliOutput(outcome);
  },
};

// ---------------------------------------------------------------------------
// batch：把逐组统计压成紧凑文本，避免大批次结果冲爆模型上下文
// ---------------------------------------------------------------------------

export interface BatchGroup {
  dataset: string;
  budget: number;
  method: string;
  runs: number;
  nmi_reduction_mean: number;
  nmi_reduction_std: number;
  budget_efficiency_mean?: number;
  runtime_s_mean?: number;
  gt_nmi_before?: number;
  gt_nmi_after_mean?: number;
  gt_nmi_reduction_mean?: number;
  win_rate_vs_random?: number;
  win_rate_vs_heuristic?: number;
  avg_gain_vs_random?: number;
  avg_gain_vs_heuristic?: number;
}

export function formatBatchOutput(outcome: CdaRunOutcome): string {
  if (outcome.timedOut) {
    return "[错误] 批量实验超时。建议减少 runs / budgets / datasets，或提高 timeoutSec 后重试。";
  }
  const raw = outcome.stdout.trim();
  if (!raw) return `[错误] CLI 无输出。stderr: ${outcome.stderr.slice(0, 800)}`;

  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  let parsed: {
    ok?: boolean;
    error?: string;
    groups?: BatchGroup[];
    csv_path?: string | null;
    markdown_path?: string | null;
    total_runs?: number;
    runtime_s?: number;
    runs_per_group?: number;
  };
  try {
    parsed = JSON.parse(lines[lines.length - 1]!) as typeof parsed;
  } catch {
    return `[错误] CLI 输出不是合法 JSON。原始输出: ${raw.slice(0, 600)} stderr: ${outcome.stderr.slice(0, 400)}`;
  }
  if (parsed.ok === false) return `[错误] 批量实验失败：${parsed.error ?? "未知错误"}`;

  const groups = parsed.groups ?? [];
  const header = [
    `批量实验完成：${parsed.total_runs ?? 0} 次运行，每组 ${parsed.runs_per_group ?? "?"} 个随机种子，` +
      `总耗时 ${parsed.runtime_s ?? "?"}s。`,
    parsed.csv_path ? `原始逐次记录 CSV：${parsed.csv_path}` : "",
    parsed.markdown_path ? `Markdown 汇总表：${parsed.markdown_path}` : "",
    "",
    "NMI 下降量格式：mean±std（20 组以上的样本标准差），越大越好。",
    "",
  ]
    .filter(Boolean)
    .join("\n");

  // 按 (dataset, budget) 排列表格，列=方法
  const byKey = new Map<string, Partial<Record<string, BatchGroup>>>();
  const datasets: string[] = [];
  const budgets: number[] = [];
  const methods: string[] = [];
  for (const g of groups) {
    if (!datasets.includes(g.dataset)) datasets.push(g.dataset);
    if (!budgets.includes(g.budget)) budgets.push(g.budget);
    if (!methods.includes(g.method)) methods.push(g.method);
    const key = `${g.dataset}|${g.budget}`;
    const entry = byKey.get(key) ?? {};
    entry[g.method] = g;
    byKey.set(key, entry);
  }
  budgets.sort((a, b) => a - b);

  const tables: string[] = [];
  for (const ds of datasets) {
    const rows = [`### ${ds}`, "", "| β | " + methods.join(" | ") + " |", "|" + "---|".repeat(methods.length + 1)];
    for (const budget of budgets) {
      const entry = byKey.get(`${ds}|${budget}`);
      if (!entry) continue;
      const cells = methods.map((m) => {
        const g = entry[m];
        if (!g) return "—";
        return `${g.nmi_reduction_mean.toFixed(4)}±${g.nmi_reduction_std.toFixed(4)}`;
      });
      rows.push(`| ${budget} | ${cells.join(" | ")} |`);
    }
    tables.push(rows.join("\n") + "\n");
  }

  // 每个 (dataset, budget) 只保留 evolutionary 的补充信息
  const details: string[] = [];
  for (const g of groups.filter((x) => x.method === "evolutionary")) {
    const bits: string[] = [];
    if (g.win_rate_vs_random !== undefined) bits.push(`对随机基线胜率 ${(g.win_rate_vs_random * 100).toFixed(0)}%`);
    if (g.win_rate_vs_heuristic !== undefined) bits.push(`对启发式胜率 ${(g.win_rate_vs_heuristic * 100).toFixed(0)}%`);
    if (g.gt_nmi_before !== undefined && g.gt_nmi_after_mean !== undefined) {
      bits.push(`真实社区 NMI ${g.gt_nmi_before.toFixed(4)}→${g.gt_nmi_after_mean.toFixed(4)}`);
    }
    if (g.budget_efficiency_mean !== undefined) bits.push(`单位预算效率 ${g.budget_efficiency_mean.toFixed(4)}`);
    if (bits.length > 0) details.push(`${g.dataset} β=${g.budget}：${bits.join("，")}`);
  }

  return [
    header,
    tables.join("\n"),
    details.length > 0 ? "### 进化攻击补充指标\n\n" + details.join("\n") : "",
    "",
    "汇报时使用上表的 mean±std，并说明 NMI 衡量的是「攻击前后检测结果差异」；" +
      "若列了真实社区 NMI，需注明那是另一套基准（检测质量退化）。",
  ]
    .filter(Boolean)
    .join("\n");
}

// ---------------------------------------------------------------------------
// batch 的执行计划：便于超时后自动降级重跑
// ---------------------------------------------------------------------------

export interface BatchPlan {
  datasets: string;
  budgets: string;
  methods: string;
  runs: number;
  seedBase: number;
  generations: number;
  popSize: number;
  guide: string;
  algorithm: string;
  csvPath: string;
  mdPath: string;
}

export function parseBatchPlan(args: Record<string, unknown>): BatchPlan {
  return {
    datasets: strArg(args, "datasets", "karate"),
    budgets: strArg(args, "budgets", "2,5,8,12,20"),
    methods: strArg(args, "methods", "evolutionary,random"),
    runs: Math.max(1, Math.floor(numArg(args, "runs", 20))),
    seedBase: Math.floor(numArg(args, "seedBase", 0)),
    generations: Math.max(1, Math.floor(numArg(args, "generations", 30))),
    popSize: Math.max(4, Math.floor(numArg(args, "popSize", 20))),
    guide: strArg(args, "guide", "degree"),
    algorithm: strArg(args, "algorithm", "louvain"),
    csvPath: strArg(args, "csvPath", ""),
    mdPath: strArg(args, "mdPath", ""),
  };
}

export function renderBatchArgs(plan: BatchPlan): string[] {
  const cliArgs = [
    "batch",
    "--datasets",
    plan.datasets,
    "--budgets",
    plan.budgets,
    "--methods",
    plan.methods,
    "--runs",
    String(plan.runs),
    "--seed-base",
    String(plan.seedBase),
    "--generations",
    String(plan.generations),
    "--pop-size",
    String(plan.popSize),
    "--guide",
    plan.guide,
    "--algorithm",
    plan.algorithm,
  ];
  if (plan.csvPath) cliArgs.push("--csv", plan.csvPath);
  if (plan.mdPath) cliArgs.push("--md", plan.mdPath);
  return cliArgs;
}

/** 计划规模估算：一次原子实验（1 数据集 × 1 预算 × 1 方法 × 1 种子）。 */
export function estimateRuns(plan: BatchPlan): number {
  const nDs = plan.datasets.split(",").filter((s) => s.trim()).length;
  const nBudget = plan.budgets.split(",").filter((s) => s.trim()).length;
  const nMethod = plan.methods.split(",").filter((s) => s.trim()).length;
  return nDs * nBudget * nMethod * plan.runs;
}

/**
 * 超时降级：把规模砍到约 1/8，优先保住"多方法对比 + 预算曲线形状"，
 * 牺牲重复次数（统计显著性）。已经很小则返回 null 表示无法再降。
 */
export function degradeBatchPlan(plan: BatchPlan): BatchPlan | null {
  if (estimateRuns(plan) <= 12) return null;

  const keepBudgetMax = 2;
  const budgets = plan.budgets.split(",").map((s) => s.trim()).filter(Boolean);
  const sampledBudgets =
    budgets.length <= keepBudgetMax
      ? budgets
      : // 均匀取样，保留首尾以维持曲线端点
        [budgets[0]!, budgets[budgets.length - 1]!].filter(
          (v, i, arr) => arr.indexOf(v) === i,
        );

  const methods = plan.methods.split(",").map((s) => s.trim()).filter(Boolean);
  const keepMethods = methods.includes("evolutionary")
    ? ["evolutionary", ...methods.filter((m) => m !== "evolutionary").slice(0, 1)]
    : methods.slice(0, 2);

  return {
    ...plan,
    budgets: sampledBudgets.join(","),
    methods: keepMethods.join(","),
    runs: Math.max(3, Math.floor(plan.runs / 4)),
    generations: Math.max(5, Math.floor(plan.generations / 2)),
    popSize: Math.max(8, Math.floor(plan.popSize / 2)),
  };
}

export function describeDowngrade(from: BatchPlan, to: BatchPlan): string {
  return (
    `[降级重跑] 原规模（${estimateRuns(from)} 次运行）超时，已自动缩小为：` +
    `methods=${to.methods}、budgets=${to.budgets}、runs=${to.runs}、` +
    `generations=${to.generations}、popSize=${to.popSize}` +
    `（${estimateRuns(to)} 次运行）。统计显著性下降，结果仅供趋势判断；` +
    `如需完整实验请手动减小 runs / budgets 或提高 timeoutSec。\n\n`
  );
}

export const cdaBatchExperimentTool: ToolDefinition = {
  id: "cda_batch_experiment",
  name: "CDA批量对比实验",
  description:
    "批量运行社区检测攻击对比实验：扫描「数据集 × 攻击预算 β × 方法 × 多个随机种子」，" +
    "输出每组的 NMI 下降量 mean±std、单位预算效率、进化攻击对两个基线的逐种子胜率，" +
    "以及可选的 CSV 原始记录和 Markdown 汇总表（可直接放进论文/报告）。\n\n" +
    "三种方法：evolutionary（进化算法，本文方法）、random（随机改边基线）、" +
    "heuristic（贪心固定策略基线：删最强社区内部边 + 加最低相似度跨社区边）。\n\n" +
    "何时用：用户要做参数敏感性分析（预算曲线）、要跟基线方法对比、" +
    "或需要统计上可靠的实验结果（多种子 mean±std）时。单次攻击请用 cda_run_attack。\n\n" +
    "耗时参考：1 数据集 × 5 预算 × 3 方法 × 20 种子约 3~4 分钟（karate 更快）。" +
    "默认 20 种子已经具备统计意义，批量较慢请把 timeoutSec 设够（默认 900 秒）。" +
    "若超时，本工具会自动按更小规模降级重跑一次（保留多方法对比与首尾预算点、降低重复次数），" +
    "并在开头用 [降级重跑] 标注——此时结果只能看趋势，不能做显著性结论。",
  enabled: true,
  risk: "safe",
  modes: ["work"],
  effectKind: "read",
  verificationPolicy: "none",
  inputSchema: {
    type: "object",
    properties: {
      datasets: {
        type: "string",
        description: "逗号分隔的数据集列表，默认 karate。可选 karate / planted / gnp 或边表文件路径",
      },
      budgets: {
        type: "string",
        description: "逗号分隔的攻击预算列表，默认 2,5,8,12,20（用于绘制预算敏感性曲线）",
      },
      methods: {
        type: "string",
        description: "逗号分隔的方法，默认 evolutionary,random。可选加 heuristic 做第二个基线",
      },
      runs: { type: "number", description: "每组重复次数（不同随机种子），默认 20" },
      seedBase: { type: "number", description: "随机种子起始值，默认 0" },
      generations: { type: "number", description: "进化代数，默认 30" },
      popSize: { type: "number", description: "种群规模，默认 20" },
      guide: { type: "string", enum: ["degree", "random"], description: "变异引导，默认 degree" },
      algorithm: {
        type: "string",
        enum: ["louvain", "greedy"],
        description: "社区检测算法，默认 louvain",
      },
      csvPath: {
        type: "string",
        description: "CSV 原始结果输出路径（绝对路径或相对 vendor/cda-core 的路径）；给出后会保存逐次记录",
      },
      mdPath: { type: "string", description: "Markdown 汇总表输出路径，给出后会保存可直接粘贴的表格" },
      timeoutSec: { type: "number", description: "计算超时秒数，默认 900（批量实验耗时较长，务必设够）" },
    },
    required: [],
  },
  execute: async (args) => {
    const plan = parseBatchPlan(args);
    const timeoutSec = Math.max(10, numArg(args, "timeoutSec", 900));

    let outcome = await runCdaCli(renderBatchArgs(plan), timeoutSec * 1000);

    // 超时自动降级重跑一次：保住"多方法 + 首尾预算点"，牺牲重复次数
    if (outcome.timedOut) {
      const smaller = degradeBatchPlan(plan);
      if (smaller) {
        // 剩余时间 = 原超时的一半，给第二次尝试足够预算
        outcome = await runCdaCli(renderBatchArgs(smaller), Math.floor(timeoutSec * 500));
        if (!outcome.timedOut) {
          return describeDowngrade(plan, smaller) + formatBatchOutput(outcome);
        }
      }
      return (
        `[错误] 批量实验超时，且降级后（${smaller ? estimateRuns(smaller) : "已最小"}` +
        ` 次运行）仍未完成。\n\n建议：\n` +
        `1. 缩小 datasets（一次只跑一个网络）\n` +
        `2. 减少 runs（20 → 5）\n` +
        `3. 减少 budgets（如只测 5,15 两个点）\n` +
        `4. 降低 generations / popSize\n` +
        `5. 提高 timeoutSec（当前 ${timeoutSec}s）`
      );
    }
    return formatBatchOutput(outcome);
  },
};

export function registerResearchTools(): void {
  toolRegistry.register(cdaListDatasetsTool);
  toolRegistry.register(cdaDetectCommunitiesTool);
  toolRegistry.register(cdaRunAttackTool);
  toolRegistry.register(cdaBatchExperimentTool);
}
