import { readFile } from "node:fs/promises";
import {
  diffPlans,
  type Engine,
  exportPlan,
  init,
  ParserError,
  type Plan,
  parsePlan,
} from "@culpritsql/plans";
import { RULES } from "./linter.js";

type PlanNode = Plan["root"];
import {
  buildExplainShareUrl,
  DEFAULT_EXPLAIN_BASE_URL,
  type SharePayloadV1,
  scrubSqlLiterals,
} from "./share.js";
import type {
  AnalyzePlanOptions,
  ComparePlanGateResult,
  ComparePlanOptions,
  LintFinding,
  PlanFullScanInfo,
  PlanGateResult,
  PlanSpillInfo,
} from "./types.js";

let wasmInitPromise: Promise<void> | null = null;

const EM_DASH_CHAR = String.fromCharCode(0x2014);

export function sanitizeText(input: string): string {
  if (!input.includes(EM_DASH_CHAR)) return input;
  return input.split(EM_DASH_CHAR).join(" - ");
}

/**
 * Initializes the `@culpritsql/plans` WebAssembly module once in Node.js or Bun
 * without network calls or deprecated wasm-bindgen parameter warnings.
 */
export async function ensurePlansWasm(): Promise<void> {
  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      try {
        const entryUrl = import.meta.resolve("@culpritsql/plans");
        const wasmUrl = new URL("./native/culprit_wasm_bg.wasm", entryUrl);
        const wasmBytes = await readFile(wasmUrl);
        await init({ module_or_path: wasmBytes });
      } catch (err) {
        wasmInitPromise = null;
        throw err;
      }
    })();
  }
  return wasmInitPromise;
}

function countPlanNodes(root: PlanNode): number {
  let count = 1;
  for (const child of root.children) {
    count += countPlanNodes(child);
  }
  return count;
}

function isFullTableScanNode(node: PlanNode): boolean {
  if (node.kind !== "scan" || !node.object) return false;
  if (node.index === null) return true;
  if (node.facts.scan_completion != null) return true;
  return /seq scan|table scan|clustered index scan|full scan/i.test(node.op);
}

function collectPlanSignals(
  root: PlanNode,
  minScanRows: number,
  scans: PlanFullScanInfo[],
  spills: PlanSpillInfo[],
): void {
  const walk = (node: PlanNode): void => {
    if (isFullTableScanNode(node) && node.object) {
      const observedRows = node.act_rows ?? node.est_rows;
      if (observedRows >= minScanRows) {
        scans.push({
          nodeId: node.id,
          op: sanitizeText(node.op),
          table: sanitizeText(node.object),
          estRows: node.est_rows,
          actRows: node.act_rows,
          subtreeCost: node.subtree_cost,
        });
      }
    }

    const spillPages = node.runtime?.spill_pages ?? 0;
    const diskUsageKb = node.facts.disk_usage_kb ?? 0;
    const hasSpillWarning = node.warnings.includes("spill");
    const sortOnDisk = node.facts.sort_on_disk === true;
    const exchangeSpill = node.facts.exchange_spill === true;

    if (hasSpillWarning || sortOnDisk || exchangeSpill || spillPages > 0 || diskUsageKb > 0) {
      const parts: string[] = [];
      if (spillPages > 0) parts.push(`${spillPages} temp spill pages`);
      if (diskUsageKb > 0) parts.push(`${diskUsageKb} KB disk usage`);
      if (sortOnDisk) parts.push("external disk sort");
      if (exchangeSpill) parts.push("parallel exchange spill");
      spills.push({
        nodeId: node.id,
        op: sanitizeText(node.op),
        detail: parts.length > 0 ? parts.join(", ") : "operator spilled intermediate data to disk",
      });
    }

    for (const child of node.children) {
      walk(child);
    }
  };

  walk(root);
}

function redactPlanPayloadText(plan: Plan, rawText: string, title: string, redact: boolean): string {
  const trimmed = rawText.trim() || plan.raw || "";
  if (!redact) return trimmed;
  try {
    return exportPlan(plan, title, "native", { redact: true, notes: [] }).contents;
  } catch {
    return scrubSqlLiterals(trimmed);
  }
}

/**
 * Parses an execution plan in WebAssembly, evaluates full-scan / spill / insight / cost gates,
 * and builds a SQL-redacted `https://explain.culpritsql.com/#s=z1...` deep link.
 */
export async function analyzePlanGate(
  planText: string,
  opts: AnalyzePlanOptions = {},
): Promise<PlanGateResult> {
  await ensurePlansWasm();
  const file = opts.file ?? "plan.json";
  const engineHint: Engine | undefined =
    opts.engine && opts.engine !== "auto" ? opts.engine : undefined;

  let plan: Plan;
  try {
    plan = parsePlan(planText.trim(), engineHint);
  } catch (err) {
    if (err instanceof ParserError) {
      throw new Error(`Invalid execution plan (${file}): ${sanitizeText(err.error.message)}`);
    }
    throw err;
  }

  const nodeCount = countPlanNodes(plan.root);
  const title = opts.title ?? `${plan.engine.toUpperCase()} Plan (${nodeCount} steps)`;
  const minScanRows = opts.minScanRows ?? 0;

  const fullTableScans: PlanFullScanInfo[] = [];
  const diskSpills: PlanSpillInfo[] = [];
  collectPlanSignals(plan.root, minScanRows, fullTableScans, diskSpills);

  const findings: LintFinding[] = [];

  if (!opts.allowSeqScan) {
    for (const scan of fullTableScans) {
      const rowDesc =
        scan.actRows != null
          ? `${scan.actRows} actual rows`
          : `${Math.round(scan.estRows)} estimated rows`;
      findings.push({
        ruleId: "PLAN001",
        severity: "medium",
        file,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        title: RULES.PLAN001.title,
        message: `Operator #${scan.nodeId} (${scan.op}) performs a full scan on '${scan.table}' (${rowDesc}, cost ${scan.subtreeCost.toFixed(2)}).`,
        suggestion: `Add a selective index supporting the filter or join columns on '${scan.table}', or pass --allow-seq-scan for small lookup tables.`,
      });
    }
  }

  for (const spill of diskSpills) {
    findings.push({
      ruleId: "PLAN002",
      severity: "high",
      file,
      line: 1,
      column: 1,
      endLine: 1,
      endColumn: 1,
      title: RULES.PLAN002.title,
      message: `Operator #${spill.nodeId} (${spill.op}) spilled to disk (${spill.detail}).`,
      suggestion:
        "Increase working memory (such as work_mem in PostgreSQL), refresh stale table statistics, or add an index that avoids large sorts/hashes.",
    });
  }

  for (const insight of plan.insights?.items ?? []) {
    if (insight.severity === "high" || insight.severity === "medium") {
      findings.push({
        ruleId: "PLAN003",
        severity: insight.severity,
        file,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        title: sanitizeText(insight.title),
        message: `${sanitizeText(insight.title)}: ${sanitizeText(insight.detail)}`,
        suggestion: sanitizeText(insight.fix),
        ...(insight.fix_sql ? { fixSql: sanitizeText(insight.fix_sql) } : {}),
      });
    }
  }

  if (typeof opts.maxCost === "number" && plan.total_cost > opts.maxCost) {
    findings.push({
      ruleId: "PLAN004",
      severity: "high",
      file,
      line: 1,
      column: 1,
      endLine: 1,
      endColumn: 1,
      title: RULES.PLAN004.title,
      message: `Plan total cost ${plan.total_cost.toFixed(2)} exceeds configured budget of ${opts.maxCost.toFixed(2)}.`,
      suggestion:
        "Inspect the highest-cost operators in Culprit Explain and add covering indexes or rewrite expensive joins.",
    });
  }

  const redact = opts.redactShare !== false;
  const redactedRaw = redactPlanPayloadText(plan, planText, title, redact);
  const redactedQuery = plan.statement
    ? redact
      ? scrubSqlLiterals(plan.statement)
      : plan.statement
    : undefined;

  const sharePayload: SharePayloadV1 = {
    v: 1,
    m: "plan",
    t: title,
    e: plan.engine,
    p: redactedRaw,
    ...(redactedQuery ? { q: redactedQuery } : {}),
  };
  const explainUrl = buildExplainShareUrl(
    sharePayload,
    opts.explainBaseUrl ?? DEFAULT_EXPLAIN_BASE_URL,
  );

  const hasHighFinding = findings.some((f) => f.severity === "high");

  return {
    passed: !hasHighFinding,
    file,
    title,
    engine: plan.engine,
    plan,
    totalCost: plan.total_cost,
    elapsedMs: plan.facts.elapsed_ms ?? plan.root.act_time_ms ?? null,
    nodeCount,
    fullTableScans,
    diskSpills,
    findings,
    explainUrl,
  };
}

function collectAccessModesByTable(root: PlanNode): Map<string, Set<"seek" | "scan">> {
  const byTable = new Map<string, Set<"seek" | "scan">>();
  const walk = (node: PlanNode): void => {
    if (node.object) {
      const key = node.object.toLowerCase();
      const set = byTable.get(key) ?? new Set<"seek" | "scan">();
      if (node.kind === "seek") {
        set.add("seek");
      } else if (isFullTableScanNode(node)) {
        set.add("scan");
      }
      if (set.size > 0) byTable.set(key, set);
    }
    for (const child of node.children) walk(child);
  };
  walk(root);
  return byTable;
}

/**
 * Compares Before and After execution plans structurally in WebAssembly, flags runtime/cost/access/spill
 * regressions, and generates a SQL-redacted `https://explain.culpritsql.com/#s=z1...` diff deep link.
 */
export async function comparePlanGate(
  beforeText: string,
  afterText: string,
  opts: ComparePlanOptions = {},
): Promise<ComparePlanGateResult> {
  await ensurePlansWasm();
  const beforeFile = opts.beforeFile ?? "before.plan";
  const afterFile = opts.afterFile ?? "after.plan";
  const beforeName = opts.beforeName ?? "Before";
  const afterName = opts.afterName ?? "After";
  const engineHint: Engine | undefined =
    opts.engine && opts.engine !== "auto" ? opts.engine : undefined;

  let beforePlan: Plan;
  let afterPlan: Plan;
  try {
    beforePlan = parsePlan(beforeText.trim(), engineHint);
  } catch (err) {
    if (err instanceof ParserError) {
      throw new Error(`Invalid baseline plan (${beforeFile}): ${sanitizeText(err.error.message)}`);
    }
    throw err;
  }
  try {
    afterPlan = parsePlan(afterText.trim(), engineHint);
  } catch (err) {
    if (err instanceof ParserError) {
      throw new Error(`Invalid candidate plan (${afterFile}): ${sanitizeText(err.error.message)}`);
    }
    throw err;
  }

  const diff = diffPlans(beforePlan, beforeName, afterPlan, afterName);
  // Sanitize any em dashes inside generated Core diff strings
  diff.headlines = diff.headlines.map(sanitizeText);
  for (const ch of diff.changes) {
    ch.title = sanitizeText(ch.title);
    if (ch.detail) ch.detail = sanitizeText(ch.detail);
  }
  for (const sc of diff.scenarios) {
    sc.title = sanitizeText(sc.title);
    if (sc.detail) sc.detail = sanitizeText(sc.detail);
  }

  const maxCostRegressionRatio = opts.maxCostRegressionRatio ?? 1.25;
  const maxTimeRegressionRatio = opts.maxTimeRegressionRatio ?? 1.5;

  const timeA = diff.time_a_ms ?? beforePlan.facts.elapsed_ms ?? null;
  const timeB = diff.time_b_ms ?? afterPlan.facts.elapsed_ms ?? null;
  let speedupFactor: number | null = null;
  if (timeA != null && timeB != null && timeA > 0 && timeB > 0) {
    speedupFactor = timeA / timeB;
  } else if (diff.cost_ratio != null && diff.cost_ratio > 0) {
    speedupFactor = 1 / diff.cost_ratio;
  }

  const regressionReasons: string[] = [];

  // 1. Measured elapsed-time regression
  const hasBothTimings = timeA != null && timeB != null && timeA > 0 && timeB > 0;
  if (hasBothTimings && timeB >= 5 && timeB / timeA >= maxTimeRegressionRatio) {
    regressionReasons.push(
      `Measured execution time regressed ${(timeB / timeA).toFixed(2)}x (${timeA.toFixed(2)} ms -> ${timeB.toFixed(2)} ms).`,
    );
  }

  // 2. Optimizer cost regression (when execution times are unavailable, or when both plans lack execution times)
  if (!hasBothTimings && diff.cost_ratio != null && diff.cost_ratio >= maxCostRegressionRatio) {
    const costA = (diff.cost_a ?? beforePlan.total_cost).toFixed(2);
    const costB = (diff.cost_b ?? afterPlan.total_cost).toFixed(2);
    regressionReasons.push(
      `Estimated optimizer cost increased ${diff.cost_ratio.toFixed(2)}x (${costA} -> ${costB}).`,
    );
  }

  // 3. New execution warnings introduced in candidate plan
  if (diff.warnings_added.length > 0) {
    regressionReasons.push(
      `Candidate plan introduced new plan warning(s): ${diff.warnings_added.join(", ")}.`,
    );
  }

  // 4. Access path degradation: table switched from Index Seek in Before to Full Table Scan in After
  const accessBefore = collectAccessModesByTable(beforePlan.root);
  const accessAfter = collectAccessModesByTable(afterPlan.root);
  for (const [table, modesBefore] of accessBefore.entries()) {
    const modesAfter = accessAfter.get(table);
    if (modesBefore.has("seek") && !modesBefore.has("scan") && modesAfter?.has("scan") && !modesAfter.has("seek")) {
      regressionReasons.push(
        `Access path on '${table}' degraded from an index seek in ${beforeName} to a full table scan in ${afterName}.`,
      );
    }
  }

  const regressed = regressionReasons.length > 0;
  const findings: LintFinding[] = regressionReasons.map((reason) => ({
    ruleId: "PLAN005",
    severity: "high",
    file: afterFile,
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: 1,
    title: RULES.PLAN005.title,
    message: reason,
    suggestion:
      "Open the side-by-side plan diff in Culprit Explain to inspect operator changes, predicate selectivity, and index usage.",
  }));

  let verdictSummary: string;
  if (hasBothTimings && timeA != null && timeB != null) {
    if (timeB < timeA) {
      verdictSummary = `${(timeA / timeB).toFixed(1)}x faster (${timeA.toFixed(2)} ms -> ${timeB.toFixed(2)} ms)`;
    } else if (timeB > timeA) {
      verdictSummary = `${(timeB / timeA).toFixed(1)}x slower (${timeA.toFixed(2)} ms -> ${timeB.toFixed(2)} ms)`;
    } else {
      verdictSummary = `Unchanged runtime (${timeA.toFixed(2)} ms)`;
    }
  } else if (diff.cost_ratio != null && diff.cost_a != null && diff.cost_b != null) {
    if (diff.cost_ratio < 1) {
      verdictSummary = `${(1 / diff.cost_ratio).toFixed(1)}x lower cost (${diff.cost_a.toFixed(2)} -> ${diff.cost_b.toFixed(2)})`;
    } else if (diff.cost_ratio > 1) {
      verdictSummary = `${diff.cost_ratio.toFixed(1)}x higher cost (${diff.cost_a.toFixed(2)} -> ${diff.cost_b.toFixed(2)})`;
    } else {
      verdictSummary = `Identical optimizer cost (${diff.cost_a.toFixed(2)})`;
    }
  } else if (diff.same_shape) {
    verdictSummary = "Identical operator shape";
  } else {
    verdictSummary = `${diff.changes.length} structural operator change(s)`;
  }

  const redact = opts.redactShare !== false;
  const redactedPa = redactPlanPayloadText(beforePlan, beforeText, beforeName, redact);
  const redactedPb = redactPlanPayloadText(afterPlan, afterText, afterName, redact);
  const sharePayload: SharePayloadV1 = {
    v: 1,
    m: "compare",
    ...(beforePlan.engine === afterPlan.engine ? { e: afterPlan.engine } : {}),
    na: beforeName,
    pa: redactedPa,
    nb: afterName,
    pb: redactedPb,
  };
  const explainUrl = buildExplainShareUrl(
    sharePayload,
    opts.explainBaseUrl ?? DEFAULT_EXPLAIN_BASE_URL,
  );

  return {
    passed: !regressed,
    regressed,
    regressionReasons,
    beforeFile,
    afterFile,
    beforeName,
    afterName,
    engine: afterPlan.engine,
    beforePlan,
    afterPlan,
    diff,
    speedupFactor,
    costChangeRatio: diff.cost_ratio,
    verdictSummary,
    findings,
    explainUrl,
  };
}
