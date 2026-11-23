import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Engine } from "@culpritsql/plans";
import { resolveSqlInputs, toRelativeDisplayPath } from "./glob.js";
import { detectSqlEngine, lintSql, RULES } from "./linter.js";
import { splitSqlStatements, tokenizeSql } from "./lexer.js";
import { analyzePlanGate, comparePlanGate, ensurePlansWasm } from "./plans.js";
import {
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  STICKY_PR_COMMENT_MARKER,
} from "./reporters.js";
import {
  buildExplainShareUrl,
  decodeShareHash,
  encodeShareHash,
  type SharePayloadV1,
  scrubSqlLiterals,
} from "./share.js";
import type {
  AnalyzePlanOptions,
  CiReport,
  ComparePlanGateResult,
  ComparePlanOptions,
  FailOnThreshold,
  LintFinding,
  LintOptions,
  PlanGateResult,
  Severity,
  SqlEngine,
} from "./types.js";

export const VERSION = "0.5.6";

export interface RunCiGateOptions {
  cwd?: string;
  sqlPatterns?: string[];
  queryPatterns?: string[];
  schemaFile?: string;
  engine?: SqlEngine;
  planFiles?: string[];
  comparePlans?: { beforeFile: string; afterFile: string } | null;
  failOn?: FailOnThreshold;
  allowSeqScan?: boolean;
  maxCost?: number;
  disabledRules?: string[];
  redactShare?: boolean;
}

const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

export function exceedsFailOnThreshold(severity: Severity, failOn: FailOnThreshold): boolean {
  if (failOn === "none") return false;
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[failOn];
}

function toPlanEngineHint(engine: SqlEngine): Engine | "auto" {
  if (engine === "auto") return "auto";
  return engine;
}

/**
 * Executes a full Culprit CI run across SQL migration globs, query globs, execution plans,
 * and Before/After plan comparisons, returning a unified `CiReport`.
 */
export async function runCiGate(opts: RunCiGateOptions = {}): Promise<CiReport> {
  const cwd = opts.cwd ?? process.cwd();
  const engine: SqlEngine = opts.engine ?? "auto";
  const failOn: FailOnThreshold = opts.failOn ?? "high";
  const redactShare = opts.redactShare !== false;

  let schemaSql: string | undefined;
  if (opts.schemaFile) {
    const schemaAbs = path.resolve(cwd, opts.schemaFile);
    schemaSql = await readFile(schemaAbs, "utf8");
  }

  const findings: LintFinding[] = [];
  const checkedFiles = new Set<string>();

  if (opts.sqlPatterns && opts.sqlPatterns.length > 0) {
    const resolvedMigrations = await resolveSqlInputs(opts.sqlPatterns, cwd);
    for (const item of resolvedMigrations) {
      checkedFiles.add(item.displayPath);
      const content = await readFile(item.absPath, "utf8");
      const fileFindings = lintSql(content, {
        file: item.displayPath,
        engine,
        mode: "migration",
        schemaSql,
        disabledRules: opts.disabledRules,
      });
      findings.push(...fileFindings);
    }
  }

  if (opts.queryPatterns && opts.queryPatterns.length > 0) {
    const resolvedQueries = await resolveSqlInputs(opts.queryPatterns, cwd);
    for (const item of resolvedQueries) {
      checkedFiles.add(item.displayPath);
      const content = await readFile(item.absPath, "utf8");
      const fileFindings = lintSql(content, {
        file: item.displayPath,
        engine,
        mode: "query",
        schemaSql,
        disabledRules: opts.disabledRules,
      });
      findings.push(...fileFindings);
    }
  }

  const planResults: PlanGateResult[] = [];
  if (opts.planFiles && opts.planFiles.length > 0) {
    for (const planPath of opts.planFiles) {
      const abs = path.resolve(cwd, planPath);
      const displayPath = toRelativeDisplayPath(abs, cwd);
      checkedFiles.add(displayPath);
      const rawPlan = await readFile(abs, "utf8");
      const res = await analyzePlanGate(rawPlan, {
        file: displayPath,
        engine: toPlanEngineHint(engine),
        allowSeqScan: opts.allowSeqScan,
        maxCost: opts.maxCost,
        redactShare,
      });
      planResults.push(res);
      findings.push(...res.findings);
    }
  }

  let compareResult: ComparePlanGateResult | null = null;
  if (opts.comparePlans) {
    const beforeAbs = path.resolve(cwd, opts.comparePlans.beforeFile);
    const afterAbs = path.resolve(cwd, opts.comparePlans.afterFile);
    const beforeDisplay = toRelativeDisplayPath(beforeAbs, cwd);
    const afterDisplay = toRelativeDisplayPath(afterAbs, cwd);
    checkedFiles.add(beforeDisplay);
    checkedFiles.add(afterDisplay);
    const [beforeText, afterText] = await Promise.all([
      readFile(beforeAbs, "utf8"),
      readFile(afterAbs, "utf8"),
    ]);
    compareResult = await comparePlanGate(beforeText, afterText, {
      beforeFile: beforeDisplay,
      afterFile: afterDisplay,
      beforeName: path.basename(beforeDisplay),
      afterName: path.basename(afterDisplay),
      engine: toPlanEngineHint(engine),
      redactShare,
    });
    findings.push(...compareResult.findings);
  }

  let high = 0;
  let medium = 0;
  let low = 0;
  for (const f of findings) {
    if (f.severity === "high") high += 1;
    else if (f.severity === "medium") medium += 1;
    else low += 1;
  }

  const thresholdTriggered = findings.some((f) => exceedsFailOnThreshold(f.severity, failOn));
  const planRegressed = Boolean(compareResult?.regressed);
  const passed = !thresholdTriggered && !(failOn !== "none" && planRegressed);

  return {
    version: VERSION,
    passed,
    failOn,
    engine,
    summary: {
      high,
      medium,
      low,
      totalFindings: findings.length,
      filesChecked: checkedFiles.size,
      plansChecked: planResults.length + (compareResult ? 2 : 0),
      planRegressed,
    },
    findings,
    planResults,
    compareResult,
  };
}

export {
  RULES,
  STICKY_PR_COMMENT_MARKER,
  analyzePlanGate,
  buildExplainShareUrl,
  comparePlanGate,
  decodeShareHash,
  detectSqlEngine,
  encodeShareHash,
  ensurePlansWasm,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  lintSql,
  resolveSqlInputs,
  scrubSqlLiterals,
  splitSqlStatements,
  tokenizeSql,
};

export type {
  AnalyzePlanOptions,
  CiReport,
  ComparePlanGateResult,
  ComparePlanOptions,
  FailOnThreshold,
  LintFinding,
  LintOptions,
  PlanGateResult,
  SharePayloadV1,
  Severity,
  SqlEngine,
};

export type {
  CiReportSummary,
  LintMode,
  PlanFullScanInfo,
  PlanSpillInfo,
  ReportFormat,
  ResolvedSqlEngine,
  RuleMeta,
} from "./types.js";
