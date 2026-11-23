import type { Engine, Plan, PlanDiff } from "@culpritsql/plans";

export type Severity = "high" | "medium" | "low";

export type FailOnThreshold = Severity | "none";

export type SqlEngine = "postgres" | "mssql" | "mysql" | "sqlite" | "yugabyte" | "auto";

export type ResolvedSqlEngine = "postgres" | "mssql" | "mysql" | "sqlite";

export type LintMode = "migration" | "query" | "all";

export type ReportFormat = "text" | "markdown" | "json" | "sarif";

export interface RuleMeta {
  id: string;
  severity: Severity;
  category: "migration" | "query" | "plan";
  title: string;
  description: string;
  helpUri: string;
}

export interface LintFinding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  title: string;
  message: string;
  suggestion: string;
  fixSql?: string;
}

export interface LintOptions {
  file?: string;
  engine?: SqlEngine;
  mode?: LintMode;
  /** Optional SQL schema snapshot text so foreign-key checks recognize pre-existing indexes. */
  schemaSql?: string;
  /** Optional list of already-indexed table columns, e.g. { orders: [["customer_id"]] }. */
  existingIndexes?: Record<string, string[][]>;
  /** Rule IDs disabled globally via CLI or configuration. */
  disabledRules?: string[];
}

export interface PlanFullScanInfo {
  nodeId: number;
  op: string;
  table: string;
  estRows: number;
  actRows: number | null;
  subtreeCost: number;
}

export interface PlanSpillInfo {
  nodeId: number;
  op: string;
  detail: string;
}

export interface AnalyzePlanOptions {
  file?: string;
  title?: string;
  engine?: Engine | "auto";
  allowSeqScan?: boolean;
  minScanRows?: number;
  maxCost?: number;
  redactShare?: boolean;
  explainBaseUrl?: string;
}

export interface PlanGateResult {
  passed: boolean;
  file: string;
  title: string;
  engine: Engine;
  plan: Plan;
  totalCost: number;
  elapsedMs: number | null;
  nodeCount: number;
  fullTableScans: PlanFullScanInfo[];
  diskSpills: PlanSpillInfo[];
  findings: LintFinding[];
  explainUrl: string | null;
}

export interface ComparePlanOptions {
  beforeFile?: string;
  afterFile?: string;
  beforeName?: string;
  afterName?: string;
  engine?: Engine | "auto";
  maxCostRegressionRatio?: number;
  maxTimeRegressionRatio?: number;
  redactShare?: boolean;
  explainBaseUrl?: string;
}

export interface ComparePlanGateResult {
  passed: boolean;
  regressed: boolean;
  regressionReasons: string[];
  beforeFile: string;
  afterFile: string;
  beforeName: string;
  afterName: string;
  engine: Engine;
  beforePlan: Plan;
  afterPlan: Plan;
  diff: PlanDiff;
  speedupFactor: number | null;
  costChangeRatio: number | null;
  verdictSummary: string;
  findings: LintFinding[];
  explainUrl: string | null;
}

export interface CiReportSummary {
  high: number;
  medium: number;
  low: number;
  totalFindings: number;
  filesChecked: number;
  plansChecked: number;
  planRegressed: boolean;
}

export interface CiReport {
  version: string;
  passed: boolean;
  failOn: FailOnThreshold;
  engine: SqlEngine;
  summary: CiReportSummary;
  findings: LintFinding[];
  planResults: PlanGateResult[];
  compareResult: ComparePlanGateResult | null;
}
