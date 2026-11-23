#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  type FailOnThreshold,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  type ReportFormat,
  runCiGate,
  type SqlEngine,
  VERSION,
} from "./index.js";

interface ParsedCliArgs {
  help: boolean;
  version: boolean;
  sqlPatterns: string[];
  queryPatterns: string[];
  schemaFile?: string;
  engine: SqlEngine;
  planFiles: string[];
  comparePlans: { beforeFile: string; afterFile: string } | null;
  failOn: FailOnThreshold;
  format: ReportFormat;
  sarifOut?: string;
  markdownOut?: string;
  jsonOut?: string;
  allowSeqScan: boolean;
  maxCost?: number;
  disabledRules: string[];
}

const VALID_ENGINES = new Set<SqlEngine>([
  "auto",
  "postgres",
  "mssql",
  "mysql",
  "sqlite",
  "yugabyte",
]);
const VALID_FAIL_ON = new Set<FailOnThreshold>(["high", "medium", "low", "none"]);
const VALID_FORMATS = new Set<ReportFormat>(["text", "markdown", "json", "sarif"]);

export function formatHelpText(): string {
  return [
    `culprit-ci v${VERSION} - SQL migration linter, query analyzer, and execution plan gate`,
    "",
    "Usage:",
    "  culprit-ci [options]",
    "",
    "Options:",
    '  --sql <glob...>             SQL migration files or globs (e.g. "migrations/*.sql")',
    '  --queries <glob...>         Application query files or globs (e.g. "src/**/*.sql")',
    "  --schema <file>             Optional schema SQL snapshot for foreign-key index checks",
    "  --engine <name>             SQL dialect: auto | postgres | mssql | mysql | sqlite | yugabyte (default: auto)",
    "  --plan <file>               Analyze and gate a single execution plan (.json, .txt, .sqlplan)",
    "  --compare <before> <after>  Compare baseline and candidate execution plans structurally",
    "  --fail-on <level>           Gate failure threshold: high | medium | low | none (default: high)",
    "  --format <fmt>              Stdout output format: text | markdown | json | sarif (default: text)",
    "  --sarif <file>              Write SARIF 2.1.0 report to file (for GitHub Code Scanning)",
    "  --markdown-out <file>       Write GitHub PR Markdown report to file",
    "  --json-out <file>           Write JSON report to file",
    "  --max-cost <number>         Fail plan gate when total optimizer cost exceeds budget",
    "  --allow-seq-scan            Allow full table scans in single-plan analysis",
    "  --disable-rule <ID>         Disable specific rule ID (repeatable or comma-separated)",
    "  -h, --help                  Show help and exit",
    "  -v, --version               Show version and exit",
    "",
    "Exit Codes:",
    "  0  Gate passed",
    "  1  Gate failed (findings met --fail-on threshold or execution plan regressed)",
    "  2  Invalid CLI arguments or unreadable input",
    "",
  ].join("\n");
}

export function parseCliArgs(argv: string[]): ParsedCliArgs {
  const parsed: ParsedCliArgs = {
    help: false,
    version: false,
    sqlPatterns: [],
    queryPatterns: [],
    engine: "auto",
    planFiles: [],
    comparePlans: null,
    failOn: "high",
    format: "text",
    allowSeqScan: false,
    disabledRules: [],
  };

  let beforePlanFlag: string | undefined;
  let afterPlanFlag: string | undefined;

  const consumeOneOrMoreValues = (startIdx: number, flagName: string): { values: string[]; nextIdx: number } => {
    const values: string[] = [];
    let idx = startIdx;
    while (idx < argv.length && !argv[idx].startsWith("-")) {
      values.push(argv[idx]);
      idx += 1;
    }
    if (values.length === 0) {
      throw new Error(`Missing value for ${flagName}`);
    }
    return { values, nextIdx: idx };
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      parsed.help = true;
      i += 1;
      continue;
    }
    if (arg === "-v" || arg === "--version") {
      parsed.version = true;
      i += 1;
      continue;
    }
    if (arg === "--allow-seq-scan") {
      parsed.allowSeqScan = true;
      i += 1;
      continue;
    }
    if (arg === "--sql") {
      const { values, nextIdx } = consumeOneOrMoreValues(i + 1, "--sql");
      parsed.sqlPatterns.push(...values);
      i = nextIdx;
      continue;
    }
    if (arg === "--queries") {
      const { values, nextIdx } = consumeOneOrMoreValues(i + 1, "--queries");
      parsed.queryPatterns.push(...values);
      i = nextIdx;
      continue;
    }
    if (arg === "--schema") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing file path for --schema");
      parsed.schemaFile = val;
      i += 2;
      continue;
    }
    if (arg === "--engine") {
      const val = argv[i + 1]?.toLowerCase() as SqlEngine | undefined;
      if (!val || !VALID_ENGINES.has(val)) {
        throw new Error(
          `Invalid --engine '${argv[i + 1] ?? ""}'. Expected one of: auto, postgres, mssql, mysql, sqlite, yugabyte`,
        );
      }
      parsed.engine = val;
      i += 2;
      continue;
    }
    if (arg === "--plan") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing file path for --plan");
      parsed.planFiles.push(val);
      i += 2;
      continue;
    }
    if (arg === "--compare") {
      const before = argv[i + 1];
      const after = argv[i + 2];
      if (!before || before.startsWith("-") || !after || after.startsWith("-")) {
        throw new Error("--compare requires two file arguments: <before-plan> <after-plan>");
      }
      parsed.comparePlans = { beforeFile: before, afterFile: after };
      i += 3;
      continue;
    }
    if (arg === "--before-plan") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing file path for --before-plan");
      beforePlanFlag = val;
      i += 2;
      continue;
    }
    if (arg === "--after-plan") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing file path for --after-plan");
      afterPlanFlag = val;
      i += 2;
      continue;
    }
    if (arg === "--fail-on") {
      const val = argv[i + 1]?.toLowerCase() as FailOnThreshold | undefined;
      if (!val || !VALID_FAIL_ON.has(val)) {
        throw new Error(
          `Invalid --fail-on '${argv[i + 1] ?? ""}'. Expected one of: high, medium, low, none`,
        );
      }
      parsed.failOn = val;
      i += 2;
      continue;
    }
    if (arg === "--format") {
      const val = argv[i + 1]?.toLowerCase() as ReportFormat | undefined;
      if (!val || !VALID_FORMATS.has(val)) {
        throw new Error(
          `Invalid --format '${argv[i + 1] ?? ""}'. Expected one of: text, markdown, json, sarif`,
        );
      }
      parsed.format = val;
      i += 2;
      continue;
    }
    if (arg === "--sarif") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing output file path for --sarif");
      parsed.sarifOut = val;
      i += 2;
      continue;
    }
    if (arg === "--markdown-out") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing output file path for --markdown-out");
      parsed.markdownOut = val;
      i += 2;
      continue;
    }
    if (arg === "--json-out") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing output file path for --json-out");
      parsed.jsonOut = val;
      i += 2;
      continue;
    }
    if (arg === "--max-cost") {
      const rawNum = argv[i + 1];
      const num = Number(rawNum);
      if (!rawNum || !Number.isFinite(num) || num < 0) {
        throw new Error(`Invalid --max-cost '${rawNum ?? ""}'. Expected a non-negative number.`);
      }
      parsed.maxCost = num;
      i += 2;
      continue;
    }
    if (arg === "--disable-rule") {
      const val = argv[i + 1];
      if (!val || val.startsWith("-")) throw new Error("Missing rule ID for --disable-rule");
      for (const id of val.split(",")) {
        const trimmed = id.trim().toUpperCase();
        if (trimmed) parsed.disabledRules.push(trimmed);
      }
      i += 2;
      continue;
    }

    throw new Error(`Unknown option '${arg}'. Run 'culprit-ci --help' for usage.`);
  }

  if (beforePlanFlag || afterPlanFlag) {
    if (!beforePlanFlag || !afterPlanFlag) {
      throw new Error("Both --before-plan and --after-plan must be provided together.");
    }
    parsed.comparePlans = { beforeFile: beforePlanFlag, afterFile: afterPlanFlag };
  }

  return parsed;
}

async function writeOutputFile(filePath: string, content: string, cwd: string): Promise<void> {
  const abs = path.resolve(cwd, filePath);
  await mkdir(path.dirname(abs), { recursive: true });
  await writeFile(abs, content, "utf8");
}

export async function runCli(
  argv: string[],
  io: {
    cwd?: string;
    stdout?: (text: string) => void;
    stderr?: (text: string) => void;
  } = {},
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const writeStdout = io.stdout ?? ((text: string) => process.stdout.write(text));
  const writeStderr = io.stderr ?? ((text: string) => process.stderr.write(text));

  let args: ParsedCliArgs;
  try {
    args = parseCliArgs(argv);
  } catch (err) {
    writeStderr(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }

  if (args.help) {
    writeStdout(`${formatHelpText()}\n`);
    return 0;
  }

  if (args.version) {
    writeStdout(`${VERSION}\n`);
    return 0;
  }

  const hasInputs =
    args.sqlPatterns.length > 0 ||
    args.queryPatterns.length > 0 ||
    args.planFiles.length > 0 ||
    args.comparePlans !== null;

  if (!hasInputs) {
    writeStderr(
      "Error: No inputs provided. Pass --sql, --queries, --plan, or --compare (see --help).\n",
    );
    return 2;
  }

  try {
    const report = await runCiGate({
      cwd,
      sqlPatterns: args.sqlPatterns,
      queryPatterns: args.queryPatterns,
      schemaFile: args.schemaFile,
      engine: args.engine,
      planFiles: args.planFiles,
      comparePlans: args.comparePlans,
      failOn: args.failOn,
      allowSeqScan: args.allowSeqScan,
      maxCost: args.maxCost,
      disabledRules: args.disabledRules,
    });

    if (args.sarifOut) {
      await writeOutputFile(args.sarifOut, `${formatSarif(report)}\n`, cwd);
    }
    if (args.markdownOut) {
      await writeOutputFile(args.markdownOut, formatMarkdown(report), cwd);
    }
    if (args.jsonOut) {
      await writeOutputFile(args.jsonOut, formatJson(report), cwd);
    }

    if (args.format === "markdown") {
      writeStdout(formatMarkdown(report));
    } else if (args.format === "json") {
      writeStdout(formatJson(report));
    } else if (args.format === "sarif") {
      writeStdout(`${formatSarif(report)}\n`);
    } else {
      writeStdout(formatText(report));
    }

    return report.passed ? 0 : 1;
  } catch (err) {
    writeStderr(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
}

const isMainModule = (() => {
  if (!process.argv[1]) return false;
  const resolvedArg = path.resolve(process.argv[1]);
  return resolvedArg.endsWith("cli.js") || resolvedArg.endsWith("cli.ts");
})();

if (isMainModule) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    },
  );
}
