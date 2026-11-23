import { RULES } from "./linter.js";
import { sanitizeText } from "./plans.js";
import type { CiReport, LintFinding, RuleMeta, Severity } from "./types.js";

export const STICKY_PR_COMMENT_MARKER = "<!-- culprit-ci-report -->";

export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  help: { text: string; markdown: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties: { tags: string[]; "problem.severity": "error" | "warning" | "recommendation" };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId: "%SRCROOT%";
      };
      region: {
        startLine: number;
        startColumn: number;
        endLine: number;
        endColumn: number;
      };
    };
  }>;
}

export interface SarifLog {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        version: string;
        rules: SarifReportingDescriptor[];
      };
    };
    results: SarifResult[];
  }>;
}

function severityToSarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function severityToProblemSeverity(
  severity: Severity,
): "error" | "warning" | "recommendation" {
  if (severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "recommendation";
}

function normalizeSarifUri(file: string): string {
  return file.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

function buildRuleDescriptor(meta: RuleMeta): SarifReportingDescriptor {
  return {
    id: meta.id,
    name: meta.title.replace(/[^A-Za-z0-9]+/g, ""),
    shortDescription: { text: sanitizeText(meta.title) },
    fullDescription: { text: sanitizeText(meta.description) },
    helpUri: meta.helpUri,
    help: {
      text: `${sanitizeText(meta.title)}: ${sanitizeText(meta.description)}`,
      markdown: `**${sanitizeText(meta.title)}**\n\n${sanitizeText(meta.description)}`,
    },
    defaultConfiguration: {
      level: severityToSarifLevel(meta.severity),
    },
    properties: {
      tags: ["sql", "database", meta.category],
      "problem.severity": severityToProblemSeverity(meta.severity),
    },
  };
}

/**
 * Formats a `CiReport` as valid SARIF 2.1.0 JSON ready for `github/codeql-action/upload-sarif@v3`.
 */
export function formatSarif(report: CiReport): string {
  const usedRuleIds: string[] = [];
  const ruleIndexMap = new Map<string, number>();

  for (const finding of report.findings) {
    if (!ruleIndexMap.has(finding.ruleId)) {
      ruleIndexMap.set(finding.ruleId, usedRuleIds.length);
      usedRuleIds.push(finding.ruleId);
    }
  }

  const rules: SarifReportingDescriptor[] = usedRuleIds.map((id) => {
    const meta: RuleMeta = RULES[id] ?? {
      id,
      severity: "medium",
      category: "migration",
      title: id,
      description: `Culprit SQL rule ${id}.`,
      helpUri: "https://github.com/culpritsql/culprit-ci",
    };
    return buildRuleDescriptor(meta);
  });

  const results: SarifResult[] = report.findings.map((f) => {
    const startLine = Math.max(1, f.line);
    const startColumn = Math.max(1, f.column);
    const endLine = Math.max(startLine, f.endLine);
    const endColumn = endLine === startLine ? Math.max(startColumn, f.endColumn) : Math.max(1, f.endColumn);
    const textParts = [sanitizeText(f.message)];
    if (f.suggestion) textParts.push(`Fix: ${sanitizeText(f.suggestion)}`);
    if (f.fixSql) textParts.push(`SQL: ${sanitizeText(f.fixSql)}`);

    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
      level: severityToSarifLevel(f.severity),
      message: {
        text: textParts.join(" "),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizeSarifUri(f.file),
              uriBaseId: "%SRCROOT%",
            },
            region: {
              startLine,
              startColumn,
              endLine,
              endColumn,
            },
          },
        },
      ],
    };
  });

  const log: SarifLog = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Culprit CI",
            informationUri: "https://github.com/culpritsql/culprit-ci",
            version: report.version,
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(log, null, 2);
}

function escapeMdCell(text: string): string {
  return sanitizeText(text)
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .trim();
}

function formatSeverityPill(severity: Severity): string {
  if (severity === "high") return "**HIGH**";
  if (severity === "medium") return "MEDIUM";
  return "LOW";
}

/**
 * Formats a `CiReport` as a GitHub Pull Request Markdown comment with status badge,
 * summary metrics, findings table, plan diff speedup verdict, and interactive Culprit Explain deep links.
 */
export function formatMarkdown(report: CiReport): string {
  const lines: string[] = [STICKY_PR_COMMENT_MARKER];
  const badgeUrl = report.passed
    ? "https://img.shields.io/badge/Culprit_CI-Passed-2ea043?style=flat-square"
    : "https://img.shields.io/badge/Culprit_CI-Failed-da3633?style=flat-square";
  const statusWord = report.passed ? "Passed" : "Failed";

  lines.push(`## Culprit SQL CI: ${statusWord}`);
  lines.push("");
  lines.push(
    `![Culprit CI ${statusWord}](${badgeUrl}) ` +
      `**High:** ${report.summary.high} | **Medium:** ${report.summary.medium} | **Low:** ${report.summary.low} | ` +
      `**Files Checked:** ${report.summary.filesChecked} | **Fail Threshold:** \`${report.failOn}\``,
  );
  lines.push("");

  if (report.compareResult) {
    const cmp = report.compareResult;
    const verdictLabel = cmp.regressed ? "Regression Detected" : "Verified";
    lines.push(`### Execution Plan Diff (${verdictLabel})`);
    lines.push("");
    lines.push(
      `- **Comparison:** \`${escapeMdCell(cmp.beforeName)}\` -> \`${escapeMdCell(cmp.afterName)}\` (\`${cmp.engine}\`)`,
    );
    lines.push(`- **Verdict:** **${sanitizeText(cmp.verdictSummary)}**`);
    if (cmp.diff.headlines.length > 0) {
      for (const hl of cmp.diff.headlines) {
        lines.push(`- ${sanitizeText(hl)}`);
      }
    }
    if (cmp.regressionReasons.length > 0) {
      for (const reason of cmp.regressionReasons) {
        lines.push(`- **Gate Failure:** ${sanitizeText(reason)}`);
      }
    }
    if (cmp.explainUrl) {
      lines.push("");
      lines.push(`[Open Interactive Diff in Culprit Explain](${cmp.explainUrl})`);
    }
    lines.push("");
  }

  if (report.planResults.length > 0) {
    lines.push("### Execution Plan Gate");
    lines.push("");
    for (const pr of report.planResults) {
      const dur = pr.elapsedMs != null ? `, elapsed ${pr.elapsedMs.toFixed(2)} ms` : "";
      lines.push(
        `- \`${escapeMdCell(pr.file)}\` (\`${pr.engine}\`): ${pr.nodeCount} operators, cost ${pr.totalCost.toFixed(2)}${dur}, ` +
          `${pr.fullTableScans.length} full scan(s), ${pr.diskSpills.length} spill(s)` +
          (pr.explainUrl ? ` ([Open Interactive Plan in Culprit Explain](${pr.explainUrl}))` : ""),
      );
    }
    lines.push("");
  }

  if (report.findings.length === 0) {
    lines.push("No SQL migration, query, or execution plan issues found.");
    lines.push("");
  } else {
    lines.push("### Findings");
    lines.push("");
    lines.push("| File:Line | Rule | Severity | Issue & Fix |");
    lines.push("| :--- | :--- | :--- | :--- |");
    for (const f of report.findings) {
      const loc = `\`${escapeMdCell(f.file)}:${f.line}:${f.column}\``;
      const fixSqlPart = f.fixSql ? ` Suggested SQL: \`${escapeMdCell(f.fixSql)}\`` : "";
      const desc = `${escapeMdCell(f.message)} **Fix:** ${escapeMdCell(f.suggestion)}${fixSqlPart}`;
      lines.push(`| ${loc} | \`${f.ruleId}\` | ${formatSeverityPill(f.severity)} | ${desc} |`);
    }
    lines.push("");
  }

  lines.push(
    "_Generated locally by [`@culpritsql/ci`](https://github.com/culpritsql/culprit-ci) with zero telemetry or query uploads._",
  );
  return `${lines.join("\n")}\n`;
}

/**
 * Formats a `CiReport` as concise human-readable terminal text.
 */
export function formatText(report: CiReport): string {
  const lines: string[] = [];
  const headerStatus = report.passed ? "PASSED" : "FAILED";
  lines.push(
    `Culprit CI v${report.version}: ${headerStatus} ` +
      `(high: ${report.summary.high}, medium: ${report.summary.medium}, low: ${report.summary.low}, fail-on: ${report.failOn})`,
  );

  if (report.compareResult) {
    const cmp = report.compareResult;
    lines.push(
      `Plan Diff [${cmp.beforeName} -> ${cmp.afterName}]: ${sanitizeText(cmp.verdictSummary)}` +
        (cmp.regressed ? " [REGRESSED]" : " [OK]"),
    );
    if (cmp.explainUrl) {
      lines.push(`  Interactive Diff: ${cmp.explainUrl}`);
    }
  }

  for (const pr of report.planResults) {
    lines.push(
      `Plan [${pr.file}]: engine=${pr.engine} steps=${pr.nodeCount} cost=${pr.totalCost.toFixed(2)} scans=${pr.fullTableScans.length} spills=${pr.diskSpills.length}`,
    );
    if (pr.explainUrl) {
      lines.push(`  Interactive Plan: ${pr.explainUrl}`);
    }
  }

  if (report.findings.length > 0) {
    lines.push("");
    for (const f of report.findings as LintFinding[]) {
      lines.push(
        `${f.file}:${f.line}:${f.column} [${f.severity.toUpperCase()}] ${f.ruleId}: ${sanitizeText(f.message)}`,
      );
      lines.push(`  Fix: ${sanitizeText(f.suggestion)}`);
      if (f.fixSql) {
        lines.push(`  SQL: ${sanitizeText(f.fixSql)}`);
      }
    }
  }

  return `${lines.join("\n")}\n`;
}

/**
 * Formats a `CiReport` as JSON (omitting heavy raw parsed plan ASTs unless requested, while keeping full summaries and URLs).
 */
export function formatJson(report: CiReport): string {
  const serializable = {
    version: report.version,
    passed: report.passed,
    failOn: report.failOn,
    engine: report.engine,
    summary: report.summary,
    findings: report.findings,
    planResults: report.planResults.map(({ plan: _plan, ...rest }) => rest),
    compareResult: report.compareResult
      ? (() => {
          const { beforePlan: _a, afterPlan: _b, ...rest } = report.compareResult;
          return rest;
        })()
      : null,
  };
  return `${JSON.stringify(serializable, null, 2)}\n`;
}
