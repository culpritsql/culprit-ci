import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../src/cli.js";
import {
  analyzePlanGate,
  comparePlanGate,
  decodeShareHash,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  lintSql,
  RULES,
  runCiGate,
  STICKY_PR_COMMENT_MARKER,
  VERSION,
} from "../src/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const PG_BEFORE_SEQSCAN_PLAN = JSON.stringify([
  {
    Plan: {
      "Node Type": "Limit",
      "Startup Cost": 43201.64,
      "Total Cost": 43206.64,
      "Plan Rows": 20,
      "Plan Width": 36,
      "Actual Startup Time": 141.2,
      "Actual Total Time": 142.5,
      "Actual Rows": 20,
      "Actual Loops": 1,
      Plans: [
        {
          "Node Type": "Sort",
          "Parent Relationship": "Outer",
          "Startup Cost": 43201.64,
          "Total Cost": 43617.89,
          "Plan Rows": 166500,
          "Plan Width": 36,
          "Actual Startup Time": 141.18,
          "Actual Total Time": 142.45,
          "Actual Rows": 20,
          "Actual Loops": 1,
          "Sort Key": ["created_at DESC"],
          "Sort Method": "external merge",
          "Sort Space Used": 8192,
          "Sort Space Type": "Disk",
          Plans: [
            {
              "Node Type": "Seq Scan",
              "Parent Relationship": "Outer",
              "Relation Name": "orders",
              Alias: "o",
              "Startup Cost": 0.0,
              "Total Cost": 39100.0,
              "Plan Rows": 166500,
              "Plan Width": 36,
              "Actual Startup Time": 0.04,
              "Actual Total Time": 98.4,
              "Actual Rows": 165900,
              "Actual Loops": 1,
              Filter: "(status = 'secret-customer-token-998877'::text)",
              "Rows Removed by Filter": 834100,
            },
          ],
        },
      ],
    },
    "Planning Time": 0.35,
    "Execution Time": 145.8,
  },
]);

const PG_AFTER_INDEX_PLAN = JSON.stringify([
  {
    Plan: {
      "Node Type": "Limit",
      "Startup Cost": 0.43,
      "Total Cost": 12.85,
      "Plan Rows": 20,
      "Plan Width": 36,
      "Actual Startup Time": 0.08,
      "Actual Total Time": 0.42,
      "Actual Rows": 20,
      "Actual Loops": 1,
      Plans: [
        {
          "Node Type": "Index Scan Backward",
          "Parent Relationship": "Outer",
          "Scan Direction": "Backward",
          "Index Name": "idx_orders_status_created_at",
          "Relation Name": "orders",
          Alias: "o",
          "Startup Cost": 0.43,
          "Total Cost": 620.5,
          "Plan Rows": 1000,
          "Plan Width": 36,
          "Actual Startup Time": 0.07,
          "Actual Total Time": 0.39,
          "Actual Rows": 20,
          "Actual Loops": 1,
          "Index Cond": "(status = 'secret-customer-token-998877'::text)",
        },
      ],
    },
    "Planning Time": 0.19,
    "Execution Time": 0.48,
  },
]);

async function decompressUrlWithWebStreams(url: string): Promise<unknown> {
  const hash = url.slice(url.indexOf("#") + 1);
  const token = new URLSearchParams(hash).get("s");
  expect(token).toBeTruthy();
  expect(token?.startsWith("z1.")).toBe(true);
  const b64 = (token ?? "").slice(3);
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64.length + 3) % 4);
  const compressed = new Uint8Array(Buffer.from(padded, "base64"));

  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  await writer.write(compressed);
  await writer.close();
  const ab = await new Response(ds.readable).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(ab));
}

describe("SQL Migration Linter (MIG001..MIG006)", () => {
  test("MIG001 flags blocking CREATE INDEX across Postgres, SQL Server, and MySQL", () => {
    const pgFindings = lintSql(
      "SET lock_timeout = '3s';\nCREATE INDEX idx_orders_status ON orders (status);",
      { file: "001.sql", engine: "postgres" },
    );
    expect(pgFindings.map((f) => f.ruleId)).toEqual(["MIG001"]);
    expect(pgFindings[0].line).toBe(2);
    expect(pgFindings[0].column).toBe(1);
    expect(pgFindings[0].fixSql).toBe(
      "CREATE INDEX CONCURRENTLY idx_orders_status ON orders (status);",
    );

    const pgSafe = lintSql(
      "SET lock_timeout = '3s';\nCREATE UNIQUE INDEX CONCURRENTLY idx_orders_code ON orders (code);",
      { file: "001_safe.sql", engine: "postgres" },
    );
    expect(pgSafe).toHaveLength(0);

    const mssqlFindings = lintSql(
      "SET LOCK_TIMEOUT 3000;\nCREATE NONCLUSTERED INDEX ix_orders_status ON dbo.orders (status);",
      { file: "002_mssql.sql", engine: "mssql" },
    );
    expect(mssqlFindings.map((f) => f.ruleId)).toEqual(["MIG001"]);
    expect(mssqlFindings[0].fixSql).toContain("WITH (ONLINE = ON)");

    const mssqlSafe = lintSql(
      "SET LOCK_TIMEOUT 3000;\nCREATE NONCLUSTERED INDEX ix_orders_status ON [dbo].[orders] (status) WITH (ONLINE = ON);",
      { file: "002_mssql_safe.sql", engine: "mssql" },
    );
    expect(mssqlSafe).toHaveLength(0);

    const mysqlFindings = lintSql(
      "CREATE INDEX idx_orders_status ON `orders` (`status`);",
      { file: "003_mysql.sql", engine: "mysql" },
    );
    expect(mysqlFindings.map((f) => f.ruleId)).toEqual(["MIG001"]);
    expect(mysqlFindings[0].fixSql).toContain("ALGORITHM=INPLACE, LOCK=NONE");

    const mysqlSafe = lintSql(
      "CREATE INDEX idx_orders_status ON `orders` (`status`) ALGORITHM=INPLACE, LOCK=NONE;",
      { file: "003_mysql_safe.sql", engine: "mysql" },
    );
    expect(mysqlSafe).toHaveLength(0);
  });

  test("MIG001 & MIG006 do NOT false-positive when CREATE TABLE is in the same migration file", () => {
    const newTableMigration = [
      "CREATE TABLE public.invoices (",
      "  id bigserial PRIMARY KEY,",
      "  account_id bigint NOT NULL REFERENCES accounts(id),",
      "  status text NOT NULL",
      ");",
      "",
      "CREATE INDEX idx_invoices_account_id ON invoices (account_id);",
      "CREATE INDEX idx_invoices_status ON public.invoices (status);",
    ].join("\n");

    const findings = lintSql(newTableMigration, {
      file: "migrations/010_create_invoices.sql",
      engine: "postgres",
    });
    expect(findings).toHaveLength(0);
  });

  test("MIG002 flags CREATE INDEX CONCURRENTLY inside explicit BEGIN / START TRANSACTION block", () => {
    const sql = [
      "BEGIN;",
      "SET LOCAL lock_timeout = '2s';",
      "CREATE INDEX CONCURRENTLY idx_users_email ON users (email);",
      "COMMIT;",
    ].join("\n");

    const findings = lintSql(sql, { file: "migrations/002_tx.sql", engine: "postgres" });
    expect(findings.some((f) => f.ruleId === "MIG002")).toBe(true);
    const mig002 = findings.find((f) => f.ruleId === "MIG002")!;
    expect(mig002.severity).toBe("high");
    expect(mig002.line).toBe(3);
    expect(mig002.column).toBe(14);
  });

  test("MIG003 flags column type changes and volatile/un-defaulted NOT NULL additions, while allowing constant defaults", () => {
    const typeRewrite = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE orders ALTER COLUMN amount TYPE numeric(18, 4);",
    ].join("\n");
    const f1 = lintSql(typeRewrite, { engine: "postgres" });
    expect(f1.map((f) => f.ruleId)).toEqual(["MIG003"]);

    const missingDefault = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE orders ADD COLUMN tenant_id uuid NOT NULL;",
    ].join("\n");
    const f2 = lintSql(missingDefault, { engine: "postgres" });
    expect(f2.map((f) => f.ruleId)).toEqual(["MIG003"]);

    const volatileDefault = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE orders ADD COLUMN trace_id uuid NOT NULL DEFAULT gen_random_uuid();",
    ].join("\n");
    const f3 = lintSql(volatileDefault, { engine: "postgres" });
    expect(f3.map((f) => f.ruleId)).toEqual(["MIG003"]);

    // Fast catalog-only metadata default in Postgres 11+ must NOT false-positive
    const safeConstantDefault = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE orders ADD COLUMN archived boolean NOT NULL DEFAULT false;",
    ].join("\n");
    const fSafe = lintSql(safeConstantDefault, { engine: "postgres" });
    expect(fSafe).toHaveLength(0);
  });

  test("MIG004 flags unindexed foreign keys and clears when covered by migration or schema snapshot", () => {
    const unindexedFk = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE order_items ADD CONSTRAINT fk_order FOREIGN KEY (order_id) REFERENCES orders(id);",
    ].join("\n");
    const findings = lintSql(unindexedFk, { file: "004_fk.sql", engine: "postgres" });
    expect(findings.map((f) => f.ruleId)).toEqual(["MIG004"]);
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].fixSql).toBe(
      "CREATE INDEX CONCURRENTLY idx_order_items_order_id ON order_items (order_id);",
    );

    // Covered via schema snapshot composite index with matching leading column
    const coveredBySchema = lintSql(unindexedFk, {
      file: "004_fk.sql",
      engine: "postgres",
      schemaSql: "CREATE INDEX idx_items_order_line ON order_items (order_id, line_no);",
    });
    expect(coveredBySchema).toHaveLength(0);

    // Wrong leading column order does NOT cover the foreign key
    const wrongLeadingOrder = lintSql(unindexedFk, {
      file: "004_fk.sql",
      engine: "postgres",
      schemaSql: "CREATE INDEX idx_items_line_order ON order_items (line_no, order_id);",
    });
    expect(wrongLeadingOrder.map((f) => f.ruleId)).toEqual(["MIG004"]);
  });

  test("SQL Server GO batch separator and -- culprit-ignore-file work cleanly", () => {
    const mssqlBatches = [
      "SET LOCK_TIMEOUT 2000",
      "GO",
      "CREATE INDEX ix_accounts_email ON dbo.accounts (email)",
      "GO",
    ].join("\n");
    const findings = lintSql(mssqlBatches, { file: "batch.sql", engine: "auto" });
    expect(findings.map((f) => f.ruleId)).toEqual(["MIG001"]);
    expect(findings[0].line).toBe(3);

    const fileSuppressed = [
      "-- culprit-ignore-file: MIG001, MIG006",
      "CREATE INDEX idx_accounts_email ON accounts (email);",
    ].join("\n");
    expect(lintSql(fileSuppressed, { engine: "postgres" })).toHaveLength(0);
  });

  test("MIG005 flags DROP TABLE, DROP COLUMN, and TRUNCATE, but ignores DROP CONSTRAINT and DROP NOT NULL", () => {
    const destructive = [
      "SET lock_timeout = '3s';",
      "DROP TABLE audit_archive;",
      "ALTER TABLE users DROP COLUMN legacy_token;",
      "TRUNCATE TABLE cache_entries;",
    ].join("\n");
    const findings = lintSql(destructive, { engine: "postgres" });
    expect(findings.map((f) => f.ruleId)).toEqual(["MIG005", "MIG005", "MIG005"]);
    expect(findings.map((f) => f.line)).toEqual([2, 3, 4]);

    const nonDestructiveDrops = [
      "SET lock_timeout = '3s';",
      "ALTER TABLE users DROP CONSTRAINT chk_old_phone;",
      "ALTER TABLE users ALTER COLUMN phone DROP NOT NULL;",
      "ALTER TABLE users ALTER COLUMN nickname DROP DEFAULT;",
    ].join("\n");
    expect(lintSql(nonDestructiveDrops, { engine: "postgres" })).toHaveLength(0);
  });

  test("MIG006 flags existing-table DDL without SET lock_timeout (Postgres) or SET LOCK_TIMEOUT (SQL Server)", () => {
    const pgNoTimeout = "ALTER TABLE accounts ADD COLUMN bio text;";
    const pgRes = lintSql(pgNoTimeout, { engine: "postgres" });
    expect(pgRes.map((f) => f.ruleId)).toEqual(["MIG006"]);
    expect(pgRes[0].severity).toBe("low");
    expect(pgRes[0].fixSql).toBe("SET lock_timeout = '3s';");

    const mssqlNoTimeout = "ALTER TABLE dbo.accounts ADD bio nvarchar(200) NULL;";
    const mssqlRes = lintSql(mssqlNoTimeout, { engine: "mssql" });
    expect(mssqlRes.map((f) => f.ruleId)).toEqual(["MIG006"]);
    expect(mssqlRes[0].fixSql).toBe("SET LOCK_TIMEOUT 3000;");
  });
});

describe("SQL Query Linter (QRY001..QRY003), Lexer Safety & Ignore Pragmas", () => {
  test("QRY001 catches UPDATE and DELETE without top-level WHERE, even with subquery WHERE", () => {
    const sql = [
      "UPDATE users SET active = false;",
      "DELETE FROM sessions;",
      "UPDATE users SET tier = (SELECT code FROM tiers WHERE id = 1);",
      "DELETE FROM sessions WHERE expires_at < now();",
    ].join("\n");
    const findings = lintSql(sql, { file: "queries.sql", mode: "query", engine: "postgres" });
    expect(findings.map((f) => f.ruleId)).toEqual(["QRY001", "QRY001", "QRY001"]);
    expect(findings.map((f) => f.line)).toEqual([1, 2, 3]);
  });

  test("QRY002 catches non-sargable column functions in WHERE without false-positiving RHS constants", () => {
    const sql = [
      "SELECT id FROM users WHERE LOWER(email) = 'alice@example.com';",
      "SELECT id FROM orders WHERE DATE(created_at) = '2026-05-01';",
      "SELECT id FROM orders WHERE YEAR(created_at) = 2026;",
      "SELECT id FROM orders WHERE CAST(external_id AS bigint) = 42;",
      "SELECT id FROM users WHERE email = LOWER('Alice@Example.com');",
    ].join("\n");
    const findings = lintSql(sql, { file: "search.sql", mode: "query", engine: "postgres" });
    expect(findings.map((f) => f.ruleId)).toEqual(["QRY002", "QRY002", "QRY002", "QRY002"]);
    expect(findings.map((f) => f.line)).toEqual([1, 2, 3, 4]);
    expect(findings[0].column).toBe(28);
  });

  test("QRY003 catches leading wildcard LIKE/ILIKE while allowing trailing prefix seeks", () => {
    const sql = [
      "SELECT * FROM products WHERE sku LIKE 'PRD-%';",
      "SELECT * FROM products WHERE name ILIKE '%widget%';",
      "SELECT * FROM users WHERE email LIKE '%.org';",
    ].join("\n");
    const findings = lintSql(sql, { file: "wildcard.sql", mode: "query", engine: "postgres" });
    expect(findings.map((f) => f.ruleId)).toEqual(["QRY003", "QRY003"]);
    expect(findings.map((f) => f.line)).toEqual([2, 3]);
  });

  test("Comments, string literals, and dollar-quoted function bodies never trigger false positives", () => {
    const trickySql = [
      "-- DROP TABLE users; DELETE FROM accounts;",
      "/* Nested /* block DROP TABLE secrets; */ comment */",
      "SELECT 'DELETE FROM users; DROP TABLE orders; LIKE ''%bad''' AS example;",
      "CREATE OR REPLACE FUNCTION cleanup_tmp() RETURNS void AS $body$",
      "BEGIN",
      "  DELETE FROM temp_events;",
      "  TRUNCATE staging_buf;",
      "END;",
      "$body$ LANGUAGE plpgsql;",
    ].join("\n");

    const findings = lintSql(trickySql, { file: "safe.sql", engine: "postgres" });
    expect(findings).toHaveLength(0);
  });

  test("-- culprit-ignore suppresses rules cleanly before statement or inline after semicolon", () => {
    const sql = [
      "SET lock_timeout = '3s';",
      "-- culprit-ignore: MIG005",
      "DROP TABLE old_events;",
      "DELETE FROM temp_tokens; -- culprit-ignore: QRY001",
    ].join("\n");

    const findings = lintSql(sql, { file: "cleanup.sql", engine: "postgres" });
    expect(findings).toHaveLength(0);
  });
});

describe("Execution Plan Gate, Share Link Compression & SARIF 2.1.0", () => {
  test("analyzePlanGate detects Seq Scan, disk Sort spill, cost budget, and scrubs SQL literals", async () => {
    const gate = await analyzePlanGate(PG_BEFORE_SEQSCAN_PLAN, {
      file: "plans/slow.json",
      maxCost: 1000,
    });

    expect(gate.passed).toBe(false);
    expect(gate.engine).toBe("postgres");
    expect(gate.fullTableScans.length).toBeGreaterThanOrEqual(1);
    expect(gate.diskSpills.length).toBeGreaterThanOrEqual(1);
    expect(gate.findings.some((f) => f.ruleId === "PLAN001")).toBe(true);
    expect(gate.findings.some((f) => f.ruleId === "PLAN002")).toBe(true);
    expect(gate.findings.some((f) => f.ruleId === "PLAN004")).toBe(true);

    expect(gate.explainUrl).toBeTruthy();
    expect(gate.explainUrl?.startsWith("https://explain.culpritsql.com/#s=z1.")).toBe(true);

    const decoded = decodeShareHash(gate.explainUrl!);
    expect(decoded).not.toBeNull();
    expect(decoded?.v).toBe(1);
    expect(decoded?.m).toBe("plan");
    expect(decoded?.p).not.toContain("secret-customer-token-998877");

    // Also verify SQL Server .sqlplan XML parsing & native Showplan literal redaction
    const mssqlXml = `<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan"><BatchSequence><Batch><Statements><StmtSimple StatementType="SELECT" StatementText="SELECT * FROM dbo.orders WHERE secret = 'mssql-private-key-42'" StatementSubTreeCost="14.5" StatementEstRows="500"><QueryPlan><RelOp NodeId="0" PhysicalOp="Table Scan" LogicalOp="Table Scan" EstimateRows="500" EstimatedTotalSubtreeCost="14.5"><TableScan Ordered="0"><Object Database="[app]" Schema="[dbo]" Table="[orders]"/></TableScan></RelOp></QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>`;
    const mssqlGate = await analyzePlanGate(mssqlXml, { file: "query.sqlplan" });
    expect(mssqlGate.engine).toBe("mssql");
    expect(mssqlGate.fullTableScans).toHaveLength(1);
    expect(mssqlGate.explainUrl?.startsWith("https://explain.culpritsql.com/#s=z1.")).toBe(true);
    const mssqlDecoded = decodeShareHash(mssqlGate.explainUrl!);
    expect(mssqlDecoded?.p).not.toContain("mssql-private-key-42");

    // Also verify SQLite EXPLAIN QUERY PLAN support
    const sqlitePlan = "QUERY PLAN\n`--SCAN invoices";
    const sqliteGate = await analyzePlanGate(sqlitePlan, { file: "sqlite.txt", engine: "sqlite" });
    expect(sqliteGate.engine).toBe("sqlite");
    expect(sqliteGate.fullTableScans).toHaveLength(1);
  });

  test("comparePlanGate verifies speedup, detects regression when reversed, and roundtrips Web DecompressionStream", async () => {
    const improvement = await comparePlanGate(PG_BEFORE_SEQSCAN_PLAN, PG_AFTER_INDEX_PLAN, {
      beforeName: "Before Index",
      afterName: "After Index",
    });

    expect(improvement.passed).toBe(true);
    expect(improvement.regressed).toBe(false);
    expect(improvement.speedupFactor).not.toBeNull();
    expect(improvement.speedupFactor!).toBeGreaterThan(100);
    expect(improvement.verdictSummary).toContain("faster");
    expect(improvement.explainUrl?.startsWith("https://explain.culpritsql.com/#s=z1.")).toBe(true);

    // Verify browser compatibility via Web DecompressionStream("deflate-raw")
    const webDecoded = (await decompressUrlWithWebStreams(improvement.explainUrl!)) as Record<
      string,
      unknown
    >;
    expect(webDecoded.v).toBe(1);
    expect(webDecoded.m).toBe("compare");
    expect(webDecoded.na).toBe("Before Index");
    expect(webDecoded.nb).toBe("After Index");
    expect(String(webDecoded.pa)).not.toContain("secret-customer-token-998877");
    expect(String(webDecoded.pb)).not.toContain("secret-customer-token-998877");

    // Reversing Before and After must fail the gate with regression details
    const regression = await comparePlanGate(PG_AFTER_INDEX_PLAN, PG_BEFORE_SEQSCAN_PLAN, {
      beforeName: "Baseline",
      afterName: "Regressed PR",
    });
    expect(regression.passed).toBe(false);
    expect(regression.regressed).toBe(true);
    expect(regression.regressionReasons.length).toBeGreaterThan(0);
    expect(regression.findings.some((f) => f.ruleId === "PLAN005")).toBe(true);
  });

  test("formatSarif emits valid SARIF 2.1.0 with 1-based physicalLocation regions and formatMarkdown emits PR comment", async () => {
    const tmpDir = await mkdtemp(path.join(os.tmpdir(), "culprit-ci-test-"));
    try {
      const migDir = path.join(tmpDir, "migrations");
      await writeFile(path.join(tmpDir, "before.json"), PG_BEFORE_SEQSCAN_PLAN, "utf8");
      await writeFile(path.join(tmpDir, "after.json"), PG_AFTER_INDEX_PLAN, "utf8");
      await stat(tmpDir);
      await import("node:fs/promises").then((fs) => fs.mkdir(migDir, { recursive: true }));
      await writeFile(
        path.join(migDir, "001_idx.sql"),
        [
          "SET lock_timeout = '3s';",
          "  CREATE INDEX idx_users_org ON users (org_id);",
        ].join("\n"),
        "utf8",
      );

      const report = await runCiGate({
        cwd: tmpDir,
        sqlPatterns: ["migrations/*.sql"],
        comparePlans: { beforeFile: "before.json", afterFile: "after.json" },
        engine: "postgres",
        failOn: "high",
      });

      expect(report.passed).toBe(false);
      expect(report.summary.high).toBe(1);

      const sarif = JSON.parse(formatSarif(report));
      expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.version).toBe(VERSION);
      expect(sarif.runs[0].tool.driver.rules[0].id).toBe("MIG001");
      expect(sarif.runs[0].results).toHaveLength(1);

      const res0 = sarif.runs[0].results[0];
      expect(res0.ruleId).toBe("MIG001");
      expect(res0.level).toBe("error");
      expect(res0.locations[0].physicalLocation.artifactLocation.uri).toBe("migrations/001_idx.sql");
      expect(res0.locations[0].physicalLocation.region).toEqual({
        startLine: 2,
        startColumn: 3,
        endLine: 2,
        endColumn: 48,
      });

      const md = formatMarkdown(report);
      expect(md.startsWith(STICKY_PR_COMMENT_MARKER)).toBe(true);
      expect(md).toContain("Open Interactive Diff in Culprit Explain");
      expect(md).toContain("https://explain.culpritsql.com/#s=z1.");
      expect(md).toContain("`migrations/001_idx.sql:2:3`");

      const txt = formatText(report);
      expect(txt).toContain("FAILED");
      const jsonOut = JSON.parse(formatJson(report));
      expect(jsonOut.summary.high).toBe(1);
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("CLI Execution & Repository Hygiene", () => {
  test("runCli and built dist/cli.js return clean 0, 1, and 2 exit codes", async () => {
    const tmpDir = await mkdtemp(path.join(os.tmpdir(), "culprit-cli-test-"));
    try {
      await writeFile(
        path.join(tmpDir, "safe.sql"),
        "SET lock_timeout = '3s';\nCREATE INDEX CONCURRENTLY idx_t_a ON t (a);\n",
        "utf8",
      );
      await writeFile(
        path.join(tmpDir, "unsafe.sql"),
        "DELETE FROM users;\n",
        "utf8",
      );

      let out = "";
      let err = "";
      const codePass = await runCli(
        [
          "--sql",
          "safe.sql",
          "--engine",
          "postgres",
          "--sarif",
          "out.sarif",
          "--markdown-out",
          "out.md",
        ],
        {
          cwd: tmpDir,
          stdout: (s) => {
            out += s;
          },
          stderr: (s) => {
            err += s;
          },
        },
      );
      expect(codePass).toBe(0);
      expect(err).toBe("");
      expect(out).toContain("PASSED");
      const sarifDisk = JSON.parse(await readFile(path.join(tmpDir, "out.sarif"), "utf8"));
      expect(sarifDisk.version).toBe("2.1.0");

      const codeFail = await runCli(["--queries", "unsafe.sql", "--fail-on", "high"], {
        cwd: tmpDir,
        stdout: () => {},
        stderr: () => {},
      });
      expect(codeFail).toBe(1);

      const codeBadArg = await runCli(["--unknown-flag"], {
        cwd: tmpDir,
        stdout: () => {},
        stderr: () => {},
      });
      expect(codeBadArg).toBe(2);

      // Verify compiled dist/cli.js binary has shebang, executable mode, and runs via Node
      const distCli = path.join(REPO_ROOT, "dist", "cli.js");
      const cliStat = await stat(distCli);
      expect((cliStat.mode & 0o111) !== 0).toBe(true);
      const cliHead = (await readFile(distCli, "utf8")).slice(0, 40);
      expect(cliHead.startsWith("#!/usr/bin/env node")).toBe(true);

      const proc = spawnSync(process.execPath, [distCli, "--queries", "unsafe.sql", "--format", "json"], {
        cwd: tmpDir,
        encoding: "utf8",
      });
      expect(proc.status).toBe(1);
      const parsedStdOut = JSON.parse(proc.stdout);
      expect(parsedStdOut.findings[0].ruleId).toBe("QRY001");
    } finally {
      await rm(tmpDir, { recursive: true, force: true });
    }
  });

  test("All repository files contain zero em dashes and zero host paths", async () => {
    const emDash = String.fromCharCode(0x2014);
    const forbiddenPrefixes = [
      ["", "Users", ""].join("/"),
      ["", "tmp", ""].join("/"),
    ];
    expect(Object.keys(RULES).length).toBeGreaterThanOrEqual(14);

    async function collectFiles(dir: string): Promise<string[]> {
      const entries = await readdir(dir, { withFileTypes: true });
      const files: string[] = [];
      for (const e of entries) {
        if (e.name === "node_modules" || e.name === ".git") continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          files.push(...(await collectFiles(full)));
        } else if (e.isFile()) {
          files.push(full);
        }
      }
      return files;
    }

    const allFiles = await collectFiles(REPO_ROOT);
    expect(allFiles.length).toBeGreaterThan(10);
    for (const f of allFiles) {
      const content = await readFile(f, "utf8");
      const rel = path.relative(REPO_ROOT, f);
      expect(content.includes(emDash)).toBe(false);
      for (const prefix of forbiddenPrefixes) {
        if (content.includes(prefix)) {
          throw new Error(`Forbidden host path prefix found in ${rel}`);
        }
      }
    }
  });
});
