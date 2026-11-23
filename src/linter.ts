import {
  type ParsedStatement,
  type SqlToken,
  splitSqlStatements,
  unquoteSqlString,
} from "./lexer.js";
import type {
  LintFinding,
  LintMode,
  LintOptions,
  ResolvedSqlEngine,
  RuleMeta,
  SqlEngine,
} from "./types.js";

const DOCS_BASE = "https://github.com/culpritsql/culprit-ci#rule-reference";

export const RULES: Record<string, RuleMeta> = {
  MIG001: {
    id: "MIG001",
    severity: "high",
    category: "migration",
    title: "Index creation blocks writes on existing table",
    description:
      "CREATE INDEX without an online build clause holds locks that block concurrent INSERT, UPDATE, and DELETE traffic on existing tables.",
    helpUri: `${DOCS_BASE}`,
  },
  MIG002: {
    id: "MIG002",
    severity: "high",
    category: "migration",
    title: "CREATE INDEX CONCURRENTLY inside transaction block",
    description:
      "PostgreSQL forbids running CREATE INDEX CONCURRENTLY or DROP INDEX CONCURRENTLY inside an explicit BEGIN / START TRANSACTION block.",
    helpUri: `${DOCS_BASE}`,
  },
  MIG003: {
    id: "MIG003",
    severity: "high",
    category: "migration",
    title: "Hazardous column type rewrite or volatile NOT NULL addition",
    description:
      "Altering an existing column's data type or adding a NOT NULL column without a safe constant default rewrites the table under an exclusive lock.",
    helpUri: `${DOCS_BASE}`,
  },
  MIG004: {
    id: "MIG004",
    severity: "medium",
    category: "migration",
    title: "Unindexed foreign key constraint",
    description:
      "Adding a FOREIGN KEY without an index on its referencing column(s) causes sequential scans during parent-row UPDATE/DELETE cascades and joins.",
    helpUri: `${DOCS_BASE}`,
  },
  MIG005: {
    id: "MIG005",
    severity: "high",
    category: "migration",
    title: "Destructive DROP or TRUNCATE without explicit ignore pragma",
    description:
      "DROP TABLE, DROP COLUMN, and TRUNCATE permanently destroy data and break backward-compatible rolling deployments unless explicitly acknowledged.",
    helpUri: `${DOCS_BASE}`,
  },
  MIG006: {
    id: "MIG006",
    severity: "low",
    category: "migration",
    title: "DDL on existing table without lock_timeout guard",
    description:
      "Acquiring DDL locks without SET lock_timeout (PostgreSQL) or SET LOCK_TIMEOUT (SQL Server) can queue behind a long query and stall all subsequent traffic.",
    helpUri: `${DOCS_BASE}`,
  },
  QRY001: {
    id: "QRY001",
    severity: "high",
    category: "query",
    title: "UPDATE or DELETE without WHERE clause",
    description:
      "Executing an UPDATE or DELETE statement with no top-level WHERE predicate mutates or deletes every row in the target table.",
    helpUri: `${DOCS_BASE}`,
  },
  QRY002: {
    id: "QRY002",
    severity: "medium",
    category: "query",
    title: "Non-sargable function wrapping column in WHERE",
    description:
      "Wrapping an indexed column in LOWER(), UPPER(), DATE(), YEAR(), or CAST() inside WHERE prevents standard B-tree index seeks.",
    helpUri: `${DOCS_BASE}`,
  },
  QRY003: {
    id: "QRY003",
    severity: "low",
    category: "query",
    title: "Leading wildcard LIKE / ILIKE predicate",
    description:
      "A pattern starting with '%' (such as LIKE '%term') cannot use a standard B-tree index for range seeks and forces a scan.",
    helpUri: `${DOCS_BASE}`,
  },
  PLAN001: {
    id: "PLAN001",
    severity: "medium",
    category: "plan",
    title: "Full table scan detected in execution plan",
    description:
      "An execution plan operator scans an entire table without an index seek.",
    helpUri: `${DOCS_BASE}`,
  },
  PLAN002: {
    id: "PLAN002",
    severity: "high",
    category: "plan",
    title: "Operator spilled intermediate data to disk",
    description:
      "Sort, Hash, or Exchange operator exceeded memory allocation and spilled temporary pages to disk.",
    helpUri: `${DOCS_BASE}`,
  },
  PLAN003: {
    id: "PLAN003",
    severity: "high",
    category: "plan",
    title: "Execution plan bottleneck insight",
    description:
      "Culprit's WebAssembly plan analyzer surfaced a high-impact execution bottleneck.",
    helpUri: `${DOCS_BASE}`,
  },
  PLAN004: {
    id: "PLAN004",
    severity: "high",
    category: "plan",
    title: "Execution plan exceeded maximum cost threshold",
    description:
      "Total optimizer subtree cost exceeded the configured CI budget.",
    helpUri: `${DOCS_BASE}`,
  },
  PLAN005: {
    id: "PLAN005",
    severity: "high",
    category: "plan",
    title: "Execution plan regression between baseline and candidate",
    description:
      "Candidate execution plan regressed in runtime, optimizer cost, access path, or spill warnings compared to the baseline plan.",
    helpUri: `${DOCS_BASE}`,
  },
};

const NON_SARGABLE_FUNCTIONS = new Set([
  "LOWER",
  "UPPER",
  "DATE",
  "YEAR",
  "MONTH",
  "DAY",
  "TRIM",
  "LTRIM",
  "RTRIM",
  "BTRIM",
  "SUBSTRING",
  "SUBSTR",
  "LEFT",
  "COALESCE",
]);

const VOLATILE_DEFAULT_FUNCTIONS = new Set([
  "RANDOM",
  "GEN_RANDOM_UUID",
  "UUID_GENERATE_V4",
  "UUID_GENERATE_V1",
  "CLOCK_TIMESTAMP",
  "TIMEofday",
  "TIMEOFDAY",
  "NEWID",
  "UUID",
  "RAND",
]);

const COMPARISON_OPS = new Set(["=", "!=", "<>", "<", ">", "<=", ">="]);

function isIdentifierToken(tok: SqlToken | undefined): boolean {
  if (!tok) return false;
  return tok.kind === "word" || tok.kind === "quoted_ident";
}

interface ParsedQualifiedName {
  full: string;
  bare: string;
  rawDisplay: string;
  nextIndex: number;
}

/**
 * Reads an optional `schema.object` or `db.schema.object` identifier chain starting at `startIdx`.
 */
function readQualifiedName(tokens: SqlToken[], startIdx: number): ParsedQualifiedName | null {
  let idx = startIdx;
  if (tokens[idx]?.upper === "ONLY") {
    idx += 1;
  }
  const parts: string[] = [];
  const rawParts: string[] = [];
  if (!isIdentifierToken(tokens[idx])) {
    return null;
  }
  parts.push(tokens[idx].ident);
  rawParts.push(tokens[idx].raw);
  idx += 1;

  while (idx + 1 < tokens.length && tokens[idx].raw === "." && isIdentifierToken(tokens[idx + 1])) {
    parts.push(tokens[idx + 1].ident);
    rawParts.push(tokens[idx + 1].raw);
    idx += 2;
  }

  const bare = parts[parts.length - 1];
  const full = parts.length >= 2 ? `${parts[parts.length - 2]}.${bare}` : bare;
  return {
    full,
    bare,
    rawDisplay: rawParts.join("."),
    nextIndex: idx,
  };
}

class TableSet {
  private readonly names = new Set<string>();

  add(name: ParsedQualifiedName): void {
    this.names.add(name.full);
    this.names.add(name.bare);
  }

  has(name: ParsedQualifiedName): boolean {
    return this.names.has(name.full) || this.names.has(name.bare);
  }
}

class TableIndexRegistry {
  private readonly byTable = new Map<string, string[][]>();

  add(tableKey: string, cols: string[]): void {
    if (cols.length === 0) return;
    const normalizedCols = cols.map((c) => c.toLowerCase());
    const keys = new Set<string>([tableKey.toLowerCase()]);
    const dot = tableKey.lastIndexOf(".");
    if (dot >= 0) {
      keys.add(tableKey.slice(dot + 1).toLowerCase());
    }
    for (const k of keys) {
      const list = this.byTable.get(k) ?? [];
      list.push(normalizedCols);
      this.byTable.set(k, list);
    }
  }

  coversForeignKey(table: ParsedQualifiedName, fkCols: string[]): boolean {
    if (fkCols.length === 0) return true;
    const target = fkCols.map((c) => c.toLowerCase());
    const candidates = [
      ...(this.byTable.get(table.full) ?? []),
      ...(this.byTable.get(table.bare) ?? []),
    ];
    for (const idxCols of candidates) {
      if (idxCols.length < target.length) continue;
      let prefixMatch = true;
      for (let i = 0; i < target.length; i++) {
        if (idxCols[i] !== target[i]) {
          prefixMatch = false;
          break;
        }
      }
      if (prefixMatch) return true;
    }
    return false;
  }
}

/**
 * Extracts a parenthesized list of column identifiers starting at `openParenIdx`.
 * Handles `(col1, col2 DESC, LOWER(col3))` by extracting leading column names.
 */
function parseParenColumnList(
  tokens: SqlToken[],
  openParenIdx: number,
): { columns: string[]; closeParenIdx: number } | null {
  if (tokens[openParenIdx]?.raw !== "(") return null;
  const columns: string[] = [];
  let depth = 1;
  let i = openParenIdx + 1;
  let segTokens: SqlToken[] = [];

  const flushSegment = (): void => {
    if (segTokens.length === 0) return;
    // Simple column: `col` or `col ASC` or `col DESC`
    if (isIdentifierToken(segTokens[0]) && segTokens[1]?.raw !== "(") {
      columns.push(segTokens[0].ident);
    } else if (
      segTokens.length >= 4 &&
      isIdentifierToken(segTokens[0]) &&
      segTokens[1]?.raw === "(" &&
      isIdentifierToken(segTokens[2])
    ) {
      // Expression index e.g. LOWER(email)
      columns.push(segTokens[2].ident);
    }
    segTokens = [];
  };

  while (i < tokens.length && depth > 0) {
    const tok = tokens[i];
    if (tok.raw === "(") {
      if (depth === 1) segTokens.push(tok);
      depth += 1;
    } else if (tok.raw === ")") {
      depth -= 1;
      if (depth === 0) {
        flushSegment();
        return { columns, closeParenIdx: i };
      }
      if (depth === 1) segTokens.push(tok);
    } else if (tok.raw === "," && depth === 1) {
      flushSegment();
    } else if (depth === 1) {
      segTokens.push(tok);
    } else if (depth === 2 && segTokens.length > 0) {
      segTokens.push(tok);
    }
    i += 1;
  }

  return null;
}

export function detectSqlEngine(tokens: SqlToken[], configured: SqlEngine = "auto"): ResolvedSqlEngine {
  if (configured === "postgres" || configured === "yugabyte") return "postgres";
  if (configured === "mssql") return "mssql";
  if (configured === "mysql") return "mysql";
  if (configured === "sqlite") return "sqlite";

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.kind === "quoted_ident") {
      if (t.raw.startsWith("[")) return "mssql";
      if (t.raw.startsWith("`")) return "mysql";
    }
    if (t.kind === "punct" && t.raw === "::") return "postgres";
    if (t.kind === "string" && t.raw.startsWith("$")) return "postgres";
    if (t.kind === "word") {
      if (
        t.upper === "CONCURRENTLY" ||
        t.upper === "TIMESTAMPTZ" ||
        t.upper === "JSONB" ||
        t.upper === "BIGSERIAL" ||
        t.upper === "ILIKE"
      ) {
        return "postgres";
      }
      if (
        t.upper === "NONCLUSTERED" ||
        t.upper === "CLUSTERED" ||
        t.upper === "NVARCHAR" ||
        (t.upper === "GO" && (i === 0 || tokens[i - 1].endLine < t.line))
      ) {
        return "mssql";
      }
      if (t.upper === "AUTO_INCREMENT" || t.upper === "INPLACE") {
        return "mysql";
      }
      if (t.upper === "AUTOINCREMENT" || t.upper === "PRAGMA") {
        return "sqlite";
      }
    }
  }

  return "postgres";
}

interface ParsedFkRef {
  table: ParsedQualifiedName;
  columns: string[];
  token: SqlToken;
  endToken: SqlToken;
}

function collectSchemaFactsFromStatements(
  statements: ParsedStatement[],
  indexRegistry: TableIndexRegistry,
): ParsedFkRef[] {
  const foreignKeys: ParsedFkRef[] = [];

  for (const stmt of statements) {
    const toks = stmt.tokens;
    if (toks.length === 0) continue;

    // 1. CREATE [UNIQUE] [CLUSTERED|NONCLUSTERED] INDEX ... ON table (cols)
    if (toks[0].upper === "CREATE") {
      let idx = 1;
      if (toks[idx]?.upper === "UNIQUE") idx += 1;
      if (
        toks[idx]?.upper === "CLUSTERED" ||
        toks[idx]?.upper === "NONCLUSTERED" ||
        toks[idx]?.upper === "FULLTEXT" ||
        toks[idx]?.upper === "SPATIAL"
      ) {
        idx += 1;
      }
      if (toks[idx]?.upper === "INDEX") {
        // Scan for ON <tableName> [USING <method>] (<cols>)
        for (let j = idx + 1; j < toks.length; j++) {
          if (toks[j].upper === "ON") {
            const tbl = readQualifiedName(toks, j + 1);
            if (tbl) {
              let afterTbl = tbl.nextIndex;
              if (toks[afterTbl]?.upper === "USING" && isIdentifierToken(toks[afterTbl + 1])) {
                afterTbl += 2;
              }
              const colList = parseParenColumnList(toks, afterTbl);
              if (colList && colList.columns.length > 0) {
                indexRegistry.add(tbl.full, colList.columns);
              }
            }
            break;
          }
        }
      }
    }

    // 2. CREATE [TEMP|TEMPORARY|UNLOGGED] TABLE [IF NOT EXISTS] <table> (...)
    if (toks[0].upper === "CREATE") {
      let idx = 1;
      if (
        toks[idx]?.upper === "TEMP" ||
        toks[idx]?.upper === "TEMPORARY" ||
        toks[idx]?.upper === "UNLOGGED"
      ) {
        idx += 1;
      }
      if (toks[idx]?.upper === "TABLE") {
        idx += 1;
        if (
          toks[idx]?.upper === "IF" &&
          toks[idx + 1]?.upper === "NOT" &&
          toks[idx + 2]?.upper === "EXISTS"
        ) {
          idx += 3;
        }
        const tbl = readQualifiedName(toks, idx);
        if (tbl && toks[tbl.nextIndex]?.raw === "(") {
          scanCreateTableElements(toks, tbl.nextIndex, tbl, indexRegistry, foreignKeys);
        }
      }
    }

    // 3. ALTER TABLE [IF EXISTS] [ONLY] <table> ...
    if (toks[0].upper === "ALTER" && toks[1]?.upper === "TABLE") {
      let idx = 2;
      if (toks[idx]?.upper === "IF" && toks[idx + 1]?.upper === "EXISTS") {
        idx += 2;
      }
      const tbl = readQualifiedName(toks, idx);
      if (tbl) {
        scanAlterTableConstraints(toks, tbl.nextIndex, tbl, indexRegistry, foreignKeys);
      }
    }
  }

  return foreignKeys;
}

function splitTopLevelParenClauses(tokens: SqlToken[], openParenIdx: number): SqlToken[][] {
  if (tokens[openParenIdx]?.raw !== "(") return [];
  const clauses: SqlToken[][] = [];
  let current: SqlToken[] = [];
  let depth = 1;
  let i = openParenIdx + 1;
  while (i < tokens.length && depth > 0) {
    const tok = tokens[i];
    if (tok.raw === "(") {
      depth += 1;
      current.push(tok);
    } else if (tok.raw === ")") {
      depth -= 1;
      if (depth === 0) {
        if (current.length > 0) clauses.push(current);
        break;
      }
      current.push(tok);
    } else if (tok.raw === "," && depth === 1) {
      if (current.length > 0) clauses.push(current);
      current = [];
    } else {
      current.push(tok);
    }
    i += 1;
  }
  return clauses;
}

function scanCreateTableElements(
  tokens: SqlToken[],
  openParenIdx: number,
  table: ParsedQualifiedName,
  indexRegistry: TableIndexRegistry,
  foreignKeys: ParsedFkRef[],
): void {
  const elements = splitTopLevelParenClauses(tokens, openParenIdx);
  for (const elem of elements) {
    if (elem.length === 0) continue;
    let start = 0;
    if (elem[0].upper === "CONSTRAINT" && isIdentifierToken(elem[1])) {
      start = 2;
    }

    // Table-level PRIMARY KEY (cols) or UNIQUE (cols) or INDEX idx (cols)
    if (elem[start]?.upper === "PRIMARY" && elem[start + 1]?.upper === "KEY") {
      let pIdx = start + 2;
      if (elem[pIdx]?.upper === "CLUSTERED" || elem[pIdx]?.upper === "NONCLUSTERED") pIdx += 1;
      const cols = parseParenColumnList(elem, pIdx);
      if (cols) indexRegistry.add(table.full, cols.columns);
      continue;
    }
    if (elem[start]?.upper === "UNIQUE") {
      let uIdx = start + 1;
      if (elem[uIdx]?.upper === "INDEX" || elem[uIdx]?.upper === "KEY") uIdx += 1;
      if (isIdentifierToken(elem[uIdx]) && elem[uIdx + 1]?.raw === "(") uIdx += 1;
      const cols = parseParenColumnList(elem, uIdx);
      if (cols) indexRegistry.add(table.full, cols.columns);
      continue;
    }
    if ((elem[start]?.upper === "INDEX" || elem[start]?.upper === "KEY") && elem.length >= start + 2) {
      let kIdx = start + 1;
      if (isIdentifierToken(elem[kIdx])) kIdx += 1;
      const cols = parseParenColumnList(elem, kIdx);
      if (cols) indexRegistry.add(table.full, cols.columns);
      continue;
    }

    // Table-level FOREIGN KEY (cols) REFERENCES ...
    if (elem[start]?.upper === "FOREIGN" && elem[start + 1]?.upper === "KEY") {
      const cols = parseParenColumnList(elem, start + 2);
      if (cols && cols.columns.length > 0) {
        foreignKeys.push({
          table,
          columns: cols.columns,
          token: elem[0],
          endToken: elem[elem.length - 1],
        });
      }
      continue;
    }

    // Column-level definition: `<col_name> <type> ...`
    if (
      isIdentifierToken(elem[0]) &&
      elem[0].upper !== "CHECK" &&
      elem[0].upper !== "EXCLUDE" &&
      elem[0].upper !== "PERIOD"
    ) {
      const colName = elem[0].ident;
      for (let k = 1; k < elem.length; k++) {
        if (elem[k].upper === "PRIMARY" && elem[k + 1]?.upper === "KEY") {
          indexRegistry.add(table.full, [colName]);
        } else if (elem[k].upper === "UNIQUE") {
          indexRegistry.add(table.full, [colName]);
        } else if (elem[k].upper === "REFERENCES") {
          foreignKeys.push({
            table,
            columns: [colName],
            token: elem[0],
            endToken: elem[elem.length - 1],
          });
        }
      }
    }
  }
}

function scanAlterTableConstraints(
  tokens: SqlToken[],
  startIdx: number,
  table: ParsedQualifiedName,
  indexRegistry: TableIndexRegistry,
  foreignKeys: ParsedFkRef[],
): void {
  for (let i = startIdx; i < tokens.length; i++) {
    if (tokens[i].upper === "PRIMARY" && tokens[i + 1]?.upper === "KEY") {
      let pIdx = i + 2;
      if (tokens[pIdx]?.upper === "CLUSTERED" || tokens[pIdx]?.upper === "NONCLUSTERED") pIdx += 1;
      const cols = parseParenColumnList(tokens, pIdx);
      if (cols) indexRegistry.add(table.full, cols.columns);
    } else if (tokens[i].upper === "UNIQUE") {
      let uIdx = i + 1;
      if (tokens[uIdx]?.upper === "INDEX" || tokens[uIdx]?.upper === "KEY") uIdx += 1;
      if (isIdentifierToken(tokens[uIdx]) && tokens[uIdx + 1]?.raw === "(") uIdx += 1;
      const cols = parseParenColumnList(tokens, uIdx);
      if (cols) indexRegistry.add(table.full, cols.columns);
    } else if (tokens[i].upper === "FOREIGN" && tokens[i + 1]?.upper === "KEY") {
      const cols = parseParenColumnList(tokens, i + 2);
      if (cols && cols.columns.length > 0) {
        foreignKeys.push({
          table,
          columns: cols.columns,
          token: tokens[i],
          endToken: tokens[tokens.length - 1],
        });
      }
    } else if (tokens[i].upper === "ADD") {
      let aIdx = i + 1;
      if (tokens[aIdx]?.upper === "COLUMN") aIdx += 1;
      if (
        tokens[aIdx]?.upper === "IF" &&
        tokens[aIdx + 1]?.upper === "NOT" &&
        tokens[aIdx + 2]?.upper === "EXISTS"
      ) {
        aIdx += 3;
      }
      if (
        isIdentifierToken(tokens[aIdx]) &&
        tokens[aIdx].upper !== "CONSTRAINT" &&
        tokens[aIdx].upper !== "FOREIGN" &&
        tokens[aIdx].upper !== "PRIMARY" &&
        tokens[aIdx].upper !== "UNIQUE" &&
        tokens[aIdx].upper !== "CHECK" &&
        tokens[aIdx].upper !== "INDEX"
      ) {
        const colName = tokens[aIdx].ident;
        // Scan until top-level comma or end of statement for inline REFERENCES / PRIMARY KEY / UNIQUE
        let depth = 0;
        for (let k = aIdx + 1; k < tokens.length; k++) {
          if (tokens[k].raw === "(") depth += 1;
          else if (tokens[k].raw === ")") depth = Math.max(0, depth - 1);
          else if (tokens[k].raw === "," && depth === 0) break;

          if (depth === 0) {
            if (tokens[k].upper === "PRIMARY" && tokens[k + 1]?.upper === "KEY") {
              indexRegistry.add(table.full, [colName]);
            } else if (tokens[k].upper === "UNIQUE") {
              indexRegistry.add(table.full, [colName]);
            } else if (tokens[k].upper === "REFERENCES") {
              foreignKeys.push({
                table,
                columns: [colName],
                token: tokens[i],
                endToken: tokens[k + 1] ?? tokens[k],
              });
              break;
            }
          }
        }
      }
    }
  }
}

function hasOnlineIndexOption(tokens: SqlToken[], engine: ResolvedSqlEngine, autoMode: boolean): boolean {
  const hasConcurrently = tokens.some((t) => t.upper === "CONCURRENTLY");
  const hasMssqlOnline = tokens.some(
    (t, i) => t.upper === "ONLINE" && tokens[i + 1]?.raw === "=" && tokens[i + 2]?.upper === "ON",
  );
  const hasMysqlOnline = tokens.some(
    (t, i) =>
      (t.upper === "LOCK" &&
        ((tokens[i + 1]?.raw === "=" && tokens[i + 2]?.upper === "NONE") ||
          tokens[i + 1]?.upper === "NONE")) ||
      (t.upper === "ALGORITHM" &&
        ((tokens[i + 1]?.raw === "=" &&
          (tokens[i + 2]?.upper === "INPLACE" || tokens[i + 2]?.upper === "INSTANT")) ||
          tokens[i + 1]?.upper === "INPLACE" ||
          tokens[i + 1]?.upper === "INSTANT")),
  );

  if (autoMode) {
    return hasConcurrently || hasMssqlOnline || hasMysqlOnline;
  }
  if (engine === "postgres") return hasConcurrently;
  if (engine === "mssql") return hasMssqlOnline;
  if (engine === "mysql") return hasMysqlOnline;
  return true;
}

function buildOnlineIndexFixSql(stmt: ParsedStatement, engine: ResolvedSqlEngine): string {
  const trimmed = stmt.rawSql.trim().replace(/;\s*$/, "");
  if (engine === "postgres") {
    return `${trimmed.replace(/^(\s*CREATE\s+(?:UNIQUE\s+)?INDEX)\b/i, "$1 CONCURRENTLY")};`;
  }
  if (engine === "mssql") {
    if (/\bWITH\s*\(/i.test(trimmed)) {
      return `${trimmed.replace(/\bWITH\s*\(/i, "WITH (ONLINE = ON, ")};`;
    }
    return `${trimmed} WITH (ONLINE = ON);`;
  }
  if (engine === "mysql") {
    return `${trimmed} ALGORITHM=INPLACE, LOCK=NONE;`;
  }
  return `${trimmed};`;
}

function isLockTimeoutStatement(tokens: SqlToken[]): boolean {
  if (tokens[0]?.upper !== "SET") return false;
  let idx = 1;
  if (tokens[idx]?.upper === "LOCAL" || tokens[idx]?.upper === "SESSION") {
    idx += 1;
  }
  return tokens[idx]?.upper === "LOCK_TIMEOUT";
}

function checkMigrationStatement(
  stmt: ParsedStatement,
  engine: ResolvedSqlEngine,
  autoMode: boolean,
  file: string,
  createdTables: TableSet,
  state: {
    inTransaction: boolean;
    hasLockTimeout: boolean;
    emittedLockTimeoutWarning: boolean;
  },
  isRuleEnabled: (ruleId: string, stmt: ParsedStatement) => boolean,
  findings: LintFinding[],
): void {
  const toks = stmt.tokens;
  if (toks.length === 0) return;

  // Track explicit transaction state
  if (
    (toks[0].upper === "BEGIN" && toks[1]?.upper !== "ATOMIC") ||
    (toks[0].upper === "START" && toks[1]?.upper === "TRANSACTION")
  ) {
    state.inTransaction = true;
    return;
  }
  if (
    toks[0].upper === "COMMIT" ||
    toks[0].upper === "ROLLBACK" ||
    toks[0].upper === "ABORT" ||
    (toks[0].upper === "END" && toks.length <= 3)
  ) {
    state.inTransaction = false;
    return;
  }

  // Track SET lock_timeout / SET LOCK_TIMEOUT
  if (isLockTimeoutStatement(toks)) {
    state.hasLockTimeout = true;
    return;
  }

  // Track CREATE TABLE so subsequent indexes/alters on the brand-new table do not false-positive
  if (toks[0].upper === "CREATE") {
    let cIdx = 1;
    if (
      toks[cIdx]?.upper === "TEMP" ||
      toks[cIdx]?.upper === "TEMPORARY" ||
      toks[cIdx]?.upper === "UNLOGGED"
    ) {
      cIdx += 1;
    }
    if (toks[cIdx]?.upper === "TABLE") {
      cIdx += 1;
      if (
        toks[cIdx]?.upper === "IF" &&
        toks[cIdx + 1]?.upper === "NOT" &&
        toks[cIdx + 2]?.upper === "EXISTS"
      ) {
        cIdx += 3;
      }
      const tbl = readQualifiedName(toks, cIdx);
      if (tbl) {
        createdTables.add(tbl);
      }
      return;
    }
  }

  const emitLockTimeoutIfNeeded = (targetTable?: ParsedQualifiedName): void => {
    if (state.hasLockTimeout || state.emittedLockTimeoutWarning) return;
    if (engine !== "postgres" && engine !== "mssql") return;
    if (targetTable && createdTables.has(targetTable)) return;
    if (!isRuleEnabled("MIG006", stmt)) return;

    state.emittedLockTimeoutWarning = true;
    const fixSql =
      engine === "mssql" ? "SET LOCK_TIMEOUT 3000;" : "SET lock_timeout = '3s';";
    const settingName = engine === "mssql" ? "SET LOCK_TIMEOUT" : "SET lock_timeout";
    findings.push({
      ruleId: "MIG006",
      severity: "low",
      file,
      line: stmt.startLine,
      column: stmt.startColumn,
      endLine: stmt.endLine,
      endColumn: stmt.endColumn,
      title: RULES.MIG006.title,
      message: `DDL modifies an existing table without setting ${settingName} first. Waiting behind an active query can stall all queued traffic on the table.`,
      suggestion: `Prepend ${fixSql} at the top of the migration and retry safely if lock acquisition times out.`,
      fixSql,
    });
  };

  // MIG001 & MIG002: CREATE [UNIQUE] INDEX / DROP INDEX CONCURRENTLY
  if (toks[0].upper === "CREATE" || toks[0].upper === "DROP") {
    const hasConcurrently = toks.some((t) => t.upper === "CONCURRENTLY");
    const hasIndexKeyword = toks.some((t, idx) => idx <= 4 && t.upper === "INDEX");

    if (hasIndexKeyword && hasConcurrently && state.inTransaction) {
      if (isRuleEnabled("MIG002", stmt)) {
        const concTok = toks.find((t) => t.upper === "CONCURRENTLY") ?? toks[0];
        findings.push({
          ruleId: "MIG002",
          severity: "high",
          file,
          line: concTok.line,
          column: concTok.column,
          endLine: stmt.endLine,
          endColumn: stmt.endColumn,
          title: RULES.MIG002.title,
          message:
            "CREATE/DROP INDEX CONCURRENTLY is placed inside an explicit BEGIN / START TRANSACTION block and will fail at runtime in PostgreSQL.",
          suggestion:
            "Remove BEGIN / COMMIT around CONCURRENTLY index builds and configure your migration runner to execute this file outside a transaction.",
        });
      }
    }

    if (toks[0].upper === "CREATE" && hasIndexKeyword) {
      let targetTable: ParsedQualifiedName | null = null;
      for (let j = 1; j < toks.length; j++) {
        if (toks[j].upper === "ON") {
          targetTable = readQualifiedName(toks, j + 1);
          break;
        }
      }

      if (targetTable && !createdTables.has(targetTable)) {
        emitLockTimeoutIfNeeded(targetTable);

        if (
          engine !== "sqlite" &&
          !hasOnlineIndexOption(toks, engine, autoMode) &&
          isRuleEnabled("MIG001", stmt)
        ) {
          const clauseHint =
            engine === "mssql"
              ? "WITH (ONLINE = ON)"
              : engine === "mysql"
                ? "ALGORITHM=INPLACE, LOCK=NONE"
                : "CONCURRENTLY";
          findings.push({
            ruleId: "MIG001",
            severity: "high",
            file,
            line: stmt.startLine,
            column: stmt.startColumn,
            endLine: stmt.endLine,
            endColumn: stmt.endColumn,
            title: RULES.MIG001.title,
            message: `Creating index on existing table '${targetTable.rawDisplay}' without ${clauseHint} blocks concurrent writes until the index build finishes.`,
            suggestion: `Add ${clauseHint} so concurrent DML can continue while the index builds.`,
            fixSql: buildOnlineIndexFixSql(stmt, engine),
          });
        }
      }
      return;
    }

    if (toks[0].upper === "DROP" && toks[1]?.upper === "TABLE") {
      let dIdx = 2;
      if (toks[dIdx]?.upper === "IF" && toks[dIdx + 1]?.upper === "EXISTS") dIdx += 2;
      const droppedTbl = readQualifiedName(toks, dIdx);
      emitLockTimeoutIfNeeded(droppedTbl ?? undefined);
      if (isRuleEnabled("MIG005", stmt)) {
        const tblLabel = droppedTbl?.rawDisplay ?? "table";
        findings.push({
          ruleId: "MIG005",
          severity: "high",
          file,
          line: stmt.startLine,
          column: stmt.startColumn,
          endLine: stmt.endLine,
          endColumn: stmt.endColumn,
          title: RULES.MIG005.title,
          message: `DROP TABLE '${tblLabel}' permanently deletes table data and breaks running application instances that still reference it.`,
          suggestion:
            "Stop reading/writing the table in an earlier release first, then annotate intentional cleanup with '-- culprit-ignore: MIG005'.",
        });
      }
      return;
    }
  }

  // MIG005: TRUNCATE [TABLE] ...
  if (toks[0].upper === "TRUNCATE") {
    let tIdx = 1;
    if (toks[tIdx]?.upper === "TABLE") tIdx += 1;
    const truncTbl = readQualifiedName(toks, tIdx);
    emitLockTimeoutIfNeeded(truncTbl ?? undefined);
    if (isRuleEnabled("MIG005", stmt)) {
      findings.push({
        ruleId: "MIG005",
        severity: "high",
        file,
        line: stmt.startLine,
        column: stmt.startColumn,
        endLine: stmt.endLine,
        endColumn: stmt.endColumn,
        title: RULES.MIG005.title,
        message: `TRUNCATE on '${truncTbl?.rawDisplay ?? "table"}' acquires an exclusive lock and permanently removes all rows.`,
        suggestion:
          "If purging data in production is intentional, acknowledge with '-- culprit-ignore: MIG005'.",
      });
    }
    return;
  }

  // ALTER TABLE checks: MIG003, MIG005 (DROP COLUMN), MIG006
  if (toks[0].upper === "ALTER" && toks[1]?.upper === "TABLE") {
    let idx = 2;
    if (toks[idx]?.upper === "IF" && toks[idx + 1]?.upper === "EXISTS") {
      idx += 2;
    }
    const targetTable = readQualifiedName(toks, idx);
    if (!targetTable) return;
    const isBrandNewTable = createdTables.has(targetTable);

    if (!isBrandNewTable) {
      emitLockTimeoutIfNeeded(targetTable);
    }

    // Split top-level comma actions after table name (e.g. ALTER TABLE t DROP COLUMN a, ALTER COLUMN b TYPE text)
    const actionSlices: SqlToken[][] = [];
    let currentAction: SqlToken[] = [];
    let depth = 0;
    for (let k = targetTable.nextIndex; k < toks.length; k++) {
      const t = toks[k];
      if (t.raw === "(") depth += 1;
      else if (t.raw === ")") depth = Math.max(0, depth - 1);
      if (t.raw === "," && depth === 0) {
        if (currentAction.length > 0) actionSlices.push(currentAction);
        currentAction = [];
      } else {
        currentAction.push(t);
      }
    }
    if (currentAction.length > 0) actionSlices.push(currentAction);

    for (const action of actionSlices) {
      if (action.length === 0) continue;
      const first = action[0];
      const last = action[action.length - 1];

      // 1. DROP [COLUMN] <col> -> MIG005 (skip DROP CONSTRAINT, DROP INDEX, DROP PRIMARY/FOREIGN KEY)
      if (first.upper === "DROP") {
        const second = action[1]?.upper;
        const isConstraintOrIndex =
          second === "CONSTRAINT" ||
          second === "INDEX" ||
          second === "KEY" ||
          second === "PRIMARY" ||
          second === "FOREIGN" ||
          second === "CHECK" ||
          second === "PARTITION";
        if (!isConstraintOrIndex && isRuleEnabled("MIG005", stmt)) {
          let colIdx = second === "COLUMN" ? 2 : 1;
          if (action[colIdx]?.upper === "IF" && action[colIdx + 1]?.upper === "EXISTS") {
            colIdx += 2;
          }
          const colName = action[colIdx]?.raw ?? "column";
          findings.push({
            ruleId: "MIG005",
            severity: "high",
            file,
            line: first.line,
            column: first.column,
            endLine: last.endLine,
            endColumn: last.endColumn,
            title: RULES.MIG005.title,
            message: `Dropping column '${colName}' from '${targetTable.rawDisplay}' breaks in-flight queries that still select or insert that column during a rolling deploy.`,
            suggestion:
              "Stop referencing the column in application code first, deploy, then add '-- culprit-ignore: MIG005' when dropping the unused column.",
          });
        }
        continue;
      }

      if (isBrandNewTable) continue;

      // 2. ALTER [COLUMN] <col> [SET DATA] TYPE ... (Postgres) or ALTER COLUMN <col> <type> (MSSQL)
      //    or MODIFY [COLUMN] / CHANGE [COLUMN] (MySQL) -> MIG003
      if (first.upper === "ALTER") {
        let aIdx = 1;
        if (action[aIdx]?.upper === "COLUMN") aIdx += 1;
        const colTok = action[aIdx];
        const afterCol = action[aIdx + 1]?.upper;
        const isPgSetType =
          afterCol === "TYPE" ||
          (afterCol === "SET" && action[aIdx + 2]?.upper === "DATA" && action[aIdx + 3]?.upper === "TYPE");
        const isMssqlAlterType =
          engine === "mssql" &&
          isIdentifierToken(colTok) &&
          isIdentifierToken(action[aIdx + 1]) &&
          afterCol !== "ADD" &&
          afterCol !== "DROP";

        if ((isPgSetType || isMssqlAlterType) && isRuleEnabled("MIG003", stmt)) {
          findings.push({
            ruleId: "MIG003",
            severity: "high",
            file,
            line: first.line,
            column: first.column,
            endLine: last.endLine,
            endColumn: last.endColumn,
            title: RULES.MIG003.title,
            message: `Changing type of column '${colTok?.raw ?? "column"}' on '${targetTable.rawDisplay}' acquires an exclusive table lock and can rewrite every row on disk.`,
            suggestion:
              "Use expand-and-contract instead: add a new nullable column, backfill in small batches, dual-write, and swap.",
          });
        }
        continue;
      }

      if (
        (first.upper === "MODIFY" || first.upper === "CHANGE") &&
        isRuleEnabled("MIG003", stmt)
      ) {
        const colIdx = action[1]?.upper === "COLUMN" ? 2 : 1;
        findings.push({
          ruleId: "MIG003",
          severity: "high",
          file,
          line: first.line,
          column: first.column,
          endLine: last.endLine,
          endColumn: last.endColumn,
          title: RULES.MIG003.title,
          message: `Modifying column '${action[colIdx]?.raw ?? "column"}' on '${targetTable.rawDisplay}' can trigger a full table copy and block concurrent writes.`,
          suggestion:
            "Verify instant/in-place DDL compatibility or migrate via expand-and-contract with a new column.",
        });
        continue;
      }

      // 3. ADD [COLUMN] <col> <type> ... NOT NULL without constant DEFAULT or with volatile DEFAULT -> MIG003
      if (first.upper === "ADD") {
        let aIdx = 1;
        if (action[aIdx]?.upper === "COLUMN") aIdx += 1;
        if (
          action[aIdx]?.upper === "IF" &&
          action[aIdx + 1]?.upper === "NOT" &&
          action[aIdx + 2]?.upper === "EXISTS"
        ) {
          aIdx += 3;
        }
        const colTok = action[aIdx];
        const isConstraintKeyword =
          colTok?.upper === "CONSTRAINT" ||
          colTok?.upper === "FOREIGN" ||
          colTok?.upper === "PRIMARY" ||
          colTok?.upper === "UNIQUE" ||
          colTok?.upper === "CHECK" ||
          colTok?.upper === "INDEX";

        if (isIdentifierToken(colTok) && !isConstraintKeyword) {
          const hasNotNull = action.some(
            (t, idx2) => t.upper === "NOT" && action[idx2 + 1]?.upper === "NULL",
          );
          if (hasNotNull && isRuleEnabled("MIG003", stmt)) {
            const defaultIdx = action.findIndex((t) => t.upper === "DEFAULT");
            let volatileFunc: string | null = null;
            if (defaultIdx !== -1) {
              for (let d = defaultIdx + 1; d < action.length; d++) {
                const dt = action[d];
                if (
                  dt.upper === "NOT" ||
                  dt.upper === "NULL" ||
                  dt.upper === "CONSTRAINT" ||
                  dt.upper === "REFERENCES" ||
                  dt.upper === "CHECK"
                ) {
                  break;
                }
                if (
                  dt.kind === "word" &&
                  action[d + 1]?.raw === "(" &&
                  VOLATILE_DEFAULT_FUNCTIONS.has(dt.upper)
                ) {
                  volatileFunc = `${dt.raw}()`;
                  break;
                }
              }
            }

            if (defaultIdx === -1) {
              findings.push({
                ruleId: "MIG003",
                severity: "high",
                file,
                line: first.line,
                column: first.column,
                endLine: last.endLine,
                endColumn: last.endColumn,
                title: RULES.MIG003.title,
                message: `Adding NOT NULL column '${colTok.raw}' to existing table '${targetTable.rawDisplay}' without a DEFAULT fails on non-empty tables or requires an exclusive rewrite.`,
                suggestion:
                  "Add the column as nullable first, backfill existing rows in batches, and enforce NOT NULL with a NOT VALID check constraint before validating.",
              });
            } else if (volatileFunc) {
              findings.push({
                ruleId: "MIG003",
                severity: "high",
                file,
                line: first.line,
                column: first.column,
                endLine: last.endLine,
                endColumn: last.endColumn,
                title: RULES.MIG003.title,
                message: `Adding NOT NULL column '${colTok.raw}' on '${targetTable.rawDisplay}' with volatile default ${volatileFunc} rewrites every row under an ACCESS EXCLUSIVE lock.`,
                suggestion:
                  "Add the column as nullable with the default for new rows, backfill existing rows in batches, then validate NOT NULL.",
              });
            }
          }
        }
      }
    }
  }
}

function findMainStatementStartAfterWith(tokens: SqlToken[]): number {
  if (tokens[0]?.upper !== "WITH") return 0;
  let idx = 1;
  if (tokens[idx]?.upper === "RECURSIVE") idx += 1;
  let depth = 0;
  while (idx < tokens.length) {
    const t = tokens[idx];
    if (t.raw === "(") {
      depth += 1;
    } else if (t.raw === ")") {
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        if (tokens[idx + 1]?.raw === ",") {
          idx += 2;
          continue;
        }
        return idx + 1;
      }
    }
    idx += 1;
  }
  return 0;
}

function checkQueryStatement(
  stmt: ParsedStatement,
  engine: ResolvedSqlEngine,
  file: string,
  isRuleEnabled: (ruleId: string, stmt: ParsedStatement) => boolean,
  findings: LintFinding[],
): void {
  const toks = stmt.tokens;
  if (toks.length === 0) return;

  // 1. QRY001: UPDATE or DELETE with no top-level WHERE clause
  const mainStart = findMainStatementStartAfterWith(toks);
  const mainVerb = toks[mainStart]?.upper;
  if ((mainVerb === "UPDATE" || mainVerb === "DELETE") && isRuleEnabled("QRY001", stmt)) {
    let depth = 0;
    let hasTopLevelWhere = false;
    for (let i = mainStart + 1; i < toks.length; i++) {
      if (toks[i].raw === "(") depth += 1;
      else if (toks[i].raw === ")") depth = Math.max(0, depth - 1);
      else if (depth === 0 && toks[i].upper === "WHERE") {
        hasTopLevelWhere = true;
        break;
      }
    }
    if (!hasTopLevelWhere) {
      const verbTok = toks[mainStart];
      findings.push({
        ruleId: "QRY001",
        severity: "high",
        file,
        line: verbTok.line,
        column: verbTok.column,
        endLine: stmt.endLine,
        endColumn: stmt.endColumn,
        title: RULES.QRY001.title,
        message: `${mainVerb} statement has no top-level WHERE clause and will modify or delete every row in the target table.`,
        suggestion: `Add an explicit WHERE predicate (or '-- culprit-ignore: QRY001' if full-table ${mainVerb} is intentional).`,
      });
    }
  }

  // 2. QRY002: Non-sargable function wrapping a column inside a WHERE clause
  if (isRuleEnabled("QRY002", stmt)) {
    let inWhere = false;
    let whereParenDepth = 0;

    for (let i = 0; i < toks.length; i++) {
      const tok = toks[i];
      if (tok.raw === "(") {
        if (inWhere) whereParenDepth += 1;
      } else if (tok.raw === ")") {
        if (inWhere) {
          if (whereParenDepth === 0) {
            inWhere = false;
          } else {
            whereParenDepth -= 1;
          }
        }
      } else if (tok.upper === "WHERE") {
        inWhere = true;
        whereParenDepth = 0;
        continue;
      } else if (
        inWhere &&
        whereParenDepth === 0 &&
        (tok.upper === "GROUP" ||
          tok.upper === "ORDER" ||
          tok.upper === "LIMIT" ||
          tok.upper === "HAVING" ||
          tok.upper === "RETURNING" ||
          tok.upper === "UNION" ||
          tok.upper === "INTERSECT" ||
          tok.upper === "EXCEPT")
      ) {
        inWhere = false;
        continue;
      }

      if (!inWhere) continue;

      const isCast = tok.kind === "word" && tok.upper === "CAST" && toks[i + 1]?.raw === "(";
      const isFunc =
        tok.kind === "word" &&
        NON_SARGABLE_FUNCTIONS.has(tok.upper) &&
        toks[i + 1]?.raw === "(";

      if (!isCast && !isFunc) continue;

      // Locate matching closing ')' of the function call
      let depth = 1;
      let closeIdx = -1;
      for (let k = i + 2; k < toks.length; k++) {
        if (toks[k].raw === "(") depth += 1;
        else if (toks[k].raw === ")") {
          depth -= 1;
          if (depth === 0) {
            closeIdx = k;
            break;
          }
        }
      }
      if (closeIdx === -1) continue;

      // Verify first argument inside (...) is a column reference (and not a literal/parameter)
      const argStart = i + 2;
      const colRef = readQualifiedName(toks, argStart);
      if (!colRef) continue;
      // Ignore SQL keyword literals like NULL, TRUE, FALSE, CURRENT_DATE, CURRENT_TIMESTAMP, NOW
      const firstArgUpper = toks[argStart]?.upper ?? "";
      if (
        firstArgUpper === "NULL" ||
        firstArgUpper === "TRUE" ||
        firstArgUpper === "FALSE" ||
        firstArgUpper === "CURRENT_DATE" ||
        firstArgUpper === "CURRENT_TIMESTAMP" ||
        firstArgUpper === "NOW" ||
        toks[argStart]?.raw.startsWith("@")
      ) {
        continue;
      }

      // Check that this function call participates in a comparison predicate (either `FUNC(col) = ...` or `... = FUNC(col)`)
      const nextTok = toks[closeIdx + 1];
      const prevTok = toks[i - 1];
      const comparedOnRight =
        nextTok !== undefined &&
        (COMPARISON_OPS.has(nextTok.raw) ||
          nextTok.upper === "IN" ||
          nextTok.upper === "BETWEEN" ||
          nextTok.upper === "LIKE" ||
          nextTok.upper === "ILIKE");
      const comparedOnLeft = prevTok !== undefined && COMPARISON_OPS.has(prevTok.raw);

      if (!comparedOnRight && !comparedOnLeft) continue;

      const fnUpper = tok.upper;
      const colDisplay = colRef.rawDisplay;
      let suggestion: string;
      let fixSql: string | undefined;

      if (fnUpper === "LOWER" || fnUpper === "UPPER") {
        const indexClause = engine === "postgres" ? "CONCURRENTLY " : "";
        suggestion = `Add a functional index on ${fnUpper}(${colDisplay}) or store normalized/case-insensitive values so the planner can seek directly.`;
        fixSql = `CREATE INDEX ${indexClause}idx_expr_${fnUpper.toLowerCase()}_${colRef.bare} ON <table> (${fnUpper}(${colRef.bare}));`;
      } else if (fnUpper === "DATE" || fnUpper === "YEAR" || fnUpper === "MONTH" || fnUpper === "DAY") {
        suggestion = `Rewrite ${fnUpper}(${colDisplay}) as a half-open range predicate (${colDisplay} >= start_ts AND ${colDisplay} < end_ts) so B-tree indexes on ${colDisplay} remain sargable.`;
      } else if (fnUpper === "CAST") {
        suggestion = `Cast the parameter or literal on the other side of the comparison instead of wrapping column '${colDisplay}' in CAST(...).`;
      } else {
        suggestion = `Avoid wrapping indexed column '${colDisplay}' in ${fnUpper}(...) inside WHERE, or create a matching expression index.`;
      }

      const endTok = comparedOnRight && toks[closeIdx + 2] ? toks[closeIdx + 2] : toks[closeIdx];
      findings.push({
        ruleId: "QRY002",
        severity: "medium",
        file,
        line: tok.line,
        column: tok.column,
        endLine: endTok.endLine,
        endColumn: endTok.endColumn,
        title: RULES.QRY002.title,
        message: `Non-sargable predicate wraps column '${colDisplay}' in ${fnUpper}(...), preventing standard B-tree index seeks.`,
        suggestion,
        ...(fixSql ? { fixSql } : {}),
      });
    }
  }

  // 3. QRY003: Leading wildcard LIKE '%...' or ILIKE '%...'
  if (isRuleEnabled("QRY003", stmt)) {
    for (let i = 0; i < toks.length - 1; i++) {
      const tok = toks[i];
      if (tok.kind !== "word" || (tok.upper !== "LIKE" && tok.upper !== "ILIKE")) {
        continue;
      }
      const patTok = toks[i + 1];
      if (patTok?.kind !== "string") continue;
      // Ignore dollar-quoted strings unless single-quoted literal
      if (!patTok.raw.includes("'")) continue;
      const patternVal = unquoteSqlString(patTok.raw);
      if (patternVal.startsWith("%")) {
        const suggestion =
          engine === "postgres"
            ? "Add a pg_trgm GIN index (USING gin (col gin_trgm_ops)), use full-text search (tsvector), or anchor the prefix without a leading '%'."
            : "Use full-text search, an inverted/n-gram index, or a reversed-column prefix index for suffix lookups.";
        findings.push({
          ruleId: "QRY003",
          severity: "low",
          file,
          line: tok.line,
          column: tok.column,
          endLine: patTok.endLine,
          endColumn: patTok.endColumn,
          title: RULES.QRY003.title,
          message: `Leading wildcard pattern ${tok.upper} ${patTok.raw} prevents B-tree index range seeks and forces a full index or table scan.`,
          suggestion,
        });
      }
    }
  }
}

/**
 * Lints a SQL string (migration or query file) and returns exact 1-based findings.
 */
export function lintSql(sql: string, options: LintOptions = {}): LintFinding[] {
  const file = options.file ?? "input.sql";
  const configuredEngine: SqlEngine = options.engine ?? "auto";
  const mode: LintMode = options.mode ?? "migration";
  const disabledSet = new Set((options.disabledRules ?? []).map((r) => r.toUpperCase()));

  const lexed = splitSqlStatements(sql);
  const resolvedEngine = detectSqlEngine(lexed.tokens, configuredEngine);
  const autoMode = configuredEngine === "auto";

  const isRuleEnabled = (ruleId: string, stmt?: ParsedStatement): boolean => {
    const upper = ruleId.toUpperCase();
    if (disabledSet.has(upper)) return false;
    if (lexed.fileIgnoredRules.has("*") || lexed.fileIgnoredRules.has(upper)) return false;
    if (stmt && (stmt.ignoredRules.has("*") || stmt.ignoredRules.has(upper))) return false;
    return true;
  };

  const indexRegistry = new TableIndexRegistry();

  // Seed existing indexes from optional programmatic configuration
  if (options.existingIndexes) {
    for (const [tbl, colLists] of Object.entries(options.existingIndexes)) {
      for (const cols of colLists) {
        indexRegistry.add(tbl, cols);
      }
    }
  }

  // Seed existing indexes from optional schema SQL snapshot
  if (options.schemaSql) {
    const schemaLexed = splitSqlStatements(options.schemaSql);
    collectSchemaFactsFromStatements(schemaLexed.statements, indexRegistry);
  }

  // Pass 1: Collect all indexes & foreign keys declared anywhere in this SQL file
  const fileForeignKeys = collectSchemaFactsFromStatements(lexed.statements, indexRegistry);

  const findings: LintFinding[] = [];
  const createdTables = new TableSet();
  const migrationState = {
    inTransaction: false,
    hasLockTimeout: false,
    emittedLockTimeoutWarning: false,
  };

  const runMigrationRules = mode === "migration" || mode === "all";
  const runQueryRules = mode === "query" || mode === "migration" || mode === "all";

  // Pass 2: Evaluate statement-by-statement migration & query rules
  for (const stmt of lexed.statements) {
    if (runMigrationRules) {
      checkMigrationStatement(
        stmt,
        resolvedEngine,
        autoMode,
        file,
        createdTables,
        migrationState,
        isRuleEnabled,
        findings,
      );
    }
    if (runQueryRules) {
      checkQueryStatement(stmt, resolvedEngine, file, isRuleEnabled, findings);
    }
  }

  // Pass 3: Evaluate MIG004 across collected foreign keys once all file-wide indexes are registered
  if (runMigrationRules) {
    for (const fk of fileForeignKeys) {
      // Locate owning statement for ignore pragma support
      const ownerStmt = lexed.statements.find(
        (s) => fk.token.offset >= s.tokens[0].offset && fk.token.offset <= s.tokens[s.tokens.length - 1].endOffset,
      );
      if (!isRuleEnabled("MIG004", ownerStmt)) continue;
      if (!indexRegistry.coversForeignKey(fk.table, fk.columns)) {
        const colsJoined = fk.columns.join(", ");
        const colsSlug = fk.columns.join("_");
        const onlineKw = resolvedEngine === "postgres" && !createdTables.has(fk.table) ? "CONCURRENTLY " : "";
        const onlineSuffix =
          resolvedEngine === "mssql" && !createdTables.has(fk.table) ? " WITH (ONLINE = ON)" : "";
        const fixSql = `CREATE INDEX ${onlineKw}idx_${fk.table.bare}_${colsSlug} ON ${fk.table.rawDisplay} (${colsJoined})${onlineSuffix};`;
        findings.push({
          ruleId: "MIG004",
          severity: "medium",
          file,
          line: fk.token.line,
          column: fk.token.column,
          endLine: fk.endToken.endLine,
          endColumn: fk.endToken.endColumn,
          title: RULES.MIG004.title,
          message: `Foreign key on '${fk.table.rawDisplay} (${colsJoined})' has no covering index in this migration or schema snapshot.`,
          suggestion: `Create an index with leading column(s) (${colsJoined}) on '${fk.table.rawDisplay}' to avoid lock amplification and full scans on parent updates/deletes.`,
          fixSql,
        });
      }
    }
  }

  // Sort deterministically by line, column, ruleId
  findings.sort((a, b) => a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId));

  return findings;
}
