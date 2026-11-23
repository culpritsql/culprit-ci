export type SqlTokenKind =
  | "word"
  | "quoted_ident"
  | "string"
  | "number"
  | "punct"
  | "comment";

export interface SqlToken {
  kind: SqlTokenKind;
  raw: string;
  /** Uppercase value for words/punctuation, or unquoted text for quoted identifiers. */
  upper: string;
  /** Normalized identifier name (lowercase, unquoted) for word and quoted_ident tokens. */
  ident: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  offset: number;
  endOffset: number;
}

export interface ParsedStatement {
  tokens: SqlToken[];
  comments: SqlToken[];
  ignoredRules: Set<string>;
  rawSql: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface LexResult {
  tokens: SqlToken[];
  statements: ParsedStatement[];
  fileIgnoredRules: Set<string>;
}

const PRAGMA_FILE_RE = /culprit-ignore-file\s*:?\s*([A-Za-z0-9_,\s*]+)/gi;
const PRAGMA_STMT_RE = /culprit-ignore(?!-file)\s*:?\s*([A-Za-z0-9_,\s*]+)/gi;

function parseRuleList(rawList: string, target: Set<string>): void {
  // Stop before trailing explanation words once we hit two spaces or common prose connectors
  const tokens = rawList
    .split(/[\s,]+/)
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  for (const tok of tokens) {
    if (tok === "ALL" || tok === "*") {
      target.add("*");
    } else if (/^(MIG|QRY|PLAN)\d{3}$/.test(tok)) {
      target.add(tok);
    } else {
      // Stop when hitting prose comment words after the rule list
      break;
    }
  }
}

export function extractIgnorePragmas(
  commentRaw: string,
  stmtRules: Set<string>,
  fileRules?: Set<string>,
): void {
  if (fileRules) {
    PRAGMA_FILE_RE.lastIndex = 0;
    let fileMatch: RegExpExecArray | null = PRAGMA_FILE_RE.exec(commentRaw);
    while (fileMatch) {
      parseRuleList(fileMatch[1] ?? "", fileRules);
      fileMatch = PRAGMA_FILE_RE.exec(commentRaw);
    }
  }

  PRAGMA_STMT_RE.lastIndex = 0;
  let stmtMatch: RegExpExecArray | null = PRAGMA_STMT_RE.exec(commentRaw);
  while (stmtMatch) {
    parseRuleList(stmtMatch[1] ?? "", stmtRules);
    stmtMatch = PRAGMA_STMT_RE.exec(commentRaw);
  }
}

function isAsciiLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isAsciiDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isWordStart(code: number): boolean {
  return isAsciiLetter(code) || code === 95 || code === 64 || code === 35 || code > 127;
}

function isWordPart(code: number): boolean {
  return isWordStart(code) || isAsciiDigit(code) || code === 36;
}

function matchDollarQuoteTag(sql: string, index: number): string | null {
  if (sql.charCodeAt(index) !== 36) return null; // '$'
  let cursor = index + 1;
  if (cursor < sql.length && sql.charCodeAt(cursor) === 36) {
    return "$$";
  }
  if (cursor >= sql.length) return null;
  const first = sql.charCodeAt(cursor);
  if (!isAsciiLetter(first) && first !== 95 && first <= 127) {
    return null;
  }
  cursor += 1;
  while (cursor < sql.length) {
    const ch = sql.charCodeAt(cursor);
    if (ch === 36) {
      return sql.slice(index, cursor + 1);
    }
    if (!isAsciiLetter(ch) && !isAsciiDigit(ch) && ch !== 95 && ch <= 127) {
      return null;
    }
    cursor += 1;
  }
  return null;
}

/**
 * Tokenizes SQL accurately tracking 1-based line and column coordinates,
 * `--` line comments, `/* ... *\/` nested block comments, `'...'` string literals,
 * `"..."` / `[...]` / `` `...` `` quoted identifiers, and `$tag$...$tag$` dollar-quoted bodies.
 */
export function tokenizeSql(sql: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  const len = sql.length;
  let i = 0;
  let line = 1;
  let col = 1;

  const advance = (count = 1): void => {
    for (let step = 0; step < count && i < len; step++) {
      const ch = sql.charCodeAt(i);
      if (ch === 10) {
        // '\n'
        i += 1;
        line += 1;
        col = 1;
      } else if (ch === 13) {
        // '\r'
        i += 1;
        if (i < len && sql.charCodeAt(i) === 10) {
          // Wait for next iteration or consume CRLF together? Let's consume single char cleanly:
          // If CRLF, advancing 2 steps handles \r then \n. If advancing 1 step on \r followed by \n:
          col += 1;
        } else {
          line += 1;
          col = 1;
        }
      } else {
        i += 1;
        col += 1;
      }
    }
  };

  while (i < len) {
    const ch = sql.charCodeAt(i);

    // Whitespace
    if (ch === 32 || ch === 9 || ch === 10 || ch === 13 || ch === 12) {
      advance(1);
      continue;
    }

    const startOffset = i;
    const startLine = line;
    const startCol = col;

    // Line comment: -- ...
    if (ch === 45 && i + 1 < len && sql.charCodeAt(i + 1) === 45) {
      advance(2);
      while (i < len && sql.charCodeAt(i) !== 10 && sql.charCodeAt(i) !== 13) {
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "comment",
        raw,
        upper: "",
        ident: "",
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Block comment: /* ... */ (supports nested /* ... */)
    if (ch === 47 && i + 1 < len && sql.charCodeAt(i + 1) === 42) {
      let depth = 1;
      advance(2);
      while (i < len && depth > 0) {
        if (sql.charCodeAt(i) === 47 && i + 1 < len && sql.charCodeAt(i + 1) === 42) {
          depth += 1;
          advance(2);
        } else if (sql.charCodeAt(i) === 42 && i + 1 < len && sql.charCodeAt(i + 1) === 47) {
          depth -= 1;
          advance(2);
        } else {
          advance(1);
        }
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "comment",
        raw,
        upper: "",
        ident: "",
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Prefixed string literal: E'...', N'...', X'...', B'...'
    if (
      (ch === 69 || ch === 101 || ch === 78 || ch === 110 || ch === 88 || ch === 120 || ch === 66 || ch === 98) &&
      i + 1 < len &&
      sql.charCodeAt(i + 1) === 39
    ) {
      const isEscapeString = ch === 69 || ch === 101;
      advance(2);
      while (i < len) {
        const c = sql.charCodeAt(i);
        if (isEscapeString && c === 92 && i + 1 < len) {
          advance(2);
          continue;
        }
        if (c === 39) {
          advance(1);
          if (i < len && sql.charCodeAt(i) === 39) {
            advance(1);
            continue;
          }
          break;
        }
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "string",
        raw,
        upper: raw.toUpperCase(),
        ident: "",
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Standard single-quoted string literal: '...'
    if (ch === 39) {
      advance(1);
      while (i < len) {
        const c = sql.charCodeAt(i);
        if (c === 39) {
          advance(1);
          if (i < len && sql.charCodeAt(i) === 39) {
            advance(1);
            continue;
          }
          break;
        }
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "string",
        raw,
        upper: raw.toUpperCase(),
        ident: "",
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // PostgreSQL dollar-quoted string literal: $$...$$ or $tag$...$tag$
    if (ch === 36) {
      const tag = matchDollarQuoteTag(sql, i);
      if (tag) {
        advance(tag.length);
        const closeIdx = sql.indexOf(tag, i);
        if (closeIdx === -1) {
          advance(len - i);
        } else {
          advance(closeIdx - i + tag.length);
        }
        const raw = sql.slice(startOffset, i);
        tokens.push({
          kind: "string",
          raw,
          upper: "",
          ident: "",
          line: startLine,
          column: startCol,
          endLine: line,
          endColumn: col,
          offset: startOffset,
          endOffset: i,
        });
        continue;
      }

      // Positional parameter $1, $2, etc.
      if (i + 1 < len && isAsciiDigit(sql.charCodeAt(i + 1))) {
        advance(1);
        while (i < len && isAsciiDigit(sql.charCodeAt(i))) {
          advance(1);
        }
        const raw = sql.slice(startOffset, i);
        tokens.push({
          kind: "punct",
          raw,
          upper: raw,
          ident: "",
          line: startLine,
          column: startCol,
          endLine: line,
          endColumn: col,
          offset: startOffset,
          endOffset: i,
        });
        continue;
      }
    }

    // Double-quoted identifier "..." or backtick identifier `...`
    if (ch === 34 || ch === 96) {
      const quote = ch;
      advance(1);
      let inner = "";
      while (i < len) {
        const c = sql.charCodeAt(i);
        if (c === quote) {
          advance(1);
          if (i < len && sql.charCodeAt(i) === quote) {
            inner += String.fromCharCode(quote);
            advance(1);
            continue;
          }
          break;
        }
        inner += sql[i];
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "quoted_ident",
        raw,
        upper: inner.toUpperCase(),
        ident: inner.toLowerCase(),
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // SQL Server bracket-quoted identifier [...]
    if (ch === 91) {
      advance(1);
      let inner = "";
      while (i < len) {
        const c = sql.charCodeAt(i);
        if (c === 93) {
          advance(1);
          if (i < len && sql.charCodeAt(i) === 93) {
            inner += "]";
            advance(1);
            continue;
          }
          break;
        }
        inner += sql[i];
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "quoted_ident",
        raw,
        upper: inner.toUpperCase(),
        ident: inner.toLowerCase(),
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Numbers
    if (isAsciiDigit(ch)) {
      advance(1);
      while (i < len && (isAsciiDigit(sql.charCodeAt(i)) || sql.charCodeAt(i) === 95)) {
        advance(1);
      }
      if (i < len && sql.charCodeAt(i) === 46 && i + 1 < len && isAsciiDigit(sql.charCodeAt(i + 1))) {
        advance(1);
        while (i < len && isAsciiDigit(sql.charCodeAt(i))) {
          advance(1);
        }
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "number",
        raw,
        upper: raw,
        ident: "",
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Unquoted words / keywords / @vars / #temp
    if (isWordStart(ch)) {
      advance(1);
      while (i < len && isWordPart(sql.charCodeAt(i))) {
        advance(1);
      }
      const raw = sql.slice(startOffset, i);
      tokens.push({
        kind: "word",
        raw,
        upper: raw.toUpperCase(),
        ident: raw.toLowerCase(),
        line: startLine,
        column: startCol,
        endLine: line,
        endColumn: col,
        offset: startOffset,
        endOffset: i,
      });
      continue;
    }

    // Two-character operators: ::, !=, <>, <=, >=, ||, ->, ->>
    if (i + 1 < len) {
      const two = sql.slice(i, i + 2);
      if (
        two === "::" ||
        two === "!=" ||
        two === "<>" ||
        two === "<=" ||
        two === ">=" ||
        two === "||" ||
        two === "->"
      ) {
        if (two === "->" && i + 2 < len && sql.charCodeAt(i + 2) === 62) {
          advance(3);
          const raw3 = "->>";
          tokens.push({
            kind: "punct",
            raw: raw3,
            upper: raw3,
            ident: "",
            line: startLine,
            column: startCol,
            endLine: line,
            endColumn: col,
            offset: startOffset,
            endOffset: i,
          });
          continue;
        }
        advance(2);
        tokens.push({
          kind: "punct",
          raw: two,
          upper: two,
          ident: "",
          line: startLine,
          column: startCol,
          endLine: line,
          endColumn: col,
          offset: startOffset,
          endOffset: i,
        });
        continue;
      }
    }

    // Single punctuation character
    advance(1);
    const raw = sql.slice(startOffset, i);
    tokens.push({
      kind: "punct",
      raw,
      upper: raw,
      ident: "",
      line: startLine,
      column: startCol,
      endLine: line,
      endColumn: col,
      offset: startOffset,
      endOffset: i,
    });
  }

  return tokens;
}

function isStandaloneGoBatchSeparator(tokens: SqlToken[], idx: number): boolean {
  const tok = tokens[idx];
  if (tok.kind !== "word" || tok.upper !== "GO") return false;
  const prevNonComment = (() => {
    for (let j = idx - 1; j >= 0; j--) {
      if (tokens[j].kind !== "comment") return tokens[j];
    }
    return null;
  })();
  if (prevNonComment && prevNonComment.endLine === tok.line) {
    return false;
  }
  const nextNonComment = (() => {
    for (let j = idx + 1; j < tokens.length; j++) {
      if (tokens[j].kind !== "comment") return tokens[j];
    }
    return null;
  })();
  if (nextNonComment && nextNonComment.line === tok.line) {
    // Allow optional batch count e.g. `GO 5`
    if (nextNonComment.kind === "number") {
      const afterNum = (() => {
        for (let j = idx + 2; j < tokens.length; j++) {
          if (tokens[j].kind !== "comment") return tokens[j];
        }
        return null;
      })();
      return !afterNum || afterNum.line > tok.line;
    }
    return false;
  }
  return true;
}

/**
 * Splits a SQL document into individual top-level statements while preserving
 * exact 1-based line/column spans and attaching leading/inline/same-line trailing
 * `-- culprit-ignore: RULE_ID` comments to the statement they govern.
 */
export function splitSqlStatements(sql: string): LexResult {
  const allTokens = tokenizeSql(sql);
  const statements: ParsedStatement[] = [];
  const fileIgnoredRules = new Set<string>();

  let currentTokens: SqlToken[] = [];
  let currentComments: SqlToken[] = [];

  const flushStatement = (semicolonToken?: SqlToken, trailingSameLineComments: SqlToken[] = []): void => {
    if (currentTokens.length === 0) {
      // Check file-level pragmas in standalone comments even if no statement tokens yet
      for (const c of currentComments) {
        extractIgnorePragmas(c.raw, new Set(), fileIgnoredRules);
      }
      return;
    }

    const allComments = [...currentComments, ...trailingSameLineComments];
    const ignoredRules = new Set<string>(fileIgnoredRules);
    for (const c of allComments) {
      extractIgnorePragmas(c.raw, ignoredRules, fileIgnoredRules);
    }
    for (const r of fileIgnoredRules) {
      ignoredRules.add(r);
    }

    const firstTok = currentTokens[0];
    const lastTok = semicolonToken ?? currentTokens[currentTokens.length - 1];

    statements.push({
      tokens: currentTokens,
      comments: allComments,
      ignoredRules,
      rawSql: sql.slice(firstTok.offset, lastTok.endOffset),
      startLine: firstTok.line,
      startColumn: firstTok.column,
      endLine: lastTok.endLine,
      endColumn: lastTok.endColumn,
    });

    currentTokens = [];
    currentComments = [];
  };

  let idx = 0;
  while (idx < allTokens.length) {
    const tok = allTokens[idx];

    if (tok.kind === "comment") {
      extractIgnorePragmas(tok.raw, new Set(), fileIgnoredRules);
      currentComments.push(tok);
      idx += 1;
      continue;
    }

    if (tok.kind === "punct" && tok.raw === ";") {
      const trailingSameLine: SqlToken[] = [];
      let lookahead = idx + 1;
      while (
        lookahead < allTokens.length &&
        allTokens[lookahead].kind === "comment" &&
        allTokens[lookahead].line === tok.endLine
      ) {
        trailingSameLine.push(allTokens[lookahead]);
        lookahead += 1;
      }
      flushStatement(tok, trailingSameLine);
      idx = lookahead;
      continue;
    }

    if (isStandaloneGoBatchSeparator(allTokens, idx)) {
      flushStatement();
      // Skip optional repeat count on same line (e.g. GO 2)
      if (
        idx + 1 < allTokens.length &&
        allTokens[idx + 1].kind === "number" &&
        allTokens[idx + 1].line === tok.line
      ) {
        idx += 2;
      } else {
        idx += 1;
      }
      continue;
    }

    currentTokens.push(tok);
    idx += 1;
  }

  flushStatement();

  // Propagate any file-level pragmas discovered later in the file to all statements
  if (fileIgnoredRules.size > 0) {
    for (const stmt of statements) {
      for (const rule of fileIgnoredRules) {
        stmt.ignoredRules.add(rule);
      }
    }
  }

  return {
    tokens: allTokens,
    statements,
    fileIgnoredRules,
  };
}

/**
 * Unquotes single-quoted SQL string token into its raw inner content.
 */
export function unquoteSqlString(raw: string): string {
  const quoteIdx = raw.indexOf("'");
  if (quoteIdx >= 0 && raw.endsWith("'") && raw.length >= quoteIdx + 2) {
    return raw.slice(quoteIdx + 1, -1).replace(/''/g, "'");
  }
  return raw;
}
