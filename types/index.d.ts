// Type definitions for regex-shield 1.0.0
// The package ships as ESM and CommonJS from the same named exports.

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export type ComplexityClass = 'linear' | 'quadratic' | 'cubic' | 'exponential';

export type RuleId =
  | 'nested-quantifier'
  | 'overlapping-adjacent-quantifiers'
  | 'overlapping-alternation-quantifier'
  | 'backreference-in-quantifier'
  | 'lookaround-in-quantifier'
  | 'nullable-quantifier-body'
  | 'multiple-unbounded-wildcards'
  | 'broad-unbounded-quantifier';

export interface FindingDetail {
  sampleChar?: string | null;
  terminator?: string;
  ranges?: Array<[number, number]>;
  starHeight?: number;
  bounds?: string;
  leftBounds?: string;
  rightBounds?: string;
  repeatUnit?: string;
  chainLength?: number;
  branches?: string[];
  [key: string]: unknown;
}

export interface Finding {
  /** Stable rule code, RS001 through RS008. */
  id: string;
  code: string;
  rule: RuleId;
  title: string;
  severity: RiskLevel;
  complexity: ComplexityClass;
  /** Always "CWE-1333" for the rules in this release. */
  cwe: string;
  /** Character offset of the relevant construct in the pattern source. */
  index: number;
  message: string;
  explanation: string;
  remediation: string;
  detail: FindingDetail;
}

export interface Witness {
  code: string;
  rule: RuleId;
  severity: RiskLevel;
  input: string;
  length: number;
  rationale: string;
}

export interface ComplexitySummary {
  starHeight: number;
  quantifierDepth: number;
  unboundedQuantifiers: number;
  alternations: number;
  backreferences: number;
  lookarounds: number;
  worstCase: ComplexityClass;
}

export interface Analysis {
  pattern: string;
  flags: string;
  safe: boolean;
  risk: RiskLevel;
  score: number;
  findings: Finding[];
  witnessHint: string;
  witnesses: Witness[];
  starHeight: number;
  complexity: ComplexitySummary;
  parsed: {
    captureCount: number;
    groupNames: string[];
  };
}

export interface AstNode {
  type: string;
  index?: number;
  end?: number;
  [key: string]: unknown;
}

export interface RootAst extends AstNode {
  type: 'root';
  pattern: string;
  flags: string;
  body: AstNode;
  captureCount: number;
  groupNames: string[];
}

export interface AnalyzeOptions {
  /** Flags used when the input is a pattern string. Defaults to "". */
  flags?: string;
  /** Lowest severity that assertSafeRegex rejects. Defaults to "medium". */
  threshold?: RiskLevel;
  /** Emit witness hints. Defaults to true. */
  witnesses?: boolean;
  /** Include the informational broad-unbounded rule. Defaults to true. */
  includeBroad?: boolean;
  /** Cap on returned findings. Defaults to 100. */
  maxFindings?: number;
}

export interface PatternInput {
  pattern: string;
  flags?: string;
}

export interface ScanResult extends Analysis {
  index: number;
}

export declare const VERSION: string;
export declare const CWE_ID: 'CWE-1333';
export declare const CWE_URL: string;

export declare const RULES: Readonly<{
  NESTED_QUANTIFIER: 'nested-quantifier';
  OVERLAPPING_ADJACENT: 'overlapping-adjacent-quantifiers';
  OVERLAPPING_ALTERNATION: 'overlapping-alternation-quantifier';
  BACKREFERENCE_IN_QUANTIFIER: 'backreference-in-quantifier';
  LOOKAROUND_IN_QUANTIFIER: 'lookaround-in-quantifier';
  NULLABLE_QUANTIFIER_BODY: 'nullable-quantifier-body';
  MULTIPLE_WILDCARDS: 'multiple-unbounded-wildcards';
  BROAD_UNBOUNDED: 'broad-unbounded-quantifier';
}>;

export declare class RegexParseError extends Error {
  name: 'RegexParseError';
  pattern: string;
  index: number;
}

export declare class UnsafeRegexError extends Error {
  name: 'UnsafeRegexError';
  pattern: string;
  flags: string;
  risk: RiskLevel;
  score: number;
  analysis: Analysis;
  findings: Finding[];
}

export declare class CharSet {
  constructor(ranges: Array<[number, number]>, meta?: Record<string, unknown>);
  readonly ranges: Array<[number, number]>;
  readonly meta: Record<string, unknown>;
  readonly isEmpty: boolean;
  readonly size: number;
  static literal(codePoint: number): CharSet;
  static category(letter: string, negated: boolean): CharSet;
  static dot(): CharSet;
  static universe(): CharSet;
  static property(raw: string, negated: boolean): CharSet;
  intersects(other: CharSet): boolean;
  intersect(other: CharSet): CharSet;
  union(other: CharSet): CharSet;
  subsetOf(other: CharSet): boolean;
  contains(codePoint: number): boolean;
  sampleCodePoint(exclude?: Array<string | number>): number | null;
  describe(limit?: number): string;
}

export declare function analyzeRegex(
  input: string | RegExp | PatternInput,
  options?: AnalyzeOptions
): Analysis;

export declare function isSafeRegex(
  input: string | RegExp | PatternInput,
  options?: AnalyzeOptions
): boolean;

export declare function assertSafeRegex(
  input: string | RegExp | PatternInput,
  options?: AnalyzeOptions
): Analysis;

export declare function scan(
  patterns: Array<string | RegExp | PatternInput>,
  options?: AnalyzeOptions
): ScanResult[];

export declare function parseRegex(pattern: string, flags?: string): RootAst;
