/**
 * Single source of truth for protocol identifiers and block-opening directives
 * recognized by this spec version. New protocols are added here in one place;
 * the parser, validator, and audit tool all read from this module.
 *
 * Experimental / unregistered identifiers MAY use the `x-` prefix (e.g.
 * `x-mypay`). Parsers MUST accept them; validators MUST NOT warn on them.
 * This is the runway for new protocols before they are formally registered.
 */

export const PAYMENT_PROTOCOLS = ['x402', 'mpp', 'ap2'] as const;
export type PaymentProtocol = (typeof PAYMENT_PROTOCOLS)[number];

export const AUTH_PROTOCOLS = ['agent-auth', 'oauth2', 'auth-md'] as const;
export type AuthProtocol = (typeof AUTH_PROTOCOLS)[number];

export const MPP_METHODS = ['tempo', 'stripe'] as const;
export type MppMethod = (typeof MPP_METHODS)[number];

/**
 * Block-opening directives. Each entry names the directive key that opens a
 * capability block in `agents.txt`. Adding a new block-level capability is a
 * matter of registering its opening directive here.
 */
export const BLOCK_OPENERS = {
  Protocols: 'payments',
  Authorization: 'authorization',
  MCP: 'mcp',
  Skills: 'skills',
  A2A: 'a2a',
  UCP: 'ucp',
  WebMCP: 'webmcp',
} as const;

export type BlockOpener = keyof typeof BLOCK_OPENERS;
export type BlockKind = (typeof BLOCK_OPENERS)[BlockOpener];

/**
 * Directives that may appear inside a block but never open one. Used by the
 * parser to distinguish "I expected this inside a block" from "this is an
 * unknown directive".
 */
export const BLOCK_BODY_DIRECTIVES = new Set([
  'Payments', // optional policy hint inside the payments block
  'Identity', // optional policy hint inside the authorization block
]);

const KNOWN_PAYMENT_SET: ReadonlySet<string> = new Set(PAYMENT_PROTOCOLS);
const KNOWN_AUTH_SET: ReadonlySet<string> = new Set(AUTH_PROTOCOLS);

export function isExperimentalIdentifier(value: string): boolean {
  return value.startsWith('x-') && value.length > 2;
}

export function isKnownPaymentProtocol(value: string): boolean {
  return KNOWN_PAYMENT_SET.has(value);
}

export function isKnownAuthProtocol(value: string): boolean {
  return KNOWN_AUTH_SET.has(value);
}

/**
 * `true` for identifiers that should silently pass validation: either formally
 * registered, or experimental via the `x-` prefix.
 */
export function isAcceptedPaymentIdentifier(value: string): boolean {
  return isKnownPaymentProtocol(value) || isExperimentalIdentifier(value);
}

export function isAcceptedAuthIdentifier(value: string): boolean {
  return isKnownAuthProtocol(value) || isExperimentalIdentifier(value);
}
