import { Mppx, tempo, stripe } from 'mppx/server'
import Stripe from 'stripe'

interface Env {
  ASSETS: Fetcher;
  MCP?:  { fetch: typeof fetch };
  AUTH?: { fetch: typeof fetch };
  // MPP — set via `wrangler secret put` (required for MPP payments)
  STRIPE_SECRET_KEY?: string;
  STRIPE_NETWORK_ID?: string;
  MPP_SECRET_KEY?: string;
  TREASURY_TEMPO?: string;   // 0x... Tempo wallet address
}

const MCP_PREFIXES  = ['/mcp', '/sse'];
const AUTH_PREFIXES = ['/.well-known/agent-configuration', '/agent/', '/capability/', '/auth'];

function matches(pathname: string, prefixes: string[]): boolean {
  return prefixes.some(p =>
    pathname === p || pathname.startsWith(p.endsWith('/') ? p : p + '/')
  );
}

function proxyTo(request: Request, binding: { fetch: typeof fetch }): Promise<Response> {
  const url = new URL(request.url);
  const fwd = new Headers(request.headers);
  if (url.search) fwd.set('x-original-query', url.search);
  return binding.fetch(new Request(request.url, {
    method:  request.method,
    headers: fwd,
    body:    ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    redirect: 'manual',
  }));
}

// ─── x402 v2 payment requirements ────────────────────────────────────────────
// Replace placeholder addresses with your real wallet addresses before deploying.
// EVM address is the same across all EVM-compatible chains.

const TREASURY_EVM    = '0x0000000000000000000000000000000000000000';
const TREASURY_SOLANA = '11111111111111111111111111111111';

// USDC.e contract on Tempo mainnet
const TEMPO_USDC_E = '0x20c0000000000000000000000000000000000000';

// Single $0.01 test amount. USDC has 6 decimals; '10000' is 0.01 USDC in atomic units.
// This endpoint exists as a payment proof-of-concept, not a revenue mechanism.
const TEST_AMOUNT = '10000';
const TEST_DESCRIPTION = 'agents.txt — payment proof-of-concept ($0.01)';

// MPP test amount: $0.01 dollar string (mppx normalizes per method).
const MPP_TEST_AMOUNT = '0.01';

// Supported chains for x402 payment. Each emits one accepts[] entry.
const CHAINS = [
  { network: 'eip155:8453',                        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: TREASURY_EVM,    base: { name: 'USDC', version: '2' } },
  { network: 'eip155:1',                           asset: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', payTo: TREASURY_EVM,    base: { name: 'USDC', version: '2' } },
  { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', payTo: TREASURY_SOLANA, base: { name: 'USDC' } },
] as const;

// 3 chains × 1 amount = 3 accepts[] entries. Agent picks chain.
const PAYMENT_TEST_ACCEPTS = CHAINS.map(chain => ({
  scheme: 'exact',
  network: chain.network,
  amount:  TEST_AMOUNT,
  asset:   chain.asset,
  payTo:   chain.payTo,
  maxTimeoutSeconds: 60,
  extra: { ...chain.base, description: TEST_DESCRIPTION },
}));

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Expose-Headers': 'X-Payment-Response',
};

// ─── MPP — lazy-initialized per-isolate ──────────────────────────────────────
// Built once on first request; env bindings are not available at module scope.
let mppxInstance: ReturnType<typeof Mppx.create> | null = null;

function getMppx(env: Env): ReturnType<typeof Mppx.create> | null {
  if (mppxInstance) return mppxInstance;

  const tempoRecipient = env.TREASURY_TEMPO;
  const hasStripe = env.STRIPE_SECRET_KEY && env.STRIPE_NETWORK_ID;

  if (!tempoRecipient && !hasStripe) return null;

  const methods: Parameters<typeof Mppx.create>[0]['methods'] = [];

  if (tempoRecipient) {
    methods.push(tempo.charge({ currency: TEMPO_USDC_E, recipient: tempoRecipient, testnet: false }));
  }

  if (hasStripe) {
    const stripeClient = new Stripe(env.STRIPE_SECRET_KEY!, { apiVersion: '2026-03-04.preview' as never });
    methods.push(stripe.charge({
      client: stripeClient,
      networkId: env.STRIPE_NETWORK_ID!,
      paymentMethodTypes: ['card', 'link'],
    }));
  }

  if (methods.length === 0) return null;

  mppxInstance = Mppx.create({
    methods,
    secretKey: env.MPP_SECRET_KEY,
    realm: 'agents.txt',
  });
  return mppxInstance;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (env.MCP  && matches(pathname, MCP_PREFIXES))  return proxyTo(request, env.MCP);
    if (env.AUTH && matches(pathname, AUTH_PREFIXES)) return proxyTo(request, env.AUTH);

    if (pathname === '/payment-test') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: CORS });
      }

      const paymentSig  = request.headers.get('Payment-Signature') ?? request.headers.get('X-Payment');
      const authPayment = request.headers.get('Authorization');
      const isMppRetry  = authPayment?.startsWith('Payment ') ?? false;

      const mppx = getMppx(env);

      // ── MPP verify (agent retrying with Authorization: Payment credential) ──
      if (isMppRetry && mppx) {
        const tempoRecipient = env.TREASURY_TEMPO ?? '';
        const result = await Mppx.compose(
          ...(tempoRecipient ? [mppx.tempo.charge({ amount: MPP_TEST_AMOUNT, description: TEST_DESCRIPTION, recipient: tempoRecipient })] : []),
          ...(env.STRIPE_NETWORK_ID ? [mppx.stripe.charge({ amount: MPP_TEST_AMOUNT, description: TEST_DESCRIPTION, currency: 'usd' })] : []),
        )(request);

        if (result.status !== 402) {
          return result.withReceipt(new Response(JSON.stringify({
            message:  'Payment-test verified. agents.txt is implemented end-to-end.',
            resource: 'https://agentstxt.dev/payment-test',
            standard: 'https://agentstxt.dev',
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...CORS },
          }));
        }
        // credential invalid — fall through to issue a fresh 402
      }

      // ── x402 verify (agent retrying with Payment-Signature) ──────────────────
      if (paymentSig) {
        let paymentPayload: unknown;
        try {
          paymentPayload = JSON.parse(atob(paymentSig));
        } catch {
          return new Response(JSON.stringify({ error: 'Invalid Payment-Signature encoding' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...CORS },
          });
        }

        const pp = paymentPayload as { accepted?: { network?: string; amount?: string } };
        const network = pp.accepted?.network;
        const amount  = pp.accepted?.amount;
        // Match on network + atomic amount. The amount is fixed at TEST_AMOUNT;
        // a payload claiming a different amount won't match and gets rejected.
        const requirements = PAYMENT_TEST_ACCEPTS.find(a =>
          a.network === network && (amount == null || a.amount === amount)
        );
        if (!requirements) {
          return new Response(JSON.stringify({ error: `Unsupported or missing network: ${network ?? '(none)'}` }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...CORS },
          });
        }

        // Delegate to the public x402 facilitator — free, no API key required.
        const facilRes = await fetch('https://x402.org/facilitator/settle', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({
            x402Version:        2,
            paymentPayload,
            paymentRequirements: requirements,
          }),
        });

        const result = await facilRes.json() as {
          success?:      boolean;
          transaction?:  string;
          network?:      string;
          payer?:        string;
          errorReason?:  string;
          errorMessage?: string;
        };

        if (!result.success) {
          return new Response(JSON.stringify({
            error:   result.errorReason  ?? 'Settlement failed',
            message: result.errorMessage ?? 'The facilitator rejected the payment.',
          }), {
            status: 402,
            headers: { 'Content-Type': 'application/json', ...CORS },
          });
        }

        const settlement = {
          success:     true,
          transaction: result.transaction!,
          network:     result.network ?? network,
          payer:       result.payer,
        };

        return new Response(JSON.stringify({
          message:  'Payment-test verified. agents.txt is implemented end-to-end.',
          resource: 'https://agentstxt.dev/payment-test',
          standard: 'https://agentstxt.dev',
          ...settlement,
        }), {
          status: 200,
          headers: {
            'Content-Type':      'application/json',
            'X-Payment-Response': btoa(JSON.stringify(settlement)),
            ...CORS,
          },
        });
      }

      // ── No payment header — issue 402 with both x402 + MPP challenge ─────────
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...CORS,
      };

      // Attach MPP WWW-Authenticate challenge if configured; also surface it in the
      // JSON body so agents reading the body see both protocols in one place.
      let mppWwwAuthenticate: string | null = null;
      if (mppx) {
        const tempoRecipient = env.TREASURY_TEMPO ?? '';
        const mppChallenge = await Mppx.compose(
          ...(tempoRecipient ? [mppx.tempo.charge({ amount: MPP_TEST_AMOUNT, description: TEST_DESCRIPTION, recipient: tempoRecipient })] : []),
          ...(env.STRIPE_NETWORK_ID ? [mppx.stripe.charge({ amount: MPP_TEST_AMOUNT, description: TEST_DESCRIPTION, currency: 'usd' })] : []),
        )(request);

        mppWwwAuthenticate = mppChallenge.challenge.headers.get('WWW-Authenticate');
        if (mppWwwAuthenticate) headers['WWW-Authenticate'] = mppWwwAuthenticate;
      }

      return new Response(JSON.stringify({
        x402Version: 2,
        error: 'Payment required',
        resource: {
          url:         'https://agentstxt.dev/payment-test',
          description: 'Proof-of-concept payment endpoint for the agents.txt standard. Fixed $0.01 test charge to demonstrate x402 v2 + MPP end-to-end. Not a revenue mechanism.',
          mimeType:    'application/json',
        },
        accepts: PAYMENT_TEST_ACCEPTS,
        ...(mppWwwAuthenticate && {
          mpp: { challenge: mppWwwAuthenticate },
        }),
      }, null, 2), {
        status: 402,
        headers,
      });
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
