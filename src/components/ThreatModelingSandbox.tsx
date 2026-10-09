import React, { useState } from 'react';
import { Crosshair, Shield, AlertTriangle, CheckCircle2, Lock, ArrowRight, RefreshCw, Layers } from 'lucide-react';

interface ThreatComponent {
  id: string;
  name: string;
  type: 'External Entity' | 'Process' | 'Data Store' | 'Data Flow' | 'Trust Boundary';
  zone: 'Untrusted Public' | 'DMZ / Perimeter' | 'Trusted Internal VPC' | 'Encrypted Storage';
  threats: {
    strideCategory: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
    description: string;
    impact: string;
    mitigation: string;
    mitigated: boolean;
  }[];
}

interface ThreatScenario {
  id: string;
  title: string;
  description: string;
  components: ThreatComponent[];
}

const SCENARIOS: ThreatScenario[] = [
  {
    id: 'ecommerce',
    title: 'Cloud E-Commerce & Payment Microservices',
    description: 'A distributed e-commerce architecture handling customer carts, coupon redemptions, and third-party credit card tokenization.',
    components: [
      {
        id: 'client-browser',
        name: 'Web Browser / Mobile Client',
        type: 'External Entity',
        zone: 'Untrusted Public',
        threats: [
          {
            strideCategory: 'Spoofing',
            description: 'Adversary uses stolen session cookies or forged JWT headers to impersonate legitimate shopper.',
            impact: 'Unauthorized access to user profile, order history, and saved addresses.',
            mitigation: 'Enforce HttpOnly, Secure, SameSite=Lax cookies with short expirations and WebAuthn MFA.',
            mitigated: true,
          },
          {
            strideCategory: 'Denial of Service',
            description: 'Botnet floods checkout endpoint with millions of concurrent checkout requests.',
            impact: 'Database connection pool exhaustion and checkout downtime for real customers.',
            mitigation: 'Deploy edge Cloudflare WAF with sliding-window Redis token bucket rate limiting.',
            mitigated: false,
          },
        ],
      },
      {
        id: 'api-gateway',
        name: 'Edge API Gateway & WAF',
        type: 'Process',
        zone: 'DMZ / Perimeter',
        threats: [
          {
            strideCategory: 'Tampering',
            description: 'Attacker tampers with request payloads or injects headers across trust boundary.',
            impact: 'Downstream microservice executes unauthorized operations due to forged X-User-Role.',
            mitigation: 'Strip all incoming client headers at the perimeter; cryptographically sign internal JWT tokens.',
            mitigated: false,
          },
          {
            strideCategory: 'Information Disclosure',
            description: 'Gateway returns verbose internal stack traces and server versions in HTTP 500 responses.',
            impact: 'Reveals internal framework versions and file paths to automated scanners.',
            mitigation: 'Enforce standardized RFC 7807 problem details with zero internal debug info leaked.',
            mitigated: true,
          },
        ],
      },
      {
        id: 'order-service',
        name: 'Order & Inventory Service',
        type: 'Process',
        zone: 'Trusted Internal VPC',
        threats: [
          {
            strideCategory: 'Elevation of Privilege',
            description: 'Race condition (TOCTOU) allows attacker to redeem a single-use promo code 50 times in parallel.',
            impact: 'Financial loss from unauthorized discounting and drained inventory.',
            mitigation: 'Enforce atomic database updates (WHERE is_used = false) within an ACID transaction.',
            mitigated: false,
          },
          {
            strideCategory: 'Repudiation',
            description: 'User disputes a fraudulent $5,000 order; system has no signed audit trail of the checkout transaction.',
            impact: 'Payment chargeback loss with no legal evidence to defend against fraud.',
            mitigation: 'Write immutable, append-only audit records with actor IP, timestamp, and digital signature.',
            mitigated: true,
          },
        ],
      },
      {
        id: 'database-store',
        name: 'Customer & Transaction Database (PostgreSQL)',
        type: 'Data Store',
        zone: 'Encrypted Storage',
        threats: [
          {
            strideCategory: 'Information Disclosure',
            description: 'SQL injection in search endpoint extracts all customer PII and password hashes.',
            impact: 'Catastrophic public data breach and regulatory GDPR/CCPA fines.',
            mitigation: 'Mandate 100% parameterized queries, PostgreSQL Row-Level Security, and least-privilege DB user.',
            mitigated: true,
          },
          {
            strideCategory: 'Tampering',
            description: 'Attacker modifies transaction row directly via compromised database connection.',
            impact: 'Altered balances or deleted audit logs.',
            mitigation: 'Enable KMS envelope encryption at rest, TLS 1.3 in transit, and database read-only replicas.',
            mitigated: false,
          },
        ],
      },
    ],
  },
  {
    id: 'oauth-server',
    title: 'OAuth 2.0 & OIDC Identity Provider',
    description: 'Central authentication server issuing JWT access tokens and ID tokens to single-page applications and mobile clients.',
    components: [
      {
        id: 'spa-client',
        name: 'Single Page App (Public Client)',
        type: 'External Entity',
        zone: 'Untrusted Public',
        threats: [
          {
            strideCategory: 'Spoofing',
            description: 'Attacker intercepts OAuth authorization code redirect via custom URI scheme.',
            impact: 'Attacker trades stolen code for user access token and takes over account.',
            mitigation: 'Mandate PKCE (Proof Key for Code Exchange) with S256 code challenge for all public clients.',
            mitigated: true,
          },
        ],
      },
      {
        id: 'token-endpoint',
        name: 'Token Issuing Engine',
        type: 'Process',
        zone: 'DMZ / Perimeter',
        threats: [
          {
            strideCategory: 'Elevation of Privilege',
            description: 'Attacker exploits algorithm confusion to sign fake tokens with RS256 public key using HS256.',
            impact: 'Universal authentication bypass granting administrative superuser access.',
            mitigation: 'Pin accepted JWT algorithms to RS256 only; validate issuer, audience, and exp timestamps.',
            mitigated: false,
          },
        ],
      },
    ],
  },
];

export const ThreatModelingSandbox: React.FC = () => {
  const [selectedScenarioId, setSelectedScenarioId] = useState('ecommerce');
  const [selectedComponentId, setSelectedComponentId] = useState('client-browser');
  const [mitigationsState, setMitigationsState] = useState<Record<string, boolean>>({});

  const scenario = SCENARIOS.find((s) => s.id === selectedScenarioId) || SCENARIOS[0];
  const activeComponent = scenario.components.find((c) => c.id === selectedComponentId) || scenario.components[0];

  const toggleMitigation = (threatIdx: number) => {
    const key = `${scenario.id}-${activeComponent.id}-${threatIdx}`;
    setMitigationsState((prev) => ({
      ...prev,
      [key]: !isThreatMitigated(threatIdx),
    }));
  };

  const isThreatMitigated = (threatIdx: number) => {
    const key = `${scenario.id}-${activeComponent.id}-${threatIdx}`;
    if (mitigationsState[key] !== undefined) {
      return mitigationsState[key];
    }
    return activeComponent.threats[threatIdx]?.mitigated ?? false;
  };

  // Compute overall security score for scenario
  let totalThreats = 0;
  let mitigatedThreats = 0;
  scenario.components.forEach((c) => {
    c.threats.forEach((t, idx) => {
      totalThreats++;
      const key = `${scenario.id}-${c.id}-${idx}`;
      const isMit = mitigationsState[key] !== undefined ? mitigationsState[key] : t.mitigated;
      if (isMit) mitigatedThreats++;
    });
  });

  const securityScore = Math.round((mitigatedThreats / totalThreats) * 100);

  return (
    <div className="space-y-8 pb-16">
      {/* Intro Header */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/80 space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-amber-400 font-semibold uppercase">
          <Crosshair className="w-4 h-4" />
          <span>Interactive STRIDE Threat Modeling Laboratory</span>
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          System Architecture & Threat Boundary Inspector
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Deconstruct real-world architectures into trust boundaries, assets, and data flows. Apply the Microsoft STRIDE
          model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
          and verify cryptographic and software mitigations.
        </p>

        {/* Scenario Switcher */}
        <div className="flex items-center gap-2 pt-2 overflow-x-auto">
          {SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              onClick={() => {
                setSelectedScenarioId(sc.id);
                setSelectedComponentId(sc.components[0].id);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                selectedScenarioId === sc.id
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {sc.title}
            </button>
          ))}
        </div>
      </div>

      {/* Main 2-Zone Stage */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Architecture Component Map (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-950 p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs text-slate-400 font-mono">Architecture Map</span>
              <h2 className="text-base font-bold text-white">{scenario.title}</h2>
            </div>
            <div className="text-right">
              <span className="text-xs text-slate-400 font-mono">Security Posture</span>
              <div className="text-lg font-bold text-cyan-400 font-mono tabular-nums">
                {securityScore}% <span className="text-xs text-slate-500 font-normal">Mitigated</span>
              </div>
            </div>
          </div>

          <p className="text-xs text-slate-400">
            Click on any architectural component below to inspect trust boundary crossings and analyze STRIDE threats:
          </p>

          {/* Component Nodes Grid */}
          <div className="space-y-3">
            {scenario.components.map((comp) => {
              const isSelected = comp.id === activeComponent.id;
              const unmitigatedCount = comp.threats.filter((t, idx) => !isThreatMitigated(idx)).length;

              return (
                <div
                  key={comp.id}
                  onClick={() => setSelectedComponentId(comp.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer select-none flex items-center justify-between gap-4 ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-950/20 shadow-md'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border ${
                        isSelected
                          ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300'
                          : 'bg-slate-800 border-slate-700 text-slate-400'
                      }`}
                    >
                      <Layers className="w-5 h-5" />
                    </div>

                    <div>
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                        <span className="text-cyan-400">{comp.type}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-slate-500">{comp.zone}</span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-100">{comp.name}</h3>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {unmitigatedCount > 0 ? (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-950/60 text-rose-300 border border-rose-900/50 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3 text-rose-400" />
                        <span>{unmitigatedCount} Open</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-900/50 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        <span>Protected</span>
                      </span>
                    )}

                    <ArrowRight className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-600'}`} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Trust Boundary Legend */}
          <div className="p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/40 text-xs text-slate-400 flex flex-wrap items-center gap-4">
            <span className="font-semibold text-slate-300">Legend:</span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Untrusted Zone
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> DMZ Perimeter
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" /> Internal VPC
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Encrypted Vault
            </span>
          </div>
        </div>

        {/* Right: STRIDE Threat Inspector (5 cols) */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/90 p-6 space-y-6">
          <div className="border-b border-slate-800 pb-3">
            <div className="text-xs font-mono text-cyan-400 mb-0.5">STRIDE Inspector</div>
            <h3 className="text-base font-bold text-white">{activeComponent.name}</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Zone: <span className="text-slate-300">{activeComponent.zone}</span> · Type:{' '}
              <span className="text-slate-300">{activeComponent.type}</span>
            </p>
          </div>

          {/* Threat Cards */}
          <div className="space-y-4">
            {activeComponent.threats.map((threat, idx) => {
              const isMitigated = isThreatMitigated(idx);

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border space-y-3 transition-colors ${
                    isMitigated
                      ? 'border-emerald-900/40 bg-slate-950/60'
                      : 'border-rose-900/50 bg-rose-950/20'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                        {threat.strideCategory}
                      </span>
                      <span className="text-xs font-semibold text-slate-300">Threat #{idx + 1}</span>
                    </div>

                    <button
                      onClick={() => toggleMitigation(idx)}
                      className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors flex items-center gap-1 ${
                        isMitigated
                          ? 'bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-300 hover:bg-rose-500/30'
                      }`}
                    >
                      {isMitigated ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Mitigated</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                          <span>Apply Patch</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div>
                    <div className="text-xs text-slate-300 font-medium leading-relaxed">
                      {threat.description}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      <span className="font-semibold text-slate-300">Impact:</span> {threat.impact}
                    </div>
                  </div>

                  {/* Remediation Pattern */}
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-[11px] text-cyan-200">
                    <span className="font-bold text-cyan-400 mr-1">Recommended Defense:</span>
                    {threat.mitigation}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
