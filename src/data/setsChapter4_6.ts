import { LearningSet } from '../types/curriculum';

export const SETS_CHAPTER_4_6: LearningSet[] = [
  // CHAPTER 4
  {
    id: '4.1',
    chapterId: 4,
    setIndex: 1,
    title: 'Defense in depth and layered security controls',
    summary: 'Design multi-layered defensive rings so single-point control failures do not cause catastrophic compromise.',
    domain: 'architecture',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-693: Protection Mechanism Failure',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Architectural Defense in Depth Rings',
        content: 'Defense in Depth assumes that any single defensive mechanism (e.g. firewall, WAF, or password check) will eventually fail or be bypassed. Defenses are structured across concentric rings: Network (VPC, security groups), Perimeter (WAF, DDoS mitigation), Application (authentication, authorization, input validation), Host/Container (unprivileged execution, read-only root filesystems), and Data (encryption at rest, tokenization, database access controls).',
        keyPrinciple: 'If an adversary breaches layer N, layer N+1 must independently detect, contain, or block the intrusion.',
      },
      {
        title: 'Preventing Single Points of Compromise',
        content: 'Never rely on perimeter firewalls or WAFs alone to stop SQL injection or XSS; application-level parameterized queries and context-aware encoding provide indispensable second-layer barriers.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker bypasses WAF with URL-encoding trick and finds backend without parameterized queries or authorization.',
      cweOrStandard: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
      impact: 'Full database exfiltration because backend developer assumed the WAF would stop all SQL injection.',
      realWorldScenario: 'An enterprise omitted parameterized queries on internal microservices because they believed their Cloudflare WAF made internal input validation redundant.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Layered Defense: Application & Storage Redundancy',
      description: 'Audit an internal service that neglected local validation believing perimeter proxies sanitized everything.',
      vulnerableCode: `// VULNERABLE: Relies entirely on upstream WAF; raw concatenation in database
app.post('/api/products/search', async (req, res) => {
  const { query } = req.body;
  // FLAW: Assumes upstream WAF blocked all malicious characters!
  const results = await db.query(
    "SELECT id, name, price FROM products WHERE name ILIKE '%" + query + "%'"
  );
  res.json(results);
});`,
      remediatedCode: `// REMEDIATED: Layered Defense with schema validation, parameterized query, and output limit
import { z } from 'zod';

const SearchSchema = z.object({
  query: z.string().trim().min(1).max(100).regex(/^[a-zA-Z0-9\\s\\-_]+$/, 'Invalid search characters')
});

app.post('/api/products/search', async (req, res) => {
  // Layer 1: Application-level schema validation
  const validation = SearchSchema.safeParse(req.body);
  if (!validation.success) {
    return res.status(400).json({ error: 'Invalid search input format' });
  }

  const sanitizedQuery = \`%\${validation.data.query}%\`;

  // Layer 2: Parameterized query (Database driver abstraction)
  const results = await db.query(
    'SELECT id, name, price FROM products WHERE name ILIKE $1 LIMIT 50',
    [sanitizedQuery]
  );

  // Layer 3: Controlled response payload (No sensitive internal fields leaked)
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.json({ results: results.rows });
});`,
      flawExplanation: 'Assuming upstream filters protect downstream execution creates brittle single points of failure that collapse when WAF rules are bypassed.',
      fixExplanation: 'Implements layered defense: strict Zod schema validation, parameterized SQL statements, query row limits, and bounded outputs.',
    },
    quiz: {
      question: 'Which design decision best exemplifies the principle of Defense in Depth?',
      options: [
        'Relying solely on a Web Application Firewall to block all XSS attacks across legacy unescaped templates.',
        'Using parameterized queries, input schema allowlists, and least-privilege database user permissions simultaneously.',
        'Storing sensitive user passwords with MD5 because the database server is behind a private subnet.',
        'Disabling HTTPS on internal microservices to improve RPC throughput.',
      ],
      correctAnswer: 1,
      explanation: 'Combining parameterized queries, input validation, and least privilege database accounts ensures security even if one layer fails.',
    },
    defenseChecklist: [
      'Never rely on upstream proxies or WAFs as the sole defense against application attacks.',
      'Enforce least privilege on database accounts (no DROP or administrative rights for application users).',
      'Run application containers with read-only root filesystems and drop all Linux capabilities.',
      'Implement network segmentation between web, API, and database tiers.',
    ],
  },
  {
    id: '4.2',
    chapterId: 4,
    setIndex: 2,
    title: 'Least privilege, separation of duties, and compartmentalization',
    summary: 'Enforce process compartmentalization, fine-grained process capabilities, and two-person authorization gates.',
    domain: 'architecture',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-272: Least Privilege Violation',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Separation of Duties (SoD) in Critical Workflows',
        content: 'Separation of Duties mandates that sensitive, high-impact operations (e.g., initiating wire transfers, deploying to production, deleting customer databases) require approval or participation from at least two distinct authorized subjects (dual control/four-eyes principle).',
        keyPrinciple: 'No single identity or credential should possess unilateral authority to perform catastrophic actions.',
      },
      {
        title: 'Process Compartmentalization',
        content: 'Compartmentalize application workloads so that if a low-privilege background worker or image processing parser is exploited, the adversary cannot reach payment keys or user databases.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Single admin user executing multi-million dollar payout without secondary manager authorization.',
      cweOrStandard: 'CWE-840: Business Logic Errors',
      impact: 'Embezzlement or rogue insider draining company accounts.',
      realWorldScenario: 'A fintech app allowed any support agent to trigger instant user account balance refunds without secondary supervisor sign-off.',
    },
    codeAuditLab: {
      language: 'TypeScript',
      title: 'Missing Dual-Authorization in High-Impact Payout Handler',
      description: 'Audit a payout engine that executes large financial transactions on single-user requests.',
      vulnerableCode: `// VULNERABLE: Single administrator can unilaterally trigger $1,000,000 transfers
app.post('/api/treasury/payout', requireAdminRole, async (req, res) => {
  const { amount, destinationIban } = req.body;
  // Unilateral execution without dual-control or threshold review
  const txn = await bankingGateway.dispatchPayout(amount, destinationIban);
  res.json({ success: true, txn });
});`,
      remediatedCode: `// REMEDIATED: Enforces Separation of Duties & Two-Person Approval for large amounts
app.post('/api/treasury/payout', requireAdminRole, async (req, res) => {
  const { amount, destinationIban, approvalId } = req.body;
  const initiatorId = req.user.id;

  if (amount > 10000) {
    // Requires verified two-person approval
    if (!approvalId) {
      const pendingApproval = await approvalService.createPendingApproval({
        type: 'LARGE_PAYOUT',
        initiatorId,
        details: { amount, destinationIban }
      });
      return res.status(202).json({
        status: 'PENDING_DUAL_APPROVAL',
        message: 'Payout exceeds threshold. A second authorized manager must approve.',
        approvalId: pendingApproval.id
      });
    }

    // Verify second approver is NOT the initiator
    const approval = await approvalService.getApproval(approvalId);
    if (!approval || !approval.approverId || approval.approverId === initiatorId) {
      return res.status(403).json({ error: 'Dual authorization required: Initiator cannot approve own transaction.' });
    }
  }

  const txn = await bankingGateway.dispatchPayout(amount, destinationIban);
  res.json({ success: true, txn });
});`,
      flawExplanation: 'Permitting single-operator execution of high-value actions creates immense fraud and account takeover vulnerability.',
      fixExplanation: 'Enforces four-eyes approval workflow verifying that the second approver is distinct from the initiator for high-value actions.',
    },
    quiz: {
      question: 'What is the primary objective of "Separation of Duties" (SoD) in enterprise application design?',
      options: [
        'To reduce server CPU usage by splitting tasks across multiple threads.',
        'To ensure no single user has sufficient authority to commit fraud or destructive changes unilaterally.',
        'To prevent frontend developers from writing SQL queries.',
        'To speed up CI/CD pipeline deployments.',
      ],
      correctAnswer: 1,
      explanation: 'Separation of duties requires multiple distinct parties to complete critical actions, preventing single points of fraud or compromise.',
    },
    defenseChecklist: [
      'Enforce two-person review for sensitive actions (e.g., prod database modifications, large funds transfers).',
      'Split microservices into compartmentalized least-privilege execution containers.',
      'Run image, PDF, and untrusted file parsers in isolated sandboxes with no network egress.',
      'Regularly audit admin permissions and remove standing elevated privileges.',
    ],
  },
  {
    id: '4.3',
    chapterId: 4,
    setIndex: 3,
    title: 'Secure defaults, fail-safe, and fail-secure design',
    summary: 'Implement out-of-the-box secure defaults (closed ports, default-deny firewalls, strict CSP, secure cookies).',
    domain: 'architecture',
    duration: '20 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-1188: Insecure Default Initialization of Resource',
    owaspTop10: 'A05:2021-Security Misconfiguration',
    concepts: [
      {
        title: 'The Philosophy of Secure Defaults',
        content: 'Software should be secure out-of-the-box without requiring users or developers to enable obscure configuration flags. Insecure options must require explicit, intentional opt-in with loud warnings. Examples: Cookies should default to HttpOnly, Secure, and SameSite=Lax; API endpoints should default to 401 Unauthorized unless marked @Public.',
        keyPrinciple: 'Security should be the path of least resistance.',
      },
      {
        title: 'Fail-Secure Architecture Patterns',
        content: 'When downstream identity providers, policy agents, or HSMs fail or time out, the system must enter a safe degraded state (deny access, freeze transactions) rather than assuming benign intent.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Insecure cookie defaults permitting JavaScript reading and cross-site transmission of session tokens.',
      cweOrStandard: 'CWE-1004: Sensitive Cookie Without \'HttpOnly\' Flag',
      impact: 'Account takeover via Cross-Site Scripting (XSS) stealing document.cookie.',
      realWorldScenario: 'A framework set session cookies with httpOnly: false by default, enabling an XSS vulnerability on a blog post to steal admin credentials.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express',
      title: 'Insecure Cookie Defaults Configuration',
      description: 'Audit session cookie initialization with permissive, insecure default flags.',
      vulnerableCode: `// VULNERABLE: Insecure defaults allow XSS reading, plaintext transmission, and CSRF
app.use(session({
  secret: 'app_secret_123',
  cookie: {
    // Missing httpOnly: true!
    // Missing secure: true!
    // Missing sameSite: 'lax' | 'strict'!
    maxAge: 24 * 60 * 60 * 1000
  }
}));`,
      remediatedCode: `// REMEDIATED: Secure defaults enforced out of the box
app.use(session({
  name: '__Host-app_session', // Uses __Host- prefix for origin and path isolation
  secret: process.env.SESSION_SECRET_KEY!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Prevents client JS access via document.cookie
    secure: process.env.NODE_ENV === 'production', // Transmitted strictly over HTTPS
    sameSite: 'lax', // Protects against cross-site request forgery
    path: '/',
    maxAge: 4 * 60 * 60 * 1000 // Bounded 4-hour lifespan
  }
}));`,
      flawExplanation: 'Omitting httpOnly and secure flags permits JavaScript to steal session tokens and transmits cookies over unencrypted plaintext HTTP.',
      fixExplanation: 'Enforces httpOnly: true, secure: true, sameSite: "lax", and the __Host- cookie security prefix.',
    },
    quiz: {
      question: 'What is the primary benefit of applying the __Host- prefix to HTTP session cookies?',
      options: [
        'It allows the cookie to be shared across all subdomains automatically.',
        'The browser enforces that the cookie is secure (HTTPS only), path is "/", and never sent to any subdomains.',
        'It compresses the cookie payload by 50%.',
        'It prevents the server from logging cookie headers.',
      ],
      correctAnswer: 1,
      explanation: 'The __Host- prefix tells modern browsers to reject the cookie unless it has Secure, path=/, and is scoped strictly to the current origin with no subdomains.',
    },
    defenseChecklist: [
      'Set all session cookies with httpOnly: true, secure: true, and sameSite: "lax" or "strict".',
      'Require explicit @Public annotations for public API endpoints; default all others to authenticated.',
      'Configure production databases to listen only on loopback or private subnet interfaces.',
      'Disable directory indexing and debug stack traces by default in production.',
    ],
  },
  {
    id: '4.4',
    chapterId: 4,
    setIndex: 4,
    title: 'Microservices, APIs, and distributed system security',
    summary: 'Architect resilient distributed systems with service mesh mTLS, token propagation, and API gateways.',
    domain: 'architecture',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-306: Missing Authentication for Critical Function',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Identity Propagation in Microservices',
        content: 'When an edge API Gateway authenticates a user, how is that identity safely conveyed across internal microservices (Service A -> Service B -> Service C)? Insecure systems pass unauthenticated headers or use a single shared superuser service account. Secure architectures mint short-lived, cryptographically signed internal identity tokens or use SPIFFE/SPIRE with mTLS.',
        keyPrinciple: 'Downstream services must know both the calling service identity AND the originating end-user subject.',
      },
      {
        title: 'Service Mesh & Mutual TLS (mTLS)',
        content: 'Service meshes (Istio, Linkerd) provide cryptographic identity, automatic certificate rotation, mutual TLS encryption, and Layer-7 authorization policies (AuthzPolicy) between microservices without requiring changes to application code.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Compromised microservice executes unauthorized operations against payment service due to lack of service identity.',
      cweOrStandard: 'CWE-284: Improper Access Control',
      impact: 'Lateral movement across internal cluster leading to payment fraud.',
      realWorldScenario: 'An attacker exploited an SSRF in a review-rating microservice to invoke the payment microservice directly, which had no caller identity verification.',
    },
    codeAuditLab: {
      language: 'TypeScript / gRPC / HTTP',
      title: 'Insecure Internal Service Identity Propagation',
      description: 'Audit an internal microservice accepting unverified user context headers from upstream callers.',
      vulnerableCode: `// VULNERABLE: Downstream service blindly trusts unverified x-user-id header
app.post('/internal/transact', async (req, res) => {
  const userId = req.headers['x-user-id']; // Spoofable by any service in VPC!
  const { amount } = req.body;
  await debitUserAccount(userId, amount);
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Downstream service verifies signed cryptographically bound internal token
import jwt from 'jsonwebtoken';

app.post('/internal/transact', async (req, res) => {
  const internalToken = req.headers['x-internal-service-token'];
  if (!internalToken || typeof internalToken !== 'string') {
    return res.status(401).json({ error: 'Missing internal service credentials' });
  }

  try {
    // 1. Verify internal token signed by API gateway private key
    const claims = jwt.verify(internalToken, process.env.INTERNAL_JWT_PUBLIC_KEY!, {
      algorithms: ['RS256'],
      issuer: 'api-gateway.internal',
      audience: 'payment-service.internal'
    }) as { sub: string; callerService: string; permissions: string[] };

    // 2. Validate calling service has explicit permission to transact
    if (claims.callerService !== 'checkout-orchestrator') {
      return res.status(403).json({ error: 'Calling service not authorized for payment transactions' });
    }

    const { amount } = req.body;
    await debitUserAccount(claims.sub, amount);
    res.json({ success: true });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired internal token' });
  }
});`,
      flawExplanation: 'Passing raw HTTP headers without cryptographic signatures lets any compromised service or rogue pod impersonate arbitrary users.',
      fixExplanation: 'Mints and verifies short-lived asymmetric JWTs with aud (audience) and iss (issuer) validation, binding user identity to caller authorization.',
    },
    quiz: {
      question: 'What standard framework provides cryptographically verifiable identities for software workloads in heterogeneous platforms?',
      options: [
        'SPIFFE / SPIRE',
        'HTTP/2 multiplexing',
        'SOAP Envelope',
        'GraphQL SDL',
      ],
      correctAnswer: 0,
      explanation: 'SPIFFE (Secure Production Identity Framework for Everyone) and SPIRE define open standards for issuing cryptographically verifiable service identities.',
    },
    defenseChecklist: [
      'Enforce mutual TLS (mTLS) with automated certificate rotation for all internal service communication.',
      'Propagate caller identity using cryptographically signed, short-lived tokens (aud and iss constrained).',
      'Implement Layer 7 egress filtering on microservice pods to block unauthorized outbound network calls.',
      'Deploy an API gateway to enforce rate limiting, WAF inspection, and authentication at the edge.',
    ],
  },
  {
    id: '4.5',
    chapterId: 4,
    setIndex: 5,
    title: 'Cloud-native, zero trust, and hybrid architecture patterns',
    summary: 'Design zero-trust architectures assuming network breach, continuous verification, and ephemeral credentials.',
    domain: 'architecture',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-1188: Insecure Default Initialization of Resource',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Core Principles of Zero Trust (NIST SP 800-207)',
        content: '1. Never trust, always verify. 2. Assume breach: Treat internal corporate and cloud VPC networks as hostile as the public internet. 3. Explicit verification: Authenticate and authorize every transaction based on all available data points (identity, location, device health, resource classification). 4. Least privilege: Provide just-in-time and just-enough access.',
        keyPrinciple: 'Perimeter-only security is obsolete. Identity is the new perimeter.',
      },
      {
        title: 'Ephemeral Credentials & Workload Identity Federation',
        content: 'Eliminate long-lived static cloud keys (e.g., AWS IAM access keys stored in .env). Use Workload Identity Federation (OIDC between GitHub Actions / Kubernetes and AWS/GCP) to exchange short-lived temporary tokens.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Static IAM access keys leaked in Git repository allowing full AWS account compromise.',
      cweOrStandard: 'CWE-798: Use of Hard-coded Credentials',
      impact: 'Rogue crypto-miners deployed and all production S3 buckets deleted.',
      realWorldScenario: 'An engineer committed AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY into a public GitHub repo, resulting in $60,000 of unauthorized EC2 GPU spinning within 30 minutes.',
    },
    codeAuditLab: {
      language: 'TypeScript / Cloud IAM',
      title: 'Static Cloud Keys vs. Ephemeral Workload Identity',
      description: 'Audit cloud SDK initialization using dangerous hardcoded static access keys.',
      vulnerableCode: `// VULNERABLE: Uses static long-lived cloud credentials in source code
import { S3Client } from '@aws-sdk/client-s3';

const s3 = new S3Client({
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE', // Static credential risk!
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  }
});`,
      remediatedCode: `// REMEDIATED: Uses IAM Roles for Service Accounts (IRSA) / DefaultCredentialProvider
import { S3Client } from '@aws-sdk/client-s3';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';

// Uses short-lived, automatically rotated STS tokens via Workload Identity / IRSA
const s3 = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: fromNodeProviderChain({
    // Automatically retrieves temporary credentials from ECS/EKS metadata or Web Identity Token
    // No static credentials ever stored in files or environment variables!
  })
});`,
      flawExplanation: 'Hardcoding or storing static credentials in files creates severe exposure risk via accidental commits, container dumps, or log leaks.',
      fixExplanation: 'Adopts temporary short-lived credentials obtained via IAM Workload Identity Federation with automatic 1-hour rotation.',
    },
    quiz: {
      question: 'Under NIST SP 800-207 Zero Trust Architecture, what is the default trust level assigned to a device located on the internal office LAN?',
      options: [
        'Implicitly trusted because it is inside the physical building.',
        'Zero trust; it must be authenticated and authorized just as if it were connecting from a public coffee shop.',
        'Trusted if it has a static IP address.',
        'Trusted if it connects via Ethernet cable rather than Wi-Fi.',
      ],
      correctAnswer: 1,
      explanation: 'Zero trust mandates that no implicit trust is granted based solely on physical or network location.',
    },
    defenseChecklist: [
      'Eliminate long-lived static cloud API access keys; use IAM roles and Workload Identity.',
      'Enforce IMDSv2 with hop-limit 1 on all AWS EC2 and container instances to prevent SSRF credential theft.',
      'Require multi-factor authentication (MFA) for all administrative and operational access.',
      'Segment workloads into micro-perimeters using network policies and security groups.',
    ],
  },

  // CHAPTER 5
  {
    id: '5.1',
    chapterId: 5,
    setIndex: 1,
    title: 'Password-based authentication, hashing, and MFA',
    summary: 'Implement secure password hashing using Argon2id, bcrypt, salting, pepper, and multi-factor authentication (TOTP/WebAuthn).',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-916: Use of Password Hash with Insufficient Computational Effort',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'Modern Password Hashing Algorithms',
        content: 'Fast cryptographic hashes like MD5, SHA-1, SHA-256, and SHA-512 are designed for high throughput and are dangerously unsuitable for password storage. Dedicated memory-hard password hashing functions—Argon2id (winner of the Password Hashing Competition), scrypt, and bcrypt—force high memory and CPU costs to thwart GPU and ASIC brute-force attacks.',
        keyPrinciple: 'Always store unique cryptographically random salts per password with modern memory-hard hashing algorithms.',
      },
      {
        title: 'Multi-Factor Authentication (MFA) Architectures',
        content: 'MFA requires verification across at least two distinct categories: Something you know (password/PIN), Something you have (hardware token, TOTP app), and Something you are (biometrics). TOTP (RFC 6238) computes HMAC-SHA1 over 30-second time steps.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker cracks millions of user passwords from leaked database dump hashed with fast SHA-256.',
      cweOrStandard: 'CWE-328: Use of Weak Hash',
      impact: 'Mass credential cracking on standard consumer GPU clusters within hours.',
      realWorldScenario: 'A major social network hashed passwords using unsalted SHA-1; when a breach leaked 100M hashes, attackers reversed 85% of them in 48 hours using rainbow tables.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Insecure Password Hashing using Fast SHA-256',
      description: 'Audit a user registration function storing passwords with raw fast hashing.',
      vulnerableCode: `// VULNERABLE: Uses fast SHA-256 hash without salt or memory hardness
import crypto from 'crypto';

async function registerUser(email: string, passwordPlain: string) {
  // Catastrophic: SHA-256 can be cracked at billions of hashes per second on GPUs
  const passwordHash = crypto.createHash('sha256').update(passwordPlain).digest('hex');
  await db.saveUser({ email, passwordHash });
}`,
      remediatedCode: `// REMEDIATED: Uses Argon2id memory-hard hashing with unique salts
import argon2 from 'argon2';

async function registerUser(email: string, passwordPlain: string) {
  // Validate minimum password length and entropy
  if (!passwordPlain || passwordPlain.length < 12) {
    throw new Error('Password must be at least 12 characters.');
  }

  // Argon2id combines Argon2i (side-channel resistant) and Argon2d (GPU resistant)
  const passwordHash = await argon2.hash(passwordPlain, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB memory
    timeCost: 3,       // 3 iterations
    parallelism: 4     // 4 threads
  });

  await db.saveUser({ email, passwordHash });
}

async function verifyLogin(passwordPlain: string, storedHash: string): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, passwordPlain);
  } catch (err) {
    return false;
  }
}`,
      flawExplanation: 'SHA-256 is designed to be extremely fast on hardware; an attacker with modern GPUs can compute over 50 billion SHA-256 hashes per second.',
      fixExplanation: 'Adopts Argon2id with 64MB memory cost, rendering parallel GPU/ASIC cracking economically infeasible.',
    },
    quiz: {
      question: 'Which password hashing algorithm is widely recommended by OWASP and cryptography standards as the current gold standard?',
      options: [
        'MD5 with a 4-character salt',
        'Argon2id with tuned memory and time parameters',
        'SHA-512 with HMAC',
        'AES-256 in CBC mode',
      ],
      correctAnswer: 1,
      explanation: 'Argon2id won the Password Hashing Competition and provides superior resistance against both GPU attacks and side-channel timing attacks.',
    },
    defenseChecklist: [
      'Enforce Argon2id or bcrypt (cost >= 12) for all password storage.',
      'Check passwords against HaveIBeenPwned / breach databases during registration and updates.',
      'Implement RFC 6238 TOTP or FIDO2/WebAuthn hardware keys for MFA.',
      'Store single-use cryptographic recovery backup codes hashed with Argon2id.',
    ],
  },
  {
    id: '5.2',
    chapterId: 5,
    setIndex: 2,
    title: 'OAuth 2.0, OpenID Connect, SAML, and SSO',
    summary: 'Master OAuth 2.0 grant types, PKCE defense against authorization code interception, OIDC tokens, and SAML assertions.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-287: Improper Authentication',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'OAuth 2.0 vs. OpenID Connect (OIDC)',
        content: 'OAuth 2.0 is an authorization delegation framework (granting access tokens with specific scopes to access APIs). It does NOT authenticate users. OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that introduces the ID Token (JWT) providing verifiable user authentication claims.',
        keyPrinciple: 'Never use OAuth 2.0 access tokens alone for user authentication; use OIDC ID Tokens with nonce verification.',
      },
      {
        title: 'Authorization Code Flow with PKCE (RFC 7636)',
        content: 'Proof Key for Code Exchange (PKCE) replaces static client secrets for public clients (SPAs, mobile apps). The client generates a random code_verifier and derives code_challenge = SHA256(code_verifier). The authorization server stores the challenge and verifies the verifier on token exchange, preventing authorization code interception attacks.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Authorization code interception attack on public mobile client without PKCE.',
      cweOrStandard: 'CWE-303: Incorrect Implementation of Authentication Algorithm',
      impact: 'Rogue app registered to same custom URI scheme steals auth code and trades it for user access token.',
      realWorldScenario: 'An iOS app used custom URI schemes without PKCE; a malicious app on the device intercepted the redirect URI and stole corporate user tokens.',
    },
    codeAuditLab: {
      language: 'TypeScript / OAuth Client',
      title: 'OAuth 2.0 Authorization Code Interception Without PKCE',
      description: 'Audit an OAuth client initiating authorization code flow without state or PKCE challenge.',
      vulnerableCode: `// VULNERABLE: Omits PKCE challenge and state parameter; vulnerable to CSRF and code interception
function buildAuthorizationUrl(clientId: string, redirectUri: string) {
  // Missing state parameter (CSRF vulnerability!)
  // Missing code_challenge and code_challenge_method (Interception vulnerability!)
  return \`https://idp.example.com/oauth/authorize?client_id=\${clientId}&redirect_uri=\${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20profile\`;
}`,
      remediatedCode: `// REMEDIATED: Secure PKCE (S256) and cryptographically bound state parameter
import crypto from 'crypto';

function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString('base64').replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

export function generateSecureOidcParams() {
  // 1. Generate high-entropy code_verifier
  const codeVerifier = base64UrlEncode(crypto.randomBytes(32));

  // 2. Derive code_challenge using SHA-256
  const codeChallenge = base64UrlEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );

  // 3. Cryptographically random CSRF state & OIDC nonce
  const state = base64UrlEncode(crypto.randomBytes(24));
  const nonce = base64UrlEncode(crypto.randomBytes(24));

  // Store codeVerifier, state, and nonce securely in session / storage
  return { codeVerifier, codeChallenge, state, nonce };
}

export function buildSecureAuthUrl(clientId: string, redirectUri: string, params: ReturnType<typeof generateSecureOidcParams>) {
  const url = new URL('https://idp.example.com/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  return url.toString();
}`,
      flawExplanation: 'Without PKCE, an attacker who intercepts the auth code can exchange it for tokens. Without state, the flow is vulnerable to login CSRF.',
      fixExplanation: 'Implements PKCE with S256 code challenge, cryptographically random state to stop CSRF, and nonce to prevent ID token replay.',
    },
    quiz: {
      question: 'Why is Proof Key for Code Exchange (PKCE) mandatory for Single Page Applications (SPAs) and mobile native apps?',
      options: [
        'Because SPAs cannot securely store a static client secret from inspection or extraction by attackers.',
        'Because PKCE speeds up cryptographic token signing.',
        'Because mobile apps cannot connect to DNS servers.',
        'Because OAuth 2.0 does not support JSON responses.',
      ],
      correctAnswer: 0,
      explanation: 'Public clients (SPAs, native apps) execute on end-user hardware and cannot keep client secrets confidential; PKCE dynamically protects code exchange without static secrets.',
    },
    defenseChecklist: [
      'Mandate PKCE with code_challenge_method=S256 for all OAuth 2.0 authorization code flows.',
      'Always validate the state parameter on redirect callback to eliminate login CSRF.',
      'Validate ID Token signature, iss, aud, exp, and nonce claims during OIDC authentication.',
      'Deprecate the OAuth 2.0 Implicit Flow entirely.',
    ],
  },
  {
    id: '5.3',
    chapterId: 5,
    setIndex: 3,
    title: 'Session management, tokens, and cookie security',
    summary: 'Design bulletproof session lifecycles, mitigate session hijacking, fixation, and JWT vulnerabilities.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-384: Session Fixation',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'Session Fixation & Regeneration',
        content: 'Session fixation occurs when an attacker forces a victim to use a known session ID. Upon successful authentication, the server MUST invalidate the existing session ID and issue a completely new cryptographically random session identifier.',
        keyPrinciple: 'Always regenerate the session identifier immediately upon privilege escalation or successful login.',
      },
      {
        title: 'JWT Vulnerabilities and Pitfalls',
        content: 'Common JWT failure modes include accepting algorithm: "none", algorithm confusion (verifying RS256 token using HMAC secret key with the public key string), lack of expiration enforcement, and storing sensitive data unencrypted in token payloads.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker exploits algorithm confusion to forge arbitrary administrative JWTs using the public RSA key as HMAC secret.',
      cweOrStandard: 'CWE-347: Improper Verification of Cryptographic Signature',
      impact: 'Total administrative authentication bypass and privilege escalation.',
      realWorldScenario: 'An enterprise API verified tokens using jwt.verify(token, key) without pinning the algorithm to RS256; attackers forged tokens using alg: HS256 signed with the public key.',
    },
    codeAuditLab: {
      language: 'TypeScript / JWT',
      title: 'Algorithm Confusion in JWT Signature Verification',
      description: 'Audit a JWT verification handler vulnerable to algorithm substitution attacks.',
      vulnerableCode: `// VULNERABLE: Does not pin algorithms; susceptible to "none" and RS256/HS256 confusion
import jwt from 'jsonwebtoken';

function verifyIncomingToken(token: string) {
  // FLAW: If attacker specifies alg: 'HS256', the library verifies using RSA_PUBLIC_KEY as HMAC secret!
  return jwt.verify(token, process.env.RSA_PUBLIC_KEY!);
}`,
      remediatedCode: `// REMEDIATED: Strictly pins asymmetric algorithm, issuer, and audience
import jwt from 'jsonwebtoken';

const RSA_PUBLIC_KEY = process.env.RSA_PUBLIC_KEY!;

interface VerifiedTokenPayload {
  sub: string;
  role: string;
  email: string;
}

export function verifyIncomingToken(token: string): VerifiedTokenPayload {
  try {
    // Explicitly restrict to RS256 only, rejecting HS256, none, etc.
    const decoded = jwt.verify(token, RSA_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'https://auth.company.com',
      audience: 'https://api.company.com',
      clockTolerance: 10 // max 10 seconds clock skew
    }) as VerifiedTokenPayload;

    return decoded;
  } catch (err) {
    logger.warn({ error: (err as Error).message }, 'JWT verification failed');
    throw new Error('Authentication token invalid or expired');
  }
}`,
      flawExplanation: 'Omitting the algorithms whitelist allows an attacker to change alg to HS256 and sign malicious tokens using the server’s publicly available RSA key.',
      fixExplanation: 'Explicitly restricts allowed algorithms to ["RS256"] and enforces expected issuer (iss) and audience (aud) claims.',
    },
    quiz: {
      question: 'What defense completely eliminates Session Fixation attacks during user login?',
      options: [
        'Encrypting the session database table with AES.',
        'Invalidating the old pre-login session ID and generating a new session ID upon successful authentication.',
        'Extending the session expiration timeout to 30 days.',
        'Using base64 encoding for session cookies.',
      ],
      correctAnswer: 1,
      explanation: 'Regenerating the session identifier upon login ensures that any session ID previously known or planted by an attacker becomes useless.',
    },
    defenseChecklist: [
      'Always regenerate session IDs upon login, privilege change, and logout.',
      'Pin allowed JWT algorithms (e.g., algorithms: [\'RS256\']) on every token verification call.',
      'Enforce maximum absolute session lifetimes alongside idle timeouts.',
      'Maintain an active token revocation blocklist (in Redis) for logged-out or compromised tokens.',
    ],
  },
  {
    id: '5.4',
    chapterId: 5,
    setIndex: 4,
    title: 'Identity federation, provisioning, and lifecycle management',
    summary: 'Implement SCIM automated user provisioning, enterprise identity federation, and offboarding de-provisioning workflows.',
    domain: 'identity-access',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-285: Improper Authorization',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'Enterprise Identity Federation Architecture',
        content: 'Enterprise federation delegates identity management to external enterprise IdPs (Okta, Azure AD, Ping Identity) using SAML 2.0 or OIDC. The Service Provider (SP) never handles enterprise passwords directly, establishing trust via cryptographic metadata exchanges and certificate pinning.',
        keyPrinciple: 'Federation decouples credential management from application logic, centralizing corporate access control.',
      },
      {
        title: 'SCIM (System for Cross-domain Identity Management)',
        content: 'SCIM 2.0 defines standard HTTP REST APIs (/Users, /Groups) to automate real-time provisioning and immediate de-provisioning. When an employee departs, the enterprise IdP calls SCIM DELETE/PATCH to instantly revoke access across all federated SaaS applications.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Orphaned account vulnerability where terminated employee retains access due to delayed de-provisioning.',
      cweOrStandard: 'CWE-287: Improper Authentication',
      impact: 'Ex-employee exfiltrates confidential intellectual property weeks after termination.',
      realWorldScenario: 'A contractor’s email was disabled in Active Directory, but their local SaaS account stayed active because the SaaS did not implement SCIM automated de-provisioning.',
    },
    codeAuditLab: {
      language: 'TypeScript / SCIM 2.0',
      title: 'SCIM Deprovisioning Handler: Immediate Session Revocation',
      description: 'Audit a SCIM user update endpoint that updates user state in SQL but fails to revoke active session tokens.',
      vulnerableCode: `// VULNERABLE: Deactivates user row but leaves active JWT sessions valid in memory/cache
app.patch('/scim/v2/Users/:id', verifyScimAuth, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  // FLAW: Active session cookies and JWTs still work until they naturally expire!
  await db.query('UPDATE users SET is_active = $1 WHERE scim_id = $2', [active, id]);
  res.status(204).send();
});`,
      remediatedCode: `// REMEDIATED: Deactivates user AND revokes all active sessions & refresh tokens immediately
app.patch('/scim/v2/Users/:id', verifyScimAuth, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  await db.query('UPDATE users SET is_active = $1, deprovisioned_at = NOW() WHERE scim_id = $2', [active, id]);

  if (active === false) {
    // 1. Invalidate all active refresh tokens in database
    await db.query('DELETE FROM refresh_tokens WHERE user_id = (SELECT id FROM users WHERE scim_id = $1)', [id]);

    // 2. Publish immediate revocation event to Redis session cluster
    await redisClient.publish('user:revoked', JSON.stringify({ scimId: id, timestamp: Date.now() }));

    // 3. Blacklist user ID in distributed cache for fast token middleware checks
    await redisClient.set(\`blacklist:user:\${id}\`, 'revoked', 'EX', 86400 * 7);
  }

  res.status(204).send();
});`,
      flawExplanation: 'Disabling a database record without invalidating active cache entries and refresh tokens allows the user to continue making authenticated API calls.',
      fixExplanation: 'Coordinates database deactivation with immediate session invalidation, refresh token deletion, and distributed Redis blacklist propagation.',
    },
    quiz: {
      question: 'What standard protocol is specifically designed to automate user provisioning and de-provisioning between Identity Providers and SaaS applications?',
      options: [
        'SCIM 2.0',
        'TLS 1.3',
        'SOAP 1.2',
        'NTP (Network Time Protocol)',
      ],
      correctAnswer: 0,
      explanation: 'SCIM (System for Cross-domain Identity Management) is the open standard REST API protocol for automating identity lifecycle management.',
    },
    defenseChecklist: [
      'Implement SCIM 2.0 endpoints for automated real-time provisioning and de-provisioning.',
      'Revoke all refresh tokens, sessions, and active WebSockets immediately upon de-provisioning.',
      'Periodically reconcile active local accounts against authoritative IdP rosters.',
      'Verify digital signatures on SAML Assertions and check NotBefore/NotOnOrAfter timestamps.',
    ],
  },
  {
    id: '5.5',
    chapterId: 5,
    setIndex: 5,
    title: 'Biometrics, passwordless authentication, and account recovery',
    summary: 'Implement FIDO2/WebAuthn public-key authentication, Passkeys, and secure account recovery channels.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-640: Weak Password Recovery Mechanism for Forgotten Password',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'FIDO2 and WebAuthn Architecture',
        content: 'WebAuthn replaces passwords with asymmetric cryptography. During registration, the user’s device (TouchID, FaceID, YubiKey) generates a key pair, storing the private key inside a hardware secure enclave (TPM) and sending only the public key to the server. During authentication, the server sends a cryptographically random challenge that the client signs with the private key.',
        keyPrinciple: 'WebAuthn is inherently phishing-resistant because browsers bind the cryptographic signature to the exact origin domain.',
      },
      {
        title: 'Secure Account Recovery Design',
        content: 'Insecure recovery mechanisms (e.g. static security questions, SMS verification susceptible to SIM-swapping) frequently undermine strong primary authentication. Recovery must use cryptographically signed time-limited out-of-band email links or multi-party emergency recovery keys.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker takes over account via predictable or easily discoverable security questions.',
      cweOrStandard: 'CWE-640: Weak Password Recovery Mechanism',
      impact: 'Bypass of strong master password and MFA via trivial social engineering.',
      realWorldScenario: 'An attacker reset a high-profile politician’s account by looking up their mother’s maiden name and high school mascot on Wikipedia.',
    },
    codeAuditLab: {
      language: 'TypeScript / WebAuthn Server',
      title: 'WebAuthn Registration Challenge Verification',
      description: 'Audit a WebAuthn response handler that fails to verify the cryptographically bound origin and challenge.',
      vulnerableCode: `// VULNERABLE: Fails to verify challenge match or expected origin
app.post('/api/webauthn/verify-register', async (req, res) => {
  const { credential } = req.body;
  // FLAW: Blindly saves public key without verifying response signature or challenge!
  await db.savePasskey({
    userId: req.user.id,
    credentialId: credential.id,
    publicKey: credential.response.publicKey
  });
  res.json({ status: 'verified' });
});`,
      remediatedCode: `// REMEDIATED: Rigorous verification using @simplewebauthn/server
import { verifyRegistrationResponse } from '@simplewebauthn/server';

app.post('/api/webauthn/verify-register', async (req, res) => {
  const { credential } = req.body;
  const expectedChallenge = await redisClient.get(\`webauthn:challenge:\${req.user.id}\`);

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'WebAuthn session expired or challenge missing' });
  }

  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge,
    expectedOrigin: 'https://app.securecompany.com',
    expectedRPID: 'securecompany.com',
    requireUserVerification: true // Enforces biometric or PIN check
  });

  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ error: 'WebAuthn cryptographic verification failed' });
  }

  // Consume challenge immediately
  await redisClient.del(\`webauthn:challenge:\${req.user.id}\`);

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

  await db.savePasskey({
    userId: req.user.id,
    credentialId: Buffer.from(credentialID).toString('base64url'),
    publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
    counter
  });

  res.json({ verified: true });
});`,
      flawExplanation: 'Skipping challenge and origin verification permits replay attacks and allows attackers to register credentials from malicious phishing domains.',
      fixExplanation: 'Verifies the cryptographic signature, checks origin binding to prevent phishing, and validates user verification flags.',
    },
    quiz: {
      question: 'Why is FIDO2/WebAuthn considered inherently immune to credential harvesting phishing attacks?',
      options: [
        'Because passwords are encrypted with 4096-bit RSA keys.',
        'Because the browser automatically verifies that the domain origin matches the relying party ID before signing the challenge.',
        'Because WebAuthn requires all users to type their mother’s maiden name.',
        'Because WebAuthn only works when connected to Ethernet.',
      ],
      correctAnswer: 1,
      explanation: 'The browser cryptographically binds the challenge signature to the exact URL origin; a fake phishing domain cannot trick the authenticator into signing for the legitimate site.',
    },
    defenseChecklist: [
      'Eliminate knowledge-based security questions entirely from account recovery.',
      'Adopt FIDO2 / WebAuthn Passkeys for seamless, phishing-resistant passwordless authentication.',
      'Ensure account recovery links expire within 15 minutes and can only be used once.',
      'Alert users via push and secondary email whenever credentials or recovery options change.',
    ],
  },

  // CHAPTER 6
  {
    id: '6.1',
    chapterId: 6,
    setIndex: 1,
    title: 'RBAC, ABAC, ReBAC, and policy-based access',
    summary: 'Implement Role-Based (RBAC), Attribute-Based (ABAC), and Relationship-Based (ReBAC) authorization architectures.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-285: Improper Authorization',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Comparing Access Control Models',
        content: 'Role-Based Access Control (RBAC) grants permissions based on static roles (Admin, Editor, Viewer). Attribute-Based Access Control (ABAC) evaluates dynamic attributes of the subject, resource, action, and environment (e.g., "Allow access if user.department == document.department AND time.isBusinessHours"). Relationship-Based Access Control (ReBAC, e.g. Google Zanzibar) determines access through relational graphs (e.g. "User is editor of Folder that contains File").',
        keyPrinciple: 'RBAC suffices for simple systems; high-scale collaborative apps require ABAC or ReBAC.',
      },
      {
        title: 'Decoupled Policy-Based Authorization',
        content: 'Hardcoding "if (user.role === \'admin\')" across hundreds of endpoints leads to brittle authorization drift. Modern architectures decouple policy evaluation into dedicated policy engines like Open Policy Agent (OPA) or Cedar.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Role explosion and coarse-grained authorization check allowing horizontal data tampering.',
      cweOrStandard: 'CWE-863: Incorrect Authorization',
      impact: 'Any user with "Editor" role can delete documents owned by other departments.',
      realWorldScenario: 'An enterprise CMS checked user.role === "editor", allowing marketing editors to edit and publish confidential legal press releases.',
    },
    codeAuditLab: {
      language: 'TypeScript / Policy',
      title: 'Coarse RBAC vs. Contextual ABAC Authorization Check',
      description: 'Audit an authorization check that verifies role name without checking resource attributes.',
      vulnerableCode: `// VULNERABLE: Coarse RBAC ignores resource department and classification
function canEditDocument(user: User, doc: Document): boolean {
  // FLAW: Allows any editor in the company to edit top-secret executive docs!
  return user.roles.includes('EDITOR');
}`,
      remediatedCode: `// REMEDIATED: Fine-grained Attribute-Based Access Control (ABAC) evaluation
interface EvaluationContext {
  user: { id: string; department: string; clearanceLevel: number; roles: string[] };
  resource: { ownerId: string; department: string; classificationLevel: number; isLocked: boolean };
  action: 'READ' | 'EDIT' | 'DELETE';
  environment: { isCorporateIp: boolean };
}

export function evaluateAbacPolicy(ctx: EvaluationContext): boolean {
  const { user, resource, action, environment } = ctx;

  // Rule 1: Document is locked against all edits
  if (action === 'EDIT' && resource.isLocked) {
    return false;
  }

  // Rule 2: Clearance level must be >= document classification
  if (user.clearanceLevel < resource.classificationLevel) {
    return false;
  }

  // Rule 3: High-classification docs require corporate IP
  if (resource.classificationLevel >= 3 && !environment.isCorporateIp) {
    return false;
  }

  // Rule 4: Department ownership or direct authoring
  const isAuthor = resource.ownerId === user.id;
  const isSameDeptEditor = user.roles.includes('EDITOR') && user.department === resource.department;

  return isAuthor || isSameDeptEditor;
}`,
      flawExplanation: 'Relying exclusively on global roles ignores document ownership, sensitivity classifications, and environmental risk factors.',
      fixExplanation: 'Evaluates dynamic subject, resource, action, and environment attributes (ABAC) to enforce contextual authorization.',
    },
    quiz: {
      question: 'Which access control model evaluates relationships in an entity graph (such as Google’s Zanzibar or Ory Keto)?',
      options: [
        'ReBAC (Relationship-Based Access Control)',
        'MAC (Mandatory Access Control)',
        'DAC (Discretionary Access Control)',
        'Static ACLs',
      ],
      correctAnswer: 0,
      explanation: 'ReBAC evaluates access based on relationships between subjects and objects within a distributed graph (e.g., membership, parentage).',
    },
    defenseChecklist: [
      'Avoid hardcoding role string checks across application controller handlers.',
      'Decouple authorization policies into testable policy evaluation functions or engines (e.g., OPA).',
      'Combine role checks with resource ownership and departmental tenant constraints.',
      'Write automated unit tests verifying both positive and negative authorization cases for every role.',
    ],
  },
  {
    id: '6.2',
    chapterId: 6,
    setIndex: 2,
    title: 'MAC, DAC, and mandatory access control models',
    summary: 'Analyze Mandatory Access Control (Bell-LaPadula, Biba) versus Discretionary Access Control (DAC) in secure operating environments.',
    domain: 'identity-access',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-285: Improper Authorization',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Discretionary (DAC) vs. Mandatory (MAC) Access Control',
        content: 'In Discretionary Access Control (DAC, typical in Unix filesystems), the creator or owner of an object has discretion to grant permissions to any other user. In Mandatory Access Control (MAC, SELinux, AppArmor), central policy enforcement rules override user desires; access is granted strictly based on system-assigned security labels.',
        keyPrinciple: 'In high-security environments, MAC prevents compromised users or Trojan apps from re-sharing sensitive data.',
      },
      {
        title: 'Bell-LaPadula vs. Biba Security Models',
        content: 'Bell-LaPadula enforces Confidentiality: "No read up, no write down" (subjects cannot read higher security levels, nor write to lower levels). Biba enforces Integrity: "No read down, no write up" (prevents high-integrity processes from being tainted by low-integrity data).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'DAC permissions allow compromised user process to grant public read permissions to classified system files.',
      cweOrStandard: 'CWE-732: Incorrect Permission Assignment for Critical Resource',
      impact: 'Ransomware or info-stealer marks confidential directory readable by world.',
      realWorldScenario: 'A web application process had discretionary permission to chmod 777 its configuration directory, enabling an attacker exploiting an RCE to make database dumps accessible to any public visitor.',
    },
    codeAuditLab: {
      language: 'TypeScript / File System',
      title: 'Permissive DAC File Mode Assignment',
      description: 'Audit file creation logic specifying insecure discretionary file permission modes.',
      vulnerableCode: `// VULNERABLE: Discretionary permissions allow all local users to read private keys
import fs from 'fs';

function storeGeneratedPrivateKey(keyPath: string, keyPem: string) {
  // Mode 0o666 grants read & write to world! Mode 0o777 grants execute!
  fs.writeFileSync(keyPath, keyPem, { mode: 0o666 });
}`,
      remediatedCode: `// REMEDIATED: Enforces strict restrictive permissions (Owner Read/Write only: 0o600)
import fs from 'fs';
import path from 'path';

function storeGeneratedPrivateKey(keyPath: string, keyPem: string) {
  const dir = path.dirname(keyPath);

  // 1. Enforce restrictive directory permissions (Owner only: 0o700)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  // 2. Write file with strict 0o600 (Read & Write by owner only, zero permissions for group/others)
  fs.writeFileSync(keyPath, keyPem, {
    mode: 0o600,
    flag: 'wx' // Atomic write; fails if file already exists
  });
}`,
      flawExplanation: 'Creating sensitive files with mode 0o666 or 0o777 allows any unprivileged process on the host to read private cryptographic keys.',
      fixExplanation: 'Restricts permissions strictly to 0o600 (owner read/write only) and secures the parent directory with 0o700.',
    },
    quiz: {
      question: 'Which classic security model is characterized by the principle of "No Read Up, No Write Down" to enforce confidentiality?',
      options: [
        'Bell-LaPadula Model',
        'Biba Integrity Model',
        'Clark-Wilson Model',
        'Graham-Denning Model',
      ],
      correctAnswer: 0,
      explanation: 'The Bell-LaPadula model enforces confidentiality by preventing subjects from reading above their clearance level or writing data down to lower clearance levels.',
    },
    defenseChecklist: [
      'Enforce restrictive umask (0027 or 0077) on application server processes.',
      'Apply SELinux or AppArmor mandatory access control profiles to production application containers.',
      'Store sensitive keys and tokens with file mode 0o600 or inside hardware-backed keychains.',
      'Prevent processes from changing their own discretionary permissions at runtime.',
    ],
  },
  {
    id: '6.3',
    chapterId: 6,
    setIndex: 3,
    title: 'Permission boundaries, privilege escalation, and least privilege',
    summary: 'Prevent vertical and horizontal privilege escalation, Broken Object Level Authorization (BOLA), and IDOR.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Vertical vs. Horizontal Privilege Escalation',
        content: 'Horizontal Privilege Escalation (IDOR / BOLA) occurs when an attacker accesses or modifies resources belonging to peers at the same privilege level (e.g. User A accessing User B’s invoice by changing invoice_id=205 to invoice_id=206). Vertical Privilege Escalation occurs when an unprivileged user gains administrative capabilities (e.g. standard user modifying their own role to "SUPERADMIN").',
        keyPrinciple: 'BOLA/IDOR is the #1 vulnerability on modern API attack surfaces.',
      },
      {
        title: 'Enforcing Cryptographic Permission Boundaries',
        content: 'Never rely on numeric auto-incrementing integer IDs in public APIs; use UUIDv4 or KSUID, and always scope queries to the authenticated tenant/owner context.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker changes accountId in JSON PUT request to modify billing settings of another corporation.',
      cweOrStandard: 'CWE-639: Authorization Bypass Through User-Controlled Key (\'IDOR\')',
      impact: 'Complete administrative tampering across enterprise accounts.',
      realWorldScenario: 'A telecommunications API allowed callers to update phone forwarding numbers via PUT /api/numbers/:id without checking whether the authenticated user owned the specified phone line.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express',
      title: 'Broken Object Level Authorization (BOLA/IDOR) on Resource Update',
      description: 'Audit an invoice update endpoint that trusts client-supplied document identifiers.',
      vulnerableCode: `// VULNERABLE: Direct object modification without ownership verification
app.put('/api/invoices/:invoiceId', authenticateUser, async (req, res) => {
  const { invoiceId } = req.params;
  const { recipientEmail, amount } = req.body;

  // FLAW: Attacker can supply ANY invoiceId and mutate another customer's invoice!
  await db.query(
    'UPDATE invoices SET recipient_email = $1, amount = $2 WHERE id = $3',
    [recipientEmail, amount, invoiceId]
  );

  res.json({ status: 'updated' });
});`,
      remediatedCode: `// REMEDIATED: Strictly scopes update query to authenticated actor and tenant
app.put('/api/invoices/:invoiceId', authenticateUser, async (req, res) => {
  const { invoiceId } = req.params;
  const { recipientEmail, amount } = req.body;
  const currentActor = req.user;

  // Input validation
  if (!isValidUUID(invoiceId)) {
    return res.status(400).json({ error: 'Invalid invoice identifier' });
  }

  // Enforces ownership boundary directly inside the atomic SQL statement
  const result = await db.query(
    \`UPDATE invoices 
     SET recipient_email = $1, amount = $2, updated_at = NOW() 
     WHERE id = $3 AND tenant_id = $4 AND (user_id = $5 OR $6 = ANY(roles))
     RETURNING id\`,
    [recipientEmail, amount, invoiceId, currentActor.tenantId, currentActor.id, 'INVOICE_ADMIN']
  );

  if (result.rowCount === 0) {
    // Return 404 to avoid leaking whether the object ID exists to attackers
    return res.status(404).json({ error: 'Invoice not found or access denied' });
  }

  res.json({ status: 'success', invoiceId: result.rows[0].id });
});`,
      flawExplanation: 'The SQL UPDATE used only invoiceId without binding tenant_id or user_id, allowing any user to overwrite invoices belonging to other organizations.',
      fixExplanation: 'Binds tenant_id, owner user_id, and role checks directly into the SQL WHERE clause, returning 404 on authorization failure to prevent ID enumeration.',
    },
    quiz: {
      question: 'Why is returning HTTP 404 (Not Found) rather than HTTP 403 (Forbidden) recommended when a user attempts an unauthorized IDOR access?',
      options: [
        'To reduce network traffic by 50%.',
        'To prevent attackers from enumerating which resource IDs exist in the system.',
        'Because HTTP 403 is deprecated in HTTP/3.',
        'To trick the browser cache into deleting the document.',
      ],
      correctAnswer: 1,
      explanation: 'Returning 403 confirms to an attacker that the targeted resource ID exists; returning 404 prevents enumeration and information disclosure.',
    },
    defenseChecklist: [
      'Bind tenantId and authenticated userId into every database SELECT, UPDATE, and DELETE query.',
      'Replace sequential integer primary keys with cryptographically random UUIDv4 or NanoIDs.',
      'Use automated authorization test suites asserting that User A cannot read or write User B’s objects.',
      'Validate mass assignment: never bind raw request bodies directly to database models.',
    ],
  },
  {
    id: '6.4',
    chapterId: 6,
    setIndex: 4,
    title: 'Multi-tenant authorization and tenant isolation',
    summary: 'Design bulletproof multi-tenant architectures: Row-Level Security (RLS), schema-per-tenant, and cryptographic isolation.',
    domain: 'identity-access',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-863: Incorrect Authorization',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Multi-Tenant Isolation Strategies',
        content: 'Multi-tenancy models range in isolation guarantees: 1. Siloed / Database-per-tenant (highest isolation, highest operational cost). 2. Schema-per-tenant (distinct Postgres schemas per tenant). 3. Shared table with Tenant ID column (most common, highest risk of cross-tenant data leakage if developer forgets WHERE tenant_id = x).',
        keyPrinciple: 'Human error in writing WHERE clauses must be prevented using database-native Row-Level Security (RLS).',
      },
      {
        title: 'PostgreSQL Row-Level Security (RLS)',
        content: 'RLS enforces tenant isolation directly inside the PostgreSQL query engine. The application sets the tenant context via SET LOCAL app.current_tenant_id = \'...\', and PostgreSQL automatically filters every query, ensuring zero possibility of cross-tenant leakage even if an application SQL query forgets the tenant filter.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Developer omits WHERE tenant_id filter in complex JOIN query, leaking competitor data.',
      cweOrStandard: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      impact: 'Critical data breach exposing private healthcare records across enterprise hospital clients.',
      realWorldScenario: 'A SaaS platform updated a search endpoint and omitted tenant_id in a secondary JOIN table, returning private lead data to competitor sales teams.',
    },
    codeAuditLab: {
      language: 'SQL / PostgreSQL RLS',
      title: 'Enforcing Database-Native Multi-Tenant Isolation via RLS',
      description: 'Audit a shared-database configuration vulnerable to omitted tenant clauses and configure PostgreSQL RLS.',
      vulnerableCode: `-- VULNERABLE: Relies entirely on application developers remembering to write WHERE tenant_id = ...
SELECT d.id, d.title, d.secret_notes 
FROM documents d 
JOIN tags t ON t.document_id = d.id 
WHERE t.name = 'confidential';
-- FLAW: Completely forgot AND d.tenant_id = :tenantId! Returns all tenants' secrets!`,
      remediatedCode: `-- REMEDIATED: PostgreSQL Row-Level Security guarantees isolation at the engine level
-- 1. Enable RLS on the table
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- 2. Define tenant isolation policy using session variable
CREATE POLICY tenant_isolation_policy ON documents
  AS RESTRICTIVE
  USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- In application connection middleware before executing queries:
-- SET LOCAL app.current_tenant_id = 'c1234567-89ab-cdef-0123-456789abcdef';
-- Now ANY SELECT/UPDATE/DELETE query is mathematically constrained to this tenant!`,
      flawExplanation: 'Relying on developers to never forget "WHERE tenant_id = x" across thousands of queries inevitably fails during tight release deadlines.',
      fixExplanation: 'Enforces PostgreSQL Row-Level Security (RLS), instructing the database engine itself to discard rows belonging to other tenants regardless of the SQL text.',
    },
    quiz: {
      question: 'What is the primary advantage of PostgreSQL Row-Level Security (RLS) over application-level WHERE filtering?',
      options: [
        'It speeds up database write speeds by 200%.',
        'It guarantees tenant boundary enforcement at the database kernel level, eliminating human error in application queries.',
        'It eliminates the need for database indexes.',
        'It bypasses the need for TLS certificates.',
      ],
      correctAnswer: 1,
      explanation: 'RLS makes tenant isolation non-bypassable at the database engine level, safeguarding against omitted WHERE clauses in application code.',
    },
    defenseChecklist: [
      'Enable PostgreSQL Row-Level Security (FORCE ROW LEVEL SECURITY) on all multi-tenant tables.',
      'Set tenant session variables in database connection pool checkouts.',
      'Isolate encryption keys per tenant (envelope encryption with tenant-specific KMS keys).',
      'Conduct automated cross-tenant penetration testing assertions in CI pipelines.',
    ],
  },
  {
    id: '6.5',
    chapterId: 6,
    setIndex: 5,
    title: 'Policy engines, authorization testing, and access reviews',
    summary: 'Implement decoupled policy engines (OPA, Cedar) and automated authorization regression test matrices.',
    domain: 'identity-access',
    duration: '20 min',
    difficulty: 'Advanced',
    cwe: 'CWE-863: Incorrect Authorization',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Decoupled Policy-as-Code Engines',
        content: 'Policy-as-Code tools like Open Policy Agent (OPA, using Rego) and AWS Cedar separate policy definitions from application business logic. Applications query the policy engine with JSON inputs (subject, action, resource, context) and receive deterministic true/false decisions.',
        keyPrinciple: 'Author policy in code, test policy in CI, enforce policy at runtime.',
      },
      {
        title: 'Automated Authorization Regression Testing',
        content: 'Access control matrices must be validated by automated permutation testing: verifying that every combination of {Role, Action, Resource Owner, Tenant} yields the expected allow or deny decision.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Authorization policy regression silently introduced in pull request allowing unprivileged access.',
      cweOrStandard: 'CWE-285: Improper Authorization',
      impact: 'Unauthenticated visitors able to view administrative user rosters.',
      realWorldScenario: 'A refactor of an API routing file changed router.use(authMiddleware) order, accidentally exposing all /admin routes to the public internet.',
    },
    codeAuditLab: {
      language: 'Rego / Open Policy Agent (OPA)',
      title: 'Declarative Authorization Policy Definition & Unit Testing',
      description: 'Audit an Open Policy Agent (OPA) Rego policy ensuring default-deny and role constraints.',
      vulnerableCode: `# VULNERABLE: Missing default deny; permissive fallback
package app.authz

# FLAW: If no rule matches, undefined behavior or default allow!
allow {
  input.user.role == "admin"
}
# Missing explicit "default allow = false"!`,
      remediatedCode: `# REMEDIATED: Strict default-deny policy with fine-grained rules and unit tests
package app.authz

import future.keywords.in

# 1. Strict default-deny rule
default allow := false

# Rule: Admins can do anything within their own tenant
allow {
  input.user.role == "admin"
  input.user.tenant_id == input.resource.tenant_id
}

# Rule: Document editors can edit documents in their department
allow {
  input.action == "documents:edit"
  input.user.role in ["editor", "manager"]
  input.user.department == input.resource.department
  input.user.tenant_id == input.resource.tenant_id
  not input.resource.is_confidential
}

# Rule: Document owners can always read their own documents
allow {
  input.action == "documents:read"
  input.user.id == input.resource.owner_id
}`,
      flawExplanation: 'Omitting "default allow := false" allows OPA evaluation to fail open or return ambiguous undefined states.',
      fixExplanation: 'Enforces explicit default deny and evaluates tenant boundaries, departmental match, and confidentiality flags in declarative Rego.',
    },
    quiz: {
      question: 'What is the primary benefit of testing authorization policies as code in a CI pipeline?',
      options: [
        'It guarantees that pull requests cannot introduce silent access control regressions or privilege leaks.',
        'It reduces the size of compiled Docker containers.',
        'It eliminates the need for database indexing.',
        'It converts HTTP requests to WebSocket connections automatically.',
      ],
      correctAnswer: 0,
      explanation: 'Policy-as-code testing verifies every permutation of permissions in CI, preventing code changes from accidentally weakening access controls.',
    },
    defenseChecklist: [
      'Define all authorization policies in declarative policy-as-code (OPA / Cedar).',
      'Enforce explicit default-deny (default allow := false) in every policy file.',
      'Run comprehensive permutation unit tests asserting both allowed and denied scenarios.',
      'Conduct automated quarterly access reviews to prune stale user permissions.',
    ],
  },
];
