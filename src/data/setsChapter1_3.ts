import { LearningSet } from '../types/curriculum';

export const SETS_CHAPTER_1_3: LearningSet[] = [
  // CHAPTER 1
  {
    id: '1.1',
    chapterId: 1,
    setIndex: 1,
    title: 'CIA triad, security goals, and application risk',
    summary: 'Master the fundamental triad of Confidentiality, Integrity, and Availability and quantify application-level operational risk.',
    domain: 'foundations',
    duration: '18 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-693: Protection Mechanism Failure',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Deconstructing the CIA Triad in Modern Software',
        content: 'Confidentiality ensures that sensitive assets are inaccessible to unauthorized actors through encryption, data masking, and access tokens. Integrity guarantees data and state remain uncorrupted by untrusted mutation or tampering via cryptographic hashes and digital signatures. Availability guarantees operational continuity, fault tolerance, and resilience against resource exhaustion and DDoS attacks.',
        keyPrinciple: 'Security is not an add-on; every feature trade-off directly impacts at least one pillar of the CIA triad.',
        bulletPoints: [
          'Confidentiality: Protecting PII, credentials, keys, and intellectual property.',
          'Integrity: Guarding against unauthorized state mutation, replay attacks, and parameter manipulation.',
          'Availability: Mitigating algorithmic complexity denial of service, resource limits, and single points of failure.',
        ],
      },
      {
        title: 'Application Risk Equation & Asset Valuation',
        content: 'Risk is formally defined as Risk = Threat × Vulnerability × Asset Impact. High-risk systems exhibit critical dependencies where low-probability threat actors can leverage minor misconfigurations to trigger catastrophic business disruption.',
        keyPrinciple: 'Quantify risk with business context rather than raw technical vulnerability severity alone.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Insecure Direct Object Reference leading to critical confidentiality breach of financial statements.',
      cweOrStandard: 'CWE-639: Authorization Bypass Through User-Controlled Key',
      impact: 'Complete exposure of private customer tax records across tenant boundaries.',
      realWorldScenario: 'An enterprise billing portal returned PDF statements by sequentially querying /api/statements?id=1024 without verifying whether the requesting user owned account 1024.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express',
      title: 'Flawed CIA Boundary: Unprotected Data Retrieval',
      description: 'Review an endpoint that fulfills requests by trusting client parameters directly without validating authorization or data integrity.',
      vulnerableCode: `// VULNERABLE: Direct parameter trust violates Confidentiality & Authorization
app.get('/api/users/:userId/financial-records', async (req, res) => {
  const { userId } = req.params;
  // Flaw: No check that req.currentUser.id === userId or has auditor privileges!
  const records = await db.query(
    'SELECT * FROM financial_records WHERE user_id = $1', 
    [userId]
  );
  res.json({ status: 'ok', data: records });
});`,
      remediatedCode: `// REMEDIATED: Enforces contextual authorization, tenant isolation, and audit logging
app.get('/api/users/:userId/financial-records', authenticateToken, async (req, res) => {
  const targetUserId = req.params.userId;
  const currentActor = req.user;

  // Enforce least privilege & ownership boundary
  const isSelf = currentActor.id === targetUserId;
  const hasComplianceRole = currentActor.roles.includes('FINANCE_AUDITOR');

  if (!isSelf && !hasComplianceRole) {
    logger.warn({ actor: currentActor.id, target: targetUserId }, 'Unauthorized record access attempt');
    return res.status(403).json({ error: 'Access denied: Insufficient privileges' });
  }

  const records = await db.query(
    'SELECT id, amount, currency, created_at FROM financial_records WHERE user_id = $1 AND tenant_id = $2',
    [targetUserId, currentActor.tenantId]
  );

  res.setHeader('Cache-Control', 'no-store');
  res.json({ status: 'success', data: records });
});`,
      flawExplanation: 'The endpoint trusted route parameters blindly, allowing any authenticated user to enumerate and download any other user’s financial records.',
      fixExplanation: 'Verifies the requesting subject against the object owner or required RBAC role, binds tenantId to prevent cross-tenant leakage, and disables sensitive caching.',
      attackVectorExample: 'GET /api/users/8821/financial-records HTTP/1.1 with an unrelated JWT token.',
    },
    quiz: {
      question: 'Which of the following scenarios constitutes a direct failure of the Integrity pillar of the CIA triad?',
      options: [
        'An attacker sniffs plaintext session tokens over an unencrypted public Wi-Fi network.',
        'A user modifies their local balance field in a hidden form input and the backend saves the altered amount.',
        'A flood of invalid HTTP requests exhausts database connection pools, taking the site offline.',
        'A third-party advertiser learns user browsing history via third-party cookies.',
      ],
      correctAnswer: 1,
      explanation: 'Integrity concerns unauthorized modification of information. Tampering with client parameters that alter stored state violates Integrity.',
    },
    defenseChecklist: [
      'Classify all data stores and endpoints by Confidentiality, Integrity, and Availability impact levels.',
      'Enforce explicit authorization checks on every state change and query.',
      'Implement strict rate limits to preserve Availability against denial-of-service.',
      'Never rely on client-side state for authorization or business logic calculations.',
    ],
  },
  {
    id: '1.2',
    chapterId: 1,
    setIndex: 2,
    title: 'Threat landscape, attack surfaces, and adversaries',
    summary: 'Analyze adversary profiles, minimize digital attack surfaces, and model modern threat actor tactics.',
    domain: 'foundations',
    duration: '20 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-1008: Architectural Attack Surface Exposure',
    owaspTop10: 'A05:2021-Security Misconfiguration',
    concepts: [
      {
        title: 'Adversary Taxonomies and Capabilities',
        content: 'Modern threat actors range from opportunistic automated bots and script kiddies to organized cybercrime syndicates and state-sponsored Advanced Persistent Threats (APTs). Designing defenses requires understanding adversary motives: financial extortion (ransomware), IP theft, espionage, or disruptive sabotage.',
        keyPrinciple: 'Defenses must scale from low-skill automated scanner resistance to resilient defense against patient, targeted adversaries.',
      },
      {
        title: 'Attack Surface Mapping & Minimization',
        content: 'An attack surface encompasses every reachable entry point: exposed HTTP endpoints, open ports, unauthenticated message brokers, client-side scripts, third-party libraries, and debug routes.',
        bulletPoints: [
          'External Surface: Public APIs, webhooks, DNS entries, and edge proxies.',
          'Internal Surface: Inter-service RPCs, message queues, and shared databases.',
          'Human & Operational Surface: DevOps pipelines, internal admin panels, and employee credentials.',
        ],
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Exposed internal actuator/metrics endpoints leaking environment variables and heap dumps.',
      cweOrStandard: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      impact: 'Extraction of production database credentials, API secret keys, and internal network maps.',
      realWorldScenario: 'A Spring Boot application had its actuator /actuator/env endpoint exposed to the public Internet, enabling attackers to dump plaintext AWS keys.',
    },
    codeAuditLab: {
      language: 'JavaScript / Node.js',
      title: 'Leaked Operational & Debug Attack Surface',
      description: 'Audit an Express application exposing diagnostic endpoints without network or authentication restrictions.',
      vulnerableCode: `// VULNERABLE: Debug and runtime metrics mounted directly on public router
app.get('/debug/info', (req, res) => {
  res.json({
    environment: process.env,
    memory: process.memoryUsage(),
    dbHost: config.database.host,
    connectionString: config.database.url
  });
});`,
      remediatedCode: `// REMEDIATED: Debug endpoints removed from public routes or restricted to internal loopback
if (process.env.NODE_ENV !== 'production') {
  app.get('/internal/diagnostics', verifyLoopbackOnly, (req, res) => {
    res.json({
      uptime: process.uptime(),
      timestamp: Date.now(),
      status: 'healthy'
      // Redact all sensitive environment variables and connection strings
    });
  });
}

function verifyLoopbackOnly(req, res, next) {
  const remoteIp = req.socket.remoteAddress;
  if (remoteIp === '127.0.0.1' || remoteIp === '::1') {
    return next();
  }
  return res.status(404).send('Not Found');
}`,
      flawExplanation: 'Exposing process.env and internal connection strings hands attackers credentials to pivot directly into internal databases.',
      fixExplanation: 'Eliminate sensitive endpoints in production, restrict diagnostic endpoints to loopback interfaces, and sanitize all diagnostic outputs.',
    },
    quiz: {
      question: 'What is the most effective first step to minimize an application’s attack surface?',
      options: [
        'Install a Web Application Firewall (WAF) in monitor-only mode.',
        'Decommission unused legacy endpoints, close unused ports, and restrict debug tools from production builds.',
        'Add complex captcha to the login page.',
        'Encrypt all internal database tables with DES.',
      ],
      correctAnswer: 1,
      explanation: 'Attack surface minimization begins with removing unused code, interfaces, endpoints, and listening services entirely.',
    },
    defenseChecklist: [
      'Maintain an automated inventory of all exposed API routes and network services.',
      'Strip debug, test, and mock routes from release build artifacts.',
      'Protect administrative panels with IP allowlists, VPN, or hardware-token MFA.',
      'Audit DNS records regularly to prevent dangling subdomain takeovers.',
    ],
  },
  {
    id: '1.3',
    chapterId: 1,
    setIndex: 3,
    title: 'Secure design principles: least privilege, defense in depth, fail-safe',
    summary: 'Implement foundational Saltzer-Schroeder secure design principles into everyday software architectures.',
    domain: 'foundations',
    duration: '22 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-272: Least Privilege Violation',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'The Saltzer and Schroeder Canonical Principles',
        content: 'Formulated in 1975, these timeless principles guide resilient software design: Economy of Mechanism (keep designs simple), Fail-Safe Defaults (default deny), Complete Mediation (check every access every time), Open Design (security does not rely on secrecy), Separation of Privilege, Least Privilege, Least Common Mechanism, and Psychological Acceptability.',
        keyPrinciple: 'Simplicity is the prerequisite for security. Complex designs contain unmanageable edge cases.',
      },
      {
        title: 'Fail-Safe Defaults vs. Fail-Open Hazards',
        content: 'When an exception, timeout, or unexpected error occurs during authentication or authorization evaluation, systems must fail closed (deny access), never fail open (grant access).',
        bulletPoints: [
          'Fail-Safe: Deny access if authorization service is unavailable.',
          'Least Privilege: Database connection strings have only SELECT/INSERT, never DROP/ALTER.',
          'Defense in Depth: Layered validation so that if WAF fails, application validation stops the payload.',
        ],
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Fail-Open exception handler permitting administrative access when authorization check throws.',
      cweOrStandard: 'CWE-636: Not Failing Securely (\'Failing Open\')',
      impact: 'Unauthenticated users gain superadmin capabilities during backend latency or network glitches.',
      realWorldScenario: 'An OAuth validation middleware caught network timeouts from the identity provider and defaulted to isAuthenticated = true to avoid breaking user experience.',
    },
    codeAuditLab: {
      language: 'TypeScript',
      title: 'Fail-Open Error Handling in Authorization Gate',
      description: 'Audit an access control check that unintentionally defaults to permission granted upon encountering errors.',
      vulnerableCode: `// VULNERABLE: Fails open on timeout or unhandled exception
async function authorizeAction(user: User, action: string): Promise<boolean> {
  let isAuthorized = false;
  try {
    const result = await policyClient.evaluate(user.id, action);
    isAuthorized = result.allowed;
  } catch (err) {
    console.error('Policy evaluation failed, allowing request for continuity:', err);
    isAuthorized = true; // CATASTROPHIC FAIL-OPEN
  }
  return isAuthorized;
}`,
      remediatedCode: `// REMEDIATED: Strict Fail-Safe Default with explicit fail-closed logic
async function authorizeAction(user: User, action: string): Promise<boolean> {
  if (!user || !user.id || !action) {
    return false; // Fail closed on missing parameters
  }

  try {
    const result = await policyClient.evaluate(user.id, action, { timeoutMs: 500 });
    return Boolean(result && result.allowed === true);
  } catch (err) {
    logger.error({ userId: user.id, action, error: err }, 'Authorization policy check failed; failing closed');
    // Always default to false on system errors or network timeouts
    return false;
  }
}`,
      flawExplanation: 'Catching errors and returning true permits attackers to cause purposeful network degradation to bypass security gates.',
      fixExplanation: 'Default to false (deny) on any exception or unexpected state and log the telemetry securely.',
    },
    quiz: {
      question: 'Which principle states that every access request must be checked on every occasion, without relying on stale cached decisions?',
      options: [
        'Economy of mechanism',
        'Complete mediation',
        'Open design',
        'Separation of privilege',
      ],
      correctAnswer: 1,
      explanation: 'Complete mediation requires that every access to every object must be checked for authority on every access.',
    },
    defenseChecklist: [
      'Initialize all authorization decisions to DENY before any business logic evaluates.',
      'Grant application database users only the minimum required DML permissions (no DDL/DROP rights).',
      'Ensure exceptions during token verification, signature checks, or network calls abort execution immediately.',
      'Avoid security through obscurity; rely on tested cryptographic standards.',
    ],
  },
  {
    id: '1.4',
    chapterId: 1,
    setIndex: 4,
    title: 'Risk management, threat intelligence, and security requirements',
    summary: 'Translate threat intelligence into actionable software security requirements and quantitative risk matrices.',
    domain: 'foundations',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1021: Improper Restriction of Rendered UI',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Actionable Security Requirements Engineering',
        content: 'Functional requirements define what software should do; security requirements define what software must NOT allow. Security user stories and abuse stories bridge the gap between product management and engineering teams.',
        keyPrinciple: 'Define non-functional security requirements (NFRs) before sprint coding commences.',
      },
      {
        title: 'Integrating Threat Intelligence (CTI)',
        content: 'Cyber Threat Intelligence feeds (ISACs, CVE feeds, MITRE ATT&CK) inform engineers about active exploits in the wild, enabling proactive patching and focused defensive controls against prevalent exploitation techniques.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Lack of rate-limiting requirements leading to automated credential stuffing attacks.',
      cweOrStandard: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
      impact: 'Mass account takeover of customer profiles via automated credential lists.',
      realWorldScenario: 'An airline loyalty program lost millions in points because login specifications lacked brute-force throttling requirements.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Enforcing Security Requirements: Account Lockout & Throttling',
      description: 'Review a login handler that checks credentials without enforcing brute-force mitigation specifications.',
      vulnerableCode: `// VULNERABLE: Missing rate limit and lockout requirement
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.findUserByEmail(email);

  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateSessionToken(user);
  res.json({ token });
});`,
      remediatedCode: `// REMEDIATED: Adheres to NFR-SEC-04: Exponential backoff and IP/account rate limits
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.findUserByEmail(email);

  // Check account locked status
  if (user && user.isLockedOut) {
    return res.status(429).json({ error: 'Account temporarily locked due to repeated failures.' });
  }

  const isMatch = user ? await verifyPassword(password, user.passwordHash) : false;

  if (!isMatch) {
    if (user) await registerFailedAttempt(user.id);
    // Constant time response to prevent timing enumeration
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  await resetFailedAttempts(user.id);
  const token = generateSecureSessionToken(user);
  res.json({ token });
});`,
      flawExplanation: 'Unlimited attempts enable attackers to test thousands of credentials per second without detection.',
      fixExplanation: 'Applies IP-based rate limiting, failed attempt counters with account lockout, and uniform response times.',
    },
    quiz: {
      question: 'Which framework catalogs real-world adversary tactics, techniques, and procedures (TTPs) across the attack lifecycle?',
      options: [
        'MITRE ATT&CK',
        'ISO 9001',
        'W3C WCAG',
        'IEEE 802.11',
      ],
      correctAnswer: 0,
      explanation: 'MITRE ATT&CK is the globally accessible knowledge base of adversary tactics and techniques based on real-world observations.',
    },
    defenseChecklist: [
      'Write explicit "Abuse Stories" alongside user stories in Jira/backlogs.',
      'Establish SLAs for addressing newly announced CVEs based on CVSS scoring and exploitability.',
      'Subscribe to relevant vulnerability feeds for all runtime frameworks and dependencies.',
      'Mandate automated rate limiting on all public authentication and password reset surfaces.',
    ],
  },
  {
    id: '1.5',
    chapterId: 1,
    setIndex: 5,
    title: 'Legal, ethical, privacy, and compliance foundations',
    summary: 'Navigate GDPR, CCPA/CPRA, HIPAA, PCI-DSS v4.0, SOC 2, and ethical security obligations in software engineering.',
    domain: 'foundations',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-359: Exposure of Private Personal Information (Privacy Violation)',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Global Privacy Frameworks & Privacy by Design',
        content: 'Regulations like GDPR (EU) and CCPA/CPRA (California) mandate Privacy by Design. Key principles include Data Minimization (only collect what is necessary), Purpose Limitation, Right to Erasure ("Right to be Forgotten"), and Consent Management.',
        keyPrinciple: 'Engineers are personally responsible for protecting personal data against reckless handling and unlawful retention.',
      },
      {
        title: 'PCI-DSS v4.0 and SOC 2 Type II Controls',
        content: 'PCI-DSS v4.0 requires tokenization of PANs, end-to-end encryption in transit, strict audit trails, and web application firewalls. SOC 2 evaluates security, availability, processing integrity, confidentiality, and privacy over sustained operational periods.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Plaintext logging of primary account numbers (PAN) and personally identifiable information in debug logs.',
      cweOrStandard: 'CWE-532: Insertion of Sensitive Information into Log File',
      impact: 'Severe regulatory fines, loss of card processing capability under PCI-DSS, and privacy violations.',
      realWorldScenario: 'An e-commerce checkout service printed full JSON request bodies to standard output, storing 500,000 credit card numbers and CVVs in plaintext CloudWatch logs.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'PII & Payment Data Leakage in Application Logs',
      description: 'Audit a logging configuration that indiscriminately serializes incoming request payloads containing sensitive personal data.',
      vulnerableCode: `// VULNERABLE: Direct dump of customer request payload to logs
app.post('/api/checkout', (req, res) => {
  // Violates GDPR data minimization & PCI-DSS requirement 3
  console.log('Processing checkout request payload:', JSON.stringify(req.body));

  const { cardNumber, cvv, expiry, ssn, email } = req.body;
  // process payment...
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Sanitizes and redacts sensitive PII and PAN fields before writing logs
const PII_KEYS_TO_MASK = new Set(['cardNumber', 'cvv', 'card_number', 'ssn', 'password', 'token']);

function sanitizeLogPayload(obj: Record<string, any>): Record<string, any> {
  const sanitized: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (PII_KEYS_TO_MASK.has(key)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeLogPayload(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

app.post('/api/checkout', (req, res) => {
  const safeData = sanitizeLogPayload(req.body);
  logger.info({ customerEmail: req.body.email ? 'MASKED' : undefined, details: safeData }, 'Processing checkout request');

  // Process payment via tokenized payment processor (never retain raw PAN)
  res.json({ success: true });
});`,
      flawExplanation: 'Raw cardholder data and personal identifiers are written to persistent log files, accessible to anyone with log read access.',
      fixExplanation: 'Redacts sensitive keys (PAN, CVV, SSN, passwords) prior to logging, and adheres to tokenization protocols.',
    },
    quiz: {
      question: 'Under GDPR and modern privacy engineering principles, what does "Data Minimization" dictate?',
      options: [
        'Storing data on as few physical servers as possible to save costs.',
        'Collecting and processing only personal data strictly necessary for the specified purpose.',
        'Compressing user records with gzip before storing them in PostgreSQL.',
        'Deleting user backups every 24 hours regardless of compliance rules.',
      ],
      correctAnswer: 1,
      explanation: 'Data Minimization mandates that personal data must be adequate, relevant, and limited to what is necessary in relation to the purposes for which they are processed.',
    },
    defenseChecklist: [
      'Automate PII and PAN redaction filters in all centralized logging pipelines.',
      'Implement automated retention policies with cryptographic deletion for expired customer records.',
      'Ensure consent flags are checked before sending user data to analytics or telemetry providers.',
      'Isolate cardholder data environments (CDE) using tokenization partners (e.g., Stripe, Adyen).',
    ],
  },

  // CHAPTER 2
  {
    id: '2.1',
    chapterId: 2,
    setIndex: 1,
    title: 'SDLC phases and security gates',
    summary: 'Embed non-negotiable security gates across requirements, architecture, coding, testing, deployment, and monitoring.',
    domain: 'lifecycle',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1053: Missing Security Architecture Check',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Shifting Security Left in Agile & CI/CD',
        content: 'Remediating a vulnerability in production costs up to 30 to 100 times more than catching it during the design or pull-request phase. Modern SSDLC replaces monolithic pre-release audits with automated, continuous gates embedded in developer workflows.',
        keyPrinciple: 'Fix bugs at the point of origin: design flaws at design time, code flaws at commit time.',
      },
      {
        title: 'The Six Core SSDLC Security Gates',
        content: '1. Inception: Security requirements & regulatory classification. 2. Design: Threat model & trust boundary audit. 3. Coding: SAST, linting, pre-commit secret scanning. 4. Build/Test: Dependency SCA & container image scanning. 5. Release: Security sign-off & DAST verification. 6. Production: RASP, logging, and bug bounty response.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Bypassing pull-request security checks allows high-severity dependency vulnerability into main branch.',
      cweOrStandard: 'CWE-1104: Use of Unmaintained Third Party Components',
      impact: 'Remote Code Execution (RCE) via vulnerable transitive library in production containers.',
      realWorldScenario: 'Developers merged a hotfix directly into production without triggering CI SCA checks, reintroducing a known Log4j vulnerability.',
    },
    codeAuditLab: {
      language: 'YAML / GitHub Actions',
      title: 'Automated SSDLC Pipeline Gate Configuration',
      description: 'Audit a CI workflow that permits security scanner failures to pass silently.',
      vulnerableCode: `# VULNERABLE: Scanners run but failures are ignored; security gate is unenforced
name: CI Build
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Secret Scanner
        run: gitleaks detect --verbose || true # FLAW: Silently ignores detected secrets!
      - name: Dependency Vulnerability Check
        run: npm audit --audit-level=critical || exit 0 # FLAW: Exits with 0 on failure!`,
      remediatedCode: `# REMEDIATED: Enforces non-bypassable security gates with automated blocker status
name: Security Gates & Verification
on:
  pull_request:
    branches: [main, release/*]
jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Enforce Secret Scanning Gate
        run: |
          gitleaks detect --verbose --exit-code 1
      - name: Software Composition Analysis (SCA) Gate
        run: |
          npm audit --audit-level=high
      - name: Static Application Security Testing (SAST)
        run: |
          npm run lint:security`,
      flawExplanation: 'Appends "|| true" or "exit 0", allowing pull requests with leaked secrets or critical vulnerabilities to pass CI undetected.',
      fixExplanation: 'Enforces non-zero exit codes on security scanner failures, blocking PR merges until vulnerabilities are resolved.',
    },
    quiz: {
      question: 'Which phase of the SSDLC is the most cost-effective stage to discover and remediate architectural security flaws?',
      options: [
        'During penetration testing just prior to deployment',
        'During the Requirements and Architectural Design phase',
        'During post-release incident response',
        'During annual compliance audits',
      ],
      correctAnswer: 1,
      explanation: 'Addressing flaws during design avoids rewrites of foundational architecture, database schemas, and API contracts.',
    },
    defenseChecklist: [
      'Define automated CI gates that block merging when High or Critical vulnerabilities are detected.',
      'Implement branch protection rules requiring at least one peer security review.',
      'Mandate pre-commit hooks to block hardcoded secrets from leaving local developer machines.',
      'Conduct formal threat modeling for all new major features and microservices.',
    ],
  },
  {
    id: '2.2',
    chapterId: 2,
    setIndex: 2,
    title: 'Security requirements and abuse cases',
    summary: 'Craft user stories with explicit negative testing requirements and adversarial abuse cases.',
    domain: 'lifecycle',
    duration: '18 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-840: Business Logic Errors',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Formulating Abuse Cases vs. Use Cases',
        content: 'While a use case describes a benign actor achieving a valid goal (e.g., "User applies discount code to cart"), an abuse case models how an adversary misuses business logic (e.g., "Adversary applies single-use discount coupon concurrently in 20 threads to redeem it 20 times").',
        keyPrinciple: 'Every critical feature must have a matching abuse case specifying expected system defenses.',
      },
      {
        title: 'Business Logic Security Requirements',
        content: 'Abuse cases require transactional atomicity, idempotent operations, invariant assertion checks, and rate limits that prevent automated exploitation of business workflows.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Race condition in promo code redemption allowing infinite coupon reuse.',
      cweOrStandard: 'CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (\'Race Condition\')',
      impact: 'Financial loss from unauthorized discounting and inventory drainage.',
      realWorldScenario: 'An online marketplace allowed users to redeem a $100 referral gift card simultaneously across multiple browser tabs because the balance check and coupon consumption were not wrapped in a database transaction.',
    },
    codeAuditLab: {
      language: 'TypeScript / SQL',
      title: 'Race Condition in Promo Code Consumption',
      description: 'Audit an asynchronous redemption handler with a check-then-act vulnerability.',
      vulnerableCode: `// VULNERABLE: Time-of-Check to Time-of-Use (TOCTOU) race condition
app.post('/api/coupon/redeem', async (req, res) => {
  const { couponCode, orderId } = req.body;
  const coupon = await db.query('SELECT * FROM coupons WHERE code = $1', [couponCode]);

  // Check
  if (!coupon || coupon.is_used) {
    return res.status(400).json({ error: 'Coupon already redeemed' });
  }

  // Artificial latency or network call
  await applyDiscountToOrder(orderId, coupon.discountAmount);

  // Act: Too late! Concurrent requests already passed the check!
  await db.query('UPDATE coupons SET is_used = TRUE WHERE code = $1', [couponCode]);
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Atomic conditional update or row-level locking with transaction
app.post('/api/coupon/redeem', async (req, res) => {
  const { couponCode, orderId } = req.body;

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // Atomic consumption: only succeeds if is_used is false at execution time
    const result = await client.query(
      'UPDATE coupons SET is_used = TRUE, redeemed_order_id = $1, redeemed_at = NOW() WHERE code = $2 AND is_used = FALSE RETURNING discount_amount',
      [orderId, couponCode]
    );

    if (result.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Coupon invalid or already redeemed.' });
    }

    const discount = result.rows[0].discount_amount;
    await applyDiscountToOrderInTx(client, orderId, discount);

    await client.query('COMMIT');
    res.json({ success: true, discount });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Redemption failed' });
  } finally {
    client.release();
  }
});`,
      flawExplanation: 'Separating the read check from the write update allows concurrent HTTP requests to pass the check before the first one flags the coupon as used.',
      fixExplanation: 'Executes an atomic SQL UPDATE with WHERE is_used = FALSE or row-level lock (FOR UPDATE) within a single ACID transaction.',
    },
    quiz: {
      question: 'Why are abuse cases essential in modern agile user story mapping?',
      options: [
        'They replace all unit tests with automated penetration tests.',
        'They force designers and developers to anticipate how adversaries will intentionally subvert valid workflows.',
        'They ensure that all code complies with CSS styling guidelines.',
        'They are required to obtain an SSL certificate from certificate authorities.',
      ],
      correctAnswer: 1,
      explanation: 'Abuse cases explicitly define adversarial behavior and force teams to design resilient defenses against business logic subversion.',
    },
    defenseChecklist: [
      'Write at least two abuse cases for every financial, authentication, or authorization story.',
      'Use atomic database operations or row-level locking for multi-step balance or inventory changes.',
      'Implement idempotency keys for critical state-altering HTTP endpoints (e.g., payments).',
      'Conduct automated concurrency tests simulating parallel requests.',
    ],
  },
  {
    id: '2.3',
    chapterId: 2,
    setIndex: 3,
    title: 'Secure design reviews and architecture checkpoints',
    summary: 'Conduct rigorous architectural checkpoints to catch trust boundary violations before writing code.',
    domain: 'lifecycle',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1188: Insecure Default Initialization of Resource',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Conducting an Architecture Review Checkpoint',
        content: 'Design reviews evaluate data flow diagrams, network boundaries, cryptographic choices, token storage, and third-party SaaS integrations. Reviews verify that components assume zero trust rather than relying on network perimeter protection.',
        keyPrinciple: 'Never assume internal traffic is safe. Internal service-to-service calls must authenticate and authorize.',
      },
      {
        title: 'Key Design Checkpoint Questions',
        content: 'Who is the caller? How is identity propagated across microservices? Where is persistent state encrypted? What happens if an upstream vendor is compromised? What is the rollback and disaster recovery strategy?',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Unauthenticated internal microservice endpoint exposed to SSRF or internal lateral movement.',
      cweOrStandard: 'CWE-306: Missing Authentication for Critical Function',
      impact: 'Attacker leverages an SSRF in a public web app to issue administrative commands to internal clusters.',
      realWorldScenario: 'The Capital One breach occurred when an SSRF in a reverse proxy allowed the attacker to reach the unauthenticated AWS metadata service (IMDSv1) and steal IAM role tokens.',
    },
    codeAuditLab: {
      language: 'TypeScript / Microservice',
      title: 'Missing Mutual Authentication in Inter-Service Communication',
      description: 'Audit an internal administrative endpoint that assumes any incoming request on the VPC is trustworthy.',
      vulnerableCode: `// VULNERABLE: Assumes any caller within the cluster network is trustworthy
app.post('/internal/purge-user-cache', (req, res) => {
  // No mTLS, no HMAC signature, no JWT token verification!
  const { targetUserId } = req.body;
  cache.del(\`user:\${targetUserId}\`);
  res.json({ status: 'purged' });
});`,
      remediatedCode: `// REMEDIATED: Enforces Service-to-Service JWT / mTLS and caller identity validation
import { verifyServiceToken } from './security/serviceAuth';

app.post('/internal/purge-user-cache', async (req, res) => {
  const serviceAuthHeader = req.headers['x-service-authorization'];

  if (!serviceAuthHeader) {
    return res.status(401).json({ error: 'Missing service token' });
  }

  try {
    const callerClaims = await verifyServiceToken(serviceAuthHeader as string);
    // Enforce that only authorized internal service identities can call this
    if (callerClaims.serviceName !== 'user-lifecycle-service') {
      logger.warn({ caller: callerClaims.serviceName }, 'Unauthorized service invocation attempt');
      return res.status(403).json({ error: 'Service not authorized for this operation' });
    }

    const { targetUserId } = req.body;
    await cache.del(\`user:\${targetUserId}\`);
    res.json({ status: 'purged' });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid service token signature' });
  }
});`,
      flawExplanation: 'Internal services omitting authentication rely entirely on perimeter firewalls; any SSRF or internal container breakout compromises the service.',
      fixExplanation: 'Enforces cryptographically signed service-to-service identity tokens or mTLS certificates with explicit caller authorization.',
    },
    quiz: {
      question: 'In modern cloud architectures, why is relying solely on network perimeter firewalls considered an insecure design anti-pattern?',
      options: [
        'Perimeter firewalls do not support IPv6 routing.',
        'Once an adversary breaches the perimeter or exploits SSRF, internal services lack any defense to stop lateral movement.',
        'Firewalls slow down database queries by 90%.',
        'Modern microservices cannot bind to TCP ports behind firewalls.',
      ],
      correctAnswer: 1,
      explanation: 'Under Zero Trust principles, the network is assumed hostile; internal services must authenticate and authorize callers independently of network topology.',
    },
    defenseChecklist: [
      'Require architectural sign-offs for any changes involving authentication or data storage.',
      'Enforce mutual TLS (mTLS) or signed Service-to-Service JWTs in service meshes.',
      'Block access to cloud metadata endpoints (enforce IMDSv2 on AWS, metadata flavor on GCP).',
      'Verify that all sensitive data assets have defined encryption at rest and in transit.',
    ],
  },
  {
    id: '2.4',
    chapterId: 2,
    setIndex: 4,
    title: 'Secure coding standards and developer responsibilities',
    summary: 'Adopt and enforce secure coding standards (OWASP, SEI CERT, CWE) and integrate linting into IDEs.',
    domain: 'lifecycle',
    duration: '20 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-710: Improper Adherence to Coding Standards',
    owaspTop10: 'A03:2021-Injection',
    concepts: [
      {
        title: 'Institutionalizing Secure Coding Standards',
        content: 'Engineering organizations must adopt recognized coding standards such as the OWASP Secure Coding Practices Quick Reference Guide and SEI CERT Coding Standards for specific languages (Java, C, C++, Python). Rules must be codified as automated linter plugins (e.g., eslint-plugin-security, Semgrep, SonarLint) running directly in developers’ IDEs.',
        keyPrinciple: 'Security standards must be automated; unautomated guidelines written in wikis are quickly forgotten.',
      },
      {
        title: 'Developer Security Responsibilities',
        content: 'Developers are the first line of defense: sanitizing inputs, handling errors securely, never hardcoding credentials, and verifying dependency provenance before installation.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Use of dangerous eval/Function or dynamic code evaluation in JavaScript/TypeScript.',
      cweOrStandard: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (\'Eval Injection\')',
      impact: 'Arbitrary remote code execution in the context of the application server.',
      realWorldScenario: 'A calculation engine used eval("x + " + userExpression) to evaluate custom customer pricing formulas, enabling attackers to execute child_process.execSync().',
    },
    codeAuditLab: {
      language: 'JavaScript / Node.js',
      title: 'Dynamic Code Execution via eval()',
      description: 'Review a dynamic formula parser violating secure coding guidelines.',
      vulnerableCode: `// VULNERABLE: Direct evaluation of untrusted user input using eval
function calculateUserFormula(baseAmount: number, userFormula: string) {
  // Violates SEI CERT / OWASP: Never execute arbitrary code strings!
  return eval(\`baseAmount * (\${userFormula})\`);
}`,
      remediatedCode: `// REMEDIATED: Uses safe AST-based mathematical expression parser
import { parse } from 'mathjs';

function calculateUserFormula(baseAmount: number, userFormula: string): number {
  // Validate input length and character set
  if (typeof userFormula !== 'string' || userFormula.length > 50) {
    throw new Error('Invalid formula length');
  }

  // Parse into safe math AST without access to globals or process
  try {
    const node = parse(userFormula);
    const result = node.evaluate({ baseAmount });
    if (typeof result !== 'number' || !Number.isFinite(result)) {
      throw new Error('Evaluation produced non-numeric result');
    }
    return result;
  } catch (err) {
    throw new Error('Invalid mathematical expression syntax');
  }
}`,
      flawExplanation: 'eval() executes arbitrary JavaScript, allowing malicious payloads like process.mainModule.require("child_process").execSync("id") to run.',
      fixExplanation: 'Replaces dangerous dynamic code execution with an isolated AST math parser with restricted variable scopes.',
    },
    quiz: {
      question: 'Which tool provides instant secure coding feedback within a developer’s IDE before code is committed to Git?',
      options: [
        'IDE plugins such as Semgrep, SonarLint, and ESLint Security',
        'Production Web Application Firewall logs',
        'Quarterly penetration test reports',
        'Database slow query analyzers',
      ],
      correctAnswer: 0,
      explanation: 'IDE linters and analyzers provide immediate real-time feedback directly at the point of code writing.',
    },
    defenseChecklist: [
      'Ban eval(), new Function(), and unsafe innerHTML bindings via ESLint rules.',
      'Configure automated pre-commit Git hooks using Husky to run linting and secret scanning.',
      'Provide regular security champion training for engineering teams.',
      'Establish a clear company policy prohibiting hardcoded API keys and tokens in source code.',
    ],
  },
  {
    id: '2.5',
    chapterId: 2,
    setIndex: 5,
    title: 'Release readiness, security sign-off, and maintenance planning',
    summary: 'Establish deployment criteria, security sign-off requirements, vulnerability patching SLAs, and end-of-life maintenance.',
    domain: 'lifecycle',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1104: Use of Unmaintained Third Party Components',
    owaspTop10: 'A06:2021-Vulnerable and Outdated Components',
    concepts: [
      {
        title: 'Release Readiness & Security Sign-Off Criteria',
        content: 'Before any release candidate deploys to production, it must fulfill defined gating criteria: zero open Critical or High SAST/SCA findings, threat model approved by AppSec, dynamic test scan executed, dependencies validated, and secrets scan clean.',
        keyPrinciple: 'Security sign-off is a verifiable audit trail, not an informal email agreement.',
      },
      {
        title: 'Maintenance Lifecycle & Remediation SLAs',
        content: 'Applications require ongoing patch governance. Standard remediation SLAs: Critical vulnerabilities patched within 24–48 hours; High vulnerabilities within 7–14 days; Medium within 30–60 days.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Deploying release without addressing known critical vulnerability in base Docker image.',
      cweOrStandard: 'CWE-1035: Vulnerable Third Party Component',
      impact: 'Container host compromise via unpatched kernel or OpenSSL exploit.',
      realWorldScenario: 'An enterprise service remained unpatched against Heartbleed and Shellshock for 18 months because it was classified as "stable" with no active maintenance plan.',
    },
    codeAuditLab: {
      language: 'Dockerfile',
      title: 'Outdated & Insecure Base Image Configuration',
      description: 'Audit a container definition running unpinned legacy packages with root privileges.',
      vulnerableCode: `# VULNERABLE: Outdated base image, running as root, no vulnerability pin
FROM node:14-alpine

WORKDIR /app
COPY . .
RUN npm install

# Runs as root user by default
CMD ["node", "server.js"]`,
      remediatedCode: `# REMEDIATED: Uses modern hardened slim image, unprivileged user, and pinned hash
FROM node:20.11-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20.11-alpine AS production
# Hardening: Run as dedicated non-root user
USER node
WORKDIR /app
COPY --chown=node:node --from=build /app/node_modules ./node_modules
COPY --chown=node:node . .

EXPOSE 3000
CMD ["node", "server.js"]`,
      flawExplanation: 'Running outdated node:14 with hundreds of known CVEs as root user permits an attacker who achieves RCE to control the container filesystem.',
      fixExplanation: 'Migrates to active LTS, installs only production dependencies, drops root privileges by switching to non-root "node" user, and optimizes layers.',
    },
    quiz: {
      question: 'What is the primary role of a Software Bill of Materials (SBOM) in the release readiness and maintenance process?',
      options: [
        'To speed up CSS compilation during production builds.',
        'To provide a comprehensive inventory of all software components, libraries, and dependencies for rapid vulnerability tracking.',
        'To bypass legal copyright audits.',
        'To replace user authentication with cryptographic proof.',
      ],
      correctAnswer: 1,
      explanation: 'An SBOM provides a formal machine-readable record of all software packages and components, allowing instant querying when new CVEs are published.',
    },
    defenseChecklist: [
      'Generate an SBOM (e.g., CycloneDX or SPDX) for every release artifact.',
      'Maintain automated container vulnerability scanning in deployment pipelines.',
      'Enforce non-root execution inside all Kubernetes pods and Docker containers.',
      'Define clear End-Of-Life (EOL) deprecation schedules for legacy application APIs.',
    ],
  },

  // CHAPTER 3
  {
    id: '3.1',
    chapterId: 3,
    setIndex: 1,
    title: 'Assets, actors, trust boundaries, and data flows',
    summary: 'Deconstruct applications into core assets, adversary actors, trust boundary crossings, and data flow paths.',
    domain: 'threat-modeling',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1022: Cross-Boundary Communication Flaw',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Core Elements of Threat Modeling',
        content: 'Threat modeling begins with four fundamental questions (Adam Shostack): 1. What are we building? 2. What can go wrong? 3. What are we going to do about it? 4. Did we do a good enough job? Systems are decomposed into Assets (what we protect), Actors (who interacts), Processes (code execution), Data Stores (persistence), and Data Flows.',
        keyPrinciple: 'Vulnerabilities concentrate at trust boundaries where data transitions between different privilege levels.',
      },
      {
        title: 'Identifying Trust Boundaries',
        content: 'A trust boundary separates components with different privilege levels or operational assumptions. Examples: Browser to Public Reverse Proxy, DMZ to Internal Database, Microservice A to Third-Party Webhook.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Trust boundary confusion where internal RPC trusts untrusted client metadata passed through proxy.',
      cweOrStandard: 'CWE-20: Improper Input Validation at Trust Boundary',
      impact: 'Attacker spoofing HTTP headers (X-Forwarded-For, X-User-Role) to bypass internal authorization.',
      realWorldScenario: 'An application trusted incoming X-Authenticated-User headers from clients because the edge load balancer failed to strip incoming client headers.',
    },
    codeAuditLab: {
      language: 'TypeScript / Gateway',
      title: 'Trust Boundary Leakage: Trusting Client Request Headers',
      description: 'Audit an API gateway that blindly forwards untrusted client headers into internal services.',
      vulnerableCode: `// VULNERABLE: Forwards client-supplied identity headers across trust boundary
app.use((req, res, next) => {
  // Attacker can pass X-User-Id: admin and X-Is-Superadmin: true in curl!
  req.headers['x-internal-user-id'] = req.headers['x-user-id'];
  req.headers['x-internal-role'] = req.headers['x-role'] || 'user';
  next();
});`,
      remediatedCode: `// REMEDIATED: Cleanses and re-authenticates identity at the trust boundary
app.use(async (req, res, next) => {
  // 1. Strip any client-supplied internal headers immediately
  delete req.headers['x-internal-user-id'];
  delete req.headers['x-internal-role'];

  // 2. Validate session token cryptographically at the boundary
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const verifiedClaims = await verifyJwtSignature(token, JWT_PUBLIC_KEY);
    // 3. Inject authoritative, verified values only
    req.headers['x-internal-user-id'] = verifiedClaims.sub;
    req.headers['x-internal-role'] = verifiedClaims.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or forged token' });
  }
});`,
      flawExplanation: 'Client requests can inject arbitrary x-user-id or x-role headers, tricking downstream backend microservices into assuming administrative identity.',
      fixExplanation: 'Strips all internal headers at the perimeter and overwrites them strictly with cryptographically validated token claims.',
    },
    quiz: {
      question: 'Where do application security flaws most frequently occur in architectural diagrams?',
      options: [
        'Within static data stores that have no inbound connections',
        'At trust boundaries where data transitions from an untrusted to a trusted zone',
        'In pure CSS frontend stylesheet files',
        'In client-side favicon assets',
      ],
      correctAnswer: 1,
      explanation: 'Trust boundaries represent transitions in privileges, making them prime targets for injection, spoofing, and privilege escalation.',
    },
    defenseChecklist: [
      'Draw explicit trust boundary lines on all application architecture diagrams.',
      'Strip and sanitize all incoming client headers at reverse proxies and API gateways.',
      'Never treat internal networks as inherently trusted environments.',
      'Authenticate and authorize every inter-service data flow crossing a trust boundary.',
    ],
  },
  {
    id: '3.2',
    chapterId: 3,
    setIndex: 2,
    title: 'STRIDE, PASTA, LINDDUN, and attack libraries',
    summary: 'Apply threat modeling methodologies including STRIDE, PASTA, LINDDUN, and CAPEC/MITRE attack patterns.',
    domain: 'threat-modeling',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1021: Improper Restriction of Rendered UI',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'The STRIDE Model (Microsoft)',
        content: 'STRIDE classifies threats into six distinct categories: Spoofing (impersonating an actor), Tampering (modifying data or code), Repudiation (denying an action occurred), Information Disclosure (exposing confidential data), Denial of Service (degrading availability), and Elevation of Privilege (gaining unauthorized capabilities).',
        keyPrinciple: 'Every component in a Data Flow Diagram maps to specific STRIDE threats (e.g. Data Stores map to Tampering, Information Disclosure, and Denial of Service).',
      },
      {
        title: 'PASTA & LINDDUN Methodologies',
        content: 'PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric, 7-step threat modeling methodology aligned with business objectives. LINDDUN focuses specifically on privacy threats (Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Repudiation threat where high-value transaction leaves no immutable audit trail.',
      cweOrStandard: 'CWE-778: Insufficient Logging',
      impact: 'Adversary denies initiating fraudulent wire transfer, and forensics cannot prove actor identity.',
      realWorldScenario: 'A banking application executed money transfers without logging user IP, session ID, or cryptographic timestamp, leaving investigators unable to prosecute unauthorized account drains.',
    },
    codeAuditLab: {
      language: 'TypeScript / Audit',
      title: 'Repudiation Flaw: Missing Authoritative Audit Trail',
      description: 'Audit a sensitive financial transaction handler that omits tamper-evident logging.',
      vulnerableCode: `// VULNERABLE: STRIDE Repudiation violation - action cannot be non-repudiably audited
app.post('/api/funds/transfer', async (req, res) => {
  const { recipientAccount, amount } = req.body;
  // Transacts funds without writing an immutable security audit event
  await ledger.transfer(req.user.id, recipientAccount, amount);
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Non-repudiable structured audit log with signature and context
import { writeImmutableAuditLog } from './services/auditLedger';

app.post('/api/funds/transfer', async (req, res) => {
  const { recipientAccount, amount } = req.body;
  const actor = req.user;
  const requestId = crypto.randomUUID();

  // Execute atomic transfer
  const txn = await ledger.transfer(actor.id, recipientAccount, amount);

  // Write tamper-evident audit record with digital signature
  await writeImmutableAuditLog({
    eventId: requestId,
    eventType: 'FINANCIAL_TRANSFER',
    timestamp: new Date().toISOString(),
    actorId: actor.id,
    actorIp: req.ip,
    userAgent: req.headers['user-agent'] || 'unknown',
    details: {
      transactionId: txn.id,
      recipientAccount,
      amount,
      currency: 'USD'
    },
    mfaVerified: actor.mfaVerifiedAt !== null
  });

  res.json({ success: true, transactionId: txn.id });
});`,
      flawExplanation: 'Without comprehensive audit trails of actor identity, IP, and timestamp, the actor can claim someone else performed the action or that the system hallucinated the transaction.',
      fixExplanation: 'Implements non-repudiable audit logging containing unique event IDs, actor IP, user agent, transaction details, and tamper-resistant storage.',
    },
    quiz: {
      question: 'In the STRIDE threat modeling framework, which security property counters the "Tampering" threat?',
      options: [
        'Confidentiality',
        'Integrity',
        'Availability',
        'Authentication',
      ],
      correctAnswer: 1,
      explanation: 'Tampering violates Integrity; cryptographic integrity checks (hashes, HMACs, digital signatures) counter tampering.',
    },
    defenseChecklist: [
      'Evaluate each system component and data flow against all six STRIDE categories.',
      'Ensure tamper-evident, append-only audit logging for all privileged transactions.',
      'Apply LINDDUN when assessing systems handling sensitive personal data.',
      'Maintain an updated catalog of applicable MITRE ATT&CK techniques for your tech stack.',
    ],
  },
  {
    id: '3.3',
    chapterId: 3,
    setIndex: 3,
    title: 'Data flow diagrams and threat modeling tools',
    summary: 'Construct architectural Data Flow Diagrams (DFD Level 0/1) and utilize threat modeling tools.',
    domain: 'threat-modeling',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1022: Cross-Boundary Communication Flaw',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'DFD Elements and Hierarchical Levels',
        content: 'Data Flow Diagrams model systems through standard elements: External Entities (users, third-party APIs), Processes (computational logic), Data Stores (databases, disk, cache), Data Flows (arrows indicating communication), and Trust Boundaries (dotted perimeters). Level 0 (Context Diagram) shows the high-level boundary; Level 1 decomposes into individual microservices and databases.',
        keyPrinciple: 'You cannot protect what you cannot diagram.',
      },
      {
        title: 'Threat Modeling Tooling Ecosystem',
        content: 'Modern threat modeling uses tools like OWASP Threat Dragon, Microsoft Threat Modeling Tool, and Threat-Modeling-as-Code frameworks (e.g., PyTM, Threagile) that version-control threat models alongside Git repositories.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Unencrypted data flow traversing third-party networks without transport encryption.',
      cweOrStandard: 'CWE-319: Cleartext Transmission of Sensitive Information',
      impact: 'Eavesdropping and credential harvesting via network packet capture.',
      realWorldScenario: 'A healthcare app sent telemetry containing patient vital signs over plaintext HTTP port 80 to a backend metrics collector.',
    },
    codeAuditLab: {
      language: 'TypeScript / Network',
      title: 'Insecure Data Flow: Plaintext Internal Traffic',
      description: 'Audit an internal HTTP client sending confidential user tokens over unencrypted channels.',
      vulnerableCode: `// VULNERABLE: Data flow crosses network boundary without encryption
import http from 'http';

function sendAuthPayloadToBackend(userData: object) {
  // Plaintext HTTP connection over public or VPC network
  const req = http.request('http://auth-service.internal:8080/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  req.write(JSON.stringify(userData));
  req.end();
}`,
      remediatedCode: `// REMEDIATED: Enforces TLS 1.3 with strict mutual certificate validation
import https from 'https';
import fs from 'fs';

const caCert = fs.readFileSync('/etc/ssl/certs/internal-ca.pem');

const httpsAgent = new https.Agent({
  ca: caCert,
  checkServerIdentity: (host, cert) => {
    // Custom hostname validation against internal domain
    if (cert.subject.CN !== 'auth-service.internal') {
      return new Error('Certificate CN does not match expected internal host');
    }
  },
  minVersion: 'TLSv1.3'
});

function sendAuthPayloadToBackend(userData: object) {
  const req = https.request('https://auth-service.internal:8443/sync', {
    method: 'POST',
    agent: httpsAgent,
    headers: { 'Content-Type': 'application/json' }
  });
  req.write(JSON.stringify(userData));
  req.end();
}`,
      flawExplanation: 'Sending authentication payloads over plaintext HTTP allows any compromised host on the network or rogue container to sniff credentials.',
      fixExplanation: 'Enforces HTTPS with TLS 1.3, verified CA certificates, and strict server identity checks.',
    },
    quiz: {
      question: 'In a standard Data Flow Diagram (DFD), which visual notation represents a boundary between different privilege levels?',
      options: [
        'A solid double circle',
        'A dashed or dotted boundary line cutting across data flow arrows',
        'A parallel horizontal bar',
        'A shaded rectangular process box',
      ],
      correctAnswer: 1,
      explanation: 'Trust boundaries are drawn as dashed lines separating elements that operate under different security contexts or privilege levels.',
    },
    defenseChecklist: [
      'Maintain an up-to-date DFD Level 1 for every production service.',
      'Treat all external entity data flows as untrusted input.',
      'Ensure every data flow crossing a trust boundary uses TLS encryption.',
      'Version-control threat models in Git alongside the application codebase.',
    ],
  },
  {
    id: '3.4',
    chapterId: 3,
    setIndex: 4,
    title: 'Attack trees, misuse cases, and adversary simulation',
    summary: 'Model adversary pathways using hierarchical attack trees and simulate realistic exploitation vectors.',
    domain: 'threat-modeling',
    duration: '20 min',
    difficulty: 'Advanced',
    cwe: 'CWE-840: Business Logic Errors',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Constructing Hierarchical Attack Trees',
        content: 'Pioneered by Bruce Schneier, attack trees represent attacks against a system in a tree structure. The root node is the adversary goal (e.g., "Exfiltrate Customer Database"). Child nodes represent sub-goals connected via AND (all sub-goals required) or OR (alternative pathways) logic.',
        keyPrinciple: 'Attack trees reveal the lowest-cost, highest-probability paths an attacker will take to breach the system.',
      },
      {
        title: 'Adversary Simulation and Misuse Scenarios',
        content: 'Simulating adversary tactics involves thinking like an attacker: How can MFA be bypassed? What if SMS gateways are intercepted? Can password reset tokens be predicted? Can rate limits be distributed across proxy botnets?',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Adversary exploits predictable password reset tokens to achieve account takeover sub-goal in attack tree.',
      cweOrStandard: 'CWE-330: Use of Insufficiently Random Values',
      impact: 'Complete administrative account takeover with zero user interaction.',
      realWorldScenario: 'A social network generated password reset tokens using Math.random() combined with Unix millisecond timestamps, allowing attackers to predict reset tokens within seconds.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Predictable Pseudo-Random Token Generation',
      description: 'Audit a password reset generator using predictable Math.random() values.',
      vulnerableCode: `// VULNERABLE: Cryptographically weak PRNG allows token prediction
function generatePasswordResetToken(userId: string): string {
  // Math.random() is NOT cryptographically secure!
  const randomSeed = Math.random().toString(36).substring(2);
  const timestamp = Date.now().toString();
  return Buffer.from(\`\${userId}:\${randomSeed}:\${timestamp}\`).toString('hex');
}`,
      remediatedCode: `// REMEDIATED: Uses cryptographically secure CSPRNG with high entropy
import crypto from 'crypto';

function generatePasswordResetToken(): { token: string; hash: string; expiresAt: Date } {
  // Generate 256 bits (32 bytes) of cryptographically secure randomness
  const rawToken = crypto.randomBytes(32).toString('hex');

  // Store only the SHA-256 hash in the database to prevent token theft from DB dumps
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15-minute expiration

  return {
    token: rawToken, // Sent to user via email/out-of-band only
    hash: tokenHash, // Stored in database
    expiresAt
  };
}`,
      flawExplanation: 'Math.random() uses predictable algorithms (like xorshift128+) whose internal state can be reconstructed by an attacker from a few observed outputs.',
      fixExplanation: 'Uses crypto.randomBytes() (CSPRNG) with 256 bits of entropy, stores only a SHA-256 hash in the database, and enforces a short expiration window.',
    },
    quiz: {
      question: 'In an attack tree, what does an "AND" condition node indicate?',
      options: [
        'The attacker only needs to achieve any one of the child steps.',
        'The attacker must successfully accomplish all child steps to achieve the parent goal.',
        'The attack is impossible to mitigate.',
        'The attack must be executed from two separate IP addresses.',
      ],
      correctAnswer: 1,
      explanation: 'An AND branch in an attack tree means all prerequisite sub-actions must be achieved for the parent attack node to succeed.',
    },
    defenseChecklist: [
      'Model root adversary goals (e.g., unauthorized data exfiltration, service disruption) into attack trees.',
      'Always generate tokens, nonces, and session identifiers using cryptographically secure PRNGs.',
      'Store only hashed representations of sensitive reset and activation tokens in databases.',
      'Test multi-step workflows against simulated adversary evasion and parameter tampering.',
    ],
  },
  {
    id: '3.5',
    chapterId: 3,
    setIndex: 5,
    title: 'Risk scoring, prioritization, and mitigation tracking',
    summary: 'Quantify threats using CVSS v3.1/v4.0, DREAD, FAIR methodologies, and track mitigation backlogs.',
    domain: 'threat-modeling',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-1025: Comparison of Incompatible Risk Metrics',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'CVSS v3.1 / v4.0 Scoring Mechanics',
        content: 'The Common Vulnerability Scoring System (CVSS) scores vulnerabilities from 0.0 to 10.0 across Base, Temporal, and Environmental metrics. Base metrics evaluate Attack Vector (Network, Adjacent, Local, Physical), Attack Complexity (Low, High), Privileges Required (None, Low, High), User Interaction (None, Required), Scope (Unchanged, Changed), and CIA impacts.',
        keyPrinciple: 'Base CVSS score measures technical severity; Environmental and Temporal metrics determine real-world organizational risk.',
      },
      {
        title: 'DREAD & FAIR Risk Quantification',
        content: 'DREAD scores: Damage, Reproducibility, Exploitability, Affected Users, and Discoverability. FAIR (Factor Analysis of Information Risk) models risk quantitatively in financial terms (Loss Event Frequency × Loss Magnitude).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Treating high-severity vulnerability as low priority due to lack of asset environmental context.',
      cweOrStandard: 'CWE-1008: Architectural Attack Surface Exposure',
      impact: 'Ransomware deployment due to delayed patching of externally facing VPN portal.',
      realWorldScenario: 'An enterprise delayed patching an unauthenticated RCE on a perimeter server because they only prioritized vulnerabilities with existing active exploit scripts.',
    },
    codeAuditLab: {
      language: 'TypeScript / Security Engine',
      title: 'Automated Risk Prioritization Calculation',
      description: 'Implement a risk prioritization function incorporating environmental exposure and asset criticality.',
      vulnerableCode: `// VULNERABLE: Evaluates priority solely based on static CVSS Base Score
function prioritizeVulnerability(finding: { cvssBase: number }): string {
  // Misleading: A CVSS 9.0 on an isolated sandbox might be lower risk than CVSS 7.0 on production DB!
  if (finding.cvssBase >= 9.0) return 'CRITICAL_P0';
  if (finding.cvssBase >= 7.0) return 'HIGH_P1';
  return 'LOW_P3';
}`,
      remediatedCode: `// REMEDIATED: Contextual risk scoring incorporating asset value and exploit availability
interface VulnerabilityContext {
  cveId: string;
  cvssBase: number;
  hasKnownExploitInWild: boolean; // CISA KEV catalog check
  isPubliclyReachable: boolean;
  assetCriticality: 'CRITICAL_DATA' | 'BUSINESS_SYSTEM' | 'INTERNAL_DEV';
}

function calculateContextualRiskPriority(context: VulnerabilityContext): {
  priority: 'P0_IMMEDIATE' | 'P1_URGENT' | 'P2_STANDARD' | 'P3_BACKLOG';
  remediationSlaHours: number;
  calculatedScore: number;
} {
  let score = context.cvssBase;

  // Escalate if actively exploited in the wild (CISA KEV)
  if (context.hasKnownExploitInWild) score += 2.0;

  // Escalate if directly accessible from public Internet
  if (context.isPubliclyReachable) score += 1.5;

  // Asset impact weighting
  if (context.assetCriticality === 'CRITICAL_DATA') score *= 1.3;
  else if (context.assetCriticality === 'INTERNAL_DEV') score *= 0.7;

  score = Math.min(10.0, Math.max(0.0, score));

  if (score >= 9.0) return { priority: 'P0_IMMEDIATE', remediationSlaHours: 24, calculatedScore: score };
  if (score >= 7.5) return { priority: 'P1_URGENT', remediationSlaHours: 72, calculatedScore: score };
  if (score >= 5.0) return { priority: 'P2_STANDARD', remediationSlaHours: 168, calculatedScore: score };
  return { priority: 'P3_BACKLOG', remediationSlaHours: 720, calculatedScore: score };
}`,
      flawExplanation: 'Relying exclusively on base CVSS scores ignores whether an asset is publicly exposed or whether active exploits exist in the wild.',
      fixExplanation: 'Weights base vulnerability severity with threat intelligence (CISA KEV), reachability, and business asset classification to compute real risk.',
    },
    quiz: {
      question: 'Which CVSS metric category accounts for an organization’s specific mitigation controls and asset criticality?',
      options: [
        'Base Metrics',
        'Environmental Metrics',
        'Exploitability Metrics',
        'Physical Metrics',
      ],
      correctAnswer: 1,
      explanation: 'Environmental metrics customize the CVSS score to reflect the organization’s environment, compensating controls, and specific asset impact.',
    },
    defenseChecklist: [
      'Integrate CISA Known Exploited Vulnerabilities (KEV) feeds into automated scanner prioritization.',
      'Establish enforceable SLAs for vulnerability remediation tied to contextual risk.',
      'Track security findings as first-class engineering tickets in sprint backlogs.',
      'Review and update risk registers on a regular sprint cadence.',
    ],
  },
];
