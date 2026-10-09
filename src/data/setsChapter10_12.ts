import { LearningSet } from '../types/curriculum';

export const SETS_CHAPTER_10_12: LearningSet[] = [
  // CHAPTER 10
  {
    id: '10.1',
    chapterId: 10,
    setIndex: 1,
    title: 'REST, GraphQL, gRPC, and WebSocket security',
    summary: 'Harden diverse API protocols against protocol-specific attack vectors: GraphQL depth DoS, gRPC reflection, and CSWSH.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-400: Uncontrolled Resource Consumption / CWE-1385',
    owaspTop10: 'API4:2023-Unrestricted Resource Consumption',
    concepts: [
      {
        title: 'Protocol-Specific Security Profiles',
        content: 'REST APIs face BOLA, mass assignment, and endpoint enumeration. GraphQL APIs introduce nested query depth recursion (e.g. author -> books -> author -> books...), cyclic batching DoS, and schema introspection leakage. gRPC uses binary HTTP/2 Protobufs, requiring mTLS and disabling production server reflection. WebSockets lack Same-Origin Policy enforcement by default, making them vulnerable to Cross-Site WebSocket Hijacking (CSWSH).',
        keyPrinciple: 'Never expose raw, unconstrained query capabilities to client runtimes.',
      },
      {
        title: 'GraphQL Defense Mechanisms',
        content: 'Enforce: 1. Maximum query depth limits (e.g., max 6 levels). 2. Query complexity analysis (cost calculation per field). 3. Disabling introspection in production. 4. Query allowlisting (Persisted Queries).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker sends deeply nested recursive GraphQL query triggering server CPU starvation and memory crash.',
      cweOrStandard: 'CWE-400: Uncontrolled Resource Consumption (GraphQL Denial of Service)',
      impact: 'Complete backend API crash affecting all legitimate users.',
      realWorldScenario: 'An attacker issued a 50-level nested GraphQL query to an unconstrained e-commerce schema, exhausting Node.js heap memory in 3 seconds.',
    },
    codeAuditLab: {
      language: 'TypeScript / GraphQL',
      title: 'Unconstrained GraphQL Query Depth & Complexity DoS',
      description: 'Audit a GraphQL server configuration omitting depth limits and complexity analysis.',
      vulnerableCode: `// VULNERABLE: Unbounded GraphQL execution allows recursive depth DoS
import { ApolloServer } from '@apollo/server';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // FLAW: Introspection enabled in production; zero query depth or complexity limits!
  introspection: true
});`,
      remediatedCode: `// REMEDIATED: Enforces query depth limits, complexity costs, and disables introspection
import { ApolloServer } from '@apollo/server';
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Disabled in production
  validationRules: [
    // 1. Limit nested query depth to max 5 levels
    depthLimit(5),
    // 2. Limit aggregate query complexity score
    createComplexityLimitRule(1000, {
      onCost: (cost) => logger.debug({ cost }, 'GraphQL query complexity computed')
    })
  ]
});`,
      flawExplanation: 'Without depth and complexity limits, an attacker can craft recursive queries that cause exponential database load and exhaust server memory.',
      fixExplanation: 'Enforces depthLimit(5), applies query complexity analysis, and disables schema introspection in production environments.',
    },
    quiz: {
      question: 'Why are WebSockets inherently vulnerable to Cross-Site WebSocket Hijacking (CSWSH) if proper origin validation is omitted?',
      options: [
        'WebSockets only run over unencrypted HTTP port 80.',
        'The browser’s Same-Origin Policy does NOT prevent cross-origin WebSocket connection handshakes; the browser sends cookies automatically.',
        'WebSockets do not support SSL certificates.',
        'WebSockets require root access on the client.',
      ],
      correctAnswer: 1,
      explanation: 'Browsers allow cross-origin WebSocket connections and include cookies in the handshake. The server must explicitly validate the Origin header to prevent CSWSH.',
    },
    defenseChecklist: [
      'Enforce query depth limits (<= 5) and query complexity analysis on all GraphQL endpoints.',
      'Disable GraphQL schema introspection in production environments.',
      'Validate the HTTP Origin header during WebSocket connection handshakes to prevent CSWSH.',
      'Disable gRPC server reflection in production deployments.',
    ],
  },
  {
    id: '10.2',
    chapterId: 10,
    setIndex: 2,
    title: 'API authentication, authorization, and scopes',
    summary: 'Design fine-grained OAuth 2.0 scopes, API key hashing, mTLS client certificates, and context validation.',
    domain: 'client-api',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-285: Improper Authorization',
    owaspTop10: 'API1:2023-Broken Object Level Authorization',
    concepts: [
      {
        title: 'API Tokens vs. API Keys',
        content: 'API Keys identify the calling application/project (for billing and quota tracking) but should NOT be used as the sole proof of end-user authorization. User-delegated authorization requires short-lived OAuth 2.0 access tokens containing granular scopes (e.g., read:orders, write:payments).',
        keyPrinciple: 'API keys identify the caller; OAuth tokens authorize the subject.',
      },
      {
        title: 'Secure API Key Storage & Hashing',
        content: 'Never store API keys in plaintext in databases. When issuing an API key (e.g. sk_live_xyz), display it ONCE to the user, store only its SHA-256 hash in the database, and verify incoming keys by hashing the incoming key and comparing with the stored hash in constant time.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker uses read-only scoped API token to invoke write/delete endpoint due to missing scope verification.',
      cweOrStandard: 'CWE-285: Improper Authorization (Scope Escalation)',
      impact: 'Unauthorized deletion of enterprise data using read-only API credentials.',
      realWorldScenario: 'An enterprise API checked whether the token was valid, but forgot to check if req.token.scopes included "write:users" on the DELETE /users endpoint.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express Middleware',
      title: 'Enforcing Fine-Grained OAuth Scopes on API Endpoints',
      description: 'Audit an API endpoint that verifies token presence but ignores required permissions scopes.',
      vulnerableCode: `// VULNERABLE: Verifies token validity but fails to verify required scopes
app.delete('/api/v1/projects/:id', verifyJwtToken, async (req, res) => {
  // FLAW: Any valid token (even one with only 'read:profile' scope) can delete projects!
  await db.deleteProject(req.params.id);
  res.json({ status: 'deleted' });
});`,
      remediatedCode: `// REMEDIATED: Enforces explicit scope requirement middleware
function requireScope(requiredScope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const tokenScopes: string[] = req.user?.scopes || [];

    if (!tokenScopes.includes(requiredScope) && !tokenScopes.includes('*')) {
      logger.warn({ user: req.user?.id, missingScope: requiredScope }, 'Insufficient token scope');
      return res.status(403).json({
        error: 'Forbidden: Insufficient scope',
        required: requiredScope
      });
    }
    next();
  };
}

app.delete(
  '/api/v1/projects/:id',
  verifyJwtToken,
  requireScope('projects:delete'), // Enforces specific scope permission
  async (req, res) => {
    // Also verify object ownership!
    const deleted = await db.deleteProject(req.params.id, req.user.tenantId);
    if (!deleted) return res.status(404).json({ error: 'Project not found' });
    res.json({ status: 'deleted' });
  }
);`,
      flawExplanation: 'Verifying token authenticity without checking authorization scopes allows clients with limited permissions to execute high-privilege operations.',
      fixExplanation: 'Implements scope checking middleware verifying that req.user.scopes contains the specific required action permission.',
    },
    quiz: {
      question: 'How should developer API keys (e.g., sk_live_...) be stored in an application’s database?',
      options: [
        'In plaintext so developers can look them up if forgotten.',
        'Hashed using a cryptographic hash (e.g., SHA-256) with only a non-sensitive prefix stored in plaintext for identification.',
        'Base64 encoded in the public user table.',
        'In client-side cookies.',
      ],
      correctAnswer: 1,
      explanation: 'Like passwords, API keys must be hashed in the database. Showing the key only once upon generation prevents key leakage if the database is breached.',
    },
    defenseChecklist: [
      'Store only cryptographic hashes (SHA-256) of API keys in databases.',
      'Enforce granular OAuth scopes (read:x, write:x) on every API route.',
      'Bind API keys to specific IP addresses or origins where feasible.',
      'Provide instant API key revocation and rolling key rotation capabilities in user dashboards.',
    ],
  },
  {
    id: '10.3',
    chapterId: 10,
    setIndex: 3,
    title: 'Rate limiting, throttling, and abuse prevention',
    summary: 'Implement Token Bucket and Sliding Window rate limiting algorithms using Redis, prevent brute force and scraping.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-770: Allocation of Resources Without Limits or Throttling',
    owaspTop10: 'API4:2023-Unrestricted Resource Consumption',
    concepts: [
      {
        title: 'Rate Limiting Algorithms',
        content: '1. Fixed Window: Counts requests in fixed time slices (vulnerable to bursts at window edges). 2. Token Bucket: Tokens replenish at a constant rate; requests consume tokens; supports bursts up to bucket capacity. 3. Sliding Window Log / Counter: Tracks timestamps in Redis sorted sets; provides precise limiting without edge-burst vulnerabilities.',
        keyPrinciple: 'Rate limit across multiple dimensions: per-IP, per-user ID, per-API key, and globally.',
      },
      {
        title: 'Standard HTTP Throttling Headers',
        content: 'When throttling, return HTTP 429 Too Many Requests with standard headers: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, and Retry-After (seconds).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Distributed credential stuffing and resource exhaustion due to absence of rate limiting.',
      cweOrStandard: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
      impact: 'Account takeover of thousands of user accounts and database server denial of service.',
      realWorldScenario: 'An attacker sent 500,000 login attempts per minute across residential botnet IPs, taking down the authentication database and hijacking accounts.',
    },
    codeAuditLab: {
      language: 'TypeScript / Redis',
      title: 'Sliding Window Rate Limiter using Redis',
      description: 'Implement a distributed sliding window rate limiter to protect sensitive endpoints.',
      vulnerableCode: `// VULNERABLE: In-memory counter without persistence or sliding window accuracy
const localCounts: Record<string, number> = {};

app.post('/api/auth/reset-password', (req, res) => {
  // FLAW: In-memory counts reset on container restart and do not sync across cluster pods!
  const ip = req.ip;
  localCounts[ip] = (localCounts[ip] || 0) + 1;
  if (localCounts[ip] > 100) {
    return res.status(429).send('Too many requests');
  }
  // process reset...
});`,
      remediatedCode: `// REMEDIATED: Distributed sliding window rate limiter backed by Redis
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL!);

export async function slidingWindowLimiter(
  key: string,
  limit: number,
  windowSeconds: number
): Promise<{ allowed: boolean; remaining: number; resetTimeMs: number }> {
  const now = Date.now();
  const windowStart = now - windowSeconds * 1000;
  const redisKey = \`ratelimit:\${key}\`;

  const pipeline = redis.pipeline();
  // 1. Remove timestamps older than the sliding window
  pipeline.zremrangebyscore(redisKey, 0, windowStart);
  // 2. Add current request timestamp
  pipeline.zadd(redisKey, now, \`\${now}-\${Math.random()}\`);
  // 3. Count total requests in window
  pipeline.zcard(redisKey);
  // 4. Set expiry to auto-clean unused keys
  pipeline.expire(redisKey, windowSeconds + 1);

  const results = await pipeline.exec();
  const requestCount = (results?.[2]?.[1] as number) || 0;

  const allowed = requestCount <= limit;
  const remaining = Math.max(0, limit - requestCount);
  const resetTimeMs = now + windowSeconds * 1000;

  return { allowed, remaining, resetTimeMs };
}`,
      flawExplanation: 'In-memory rate limiters fail completely in multi-pod load-balanced environments and reset upon every server restart.',
      fixExplanation: 'Uses a distributed Redis sliding window log (sorted sets) providing synchronized, cluster-wide rate limiting with accurate time boundaries.',
    },
    quiz: {
      question: 'Which HTTP status code should be returned to clients when a rate limit threshold is exceeded?',
      options: [
        'HTTP 401 Unauthorized',
        'HTTP 429 Too Many Requests',
        'HTTP 500 Internal Server Error',
        'HTTP 403 Forbidden',
      ],
      correctAnswer: 1,
      explanation: 'RFC 6585 defines HTTP 429 Too Many Requests specifically for rate limiting and throttling conditions.',
    },
    defenseChecklist: [
      'Enforce rate limiting on all public API endpoints using distributed caches (Redis).',
      'Apply aggressive rate limits (e.g. 5 attempts / 15 mins) on login, registration, and reset routes.',
      'Return standard Retry-After headers with HTTP 429 responses.',
      'Implement tiered rate limits: higher quotas for authenticated, paying API keys.',
    ],
  },
  {
    id: '10.4',
    chapterId: 10,
    setIndex: 4,
    title: 'Schema validation, input/output filtering, and versioning',
    summary: 'Prevent mass assignment and data leakage using strict OpenAPI / JSON schema contracts and DTO output filters.',
    domain: 'client-api',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (\'Mass Assignment\')',
    owaspTop10: 'API3:2023-Broken Object Property Level Authorization',
    concepts: [
      {
        title: 'Mass Assignment (Auto-Binding) Exploits',
        content: 'Modern ORMs and frameworks automatically bind HTTP request bodies directly to database models. If developers do not explicitly filter incoming fields, an attacker can append unexpected attributes (e.g. { "isAdmin": true, "verified": true, "balance": 999999 }) into profile update requests, escalating privileges.',
        keyPrinciple: 'Never pass raw request bodies directly to ORM create() or update() methods.',
      },
      {
        title: 'Output Data Filtering & DTOs',
        content: 'APIs must not return entire raw database records. Use strict Data Transfer Objects (DTOs) or serialization serializers to ensure sensitive columns (password_hash, ssn, stripe_customer_id, internal_notes) are never leaked in API JSON responses.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker injects "role": "admin" in user update PUT payload to achieve vertical privilege escalation.',
      cweOrStandard: 'CWE-915: Mass Assignment',
      impact: 'Immediate superuser administrative account creation.',
      realWorldScenario: 'GitHub in 2012 suffered a famous mass assignment vulnerability when a researcher added an SSH key to the Rails organization by injecting public_key parameters.',
    },
    codeAuditLab: {
      language: 'TypeScript / Prisma & Express',
      title: 'Mass Assignment in User Profile Update',
      description: 'Audit an endpoint passing raw req.body directly into an ORM update call.',
      vulnerableCode: `// VULNERABLE: Direct mass assignment binds all client-supplied keys into the database
app.put('/api/users/profile', authenticateUser, async (req, res) => {
  // Attacker sends: { "name": "Alice", "role": "ADMIN", "isSuperuser": true }
  const updatedUser = await db.user.update({
    where: { id: req.user.id },
    data: req.body // CATASTROPHIC MASS ASSIGNMENT!
  });
  // Also leaks passwordHash in output response!
  res.json(updatedUser);
});`,
      remediatedCode: `// REMEDIATED: Strict DTO schema allowlist for input and output projection
import { z } from 'zod';

// 1. Strict Input Schema: Only allow specific editable fields
const UpdateProfileInput = z.object({
  displayName: z.string().trim().min(2).max(50),
  bio: z.string().max(250).optional()
}).strict(); // Disallows any unrecognized keys

app.put('/api/users/profile', authenticateUser, async (req, res) => {
  const parseResult = UpdateProfileInput.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'Invalid profile attributes' });
  }

  // 2. Pass ONLY validated safe properties to the ORM
  const updated = await db.user.update({
    where: { id: req.user.id },
    data: {
      displayName: parseResult.data.displayName,
      bio: parseResult.data.bio ?? null
    },
    // 3. Strict Output Projection: Never select or return password hashes or internal roles
    select: {
      id: true,
      displayName: true,
      bio: true,
      updatedAt: true
    }
  });

  res.json({ user: updated });
});`,
      flawExplanation: 'Passing req.body directly into the database allows attackers to overwrite administrative fields like role, balance, or permissions.',
      fixExplanation: 'Enforces strict input validation schemas accepting only allowed fields, and explicitly selects only safe attributes in the output projection.',
    },
    quiz: {
      question: 'What is the most effective defense against Mass Assignment vulnerabilities in modern web APIs?',
      options: [
        'Encoding all JSON values in Base64.',
        'Defining explicit Input Data Transfer Objects (DTOs) that only map known, safe fields to the database.',
        'Adding more RAM to the database server.',
        'Disabling HTTP PUT requests.',
      ],
      correctAnswer: 1,
      explanation: 'Explicit DTOs and schema validators reject or discard unexpected fields, preventing attackers from modifying sensitive internal attributes.',
    },
    defenseChecklist: [
      'Never pass req.body or raw query objects directly to database insert or update queries.',
      'Use strict DTO schemas with .strict() validation on all input payloads.',
      'Explicitly select returned fields in database queries; never return full model rows.',
      'Version API endpoints (e.g. /v1/, /v2/) and deprecate legacy unvalidated versions.',
    ],
  },
  {
    id: '10.5',
    chapterId: 10,
    setIndex: 5,
    title: 'API gateways, monitoring, and service mesh security',
    summary: 'Deploy API Gateways (Kong, Envoy) for edge authentication, centralized WAF, anomaly detection, and mTLS mesh.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-1008: Architectural Attack Surface Exposure',
    owaspTop10: 'A05:2021-Security Misconfiguration',
    concepts: [
      {
        title: 'The Edge API Gateway Pattern',
        content: 'An API Gateway acts as the single entry point for all external clients, centralizing non-functional security cross-cutting concerns: TLS termination, DDoS protection, rate limiting, JWT token validation, CORS enforcement, and request logging.',
        keyPrinciple: 'Centralize security policies at the gateway so backend microservices can focus on core domain logic.',
      },
      {
        title: 'Service Mesh & Istio Security Architecture',
        content: 'While API Gateways handle North-South (client-to-backend) traffic, Service Meshes (Istio, Envoy) secure East-West (service-to-service) traffic within the internal cluster using sidecar proxies, enforcing mutual TLS and fine-grained AuthorizationPolicies.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker accesses internal microservice directly on public cloud port, bypassing edge API Gateway.',
      cweOrStandard: 'CWE-284: Improper Access Control',
      impact: 'Complete bypass of edge authentication, WAF rules, and rate limits.',
      realWorldScenario: 'A backend container was configured with a public IP on AWS; attackers found it via Shodan and queried it directly without passing through the Kong gateway.',
    },
    codeAuditLab: {
      language: 'YAML / Kubernetes & Envoy',
      title: 'Kubernetes Network Policy & Gateway Ingress Isolation',
      description: 'Audit a Kubernetes deployment allowing unauthorized external traffic directly into backend pods.',
      vulnerableCode: `# VULNERABLE: No NetworkPolicy; any pod or external IP can reach backend service directly
apiVersion: v1
kind: Service
metadata:
  name: billing-service
spec:
  type: LoadBalancer # FLAW: Exposes internal microservice directly to the public internet!
  ports:
    - port: 8080
      targetPort: 8080`,
      remediatedCode: `# REMEDIATED: Restricts ingress strictly to API Gateway via Kubernetes NetworkPolicy
apiVersion: v1
kind: Service
metadata:
  name: billing-service
spec:
  type: ClusterIP # Internal cluster access only
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-only-api-gateway
spec:
  podSelector:
    matchLabels:
      app: billing-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway # Only traffic from verified Gateway pods allowed!
      ports:
        - protocol: TCP
          port: 8080`,
      flawExplanation: 'Exposing backend microservices via public LoadBalancer services allows adversaries to bypass gateway authentication and security filters entirely.',
      fixExplanation: 'Switches backend services to ClusterIP and enforces a Kubernetes NetworkPolicy permitting ingress strictly from the API Gateway.',
    },
    quiz: {
      question: 'In modern cloud architectures, what is the distinction between North-South traffic and East-West traffic?',
      options: [
        'North-South is UDP traffic; East-West is TCP traffic.',
        'North-South represents external client-to-datacenter traffic; East-West represents internal service-to-service communication.',
        'North-South represents database queries; East-West represents HTML rendering.',
        'North-South is encrypted; East-West cannot be encrypted.',
      ],
      correctAnswer: 1,
      explanation: 'North-South traffic enters the system from external clients; East-West traffic flows between internal services within the application network.',
    },
    defenseChecklist: [
      'Isolate backend microservices inside private subnets with zero direct public internet ingress.',
      'Enforce Kubernetes NetworkPolicies to permit traffic strictly from approved API Gateway pods.',
      'Terminate TLS and enforce rate limiting at the API Gateway perimeter.',
      'Enable mutual TLS (mTLS) in service meshes for all internal East-West communications.',
    ],
  },

  // CHAPTER 11
  {
    id: '11.1',
    chapterId: 11,
    setIndex: 1,
    title: 'Android and iOS security models',
    summary: 'Analyze Android Sandboxing, UID isolation, iOS Secure Enclave, App Transport Security (ATS), and permission models.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-272: Least Privilege Violation',
    owaspTop10: 'M1:2024-Improper Credential Usage',
    concepts: [
      {
        title: 'Android Security Model Architecture',
        content: 'Android assigns each installed application a unique Linux User ID (UID), executing it in an isolated Linux process sandbox. Apps cannot access each other’s files or memory. Android 10+ enforces Scoped Storage, restricting apps to their private directories unless explicit runtime permissions are granted.',
        keyPrinciple: 'Operating system sandboxes provide foundational isolation; permissions govern cross-boundary access.',
      },
      {
        title: 'iOS Security Architecture & Secure Enclave',
        content: 'iOS runs apps under the unprivileged "mobile" user inside an App Sandbox container. The Secure Enclave Processor (SEP) is an isolated hardware co-processor managing cryptographic keys, biometric evaluation (Touch ID/Face ID), and memory encryption independently from the main application processor.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Android app exports sensitive ContentProvider or Activity without permissions, allowing rogue apps to steal data.',
      cweOrStandard: 'CWE-926: Improper Export of Android Application Components',
      impact: 'Malicious app installed on device reads private chats or credentials from vulnerable app.',
      realWorldScenario: 'A banking app exported an Activity containing sensitive account balance data with android:exported="true" and no signature permission, allowing any third-party app to launch it and view balances.',
    },
    codeAuditLab: {
      language: 'XML / Android Manifest',
      title: 'Insecurely Exported Android Component',
      description: 'Audit an AndroidManifest.xml exposing internal Activities to other apps on the device.',
      vulnerableCode: `<!-- VULNERABLE: Exported activity with no permission requirement -->
<activity
    android:name=".InternalUserDashboardActivity"
    android:exported="true">
    <!-- FLAW: Any app on the device can launch this Activity and bypass login! -->
    <intent-filter>
        <action android:name="com.example.app.VIEW_INTERNAL_DASHBOARD" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>`,
      remediatedCode: `<!-- REMEDIATED: Unexported or protected by signature permission -->
<activity
    android:name=".InternalUserDashboardActivity"
    android:exported="false">
    <!-- Restricts access strictly to internal components of the same APK -->
</activity>

<!-- If cross-app communication is required, restrict with signature permission -->
<permission
    android:name="com.example.app.permission.ACCESS_INTERNAL"
    android:protectionLevel="signature" /> <!-- Only apps signed by same developer certificate -->

<activity
    android:name=".PartnerSyncActivity"
    android:exported="true"
    android:permission="com.example.app.permission.ACCESS_INTERNAL" />`,
      flawExplanation: 'Setting android:exported="true" without permission requirements allows any rogue application installed on the phone to invoke internal screens.',
      fixExplanation: 'Sets android:exported="false" for internal screens and uses protectionLevel="signature" for components that must communicate across apps.',
    },
    quiz: {
      question: 'What is the role of the Secure Enclave in Apple iOS devices?',
      options: [
        'To speed up 3D gaming graphics.',
        'A dedicated hardware coprocessor that manages cryptographic keys and biometric data isolated from the main application processor.',
        'To compress photos before uploading to iCloud.',
        'To scan all outgoing network packets for spam.',
      ],
      correctAnswer: 1,
      explanation: 'The Secure Enclave is a separate hardware security processor that keeps cryptographic keys and biometric templates protected even if the main iOS kernel is compromised.',
    },
    defenseChecklist: [
      'Set android:exported="false" on all Android Activities, Receivers, and Services unless explicitly required.',
      'Use signature-level permissions for inter-app communication between apps you own.',
      'Enforce App Transport Security (ATS) on iOS to prohibit plaintext HTTP traffic.',
      'Request runtime permissions only when the feature is actively needed, explaining the context to the user.',
    ],
  },
  {
    id: '11.2',
    chapterId: 11,
    setIndex: 2,
    title: 'Secure local storage, Keychain, and Keystore',
    summary: 'Store sensitive mobile secrets using Android Keystore / EncryptedSharedPreferences and iOS Keychain Services.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
    owaspTop10: 'M2:2024-Insecure Data Storage',
    concepts: [
      {
        title: 'Mobile Secure Storage Architectures',
        content: 'Storing tokens or passwords in SharedPreferences (Android) or UserDefaults/plist (iOS) stores them in plaintext files that are easily dumped on rooted/jailbroken devices or via system backups. Secure storage requires hardware-backed encryption: Android Keystore system and iOS Keychain Services.',
        keyPrinciple: 'Never store credentials or encryption keys in plaintext mobile preferences or databases.',
      },
      {
        title: 'Android Keystore & EncryptedSharedPreferences',
        content: 'The Android Keystore lets apps generate cryptographic keys that never enter the app’s process memory. Jetpack Security provides EncryptedSharedPreferences, which transparently encrypts keys and values using AES-256-GCM backed by the Keystore master key.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker extracts plaintext auth token from app’s SharedPreferences file in a device backup.',
      cweOrStandard: 'CWE-312: Cleartext Storage of Sensitive Information',
      impact: 'Account takeover via stolen mobile authentication tokens.',
      realWorldScenario: 'An enterprise healthcare app saved patient authentication tokens in unencrypted SharedPreferences; adb backup allowed full extraction of the token file without rooting.',
    },
    codeAuditLab: {
      language: 'Kotlin / Android Security',
      title: 'Insecure SharedPreferences vs. EncryptedSharedPreferences',
      description: 'Audit mobile local storage logic storing authentication tokens in plaintext.',
      vulnerableCode: `// VULNERABLE: Plaintext SharedPreferences file easily read by backup or root
val sharedPref = context.getSharedPreferences("user_session", Context.MODE_PRIVATE)
with(sharedPref.edit()) {
    // FLAW: Plaintext token written to /data/data/com.example/shared_prefs/user_session.xml
    putString("auth_token", token)
    apply()
}`,
      remediatedCode: `// REMEDIATED: Uses Jetpack Security EncryptedSharedPreferences with hardware MasterKey
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

// 1. Create or retrieve hardware-backed MasterKey from Android Keystore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .setUserAuthenticationRequired(false) // Or true for biometric prompt requirement
    .build()

// 2. Instantiate hardware-encrypted SharedPreferences
val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_session_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

with(securePrefs.edit()) {
    putString("auth_token", token)
    apply()
}`,
      flawExplanation: 'Standard SharedPreferences stores data in unencrypted XML files on disk, readable via ADB backups or on rooted devices.',
      fixExplanation: 'Adopts EncryptedSharedPreferences with AES-256-GCM value encryption and AES-256-SIV key encryption backed by the Android Keystore.',
    },
    quiz: {
      question: 'Where should sensitive authentication tokens and private keys be stored on Apple iOS applications?',
      options: [
        'In UserDefaults as a base64 encoded string.',
        'In iOS Keychain Services with kSecAttrAccessibleAfterFirstUnlock.',
        'In an unencrypted SQLite database inside the app bundle.',
        'In the user’s camera roll.',
      ],
      correctAnswer: 1,
      explanation: 'iOS Keychain Services encrypts sensitive items using hardware-backed keys tied to the device passcode and Secure Enclave.',
    },
    defenseChecklist: [
      'Store all tokens, passwords, and PII using Android EncryptedSharedPreferences and iOS Keychain.',
      'Set android:allowBackup="false" in AndroidManifest.xml to prevent adb backup token dumping.',
      'Bind sensitive keys in Keystore to biometric authentication (setUserAuthenticationRequired).',
      'Disable screen caching on sensitive views by setting FLAG_SECURE on Android.',
    ],
  },
  {
    id: '11.3',
    chapterId: 11,
    setIndex: 3,
    title: 'Mobile authentication, biometrics, and app permissions',
    summary: 'Implement BiometricPrompt, CryptoObject cryptographic gating, and runtime permission principles.',
    domain: 'platforms',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-287: Improper Authentication',
    owaspTop10: 'M3:2024-Insecure Authentication/Authorization',
    concepts: [
      {
        title: 'Cryptographic Biometric Verification (CryptoObject)',
        content: 'Naive mobile apps treat biometric success as a simple boolean callback (onAuthenticationSucceeded -> grant access). An attacker with a rooted phone can easily hook the boolean check with Frida. Secure mobile biometrics uses a CryptoObject: the Keystore key is unlocked ONLY upon genuine biometric verification, and that key is required to decrypt the session token.',
        keyPrinciple: 'Never trust boolean biometric callbacks. Gate actual cryptographic decryption behind the biometric event.',
      },
      {
        title: 'Principle of Least Privilege in App Permissions',
        content: 'Apps should request the absolute minimum permissions needed. Avoid coarse background location when foreground fine location suffices. Use system pickers (Photo Picker) rather than asking for full storage access.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker uses Frida dynamic instrumentation to hook boolean biometric check and bypass fingerprint login.',
      cweOrStandard: 'CWE-287: Improper Authentication (Client-Side Boolean Bypass)',
      impact: 'Immediate bypass of mobile biometric lock screen.',
      realWorldScenario: 'A banking application had onBiometricSuccess() { showDashboard(); }; an attacker used a 3-line Frida script to return true, bypassing authentication completely.',
    },
    codeAuditLab: {
      language: 'Kotlin / Android BiometricPrompt',
      title: 'Boolean Biometric Check vs. Cryptographic CryptoObject Gating',
      description: 'Audit a biometric callback relying on easily hookable boolean logic.',
      vulnerableCode: `// VULNERABLE: Easily bypassed via Frida script hooking onAuthenticationSucceeded
biometricPrompt.authenticate(promptInfo)

override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
  // FLAW: Frida can easily call this method directly or hook the boolean return!
  openBankingDashboard()
}`,
      remediatedCode: `// REMEDIATED: Cryptographically gated biometric authentication using CryptoObject
val cipher = getSecretCipher() // Initialized with Keystore key requiring biometric auth
val cryptoObject = BiometricPrompt.CryptoObject(cipher)

// Authenticate WITH the CryptoObject
biometricPrompt.authenticate(promptInfo, cryptoObject)

override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
  // Key is ONLY unlocked if hardware biometric verification succeeded
  val authenticatedCipher = result.cryptoObject?.cipher
  if (authenticatedCipher != null) {
    // Decrypt the stored encrypted session token using the unlocked cipher
    val sessionToken = decryptToken(encryptedTokenBytes, authenticatedCipher)
    sendAuthenticatedApiRequest(sessionToken)
  }
}`,
      flawExplanation: 'Relying on a client-side boolean callback allows attackers with Frida or Xposed to hook the callback and enter the app without a fingerprint.',
      fixExplanation: 'Passes a CryptoObject tied to a Keystore key, ensuring that the actual decryption of the session token cannot occur without hardware biometric validation.',
    },
    quiz: {
      question: 'Why is tying mobile biometric authentication to a CryptoObject more secure than a standard boolean callback?',
      options: [
        'Because CryptoObject makes the fingerprint sensor scan faster.',
        'Because the cryptographic key required to decrypt the session token is only unlocked by the hardware enclave upon successful biometric match, defeating Frida hook bypasses.',
        'Because CryptoObject uploads the fingerprint to the cloud.',
        'Because CryptoObject prevents the phone from running out of battery.',
      ],
      correctAnswer: 1,
      explanation: 'With a CryptoObject, the underlying decryption key physically cannot decrypt the token without genuine hardware authentication, rendering client-side boolean hooking useless.',
    },
    defenseChecklist: [
      'Use BiometricPrompt with CryptoObject for all biometric-authenticated transactions.',
      'Use modern Android Photo Picker instead of requesting full READ_EXTERNAL_STORAGE permissions.',
      'Audit third-party SDKs to ensure they are not requesting unneeded device permissions.',
      'Re-authenticate with server credentials when performing high-risk actions (e.g. wire transfers).',
    ],
  },
  {
    id: '11.4',
    chapterId: 11,
    setIndex: 4,
    title: 'Network security, certificate pinning, and secure APIs',
    summary: 'Implement SSL Certificate Pinning, Network Security Configuration, and defense against mobile MitM proxies.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-295: Improper Certificate Validation',
    owaspTop10: 'M5:2024-Insecure Communication',
    concepts: [
      {
        title: 'Mobile Man-in-the-Middle (MitM) Threat',
        content: 'Adversaries and security researchers install custom CA certificates on mobile devices (or in emulators) and route traffic through proxies (Burp Suite, Charles, mitmproxy) to inspect and tamper with encrypted HTTPS traffic. By default, standard TLS trusts all system and user installed CAs.',
        keyPrinciple: 'Pin public key hashes to reject rogue or user-installed CA certificates.',
      },
      {
        title: 'Certificate Pinning & Network Security Config',
        content: 'Certificate pinning restricts trusted certificates to a specific public key Subject Public Key Info (SPKI) SHA-256 hash. Android uses res/xml/network_security_config.xml; iOS uses URLSessionDelegate or TrustKit. Always include backup pins to avoid app bricking upon certificate renewal.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker intercepts encrypted mobile traffic using user-installed CA certificate to harvest credentials.',
      cweOrStandard: 'CWE-295: Improper Certificate Validation',
      impact: 'Plaintext interception and tampering with all mobile API traffic.',
      realWorldScenario: 'A cryptocurrency wallet app trusted user-installed root CAs on Android; malware installed a CA certificate and drained user wallets by intercepting private keys.',
    },
    codeAuditLab: {
      language: 'XML / Android Network Security Config',
      title: 'Android Network Security Configuration with SPKI Pinning',
      description: 'Audit network security configuration to restrict CA trust and pin public keys.',
      vulnerableCode: `<!-- VULNERABLE: Trusts user certificates; allows trivial Burp Suite interception -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" /> <!-- FLAW: Allows any user-installed CA to intercept! -->
        </trust-anchors>
    </base-config>
</network-security-config>`,
      remediatedCode: `<!-- REMEDIATED: Prohibits cleartext, disallows user CAs, and enforces SPKI pinning -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" /> <!-- System CAs only; rejects user CAs -->
        </trust-anchors>
    </base-config>

    <domain-config>
        <domain includeSubdomains="true">api.securecompany.com</domain>
        <pin-set expiration="2027-01-01">
            <!-- Primary certificate public key SPKI SHA-256 hash -->
            <pin digest="SHA-256">k2v657xUM4MpNGnqw5Jh06evME2Ip0rNDUgAr9RUC+k=</pin>
            <!-- Mandatory backup pin for certificate rotation -->
            <pin digest="SHA-256">YW63XWScGAeAqLLnk9R8oEvXZypGqi+50Jcn44ipXYw=</pin>
        </pin-set>
    </domain-config>
</network-security-config>`,
      flawExplanation: 'Permitting user CA certificates allows anyone to install a proxy certificate on the phone and intercept all sensitive API traffic in plaintext.',
      fixExplanation: 'Disallows cleartext traffic, rejects user certificates, and pins SHA-256 public key hashes with an explicit backup rotation pin.',
    },
    quiz: {
      question: 'Why must certificate pinning configurations always include at least one backup pin?',
      options: [
        'Because Google Play will reject the app without a backup pin.',
        'To prevent the mobile application from permanently losing API connectivity if the primary server certificate expires or is revoked.',
        'To enable Bluetooth connectivity.',
        'To support older 2G networks.',
      ],
      correctAnswer: 1,
      explanation: 'If the server’s primary certificate is compromised or rotated and the app only pins that single key, all client apps will fail to connect until an app store update is released.',
    },
    defenseChecklist: [
      'Prohibit cleartext HTTP traffic across all mobile applications (cleartextTrafficPermitted=false).',
      'Disallow user-installed CAs in production Android Network Security Configurations.',
      'Implement SPKI certificate pinning with at least one verified backup pin.',
      'Deploy Certificate Transparency monitoring for all production domains.',
    ],
  },
  {
    id: '11.5',
    chapterId: 11,
    setIndex: 5,
    title: 'Reverse engineering, tamper detection, and obfuscation',
    summary: 'Protect mobile binaries using ProGuard/R8 obfuscation, root/jailbreak detection, and anti-debugging controls.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-656: Reliance on Security Through Obscurity Alone',
    owaspTop10: 'M8:2024-Software Integrity',
    concepts: [
      {
        title: 'Mobile Binary Reverse Engineering',
        content: 'Android APKs can be decompiled into readable Java source code in seconds using tools like JADX and apktool. iOS Mach-O binaries can be disassembled in Ghidra/IDA Pro. Obfuscation tools (ProGuard, R8, DexGuard) rename classes, fields, and methods to meaningless symbols, flatten control flow, and encrypt sensitive strings.',
        keyPrinciple: 'Obfuscation slows down reverse engineering but is not a substitute for server-side authorization.',
      },
      {
        title: 'Tamper & Root/Jailbreak Detection',
        content: 'Check for signs of rooting (Superuser.apk, /system/xbin/su, test-keys build tags, Magisk mount points) and verify APK signature integrity at runtime using Google Play Integrity API or Apple DeviceCheck.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker decompiles unobfuscated APK, finds hardcoded payment encryption keys, and patches check logic.',
      cweOrStandard: 'CWE-798: Use of Hard-coded Credentials / CWE-693',
      impact: 'Extraction of sensitive proprietary algorithms and offline authentication bypass.',
      realWorldScenario: 'A mobile game stored in-app purchase validation logic locally; an attacker used apktool to change if (isPaid) to always true and re-signed the APK.',
    },
    codeAuditLab: {
      language: 'Kotlin / Root Detection & Play Integrity',
      title: 'Heuristic Root Detection & Play Integrity Verification',
      description: 'Implement multi-layered client integrity checks and Play Integrity token verification.',
      vulnerableCode: `// VULNERABLE: Trivial client-side boolean check without server-side verification
fun isDeviceSafe(): Boolean {
  // Can be bypassed in 1 line of Frida: RootBeer.isRooted.implementation = function() { return false; }
  return !RootBeer(context).isRooted
}`,
      remediatedCode: `// REMEDIATED: Combines multi-heuristic local checks with cryptographically signed Google Play Integrity API
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

class DeviceIntegrityChecker(private val context: Context) {
  // 1. Local heuristic check for obvious root binaries
  fun hasRootArtifacts(): Boolean {
    val paths = arrayOf(
      "/system/app/Superuser.apk",
      "/system/xbin/su",
      "/system/bin/su",
      "/sbin/su",
      "/data/local/xbin/su"
    )
    return paths.any { File(it).exists() }
  }

  // 2. Server-authoritative Play Integrity check
  fun requestServerAttestation(nonce: String, onTokenReceived: (String) -> Unit) {
    val integrityManager = IntegrityManagerFactory.create(context)
    val request = IntegrityTokenRequest.builder()
      .setCloudProjectNumber(1234567890L)
      .setNonce(nonce) // Server-generated cryptographically random nonce
      .build()

    integrityManager.requestIntegrityToken(request)
      .addOnSuccessListener { response ->
        // Send cryptographically signed token to backend server to verify device verdict
        onTokenReceived(response.token())
      }
  }
}`,
      flawExplanation: 'Client-only root checks can be easily bypassed using dynamic instrumentation frameworks (Frida) by hooking the boolean method.',
      fixExplanation: 'Pairs local root heuristics with the Google Play Integrity API, where the backend server verifies a cryptographically signed hardware attestation token.',
    },
    quiz: {
      question: 'Why should mobile tamper detection decisions always be validated on the backend server rather than entirely on the mobile client?',
      options: [
        'Because mobile phones do not have clocks.',
        'Because an attacker who controls the client hardware can alter client-side memory and hook any boolean check to always return true.',
        'Because server validation saves battery on the phone.',
        'Because Apple App Store guidelines forbid local checks.',
      ],
      correctAnswer: 1,
      explanation: 'The client device is under the attacker’s physical control; any decision made solely on the client can be manipulated via debugging or runtime hooking.',
    },
    defenseChecklist: [
      'Enable R8/ProGuard obfuscation, shrinking, and resource optimization on all release builds.',
      'Validate device and app integrity using Google Play Integrity API or Apple App Attest.',
      'Never store master secrets, private keys, or sensitive business logic inside mobile client binaries.',
      'Detect debuggers (android.os.Debug.isDebuggerConnected()) and exit on unauthorized attachment.',
    ],
  },

  // CHAPTER 12
  {
    id: '12.1',
    chapterId: 12,
    setIndex: 1,
    title: 'Desktop sandboxing, permissions, and OS integration',
    summary: 'Harden desktop runtimes (Electron, Tauri, native) using AppContainer, App Sandbox, and IPC message filtering.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-265: Privilege / Sandbox Issues',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'Electron Security & Node.js Integration Hazards',
        content: 'Electron pairs Chromium with Node.js. If nodeIntegration: true is set or contextIsolation: false, any XSS vulnerability in the web frontend escalates instantly into arbitrary native OS command execution (e.g. require(\'child_process\').execSync(\'calc.exe\')).',
        keyPrinciple: 'Never enable nodeIntegration in renderer processes. Always enforce contextIsolation: true with strict IPC preload bridges.',
      },
      {
        title: 'Native Desktop Sandboxing (macOS & Windows)',
        content: 'macOS App Sandbox restricts apps to containerized directories and requires specific entitlements for network, camera, and microphone. Windows AppContainer provides low-integrity process sandboxing with restricted token privileges.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'XSS in Electron application executes arbitrary OS shell commands via exposed Node.js runtime.',
      cweOrStandard: 'CWE-94: Improper Control of Generation of Code (\'Code Injection\')',
      impact: 'Full remote shell execution on user’s laptop upon loading a malicious webpage.',
      realWorldScenario: 'A popular desktop messaging app configured nodeIntegration: true; an XSS in a chat message opened a reverse shell on the victim’s MacBook.',
    },
    codeAuditLab: {
      language: 'TypeScript / Electron',
      title: 'Insecure Electron BrowserWindow Configuration',
      description: 'Audit an Electron main process BrowserWindow configuration enabling dangerous node integration.',
      vulnerableCode: `// VULNERABLE: Node integration enabled and context isolation disabled
const mainWindow = new BrowserWindow({
  webPreferences: {
    // Catastrophic: Any XSS achieves full host RCE!
    nodeIntegration: true,
    contextIsolation: false
  }
});
mainWindow.loadURL('https://untrusted-content.example.com');`,
      remediatedCode: `// REMEDIATED: Secure Electron isolation with safe contextBridge
import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';

const mainWindow = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false, // Prevents renderer from accessing Node.js
    contextIsolation: true, // Isolates renderer context from preload script
    sandbox: true,          // Chromium sandbox enabled
    preload: path.join(__dirname, 'preload.js')
  }
});

// In preload.js: Expose ONLY safe, strictly validated IPC channels
// contextBridge.exposeInMainWorld('secureApi', {
//   sendAlert: (msg: string) => ipcRenderer.send('safe-alert', msg)
// });

// In main process: Validate all incoming IPC messages
ipcMain.on('safe-alert', (event, msg) => {
  if (typeof msg === 'string' && msg.length < 200) {
    console.log('Safe alert received:', msg);
  }
});`,
      flawExplanation: 'nodeIntegration: true gives the web page direct access to Node.js APIs (fs, child_process), allowing any XSS to compromise the operating system.',
      fixExplanation: 'Enforces nodeIntegration: false, contextIsolation: true, sandbox: true, and communicates through a strictly validated contextBridge.',
    },
    quiz: {
      question: 'In modern Electron application architecture, which setting is essential to prevent client-side web scripts from accessing Node.js primitives?',
      options: [
        'contextIsolation: true and nodeIntegration: false',
        'fullscreen: true',
        'enableRemoteModule: true',
        'webSecurity: false',
      ],
      correctAnswer: 0,
      explanation: 'Enabling context isolation and disabling node integration ensures that renderer web pages cannot access Node.js runtime APIs.',
    },
    defenseChecklist: [
      'Enforce contextIsolation: true and nodeIntegration: false across all Electron BrowserWindow instances.',
      'Enable sandbox: true to run renderer processes within the Chromium sandbox.',
      'Validate all IPC messages in the main process; never trust parameters sent from renderer.',
      'Sign desktop binaries with an EV Code Signing certificate to satisfy Windows SmartScreen and Apple Gatekeeper.',
    ],
  },
  {
    id: '12.2',
    chapterId: 12,
    setIndex: 2,
    title: 'Update mechanisms, code signing, and secure distribution',
    summary: 'Design cryptographic auto-update pipelines (TUF / Squirrel), code signing verification, and tamper-proof distribution.',
    domain: 'platforms',
    duration: '20 min',
    difficulty: 'Advanced',
    cwe: 'CWE-494: Download of Code Without Integrity Check',
    owaspTop10: 'A08:2021-Software and Data Integrity Failures',
    concepts: [
      {
        title: 'The Update Mechanism Attack Vector',
        content: 'Auto-update mechanisms run with elevated privileges to replace executable binaries on user machines. If an update mechanism downloads unverified executables over HTTP or fails to verify cryptographic digital signatures, attackers can execute mass supply-chain compromises (e.g. SolarWinds, NotPetya).',
        keyPrinciple: 'Update payloads must be cryptographically signed, verified before execution, and delivered over authenticated channels.',
      },
      {
        title: 'The Update Framework (TUF)',
        content: 'TUF provides resilience against key compromise, replay attacks, and freeze attacks by separating responsibilities across Root, Targets, Snapshot, and Timestamp cryptographic metadata roles.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker performs MitM on unauthenticated auto-update feed to deliver malicious Trojan installer.',
      cweOrStandard: 'CWE-494: Download of Code Without Integrity Check',
      impact: 'Mass deployment of ransomware to all installed desktop clients.',
      realWorldScenario: 'The CCleaner supply chain incident delivered malware to 2.2 million users through a compromised official software update server.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js Update Client',
      title: 'Insecure Binary Auto-Update Downloader',
      description: 'Audit an updater that executes downloaded binaries without signature or hash validation.',
      vulnerableCode: `// VULNERABLE: Downloads binary over HTTP and executes without signature verification
import http from 'http';
import { exec } from 'child_process';
import fs from 'fs';

function downloadAndRunUpdate(versionUrl: string) {
  // FLAW: Plaintext HTTP and zero cryptographic signature check!
  http.get(versionUrl, (res) => {
    const file = fs.createWriteStream('/tmp/update.exe');
    res.pipe(file);
    file.on('finish', () => {
      // Executes untrusted downloaded binary directly!
      exec('/tmp/update.exe /silent');
    });
  });
}`,
      remediatedCode: `// REMEDIATED: Enforces HTTPS, SHA-256 hash check, and Ed25519 digital signature validation
import https from 'https';
import crypto from 'crypto';
import fs from 'fs';

const TRUSTED_VENDOR_PUBLIC_KEY = process.env.VENDOR_SIGNING_PUBLIC_KEY!; // Ed25519 public key

interface UpdateManifest {
  version: string;
  url: string;
  sha256: string;
  signature: string; // Ed25519 signature of the SHA-256 hash
}

export function verifyAndApplyUpdate(manifest: UpdateManifest, downloadedBuffer: Buffer): boolean {
  // 1. Compute and verify SHA-256 digest of downloaded payload
  const computedHash = crypto.createHash('sha256').update(downloadedBuffer).digest('hex');
  if (computedHash !== manifest.sha256) {
    throw new Error('Integrity failure: Checksum mismatch');
  }

  // 2. Verify vendor cryptographic digital signature
  const isSignatureValid = crypto.verify(
    null, // null for Ed25519
    Buffer.from(manifest.sha256),
    TRUSTED_VENDOR_PUBLIC_KEY,
    Buffer.from(manifest.signature, 'base64')
  );

  if (!isSignatureValid) {
    throw new Error('Cryptographic signature verification failed: Untrusted update binary');
  }

  return true;
}`,
      flawExplanation: 'Executing downloaded binaries without digital signature and integrity checks enables network attackers to replace updates with malicious payloads.',
      fixExplanation: 'Verifies the SHA-256 hash of the binary and validates an Ed25519 cryptographic signature from the vendor’s private signing key.',
    },
    quiz: {
      question: 'Which security framework provides comprehensive protection against key compromises, replay attacks, and freeze attacks in software update systems?',
      options: [
        'The Update Framework (TUF)',
        'OAuth 2.0',
        'HTTP/2',
        'SNMPv3',
      ],
      correctAnswer: 0,
      explanation: 'The Update Framework (TUF) is the industry standard specification for securing software update systems against sophisticated compromise.',
    },
    defenseChecklist: [
      'Cryptographically sign all desktop binaries, installers, and auto-update packages.',
      'Enforce digital signature verification (e.g. Ed25519 / RSA) before executing update packages.',
      'Deliver updates strictly over HTTPS from authenticated CDNs.',
      'Implement multi-role signing based on The Update Framework (TUF) principles.',
    ],
  },
  {
    id: '12.3',
    chapterId: 12,
    setIndex: 3,
    title: 'Embedded constraints, secure boot, and hardware roots of trust',
    summary: 'Architect embedded security: Hardware Roots of Trust (TPM, eHSM), Secure Boot chains, and memory protection.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-1274: Improper Access Control for Volatile Memory Containing Boot Code',
    owaspTop10: 'A08:2021-Software and Data Integrity Failures',
    concepts: [
      {
        title: 'Hardware Root of Trust & Secure Boot Chain',
        content: 'Security in embedded devices begins in immutable hardware: Mask ROM (Root of Trust for Verification). The ROM verifies the digital signature of the First Stage Bootloader (FSBL), which verifies the Second Stage Bootloader (U-Boot), which verifies the OS kernel, which verifies the application filesystem. If any link in the chain fails signature verification, boot halts.',
        keyPrinciple: 'Trust must anchor in immutable hardware; software cannot verify itself.',
      },
      {
        title: 'TPM 2.0 & Platform Configuration Registers (PCRs)',
        content: 'Trusted Platform Modules (TPMs) provide secure key storage, hardware random number generation, and remote attestation. PCRs record cryptographic measurements of boot components, enabling cryptographic "sealing" where keys are only released if the system boots into a verified clean state.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker flashes modified firmware with backdoor because device bootloader omits signature verification.',
      cweOrStandard: 'CWE-1274: Insecure Boot Process',
      impact: 'Permanent hardware rootkit and botnet enrollment (e.g. Mirai botnet).',
      realWorldScenario: 'An IoT IP camera accepted unsigned firmware updates over local web interface, enabling the Mirai botnet to overwrite firmware on 600,000 devices.',
    },
    codeAuditLab: {
      language: 'C / Embedded Bootloader',
      title: 'Unverified Firmware Boot vs. Cryptographic Secure Boot Verification',
      description: 'Audit an embedded bootloader jump routine that executes code from flash without signature verification.',
      vulnerableCode: `// VULNERABLE: Jumps directly to flash address without checking digital signature
void boot_firmware(uint32_t flash_address) {
  // FLAW: Executes whatever code is in flash! Attacker can flash backdoored OS!
  void (*firmware_entry)(void) = (void (*)(void))flash_address;
  firmware_entry();
}`,
      remediatedCode: `// REMEDIATED: Secure boot verifies cryptographic signature against Root-of-Trust key
#include <stdbool.h>
#include "crypto_ed25519.h"

extern const uint8_t HARDWARE_FUSED_ROOT_PUBLIC_KEY[32]; // Immutable fused hardware key

bool verify_and_boot_firmware(uint32_t flash_addr, uint32_t img_len, const uint8_t *signature) {
  const uint8_t *firmware_payload = (const uint8_t *)flash_addr;

  // 1. Verify firmware cryptographic signature against immutable hardware public key
  int verify_status = ed25519_verify(
    signature,
    firmware_payload,
    img_len,
    HARDWARE_FUSED_ROOT_PUBLIC_KEY
  );

  if (verify_status != 1) {
    // Halts execution and triggers hardware rollback or panic on signature failure
    secure_hardware_panic_halt();
    return false;
  }

  // 2. Signature valid: safe to jump to verified firmware image
  void (*firmware_entry)(void) = (void (*)(void))flash_addr;
  firmware_entry();
  return true;
}`,
      flawExplanation: 'Jumping to a flash memory address without cryptographic verification allows attackers with physical or flashing access to execute malicious backdoored kernels.',
      fixExplanation: 'Verifies the digital signature of the firmware payload against an immutable hardware-fused public key before jumping to code execution.',
    },
    quiz: {
      question: 'What is the purpose of Platform Configuration Registers (PCRs) in a Trusted Platform Module (TPM)?',
      options: [
        'To regulate the CPU temperature.',
        'To store cryptographic measurements (hashes) of system boot stages for remote attestation and data sealing.',
        'To increase RAM bus speeds.',
        'To store device screen brightness settings.',
      ],
      correctAnswer: 1,
      explanation: 'PCRs record hashes of each stage of the boot process; keys can be sealed to specific PCR values so they are only released if the boot chain is unmodified.',
    },
    defenseChecklist: [
      'Enable hardware-enforced Secure Boot on all embedded chips and microcontrollers.',
      'Burn vendor cryptographic public keys into One-Time-Programmable (OTP) eFuses.',
      'Disable hardware debug interfaces (JTAG, SWD, UART) before production manufacturing.',
      'Seal encryption keys in TPM/eHSM tied to clean PCR measurements.',
    ],
  },
  {
    id: '12.4',
    chapterId: 12,
    setIndex: 4,
    title: 'IoT identity, provisioning, and device lifecycle security',
    summary: 'Manage IoT device identities, zero-touch manufacturing provisioning, X.509 device certificates, and mTLS cloud connectivity.',
    domain: 'platforms',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'IoT Identity: Eliminating Shared Credentials',
        content: 'Historical IoT devices shared static hardcoded credentials (e.g. admin:admin, root:123456) across millions of manufactured units, resulting in massive botnets (Mirai). Modern IoT security mandates unique, per-device cryptographic identity: each physical unit possesses its own private key generated inside a secure element (e.g., ATECC608A) and a unique X.509 device certificate.',
        keyPrinciple: 'Every physical IoT device must have a unique, non-extractable cryptographic identity.',
      },
      {
        title: 'Zero-Touch Provisioning (FIDO Device Onboard / EST)',
        content: 'FIDO Device Onboard (FDO) and Enrollment over Secure Transport (EST) allow devices to securely onboard onto cloud management platforms (AWS IoT Core, Azure IoT Hub) automatically without manual credential configuration.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Millions of IoT devices hacked via factory-default telnet/SSH passwords.',
      cweOrStandard: 'CWE-1392: Use of Default Credentials in Factory Shipped Device',
      impact: 'Devices hijacked into massive distributed DDoS botnet.',
      realWorldScenario: 'The Mirai botnet scanned the Internet for 64 default factory usernames and passwords, recruiting over 600,000 IoT devices and launching 1 Tbps DDoS attacks.',
    },
    codeAuditLab: {
      language: 'TypeScript / MQTT IoT Client',
      title: 'Shared Factory Credentials vs. X.509 Mutual TLS Authentication',
      description: 'Audit an IoT connection client authenticating with hardcoded credentials.',
      vulnerableCode: `// VULNERABLE: Shared hardcoded factory credentials across all manufactured devices
import mqtt from 'mqtt';

const client = mqtt.connect('mqtt://iot-broker.company.com', {
  // FLAW: Same username/password burned into thousands of customer devices!
  username: 'factory_device',
  password: 'DefaultDevicePassword2026'
});`,
      remediatedCode: `// REMEDIATED: Per-device unique X.509 client certificate with mTLS
import mqtt from 'mqtt';
import fs from 'fs';

// Each device has a unique certificate and private key burned into secure element
const client = mqtt.connect('mqtts://iot-broker.company.com:8883', {
  key: fs.readFileSync('/etc/ssl/device-private.key'),
  cert: fs.readFileSync('/etc/ssl/device-cert.crt'),
  ca: fs.readFileSync('/etc/ssl/cloud-root-ca.pem'),
  clientId: 'device-serial-9988124',
  protocol: 'mqtts',
  rejectUnauthorized: true
});

client.on('connect', () => {
  logger.info('Device mutually authenticated and connected via mTLS');
});`,
      flawExplanation: 'Shared credentials burned into firmware allow an attacker who reverses one device to authenticate as every device in the fleet.',
      fixExplanation: 'Adopts per-device unique X.509 client certificates and mutual TLS (mTLS), ensuring compromised device credentials cannot affect the rest of the fleet.',
    },
    quiz: {
      question: 'What is the most effective approach to eliminate shared default passwords across manufactured IoT devices?',
      options: [
        'Printing the default password on a sticker on the box.',
        'Provisioning unique, per-device private keys and X.509 certificates generated in a hardware secure element during factory manufacturing.',
        'Disabling all passwords and allowing unauthenticated access.',
        'Changing the Wi-Fi frequency to 5GHz.',
      ],
      correctAnswer: 1,
      explanation: 'Unique per-device cryptographic credentials generated in hardware ensure no two devices share keys, defeating credential-stuffing botnets.',
    },
    defenseChecklist: [
      'Ban static default credentials across all manufactured hardware models.',
      'Provision unique X.509 device certificates into hardware secure elements (e.g. ATECC608).',
      'Enforce mutual TLS (mTLS) for all MQTT and HTTPS device-to-cloud communications.',
      'Maintain automated revocation mechanisms (CRLs/OCSP) for compromised device certificates.',
    ],
  },
  {
    id: '12.5',
    chapterId: 12,
    setIndex: 5,
    title: 'Firmware, OTA updates, and constrained device protection',
    summary: 'Design robust Over-The-Air (OTA) firmware pipelines with A/B dual-bank partitioning, anti-rollback, and memory safety.',
    domain: 'platforms',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-494: Download of Code Without Integrity Check / Anti-Rollback',
    owaspTop10: 'A08:2021-Software and Data Integrity Failures',
    concepts: [
      {
        title: 'A/B Dual-Bank Partitioning & Fallback',
        content: 'Constrained IoT devices frequently update over flaky cellular or satellite connections. A single corrupt update could permanently brick devices deployed in remote fields. A/B dual-bank partitioning writes updates to an inactive partition (Bank B), marks it unconfirmed, reboots, and confirms only if a watchdog self-test passes. If verification fails, it rolls back automatically to Bank A.',
        keyPrinciple: 'Never update an active running partition directly; always use dual-bank A/B fallback.',
      },
      {
        title: 'Hardware Anti-Rollback (Downgrade Defense)',
        content: 'Even with cryptographically signed firmware, attackers can flash older, legitimately signed firmware that contains a known, unpatched vulnerability. Anti-rollback mechanisms burn monotonic version counters into hardware eFuses, preventing the bootloader from executing firmware with a lower version number.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker downgrades device firmware to older vulnerable signed version to exploit patched buffer overflow.',
      cweOrStandard: 'CWE-1188: Insecure Default Initialization / Firmware Rollback Flaw',
      impact: 'Reintroduction of critical vulnerabilities on fully patched devices.',
      realWorldScenario: 'Attackers downgraded game console firmware to a legacy version signed two years prior, re-enabling a patched memory overflow vulnerability to dump master keys.',
    },
    codeAuditLab: {
      language: 'C / Bootloader Anti-Rollback',
      title: 'Firmware Version Anti-Rollback eFuse Verification',
      description: 'Audit firmware update logic to enforce monotonic security version counters.',
      vulnerableCode: `// VULNERABLE: Verifies cryptographic signature but fails to check monotonic version
bool process_ota_update(const uint8_t *new_fw, uint32_t len, const uint8_t *sig) {
  // Signature is valid, BUT firmware version is older with known CVE!
  if (!verify_signature(new_fw, len, sig)) return false;
  // FLAW: Flashes older vulnerable version directly!
  flash_write(BANK_B_ADDR, new_fw, len);
  return true;
}`,
      remediatedCode: `// REMEDIATED: Enforces monotonic security counter against hardware eFuses
#include "hardware_efuse.h"

typedef struct {
  uint32_t magic;
  uint32_t security_version; // Monotonic anti-rollback counter
  uint32_t image_size;
} fw_header_t;

bool process_ota_update(const uint8_t *new_fw, uint32_t len, const uint8_t *sig) {
  if (!verify_signature(new_fw, len, sig)) {
    return false;
  }

  const fw_header_t *header = (const fw_header_t *)new_fw;
  uint32_t current_fused_version = efuse_read_security_version();

  // Enforce strict anti-rollback: new firmware version MUST be >= fused version
  if (header->security_version < current_fused_version) {
    log_security_alert("Rollback attempt detected: firmware rejected");
    return false;
  }

  // Flash to inactive Bank B
  flash_write(BANK_B_ADDR, new_fw, len);

  // If new version is higher, burn monotonic eFuses permanently
  if (header->security_version > current_fused_version) {
    efuse_burn_security_version(header->security_version);
  }

  return true;
}`,
      flawExplanation: 'Checking only cryptographic signatures allows downgrade attacks where attackers install legitimately signed older firmware containing exploitable flaws.',
      fixExplanation: 'Compares the firmware’s security version counter against immutable hardware eFuses, permanently burning the new version to block downgrade attempts.',
    },
    quiz: {
      question: 'Why are hardware eFuses or monotonic counters necessary in firmware Over-The-Air (OTA) update systems?',
      options: [
        'To speed up download speeds.',
        'To prevent downgrade (rollback) attacks where an attacker flashes legitimately signed but vulnerable legacy firmware.',
        'To compress firmware images.',
        'To format the SD card.',
      ],
      correctAnswer: 1,
      explanation: 'Monotonic eFuses record the highest installed security version, preventing attackers from installing older signed firmware with known vulnerabilities.',
    },
    defenseChecklist: [
      'Implement A/B dual-bank partitioning with watchdog auto-rollback on update failure.',
      'Enforce hardware anti-rollback using monotonic security counters in eFuses.',
      'Sign all OTA update packages using offline air-gapped private keys.',
      'Encrypt firmware binaries at rest to protect intellectual property and proprietary algorithms.',
    ],
  },
];
