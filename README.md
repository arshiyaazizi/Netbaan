# Unique Vulnerability Identification

## Problem Description
In the field of cybersecurity, various tools and products have been developed to identify vulnerabilities in websites. During a system vulnerability assessment, multiple tools might detect the same vulnerability but fail to provide a unique identifier for it. The goal of this task is to identify similar vulnerabilities reported by different tools.

Develop a content similarity detection service capable of identifying vulnerabilities with identical content. This service should retrieve information from a PostgreSQL database and expose the results through an API.

### Data Structure
Each data record represents a vulnerability and includes the following fields:
- `title`: The title of the vulnerability.
- `endpoint`: The local address of the application that is vulnerable.
- `severity`: The severity of the vulnerability (e.g., critical, high, medium, low, info).
- `cve`: The CVE identifier of the vulnerability.
- `Description`: A detailed description of the vulnerability.
- `sensor`: The tool that detected the vulnerability.

## Output
The results should be provided via the API, where similar vulnerabilities share identical tags.
```json
[
  {
    "cve": "CVE-2021-1111",
    "description": "A critical SQL injection vulnerability found in the login form, allowing SQL queries injection.",
    "endpoint": "/login",
    "id": 760,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_1",
    "title": "SQL Injection in login form"
  },
  {
    "cve": "CVE-2022-2222",
    "description": "The admin login page may have an SQL injection flaw that allows malicious SQL queries.",
    "endpoint": "/login",
    "id": 761,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_2",
    "title": "Suspected SQL Injection in adminstrator login"
  },
  {
    "cve": NaN,
    "description": "A Cross-Site Scripting (XSS) issue in the user profile page allows script injection.",
    "endpoint": "/profile",
    "id": 762,
    "sensor": "ToolA",
    "severity": "medium",
    "tag": "group_3",
    "title": "XSS in user profile"
  },
  {
    "cve": NaN,
    "description": "Profile page is vulnerable to XSS if user-provided scripts are not sanitized.",
    "endpoint": "/profile",
    "id": 764,
    "sensor": "ToolB",
    "severity": "high",
    "tag": "group_3",
    "title": "Cross-Site Scripting in profile page"
  },
  {
    "cve": NaN,
    "description": "Reflected XSS discovered in profile endpoint, enabling malicious script execution.",
    "endpoint": "/profile",
    "id": 790,
    "sensor": "ToolC",
    "severity": "medium",
    "tag": "group_3",
    "title": "Reflected XSS on user profile"
  },
  {
    "cve": NaN,
    "description": "The /profile endpoint can be exploited to run arbitrary commands on the server.",
    "endpoint": "/profile",
    "id": 793,
    "sensor": "ToolB",
    "severity": "critical",
    "tag": "group_3",
    "title": "Remote code execution found at /profile"
  },
  {
    "cve": NaN,
    "description": "Profile authorization bypass could let normal users access privileged info.",
    "endpoint": "/profile",
    "id": 794,
    "sensor": "ToolB",
    "severity": "medium",
    "tag": "group_3",
    "title": "Profile authorization bypass"
  },
  {
    "cve": NaN,
    "description": "Leaking configuration data at /config can give attackers insights into the system.",
    "endpoint": "/config",
    "id": 763,
    "sensor": "ToolC",
    "severity": "medium",
    "tag": "group_4",
    "title": "Config information disclosure"
  },
  {
    "cve": NaN,
    "description": "Attackers can achieve code execution on the server via /config if not patched.",
    "endpoint": "/config",
    "id": 772,
    "sensor": "ToolD",
    "severity": "high",
    "tag": "group_4",
    "title": "Remote Code Execution at /config"
  },
  {
    "cve": NaN,
    "description": "Application config files are publicly accessible, causing information disclosure.",
    "endpoint": "/config",
    "id": 773,
    "sensor": "ToolA",
    "severity": "low",
    "tag": "group_4",
    "title": "Information disclosure in config"
  },
  {
    "cve": "CVE-2025-1234",
    "description": "Obsolete version 2.2.x can be exploited via SSTI, leading to arbitrary code execution.",
    "endpoint": "/apache",
    "id": 765,
    "sensor": "ToolD",
    "severity": "high",
    "tag": "group_5",
    "title": "Obsolete Apache vulnerable to template injection"
  },
  {
    "cve": "CVE-2025-1234",
    "description": "Apache 2.2.x is vulnerable to server-side template injection, potentially leading to RCE.",
    "endpoint": "/apache",
    "id": 768,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_5",
    "title": "Server-Side Template Injection in old Apache"
  },
  {
    "cve": NaN,
    "description": "Comment injection flaw at /comments endpoint allows attacker-supplied commands.",
    "endpoint": "/comments",
    "id": 766,
    "sensor": "ToolB",
    "severity": "high",
    "tag": "group_6",
    "title": "Comment injection in comments"
  },
  {
    "cve": NaN,
    "description": "The /comments section is vulnerable to injection of arbitrary code via user content.",
    "endpoint": "/comments",
    "id": 791,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_6",
    "title": "Comments injection flaw"
  },
  {
    "cve": "CVE-2023-3333",
    "description": "The user profile section may allow XSS due to unsanitized input fields.",
    "endpoint": "/profile",
    "id": 767,
    "sensor": "ToolD",
    "severity": "medium",
    "tag": "group_7",
    "title": "Profile XSS vulnerability"
  },
  {
    "cve": NaN,
    "description": "Malicious file upload possible if the upload endpoint is not validating file types.",
    "endpoint": "/upload",
    "id": 769,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_8",
    "title": "Insecure file upload (upload endpoint)"
  },
  {
    "cve": NaN,
    "description": "A file upload flaw at /upload can be exploited to run arbitrary code on the server.",
    "endpoint": "/upload",
    "id": 770,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_8",
    "title": "File upload flaw in endpoint"
  },
  {
    "cve": "CVE-2028-0001",
    "description": "Application accidentally exposes secret keys in the /secret route, allowing unauthorized access.",
    "endpoint": "/secret",
    "id": 771,
    "sensor": "ToolA",
    "severity": "medium",
    "tag": "group_9",
    "title": "Secret key exposure"
  },
  {
    "cve": "CVE-2028-0002",
    "description": "Malicious cache injection is possible in /assets, enabling attackers to serve rogue content.",
    "endpoint": "/assets",
    "id": 774,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_10",
    "title": "Cache poisoning in /assets"
  },
  {
    "cve": "CVE-2028-0003",
    "description": "An unclaimed subdomain can be taken over, letting attackers host malicious content.",
    "endpoint": "/subdomain",
    "id": 775,
    "sensor": "ToolC",
    "severity": "critical",
    "tag": "group_11",
    "title": "Subdomain takeover vulnerability"
  },
  {
    "cve": "CVE-2022-5555",
    "description": "Sensitive data in config is exposed, leading to information disclosure issues.",
    "endpoint": "/config",
    "id": 776,
    "sensor": "ToolB",
    "severity": "high",
    "tag": "group_12",
    "title": "Public config leads to info disclosure"
  },
  {
    "cve": "CVE-2022-5555",
    "description": "A critical misconfiguration in /config reveals sensitive credentials and secrets.",
    "endpoint": "/config",
    "id": 779,
    "sensor": "ToolD",
    "severity": "critical",
    "tag": "group_12",
    "title": "Misconfigured config endpoint"
  },
  {
    "cve": NaN,
    "description": "/session endpoint fails to renew session IDs. causing session fixation attacks.",
    "endpoint": "/session",
    "id": 777,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_13",
    "title": "Session fixation in session"
  },
  {
    "cve": NaN,
    "description": "Session fixation bug discovered in /session endpoint enables reusing another user's session token.",
    "endpoint": "/session",
    "id": 786,
    "sensor": "ToolB",
    "severity": "high",
    "tag": "group_13",
    "title": "Session fixation discovered"
  },
  {
    "cve": "CVE-2025-0003",
    "description": "The profile endpoint fails to check user roles leading to authorization bypass.",
    "endpoint": "/profile",
    "id": 778,
    "sensor": "ToolC",
    "severity": "medium",
    "tag": "group_14",
    "title": "Profile authorization bypass vulnerability"
  },
  {
    "cve": "CVE-2021-4444",
    "description": "Attackers can upload arbitrary files via the upload endpoint, leading to RCE.",
    "endpoint": "/upload",
    "id": 780,
    "sensor": "ToolB",
    "severity": "critical",
    "tag": "group_15",
    "title": "Arbitrary file upload vulnerability"
  },
  {
    "cve": "CVE-2021-4444",
    "description": "The file upload endpoint accepts potentially harmful files without proper checks.",
    "endpoint": "/upload",
    "id": 781,
    "sensor": "ToolD",
    "severity": "medium",
    "tag": "group_15",
    "title": "Unauthenticated file upload vulnerability"
  },
  {
    "cve": NaN,
    "description": "Cart checkout page is susceptible to CSRF attacks through unprotected forms.",
    "endpoint": "/cart",
    "id": 782,
    "sensor": "ToolB",
    "severity": "medium",
    "tag": "group_16",
    "title": "CSRF vulnerability in cart checkout"
  },
  {
    "cve": NaN,
    "description": "A CSRF vulnerability in the cart checkout flow can allow malicious form submissions.",
    "endpoint": "/cart",
    "id": 801,
    "sensor": "ToolA",
    "severity": "medium",
    "tag": "group_16",
    "title": "CSRF in cart checkout"
  },
  {
    "cve": "CVE-2024-0001",
    "description": "Attackers can manipulate file paths to access unauthorized directories in /files endpoint.",
    "endpoint": "/files",
    "id": 783,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_17",
    "title": "Directory Traversal in files"
  },
  {
    "cve": NaN,
    "description": "Encryption mechanism in /api/encrypt is weak. allowing potential data exposure.",
    "endpoint": "/api/encrypt",
    "id": 784,
    "sensor": "ToolD",
    "severity": "medium",
    "tag": "group_18",
    "title": "Weak encryption in api encrypt"
  },
  {
    "cve": "CVE-2027-1001",
    "description": "Unvalidated file input in /profile allows remote code execution.",
    "endpoint": "/profile",
    "id": 785,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_19",
    "title": "Arbitrary code execution in /profile"
  },
  {
    "cve": "CVE-2025-0002",
    "description": "Malicious users can inject code into comments leading to remote script execution.",
    "endpoint": "/comments",
    "id": 787,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_20",
    "title": "Comment injection vulnerability"
  },
  {
    "cve": NaN,
    "description": "Potential SQL injection vulnerability in the admin login flow, leading to database compromise.",
    "endpoint": "/login",
    "id": 788,
    "sensor": "ToolD",
    "severity": "critical",
    "tag": "group_21",
    "title": "Potential login SQL injection"
  },
  {
    "cve": NaN,
    "description": "SQL injection detected at the login endpoint. Possible to inject SQL commands.",
    "endpoint": "/login",
    "id": 792,
    "sensor": "ToolB",
    "severity": "medium",
    "tag": "group_21",
    "title": "SQL Injection vulnerability (login)"
  },
  {
    "cve": NaN,
    "description": "Lack of HSTS policy in the /secure endpoint leads to potential SSL stripping attacks.",
    "endpoint": "/secure",
    "id": 789,
    "sensor": "ToolB",
    "severity": "low",
    "tag": "group_22",
    "title": "Missing HSTS policy"
  },
  {
    "cve": "CVE-2025-0004",
    "description": "Session fixation in /session allows attackers to hijack valid sessions after login.",
    "endpoint": "/session",
    "id": 795,
    "sensor": "ToolA",
    "severity": "high",
    "tag": "group_23",
    "title": "Session fixation vulnerability"
  },
  {
    "cve": "CVE-2025-0004",
    "description": "A critical session fixation flaw in /session can compromise user accounts.",
    "endpoint": "/session",
    "id": 797,
    "sensor": "ToolD",
    "severity": "critical",
    "tag": "group_23",
    "title": "Session fixation flaw"
  },
  {
    "cve": NaN,
    "description": "An end-of-life Apache version is prone to server-side template injection attacks.",
    "endpoint": "/apache",
    "id": 796,
    "sensor": "ToolC",
    "severity": "medium",
    "tag": "group_24",
    "title": "SSTI vulnerability in EOL Apache"
  },
  {
    "cve": NaN,
    "description": "Outdated Apache release allows server-side template injection if template engine is misconfigured.",
    "endpoint": "/apache",
    "id": 799,
    "sensor": "ToolB",
    "severity": "critical",
    "tag": "group_24",
    "title": "Apache 2.2.9 with SSTI flaw"
  },
  {
    "cve": NaN,
    "description": "CRLF injection discovered in the /headers endpoint, allowing partial HTTP response splitting.",
    "endpoint": "/headers",
    "id": 798,
    "sensor": "ToolA",
    "severity": "medium",
    "tag": "group_25",
    "title": "CRLF injection in /headers"
  },
  {
    "cve": "CVE-2027-1002",
    "description": "A flaw in /config triggers remote code execution with crafted payloads.",
    "endpoint": "/config",
    "id": 800,
    "sensor": "ToolC",
    "severity": "high",
    "tag": "group_26",
    "title": "RCE vulnerability in /config"
  }
]
```
