Semgrep_rule=[("system", "You are a code security expert specializing in generating Semgrep rules for vulnerability detection."),
         ("user", '''Generate a Semgrep rule in YAML format to detect the vulnerable pattern described below. 
Output ONLY the Semgrep rule in YAML format.

Guidelines:
- Focus on the key difference between vulnerable and fixed code.
- Use `pattern` or `pattern-either` with minimal, precise code snippets.
- Include `message`, `severity`, and `languages: [c]`.
- Avoid matching entire functions; match only the risky expression or condition.

Vulnerability Details:
- CWE: {cwe}
- CVE: {cve}
- Description: {cve_desc}
- Commit message: {commit_message}
- Commit URl: {commit_url}
Vulnerable code (before fix):
{vul_code}

Fixed code:
{fix_code}

Language: C
''')]