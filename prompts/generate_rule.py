Semgrep_rule_prompt=[{"role":"system", "content":"You are a code security expert specializing in generating Semgrep rules for vulnerability detection."},
         {"role":"user", "content": '''Generate a Semgrep rule in YAML format to detect the vulnerable pattern described below. 
Output ONLY the Semgrep rule in YAML format.

Guidelines:
- Focus on the key difference between vulnerable and fixed code.
- Do not create autofix rules, such as `fix` and `fix-regex`.
- Use `pattern` or `pattern-either` with precise code snippets.
- Include `message`, `severity`, and `languages: [c]`.
- Avoid matching entire functions; match only the risky expression or condition.
- Prefer `pattern-not` or `pattern-not-inside` to exclude safe wrappers or test code.

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

Language: C/C++
'''}]

fix_rule_prompt=[
    {"role": "system", "content": "You are a code security expert specializing in generating Semgrep rules for vulnerability detection."},
    {
        "role": "user",
        "content": '''Given the following Semgrep rule and its test output, identify  the cause of the failure and fix the rule. Return ONLY the corrected Semgrep rule in YAML format.
Semgrep Rule:
{semgrep_rule}
Test Output:
{test_output}'''}
]