detect_prompt = sample = [
    {
        "role": "system",
        "content": "You are a code security expert who analyzes the given code to detect the security vulnerability.",
    },
    {
        "role": "user",
        "content": "Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or improper input validation. Respond only with '[VULNERABLE]' or '[SAFE]'.\n\n```c\n{code}\n```",
    }
]
