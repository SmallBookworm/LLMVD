llamafactory-cli webchat ./models/deepseek.yaml 

FORCE_TORCHRUN=1 llamafactory-cli train ./models/qwen_lora_sft.yaml

1. src/llamafactory/data/template.py 中使用 register_template 方法为自定义模型注册 chat_template。
```python
register_template(
    name="qwen-pwz",
    format_user=StringFormatter(slots=["<|im_start|>user\n{{content}}<|im_end|>\n<|im_start|>assistant\n"]),
    format_assistant=StringFormatter(slots=["{{content}}<|im_end|>\n"]),
    format_system=StringFormatter(slots=["<|im_start|>system\n{{content}}<|im_end|>\n"]),
    format_function=FunctionFormatter(slots=["{{content}}<|im_end|>\n"], tool_format="qwen"),
    format_observation=StringFormatter(
        slots=["<|im_start|>user\n<tool_response>\n{{content}}\n</tool_response><|im_end|>\n<|im_start|>assistant\n"]
    ),
    format_tools=ToolFormatter(tool_format="qwen"),
    default_system="You are a code security expert who analyzes the given code to detect the security vulnerability.",
    stop_words=["<|im_end|>"],
    replace_eos=True,
)
```