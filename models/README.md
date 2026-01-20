# fine-tune
uv pip install torch torchvision --index-url https://download.pytorch.org/whl/nightly/cu128

[LLaMA Factory](https://github.com/hiyouga/LlamaFactory/tree/main)

src/llamafactory/data/template.py 中使用 register_template 方法为自定义模型注册 chat_template。
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
# model set
Qwen2.5-Coder-7B-Instruct: 

generation_config.json
```
{
  "bos_token_id": 151643,
  "pad_token_id": 151643,
  "do_sample": true,
  "eos_token_id": [
    151645,
    151643
  ],
  "repetition_penalty": 1.1,
  "temperature": 0.7,
  "top_p": 0.8,
  "top_k": 20,
  "transformers_version": "4.44.0"
}
```

we set temperature to 0.1

# command
llamafactory-cli webui

FORCE_TORCHRUN=1 llamafactory-cli train ./models/llamafactory_yaml/qwen_lora_sft.yaml
