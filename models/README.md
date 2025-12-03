llamafactory-cli webchat ./models/deepseek.yaml 

FORCE_TORCHRUN=1 llamafactory-cli train ./models/qwen_lora_sft.yaml
