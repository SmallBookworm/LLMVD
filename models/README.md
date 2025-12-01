llamafactory-cli webchat ./models/deepseek.yaml 

CUDA_VISIBLE_DEVICES=0,1 llamafactory-cli train ./models/deepseek2_lora_sft.yaml
