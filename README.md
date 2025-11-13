# files
main.py: detect vulnerabilities by LLMs
generate.py: generate,test and fix rules 
train.py: slice data by CWE.

# analysis tools
joern semgrep

# dataset
1. devign: dict_keys(['project', 'commit_id', 'target', 'func'])  total(27318) vul(12460)
2. primevul_train_paired: dict_keys(['idx', 'project', 'commit_id', 'project_url', 'commit_url', 'commit_message', 'target', 'func', 'func_hash', 'file_name', 'file_hash', 'cwe', 'cve', 'cve_desc', 'nvd_url']) total(7578) vul(3789)

# run:
local_huggingface_model: .venv/bin/python main.py --dataset devign --base_model Meta-Llama-3-8B

default model: .venv/bin/python main.py --dataset devign

generate rules: python generate.py --dataset primevul_train_paired

# metrics
Accuracy: 0.6364
Precision: 0.6667
Recall: 0.6667
FPR: 0.4000
F1: 0.6667

naive (qwen-max):       Total positive samples: 201, True Positives: 110, Run Errors: 63
fixed rules (gemma3): Total positive samples: 201, True Positives: 119, Run Errors: 50