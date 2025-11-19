# files
main.py: detect vulnerabilities by LLMs
generate.py: generate,test and fix rules 
train.py: slice data by CWE.

# analysis tools
joern semgrep

# dataset
1. devign: dict_keys(['project', 'commit_id', 'target', 'func'])  total(27318) vul(12460)
2. primevul_train_paired: dict_keys(['idx', 'project', 'commit_id', 'project_url', 'commit_url', 'commit_message', 'target', 'func', 'func_hash', 'file_name', 'file_hash', 'cwe', 'cve', 'cve_desc', 'nvd_url']) total(7578) vul(3789).
In primevul dataset, there are repeated samples. For example, same idx samples(two 349259 samples, two 439495 samples) in primevul_test_paired.

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

# test data
try 201 rules:
naive (qwen-max):       Total positive samples: 201, True Positives: 110, Run Errors: 63
fixed rules (gemma3): Total positive samples: 201, True Positives: 119, Run Errors: 50

native (qwen-plus): Total positive samples: 201, True Positives: 90, Run Errors: 44
fixed rules (gemma3): Total positive samples: 201, True Positives: 93, Run Errors: 32