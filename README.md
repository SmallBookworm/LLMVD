# Thinking
useful rules. rain for what

# workflow
![overview](./assert/workflow.svg "overview")

generate:
generate_semgrep_rules | genertate_rule_batch -> (get_semgrep_rules_from_batch_response) -> validate_rules -> test_rule_positive (train dataset, get_rule_data) -> fix_rule -> test_rule_positive -> move_rules_bystatus -> test_rule_negative (train dataset) -> move_rules_bystatus -> test_rules_batch | test_cwe_rules (test dataset) -> print_metrics_from_csv
# files
main.py: detect vulnerabilities by LLMs
generate.py: generate,test and fix rules 
train.py: slice data by CWE.

# analysis tools
joern semgrep

# dataset
1. devign: dict_keys(['project', 'commit_id', 'target', 'func'])  total(27318) vul(12460)
2. primevul_train_paired: dict_keys(['idx', 'project', 'commit_id', 'project_url', 'commit_url', 'commit_message', 'target', 'func', 'func_hash', 'file_name', 'file_hash', 'cwe', 'cve', 'cve_desc', 'nvd_url']) total(7578) vul(3789).
primevul_test total(24788) vul(549)
In primevul dataset, there are repeated samples. For example, same idx samples(two 349259 samples, two 439495 samples) in primevul_test_paired.
3. reveal: total(22734) vul(2240)

# run:
local_huggingface_model: .venv/bin/python main.py --dataset devign --base_model Meta-Llama-3-8B

default model: .venv/bin/python main.py --dataset devign

generate rules: python generate.py --dataset primevul_train_paired

# semgrep output 
## error types:
 {'PartialParsing', 'InvalidRuleSchemaError', 'Other syntax error', 'Rule parse error', 'SemgrepError', 'Syntax error'}
rule errors: 'InvalidRuleSchemaError', 'Rule parse error'

# test result
1. static analysis layer
## primevul test paired:
### True positive rules:
semgrep test all:
Length: 870
Accuracy: 0.4989
Precision: 0.4994
Recall: 0.9310
FPR: 0.9333         
F1: 0.6501
semgrep test by cwe rules:
Length: 870
Accuracy: 0.5011
Precision: 0.5040
Recall: 0.1448
FPR: 0.1425
F1: 0.2250

### True negative rules:
True positive: 1625, -> True Negatives: 1027, Run Errors: 0
semgrep test all:
Total:870, true_positive:322,false_positive:329, Precision:0.4946236559139785
Length: 870
Accuracy: 0.4897
Precision: 0.4931
Recall: 0.7402
FPR: 0.7609
F1: 0.5919
semgrep test by cwe rules:
Total:870, true_positive:21,false_positive:18, Precision:0.5384615384615384
Length: 870
Accuracy: 0.5023
Precision: 0.5250
Recall: 0.0483
FPR: 0.0437
F1: 0.0884

### negative:1411 (rules_fixed_negative)
Length: 870, positive samples num:435, negative samples num:435, true_positive:340, false_positive:350
Accuracy: 0.4885
Precision: 0.4928
Recall: 0.7816
FPR: 0.8046
F1: 0.6044

## primevul train paired ? !
### native 3789
test total:841158, rule num:3789, true_positive:205,false_positive:157, Precision:0.5662983425414365
Length: 7578, positive samples num:3789, negative samples num:3789, true_positive:205, false_positive:157
Accuracy: 0.5063
Precision: 0.5663
Recall: 0.0541
FPR: 0.0414
F1: 0.0988

### True Negatives: 1027
semgrep test all:
Length: 7578, positive samples num:3789, negative samples num:3789, true_positive:2092, false_positive:1438
Accuracy: 0.5863
Precision: 0.5926
Recall: 0.5521
FPR: 0.3795
F1: 0.5717

### fixed rules:666 (positive) + positive:1625 =2291 (rules_fixed_selected)
test total:817992, rule num:2291, true_positive:3146,false_positive:3010, Precision:0.5110461338531515
Length: 7578, positive samples num:3789, negative samples num:3789, true_positive:3146, false_positive:3012
Accuracy: 0.5177
Precision: 0.5109
Recall: 0.8303
FPR: 0.7949
F1: 0.6326

### (fixed rules:666 + positive:1625) -> negative:1411 (rules_fixed_negative)
test total:734678, rule num:1411, true_positive:2765,false_positive:2225, Precision:0.5541082164328658
Length: 7578, positive samples num:3789, negative samples num:3789, true_positive:2765, false_positive:2225
Accuracy: 0.5713
Precision: 0.5541
Recall: 0.7297
FPR: 0.5872
F1: 0.6299

## primevul test
### (fixed rules:666 + positive:1625)
test total:2677104, rule num:2291, true_positive:456,false_positive:12867, Precision:0.03422652555730691
Length: 24788, positive samples num:549, negative samples num:24239, true_positive:456, false_positive:12867
Accuracy: 0.4772
Precision: 0.0342
Recall: 0.8306
FPR: 0.5308
F1: 0.0657
### (fixed rules:666 + positive:1625) -> negative:1411
test total:2404436, rule num:1411, true_positive:265,false_positive:5551, Precision:0.04556396148555708
Length: 24788, positive samples num:549, negative samples num:24239, true_positive:265, false_positive:5551
Accuracy: 0.7646
Precision: 0.0456
Recall: 0.4827
FPR: 0.2290
F1: 0.0833

## devign
### negative:1411
test total:2649846, rule num:1411, true_positive:4414,false_positive:5205, Precision:0.458883459819108
Length: 27318, positive samples num:12460, negative samples num:14858, true_positive:4414, false_positive:5205
Accuracy: 0.5149
Precision: 0.4589
Recall: 0.3543
FPR: 0.3503
F1: 0.3998

## reveal
### negative:1411
test total:2205198, rule num:1411, true_positive:751,false_positive:4887, Precision:0.13320326356864137
Length: 22734, positive samples num:2240, negative samples num:20494, true_positive:751, false_positive:4887
Accuracy: 0.7195
Precision: 0.1332
Recall: 0.3353
FPR: 0.2385
F1: 0.1907

# try generate rules data
try 201 rules:
naive (qwen-max):       Total positive samples: 201, True Positives: 110, Run Errors: 63
fixed rules (gemma3): Total positive samples: 201, True Positives: 119, Run Errors: 50

naive (qwen-plus): Total positive samples: 201, True Positives: 90, Run Errors: 44
fixed rules (gemma3): Total positive samples: 201, True Positives: 93, Run Errors: 32

2. model learning layer
## primevul_train_paired_data (32768 cutoff)
jsonl length: 7570
Total items: 7570
### Qwen2.5-Coder-7B-Instruct (origin)
Failed generations: 0
True Positives: 300, False Positives: 265, True Negatives: 3520, False Negatives: 3485
Accuracy: 0.5046, Precision: 0.5310, Recall: 0.0793, F1 Score: 0.1379, FPR: 0.0700
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired
Failed generations: 0
True Positives: 2149, False Positives: 1743, True Negatives: 2042, False Negatives: 1636
Accuracy: 0.5536, Precision: 0.5522, Recall: 0.5678, F1 Score: 0.5599, FPR: 0.4605
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data
Failed generations: 0
True Positives: 2034, False Positives: 1719, True Negatives: 2066, False Negatives: 1751
Accuracy: 0.5416, Precision: 0.5420, Recall: 0.5374, F1 Score: 0.5397, FPR: 0.4542

### negative_rules and Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data (model only for negative samples)
total from csv: 4990
Total items: 7578
Failed generations: 0
True Positives: 3396, False Positives: 3051, True Negatives: 738, False Negatives: 393
Accuracy: 0.5455, Precision: 0.5268, Recall: 0.8963, F1 Score: 0.6635, FPR: 0.8052

### negative_rules and Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data (model only for positive samples)
Total items: 7570,real total7570
True Positives: 1403, False Positives: 900, True Negatives: 2885, False Negatives: 2382
Accuracy: 0.5664, Precision: 0.6092, Recall: 0.3707, F1 Score: 0.4609, FPR: 0.2378
### negative_rules and Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired (model only for positive samples)
Total items: 7570,real total7570
1json length: 7570,2json length: 7578
Problem count (different prompts): 0
Total items: 7570,real total7570
True Positives: 1501, False Positives: 938, True Negatives: 2847, False Negatives: 2284
Accuracy: 0.5744, Precision: 0.6154, Recall: 0.3966, F1 Score: 0.4823, FPR: 0.2478

## primevul_test_paired_data (32768 cutoff)
jsonl length: 870
Total items: 870
### Qwen2.5-Coder-7B-Instruct (origin)
Failed generations: 0
True Positives: 19, False Positives: 21, True Negatives: 414, False Negatives: 416
Accuracy: 0.4977, Precision: 0.4750, Recall: 0.0437, F1 Score: 0.0800, FPR: 0.0483
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired
Failed generations: 0
True Positives: 243, False Positives: 202, True Negatives: 233, False Negatives: 192
Accuracy: 0.5471, Precision: 0.5461, Recall: 0.5586, F1 Score: 0.5523, FPR: 0.4644
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data
Failed generations: 0
True Positives: 231, False Positives: 199, True Negatives: 236, False Negatives: 204
Accuracy: 0.5368, Precision: 0.5372, Recall: 0.5310, F1 Score: 0.5341, FPR: 0.4575
### negative_rules and Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data (model only for positive samples)
True Positives: 164, False Positives: 153, True Negatives: 282, False Negatives: 271
Accuracy: 0.5126, Precision: 0.5174, Recall: 0.3770, F1 Score: 0.4362, FPR: 0.3517
### negative_rules and Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired (model only for positive samples)
True Positives: 187, False Positives: 156, True Negatives: 279, False Negatives: 248
Accuracy: 0.5356, Precision: 0.5452, Recall: 0.4299, F1 Score: 0.4807, FPR: 0.3586

## primevul_fixed_negative_train_data_by_cvs (after rules, 2588)
jsonl length: 2588
Total items: 2588
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired
Failed generations: 0
True Positives: 642, False Positives: 841, True Negatives: 723, False Negatives: 382
Accuracy: 0.5274, Precision: 0.4329, Recall: 0.6270, F1 Score: 0.5122, FPR: 0.5377
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data
Failed generations: 0
True Positives: 631, False Positives: 826, True Negatives: 738, False Negatives: 393
Accuracy: 0.5290, Precision: 0.4331, Recall: 0.6162, F1 Score: 0.5087, FPR: 0.5281

## devign
jsonl length: 27309
Total items: 27309
### Qwen2.5-Coder-7B-Instruct (origin)
Failed generations: 0
True Positives: 924, False Positives: 654, True Negatives: 14201, False Negatives: 11530
Accuracy: 0.5538, Precision: 0.5856, Recall: 0.0742, F1 Score: 0.1317, FPR: 0.0440
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_train_paired
Failed generations: 0
True Positives: 8679, False Positives: 10428, True Negatives: 4427, False Negatives: 3775
Accuracy: 0.4799, Precision: 0.4542, Recall: 0.6969, F1 Score: 0.5500, FPR: 0.7020
### Qwen2.5-Coder-7B-Instruct/lora/sft_primevul_fixed_negative_4096_data
Failed generations: 0
True Positives: 8780, False Positives: 10774, True Negatives: 4081, False Negatives: 3674
Accuracy: 0.4709, Precision: 0.4490, Recall: 0.7050, F1 Score: 0.5486, FPR: 0.7253

## reveal

# to do
1. fix rules that get false negative result in first positive test and false positive.
2. remove_fix_pattern in rule yaml file by python code.
3. when semgrep output errors unrelated to rule (errors about code), we should detect code vul by other method.  (only a few, maybe 151 functions in primevul)

uv pip install --pre torch torchvision torchaudio --index-url https://download.pytorch.org/whl/nightly/cu128