# workflow
![overview](./assert/workflow.svg "overview")

generate:
generate_semgrep_rules | genertate_rule_batch -> (get_semgrep_rules_from_batch_response) -> validate_rules -> test_rule_positive (train dataset, get_rule_data) -> fix_rule -> test_rule_positive -> move_rules_bystatus -> test_rule_negative (train dataset) -> move_rules_bystatus -> test_each_rule_on_dataset -> filter_rules_by_precision -> test_rules_batch | test_cwe_rules (test dataset) -> print_metrics_from_csv
# files
1. main.py: detect vulnerabilities by LLMs
2. generate.py: generate,test and fix rules 
3. train.py: generate train or test data in Alpaca format. For different system in other paper, we use their own instruction.
4. /models: transform data format. fine-tune and evaluate model (be used by llamafactory)

# analysis tools
joern semgrep

# dataset
1. devign: dict_keys(['project', 'commit_id', 'target', 'func'])  total(27318) vul(12460)
2. primevul_train_paired: dict_keys(['idx', 'project', 'commit_id', 'project_url', 'commit_url', 'commit_message', 'target', 'func', 'func_hash', 'file_name', 'file_hash', 'cwe', 'cve', 'cve_desc', 'nvd_url']) total(7578) vul(3789).  
primevul_test_paired: total(870).  
primevul_test total(24788) vul(549).  
(In primevul dataset, there are repeated samples. For example, same idx samples(two 349259 samples, two 439495 samples) in primevul_test_paired.)

3. reveal: total(22734) vul(2240)

# semgrep output 
## error types:
 {'PartialParsing', 'InvalidRuleSchemaError', 'Other syntax error', 'Rule parse error', 'SemgrepError', 'Syntax error'}  
rule errors: 'InvalidRuleSchemaError', 'Rule parse error'

# to do (maybe)
1. fix rules that get false negative result in first positive test and false positive.
2. remove_fix_pattern in rule yaml file by python code.
3. when semgrep output errors unrelated to rule (errors about code), we should detect code vul by other method.  (only a few, maybe 151 functions in primevul)
