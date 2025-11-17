from data_process.utils.loader import load_devign, load_primevul
from getresdata_csv import print_metrics_from_csv
from data_process.utils.process import list_by_idx
from data_process.utils.misc import langchain_to_openai_messages

import tools.semgrep as semgrep

import pandas as pd

from typing import Literal

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_qwq import ChatQwen
from langchain_ollama import ChatOllama


from prompts.generate_rule import Semgrep_rule_prompt, fix_rule_prompt

import argparse
import getpass
import os
import re
import json
import jsonlines
import yaml

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/LLM-Research/"

os.environ["DASHSCOPE_API_BASE"] = "https://dashscope.aliyuncs.com/compatible-mode/v1"

if not os.environ.get("DASHSCOPE_API_KEY"):
    os.environ["DASHSCOPE_API_KEY"] = getpass.getpass("Enter API key for dashscope:")


def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="dataset name")
    parser.add_argument(
        "--model_name", default="gemma3:27b", type=str, help="The model to be used."
    )
    # parser.add_argument("--model_type", default="gemma3", type=str,
    #                     help="The model architecture to be used.")
    parser.add_argument("--output", default="./output", help="output path")
    args = parser.parse_args()
    return args


def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Directory '{directory}' created")
    else:
        print(f"Directory '{directory}' already exists")


# generate rule generate batch jsonl
def genertate_rule_batch(
    data, batch_path="./semgrep_generate.jsonl", model="qwen3-max"
):
    prompt_template_rules = ChatPromptTemplate.from_messages(Semgrep_rule_prompt)
    total = 0
    jsonl_data = []
    for i in range(0, len(data), 2):

        message_generate = prompt_template_rules.invoke(
            {
                "cwe": data[i].get("cwe", "N/A"),
                "cve": data[i].get("cve", "N/A"),
                "cve_desc": data[i].get("cve_desc", "N/A"),
                "commit_message": data[i].get("commit_message", "N/A"),
                "commit_url": data[i].get("commit_url", "N/A"),
                "vul_code": data[i]["func"],
                "fix_code": data[i + 1]["func"],
            }
        )

        json_data = {
            "custom_id": f"{data[i]['idx']}",
            "method": "POST",
            "url": "/v1/chat/completions",
            "body": {
                "model": model,
                "messages": langchain_to_openai_messages(
                    message_generate.to_messages()
                ),
            },
        }
        jsonl_data.append(json_data)

        total += 1
    print(f"Total semgrep generation samples: {total}")
    with jsonlines.open(batch_path, mode="w") as writer:
        for oneline in jsonl_data:
            writer.write(oneline)


# get batch semgrep rules
def get_semgrep_rules_from_batch_response(
    batch_response_path, raw_data, output_rules_path="./rules/"
):
    idx_list = list_by_idx(raw_data)
    with jsonlines.open(batch_response_path, mode="r") as reader:
        for obj in reader:
            custom_id = int(obj.get("custom_id"))
            body = obj.get("response").get("body")
            choices = body.get("choices", [])
            if not choices:
                print(f"No choices found for id {custom_id}")
                continue
            rule_text = choices[0].get("message", {}).get("content", "")
            # 使用正则表达式去掉开头的 ```yaml 和结尾的 ```
            cleaned_yaml = re.sub(r"^```yaml\s*\n?", "", rule_text, flags=re.MULTILINE)
            cleaned_yaml = re.sub(r"\n?```$", "", cleaned_yaml, flags=re.MULTILINE)

            directory = f"{output_rules_path}/{idx_list[custom_id]['cwe'][0]}/"
            create_directory(directory)
            rule_path = f"{directory}/semgrep_rule_{custom_id}.yaml"
            if os.path.exists(rule_path):
                print(f"Rule already exists for id {custom_id}, skipping.")
                continue
            with open(rule_path, "w") as f:
                f.write(cleaned_yaml)
            print(f"Semgrep rule saved to {rule_path}")


def generate_semgrep_rules(model, dataset, start=0, end=None):
    prompt_template_rules = ChatPromptTemplate.from_messages(Semgrep_rule_prompt)

    if dataset == "primevul_train_paired":
        data = load_primevul()
    else:
        print(f"Dataset {dataset} not supported yet.")
        return 0

    total = 0
    for i in range(0, len(data), 2):
        if i < start:
            continue
        if end and i >= end:
            break

        message_generate = prompt_template_rules.invoke(
            {
                "cwe": data[i].get("cwe", "N/A"),
                "cve": data[i].get("cve", "N/A"),
                "cve_desc": data[i].get("cve_desc", "N/A"),
                "commit_message": data[i].get("commit_message", "N/A"),
                "commit_url": data[i].get("commit_url", "N/A"),
                "vul_code": data[i]["func"],
                "fix_code": data[i + 1]["func"],
            }
        )

        create_directory("./temp/test_generate")
        messages_path = f"./temp/test_generate/semgrep_generate_{data[i]['idx']}.text"
        with open(messages_path, "w") as f:
            f.write(message_generate.to_messages()[-1].content)
        print(f"Semgrep generate messages saved to {messages_path}")

        response = model.invoke(message_generate)
        if response:
            # reasoning = response.additional_kwargs.get("reasoning_content", "")
            # print(f"Limited reasoning: {reasoning}")

            rule_text = response.content
            # 使用正则表达式去掉开头的 ```yaml 和结尾的 ```
            cleaned_yaml = re.sub(r"^```yaml\s*\n?", "", rule_text, flags=re.MULTILINE)
            cleaned_yaml = re.sub(r"\n?```$", "", cleaned_yaml, flags=re.MULTILINE)
            directory = f"./rules/{data[i]['cwe'][0]}"
            create_directory(directory)
            rule_path = f"{directory}/semgrep_rule_{data[i]['idx']}.yaml"
            with open(rule_path, "w") as f:
                f.write(cleaned_yaml)
            print(f"Semgrep rule saved to {rule_path}")
            total += 1
    return total


def save_code(code, filepath="./temp/temp_code.c"):
    with open(filepath, "w") as f:
        f.write(code)


def rule_num(path="./rules/"):
    count = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".yaml"):
                count += 1
    return count


def test_rule_positive(rule_root="./rules/"):
    semgrep_runner = semgrep.SemgrepRunner()
    create_directory("./temp/semgrep/")

    data = load_primevul()
    total = 0
    cwe_status = {}
    # positive code (vul)
    tp = 0
    p_error = 0
    for i in range(0, len(data), 2):
        sample = data[i]

        filepath = f"./temp/temp_code.c"
        save_code(sample["func"], filepath)



        rule_path = rule_root + f'{sample["cwe"][0]}/semgrep_rule_{sample["idx"]}.yaml'
        print(f"Testing rule: {rule_path}")
        if not os.path.exists(rule_path):
            print(f'Rule not found for {sample["cwe"][0]} idx {sample["idx"]}')
            break
        
        if sample["target"] == 1:
            total += 1
        else:
            print("error")

        result = semgrep_runner.run_rule(
            rule_path=rule_path,
            target_path=filepath,
            output_path=f'./temp/semgrep/semgrep_output_{sample["idx"]}.json',
        )

        cwe_name = sample["cwe"][0]
        if cwe_name not in cwe_status:
            cwe_status[cwe_name] = {"total": 0, "true_positive": [], "p_error": []}
        cwe_status[cwe_name]["total"] += 1

        if "result" in result:
            output = json.loads(result["result"].stdout)
            if output.get("results"):
                tp += 1
                cwe_status[cwe_name]["true_positive"].append(sample["idx"])
        else:
            # semgrep output stderr
            p_error += 1
            cwe_status[cwe_name]["p_error"].append(sample["idx"])

    print(
        f"Total positive samples: {total}, True Positives: {tp}, Run Errors: {p_error}"
    )
    return cwe_status


def test_rule_negative():
    semgrep_runner = semgrep.SemgrepRunner()
    create_directory("./temp/semgrep/negative/")

    data = load_primevul()
    total = 0
    # negative code (non-vul)
    tn = 0
    n_error = 0
    for i in range(1, len(data), 2):
        sample = data[i]

        filepath = f"./temp/temp_code.c"
        save_code(sample["func"], filepath)

        if sample["target"] == 0:
            total += 1
        else:
            print("error")
        cwe = data[i - 1]["cwe"][0]
        idx = data[i - 1]["idx"]
        rule_path = f"./rules/{cwe}/semgrep_rule_{idx}.yaml"
        if not os.path.exists(rule_path):
            print(f"Rule not found for CWE {cwe} idx {idx}")
            break

        result = semgrep_runner.run_rule(
            rule_path=rule_path,
            target_path=filepath,
            output_path=f'./temp/semgrep/negative/semgrep_output_{sample["idx"]}_{idx}.json',
        )
        if "result" in result:
            output = json.loads(result["result"].stdout)
            if not output.get("results"):
                tn += 1
        else:
            # semgrep output stderr
            n_error += 1

    print(
        f"Total negative samples: {total}, True Negatives: {tn}, Run Errors: {n_error}"
    )


def fix_rule(model, rules_path="./rules/"):
    create_directory(f"{rules_path}fixed_rules/")
    prompt_template_fix = ChatPromptTemplate.from_messages(fix_rule_prompt)

    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith(".yaml"):
                idx = file.split("_")[-1].split(".")[0]
                rule_path = os.path.join(root, file)
                fixed_rule_path = (
                    rules_path + "fixed_rules/" + os.path.relpath(rule_path, rules_path)
                )

                with open(rule_path, "r") as f:
                    rule_content = f.read()
                # save test output for reference
                create_directory(os.path.dirname(fixed_rule_path))
                with open(fixed_rule_path, "w") as f:
                    f.write(rule_content)

                # only fix fail rules, which are "rule error" without results when semgrep test positive cases.
                with open(f"./temp/semgrep/semgrep_output_{idx}.json", "r") as f:
                    test_output = f.read()
                if test_output.strip() == "":
                    print(
                        "\033[31m"
                        + f"Empty test output, skipping rule: {rule_path}"
                        + "\033[0m"
                    )
                    continue
                test_output_json = json.loads(test_output)
                if test_output_json.get("results") or not test_output_json.get(
                    "errors"
                ):
                    print(f"Rule works fine, no need to fix: {rule_path}")
                    continue

                # read semgrep rule yaml
                try:
                    rule_yaml = yaml.safe_load(rule_content)
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML for rule {rule_path}: {e}")
                # remove fix patterns in semgrep rules
                if rule_yaml:
                    for rule in rule_yaml.get("rules", []):
                        res = rule.pop(
                            "fix", None
                        )  # 使用 pop 并提供默认值 None，避免 KeyError
                        if res:
                            print(f"Removed fix: {res}")
                            print(f"file: {rule_path}")

                # feedback model. Is it better to remove spans in errors?
                message_fix = prompt_template_fix.invoke(
                    {
                        "semgrep_rule": rule_content,
                        "test_output": {"errors": test_output_json.get("errors", [])},
                    }
                )

                response = model.invoke(message_fix)
                if response:
                    rule_text = response.content
                    # 使用正则表达式去掉开头的 ```yaml 和结尾的 ```
                    cleaned_yaml = re.sub(
                        r"^```yaml\s*\n?", "", rule_text, flags=re.MULTILINE
                    )
                    cleaned_yaml = re.sub(
                        r"\n?```$", "", cleaned_yaml, flags=re.MULTILINE
                    )

                    with open(fixed_rule_path, "w") as f:
                        f.write(cleaned_yaml)
                    print(f"Fixed Semgrep rule saved to {fixed_rule_path}")


def vaildate_rules(data, rules_path="./rules/"):

    total = rule_num(rules_path)

    generate_num = 0
    for i in range(0, len(data), 2):
        if generate_num >= total:
            print("All rules validated.")
            print(f"i: {i}")
            break
        sample = data[i]
        cwe = sample["cwe"][0]
        idx = sample["idx"]
        rule_path = f"{rules_path}{cwe}/semgrep_rule_{idx}.yaml"
        if not os.path.exists(rule_path):
            print(f"Rule not found for CWE {cwe} idx {idx}")
            continue
        with open(rule_path, "r") as f:
            rule_content = f.read()
        if len(rule_content.strip()) > 6:
            generate_num += 1
        else:
            print(f"Empty rule content for CWE {cwe} idx {idx}")
    print(f"Total rules: {total}, Generated rules: {generate_num}")

def save_cwe_status():
    cwe_status = test_rule_positive("./rules/")
    with open('./cwe_status.json', 'w') as f:
        json.dump(cwe_status, f, indent=4)
    total=0
    tp=0
    p_error=0
    for cwe in cwe_status:
        total+=cwe_status[cwe]['total']
        tp+=len(cwe_status[cwe]['true_positive'])
        p_error+=len(cwe_status[cwe]['p_error'])
    print(f'Total positive samples: {total}, True Positives: {tp}, Run Errors: {p_error}')
    for cwe in cwe_status:
        print(f"CWE-{cwe}: Total: {cwe_status[cwe]['total']}, True Positives: {len(cwe_status[cwe]['true_positive'])}, Run Errors: {len(cwe_status[cwe]['p_error'])}")

if __name__ == "__main__":
    # args = parse_args()
    # model=ChatQwen(model="qwen3-max", temperature=0.1)
    # print(generate_semgrep_rules(model, args.dataset))
    print(f'Total semgrep rules: {rule_num()}')

    # test_rule_negative()
    # save_cwe_status()

    # semgrep.SemgrepRunner.read_semgrep_output('./temp/semgrep/negative/')

    # fix_rule(ChatOllama(model="gemma3:27b"), './rules_qwen-plus/')

    # genertate_rule_batch(load_primevul())
    get_semgrep_rules_from_batch_response(
        batch_response_path="./temp/semgrep_1583_result.jsonl",
        raw_data=load_primevul(),
        output_rules_path="./rules/",
    )
