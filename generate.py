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
from ruamel.yaml import YAML
from pathlib import Path
import shutil


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


def create_directory(directory, print_info=True):
    if not os.path.exists(directory):
        os.makedirs(directory)
        if print_info:
            print(f"Directory '{directory}' created")
    else:
        if print_info:
            print(f"Directory '{directory}' already exists")


def new_directory(directory):
    if os.path.exists(directory):
        print(f"Directory '{directory}' exists, remove it first.")
        shutil.rmtree(directory)
    os.makedirs(directory)
    print(f"Directory '{directory}' created")


# generate rule generate batch jsonl
def genertate_rule_batch(
    data, batch_path="./semgrep_generate.jsonl", model="qwen3-max"
):
    prompt_template_rules = ChatPromptTemplate.from_messages(Semgrep_rule_prompt)
    total = 0
    jsonl_data = []
    for i in range(0, len(data), 2):
        if  data[i].get("cwe", "N/A") !=  data[i + 1]["cwe"]:
            print(f"Warning: CWE mismatch at idx {data[i]['idx']} and {data[i+1]['idx']}")
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


# test in primevul dataset (train paired)
# strict mode: if rule not found, stop testing
def test_rule_positive(rule_root="./rules/", output_path="./temp/semgrep/positive/", strict =True):
    semgrep_runner = semgrep.SemgrepRunner()
    new_directory(output_path)

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
            if strict:
                break
            else:
                continue

        if sample["target"] == 1:
            total += 1
        else:
            print("error")

        result = semgrep_runner.run_rule(
            rule_path=rule_path,
            target_path=filepath,
            output_path= output_path + f'/semgrep_output_{sample["idx"]}.json',
        )

        cwe_name = sample["cwe"][0]
        if cwe_name not in cwe_status:
            cwe_status[cwe_name] = {
                "total": 0,
                "true_positive": [],
                "p_error": [],
                "failed_info": [],
            }
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
            cwe_status[cwe_name]["failed_info"].append(result)

    print(
        f"Total positive samples: {total}, True Positives: {tp}, Run Errors: {p_error}"
    )
    return cwe_status


# negative test output with sample idx and rule idx (from positive sample)
def test_rule_negative(rule_root="./rules/"):
    semgrep_runner = semgrep.SemgrepRunner()
    new_directory("./temp/semgrep/negative/")

    data = load_primevul()
    total = 0
    cwe_status = {}
    # negative code (non-vul)
    tn = 0
    n_error = 0
    for i in range(1, len(data), 2):
        sample = data[i]

        filepath = f"./temp/temp_code.c"
        save_code(sample["func"], filepath)

        cwe = data[i - 1]["cwe"][0]
        idx = data[i - 1]["idx"]
        rule_path = rule_root + f"{cwe}/semgrep_rule_{idx}.yaml"
        if not os.path.exists(rule_path):
            print(f"Rule not found for CWE {cwe} idx {idx}")
            continue

        if sample["target"] == 0:
            total += 1
        else:
            print("error")

        result = semgrep_runner.run_rule(
            rule_path=rule_path,
            target_path=filepath,
            output_path=f'./temp/semgrep/negative/semgrep_output_{sample["idx"]}_{idx}.json',
        )

        if cwe not in cwe_status:
            cwe_status[cwe] = {
                "total": 0,
                "true_negative": [],
                "n_error": [],
                "failed_info": [],
            }
        cwe_status[cwe]["total"] += 1

        if "result" in result:
            output = json.loads(result["result"].stdout)
            if not output.get("results"):
                tn += 1
                cwe_status[cwe]["true_negative"].append(idx)
        else:
            # semgrep output stderr
            n_error += 1
            cwe_status[cwe]["n_error"].append(idx)
            cwe_status[cwe]["failed_info"].append(result)

    print(
        f"Total negative samples: {total}, True Negatives: {tn}, Run Errors: {n_error}"
    )
    return cwe_status


def count_c_files(directory):
    path = Path(directory)
    return len(list(path.glob("*.c")))


def count_yaml_files(directory):
    path = Path(directory)
    yaml_count = len(list(path.glob("*.yaml")))
    return yaml_count


# test dataset with all rules, which divide by cwe
def test_rules_batch(rule_path, dataset, cvs_name="semgrep_primevul.cvs"):
    semgrep_runner = semgrep.SemgrepRunner()
    new_directory("./temp/semgrep/test_rules_batch/")

    csvfile = f"./result/{cvs_name}"
    filepath = "./temp/temp_code/"
    new_directory(filepath)

    total = 0
    idx_dataset = {}
    for sample in dataset:
        total += 1
        idx = sample["idx"]
        code_path = f"{filepath}code_{total}_{idx}.c"
        if os.path.exists(code_path):
            print(f"code already exists: {code_path}")
        save_code(sample["func"], code_path)
        if idx_dataset.get(f"{idx}"):
            print(f"same sample:{idx}")
            print(str(idx_dataset.get(f"{idx}")) == str(sample))
        else:
            idx_dataset[f"{idx}"] = sample

    cwe_rules = {}
    top_level_dirs = next(os.walk(rule_path))[1]
    top_dirs_num = len(top_level_dirs)
    test_num = 0
    for cwe_dir in top_level_dirs:
        test_num += 1
        print(f"Testing CWE: {cwe_dir} ({test_num}/{top_dirs_num})")
        cwe_rules[cwe_dir] = {
            "rules_num": count_yaml_files(
                os.path.join(rule_path, cwe_dir),
            ),
            "total": 0,
            "false_positive": [],
            "true_positive": [],
            "positive_path": set(),
            "result": {},
            "error": set(),
        }
        result = semgrep_runner.run_rule(
            rule_path=f"{rule_path}{cwe_dir}/",
            target_path=filepath,
            output_path=f"./temp/semgrep/test_rules_batch/semgrep_output_{cwe_dir}.json",
        )
        cwe_rules[cwe_dir]["total"] = count_c_files(filepath)
        if "result" in result:
            output = json.loads(result["result"].stdout)
            for res in output.get("results", []):
                code_path = res.get("path", "")
                cwe_rules[cwe_dir]["positive_path"].add(code_path)
                try:
                    filename = os.path.basename(code_path)
                    # code_CWE123_456.c → split by '_'
                    parts = filename.split("_")
                    if len(parts) < 3:
                        print(f"Warning: unexpected filename {filename}")
                        continue
                    idx = parts[-1].split(".")[0]
                except Exception as e:
                    print(f"Error parsing idx from path {code_path}: {e}")
                    continue
                cwe_rules[cwe_dir]["result"][idx] = res
                sample = idx_dataset.get(idx)
                if sample.get("target") == 1:
                    cwe_rules[cwe_dir]["true_positive"].append(int(idx))
                else:
                    cwe_rules[cwe_dir]["false_positive"].append(int(idx))
        else:
            print(f"Semgrep run error for {cwe_dir}")

    fp = set()
    tp = set()
    path = set()
    for cwe in cwe_rules:
        tp.update(cwe_rules[cwe]["true_positive"])
        fp.update(cwe_rules[cwe]["false_positive"])
        path.update(cwe_rules[cwe]["positive_path"])
    print(
        f"Total:{total}, true_positive:{len(tp)},false_positive:{len(fp)}, Precision:{len(tp)/(len(tp)+len(fp) if (len(tp)+len(fp)) > 0 else 1)}"
    )

    # There are repeated samples.
    for i, sample in enumerate(dataset):
        idx = sample["idx"]
        if sample.get("cwe") and type(sample["cwe"]) == list:
            cwe = sample["cwe"][0]
        else:
            cwe = "N/A"
        prediction = 1 if (idx in tp or idx in fp) else 0
        # attention: when a rule detect a vul for a sample,  sample's cwe can be different from rule cwe
        res = {}
        if cwe_rules.get(cwe):
            res = cwe_rules[cwe]["result"].get(str(idx), {})
        temp_df = pd.DataFrame(
            {
                "Idx": idx,
                "CWE": cwe,
                "Code": [sample["func"]],
                "Label": [sample["target"]],
                "Prediction": [prediction],
                "Response": [str(res)],
            }
        )
        temp_df.to_csv(csvfile, index=False, mode="w" if i == 0 else "a", header=i == 0)
    print_metrics_from_csv(csvfile)

    return cwe_rules


# only use corresponding cwe rules to test cwe samples
# skip cwe rule without samples
def test_cwe_rules(rule_path, dataset, cvs_name="semgrep_cwe_primevul.cvs"):
    semgrep_runner = semgrep.SemgrepRunner()
    new_directory("./temp/semgrep/test_cwe_rules/")

    csvfile = f"./result/{cvs_name}"

    # save code
    cwe_to_samples = {}
    filepath_base = "./temp/temp_cwe_code/"
    new_directory(filepath_base)

    for sample in dataset:
        cwe = sample["cwe"][0]
        if cwe not in cwe_to_samples:
            cwe_to_samples[cwe] = []
        cwe_to_samples[cwe].append(sample)

    cwe_filepaths = {}  # 记录每个 CWE 对应的代码目录
    for cwe, samples in cwe_to_samples.items():
        cwe_dir = os.path.join(filepath_base, cwe)
        create_directory(cwe_dir)
        cwe_filepaths[cwe] = cwe_dir
        for sample in samples:
            idx = sample["idx"]
            code_path = os.path.join(cwe_dir, f"code_{cwe}_{idx}.c")
            save_code(sample["func"], code_path)

    idx_dataset = {str(sample["idx"]): sample for sample in dataset}

    cwe_rules = {}
    top_level_dirs = next(os.walk(rule_path))[1]

    for cwe_dir in top_level_dirs:
        print(cwe_dir)
        # 只处理 dataset 中实际出现的 CWE（可选）
        # if cwe_dir not in cwe_to_samples:
        #     continue

        cwe_rules[cwe_dir] = {
            "rules_num": count_yaml_files(
                os.path.join(rule_path, cwe_dir),
            ),
            "total": 0,
            "false_positive": [],
            "true_positive": [],
            "positive_path": set(),
            "result": {},
            "error": set(),
        }

        # 获取该 CWE 对应的样本代码目录
        target_path = cwe_filepaths.get(cwe_dir)
        if target_path is None or not os.path.exists(target_path):
            print(f"No samples for {cwe_dir}, skipping.")
            continue

        result = semgrep_runner.run_rule(
            rule_path=os.path.join(rule_path, cwe_dir),
            target_path=target_path,  # ← 只扫描这个 CWE 的样本
            output_path=f"./temp/semgrep/test_cwe_rules/semgrep_output_{cwe_dir}.json",
        )

        cwe_rules[cwe_dir]["total"] = count_c_files(target_path)
        if "result" in result:
            output = json.loads(result["result"].stdout)
            for res in output.get("results", []):
                code_path = res.get("path", "")
                cwe_rules[cwe_dir]["positive_path"].add(code_path)
                # 安全解析 idx：从文件名提取
                filename = os.path.basename(code_path)
                # 假设格式: code_CWE123_456.c → split by '_'
                parts = filename.split("_")
                if len(parts) < 3:
                    print(f"Warning: unexpected filename {filename}")
                    continue
                idx = parts[-1].split(".")[0]  # '456.c' -> '456'
                cwe_rules[cwe_dir]["result"][idx] = res
                sample = idx_dataset.get(idx)
                if sample is None:
                    print(f"Warning: idx {idx} not found in dataset")
                    continue
                if sample["target"] == 1:
                    cwe_rules[cwe_dir]["true_positive"].append(idx)  # ← 保持 str 类型！
                else:
                    cwe_rules[cwe_dir]["false_positive"].append(idx)
        else:
            print(f"Semgrep run error for {cwe_dir}")

    fp = set()
    tp = set()
    path = set()
    for cwe in cwe_rules:
        tp.update(cwe_rules[cwe]["true_positive"])  # 已是 str
        fp.update(cwe_rules[cwe]["false_positive"])  # 已是 str
        path.update(cwe_rules[cwe]["positive_path"])
    print(
        f"Total:{len(dataset)}, true_positive:{len(tp)},false_positive:{len(fp)}, Precision:{len(tp)/(len(tp)+len(fp))}"
    )

    # There are repeated samples.
    for i, sample in enumerate(dataset):
        idx = str(sample["idx"])
        cwe = sample["cwe"][0]
        prediction = 1 if (idx in tp or idx in fp) else 0
        # attention: when a rule detect a vul for a sample,  sample's cwe can be different from rule cwe
        res = {}
        if cwe_rules.get(cwe):
            res = cwe_rules[cwe]["result"].get(idx, {})
        temp_df = pd.DataFrame(
            {
                "Idx": [int(idx)],
                "CWE": [cwe],
                "Code": [sample["func"]],
                "Label": [sample["target"]],
                "Prediction": [prediction],
                "Response": [str(res)],
            }
        )
        temp_df.to_csv(csvfile, index=False, mode="w" if i == 0 else "a", header=i == 0)
    print_metrics_from_csv(csvfile)

    return cwe_rules


# test dataset with every rules
def test_each_rule_on_dataset(
    rule_path, dataset, csv_name="semgrep_each_rule_result.csv"
):
    """
    Test each Semgrep rule individually on the provided dataset.
    Args:
        rule_path (str): Path to the directory containing Semgrep rule files.
        dataset (list): List of samples, each sample is a dict with keys like 'idx', 'cwe', 'func', 'target'.
        csv_name (str): Name of the output CSV file to store results.
    """
    semgrep_runner = semgrep.SemgrepRunner()
    temp_code_dir = "./temp/temp_code_each_rule/"
    output_dir = "./temp/semgrep/test_each_rule/"
    result_csv = f"./result/{csv_name}"
    new_directory(temp_code_dir)
    new_directory(output_dir)

    idx_to_sample = {}
    for sample in dataset:
        idx = str(sample["idx"])
        cwe = sample["cwe"][0] if sample["cwe"] else "unknown"
        code_path = os.path.join(temp_code_dir, f"code_{cwe}_{idx}.c")
        save_code(sample["func"], code_path)
        idx_to_sample[idx] = sample

    rule_files = []
    for root, _, files in os.walk(rule_path):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                rule_files.append(os.path.join(root, file))

    print(f"Found {len(rule_files)} rule files to test.")

    all_rule_results = {}

    for rule_file in rule_files:
        rule_idx = rule_file.split("_")[-1].split(".")[0]
        rule_key = os.path.abspath(rule_file)
        print(f"Testing rule: {rule_file}")

        output_json_path = os.path.join(output_dir, f"semgrep_output_{rule_idx}.json")
        result = semgrep_runner.run_rule(
            rule_path=rule_file,
            target_path=temp_code_dir,
            output_path=output_json_path,
        )

        rule_result = {
            "rule_file": rule_file,
            "total_samples": len(dataset),
            "detected_paths": set(),
            "true_positive": [],
            "false_positive": [],
            "error": False,
            "raw_output": None,
        }

        if "result" not in result:
            print(f"⚠️  Semgrep error for rule: {rule_file}")
            rule_result["error"] = True
            all_rule_results[rule_key] = rule_result
            continue

        try:
            output = json.loads(result["result"].stdout)
            rule_result["raw_output"] = output
            for res in output.get("results", []):
                path = res.get("path", "")
                rule_result["detected_paths"].add(path)

                filename = os.path.basename(path)
                try:
                    idx = filename.split("_")[-1].split(".")[0]
                except Exception:
                    print(f"⚠️  Cannot parse idx from path: {path}")
                    continue

                sample = idx_to_sample.get(idx)
                if not sample:
                    print(f"⚠️  Sample idx={idx} not found in dataset.")
                    continue

                # 判断 TP / FP
                if sample["target"] == 1:
                    rule_result["true_positive"].append(int(idx))
                else:
                    rule_result["false_positive"].append(int(idx))

        except Exception as e:
            print(f"❌ Error parsing Semgrep output for {rule_file}: {e}")
            rule_result["error"] = True

        all_rule_results[rule_key] = rule_result

        # Optional: Write sample-level predictions for this rule (aggregatable)

    summary_rows = []
    for rule_key, res in all_rule_results.items():
        tp = len(res["true_positive"])
        fp = len(res["false_positive"])
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        summary_rows.append(
            {
                "Rule_File": res["rule_file"],
                "Total_Samples": res["total_samples"],
                "True_Positive": tp,
                "False_Positive": fp,
                "Precision": precision,
                "Error": res["error"],
                "Detected_Count": len(res["detected_paths"]),
            }
        )

    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(result_csv, index=False)
    print(f"✅ Summary saved to {result_csv}")

    return all_rule_results


def filter_rules_by_fpr(
    rule_path, dataset, output_filtered_dir="./rules_fpr/", fpr_threshold=0.01
):
    """
    Filter Semgrep rules based on False Positive Rate (FPR) on the given dataset. Run every rule singely.
    Args:
        rule_path (str): Path to the directory containing Semgrep rule files.
        dataset (list): List of samples, each sample is a dict with keys like 'idx', 'cwe', 'func', 'target'.
        output_filtered_dir (str): Directory to save filtered rules.
        fpr_threshold (float): Maximum allowed FPR to keep a rule.
    Returns:
        list: List of tuples containing (source_rule_path, destination_rule_path, fpr).
    """
    # Step 1: 运行评估
    results = test_each_rule_on_dataset(rule_path, dataset)

    # Step 2: 创建输出目录
    os.makedirs(output_filtered_dir, exist_ok=True)

    # Step 3: 统计安全样本数
    negatives_samples = sum(1 for s in dataset if s["target"] == 0)
    total_samples = len(dataset)

    filtered_rules = []

    for rule_abs_path, res in results.items():
        if res["error"]:
            print(f"⚠️ Skipping rule due to error: {rule_abs_path}")
            continue

        tp = len(res["true_positive"])
        fp = len(res["false_positive"])
        total_positives = tp + fp

        fpr = fp / negatives_samples if negatives_samples > 0 else 0.0

        rule_src = rule_abs_path
        rule_filename = os.path.basename(rule_src)

        if fpr < fpr_threshold:
            dst_path = rule_src.replace(rule_path, output_filtered_dir)
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            shutil.copy2(rule_src, dst_path)
            filtered_rules.append((rule_src, dst_path, fpr))
            print(f"✅ Kept rule (FPR={fpr:.3f}): {rule_filename}")

    print(
        f"\n🎉 Total {len(filtered_rules)} rules kept (FPR < {fpr_threshold*100:.0f}%) and copied to {output_filtered_dir}"
    )
    return filtered_rules


# remove fix patterns in semgrep rules
def fix_yaml(rule_content, rule_path):
    result = {
        "fixed": False,
        "removed": [],
        "fixed_content": rule_content,
        "error": None,
    }
    # read semgrep rule yaml
    yaml = YAML()
    rule_yaml = None
    try:
        rule_yaml = yaml.load(rule_content)
    except Exception as e:
        result["error"] = f"Error parsing YAML: {e}"
        print(f"Error parsing YAML for rule {rule_path}: {e}")
    # remove fix patterns in semgrep rules
    if rule_yaml and "rules" in rule_yaml:
        print(f"Fixing rule: {rule_path}")
        for rule in rule_yaml.get("rules", []):
            res = rule.pop("fix", None)  # 使用 pop 并提供默认值 None，避免 KeyError
            if res:
                result["fixed"] = True
                result["removed"].append(res)
                print(f"Removed fix: {res}")
        result["fixed_content"] = yaml.dump(rule_yaml)
        return result
    return result


# need errors in rule test output
# some test func code is wrong, so we get Syntax error in semgrep output. Did not skip in this function.
def fix_rule(
    model,
    rules_path="./rules/",
    fixed_path="./rules_fixed/",
    test_output_result="./temp/semgrep/positive/",
    remove_fix_pattern=False,
):
    new_directory(fixed_path)
    # test rules grammar
    semgrep_runner = semgrep.SemgrepRunner()
    # any code file for semgrep test
    filepath = f"./temp/temp_code.c"

    total = 0
    fix_yaml_count = 0
    prompt_template_fix = ChatPromptTemplate.from_messages(fix_rule_prompt)

    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith(".yaml"):
                total += 1
                idx = file.split("_")[-1].split(".")[0]
                rule_path = os.path.join(root, file)
                fixed_rule_path = fixed_path + os.path.relpath(rule_path, rules_path)

                with open(rule_path, "r") as f:
                    rule_content = f.read()
                # save test output for reference
                create_directory(os.path.dirname(fixed_rule_path), print_info=False)
                with open(fixed_rule_path, "w") as f:
                    f.write(rule_content)

                # only fix fail rules, which are "rule error" without results when semgrep test positive cases.
                test_json_path = test_output_result + f"semgrep_output_{idx}.json"
                if not os.path.exists(test_json_path):
                    print(f"Test output not found.")
                    error_info = ""
                    result = semgrep_runner.run_rule(
                        rule_path=rule_path,
                        target_path=filepath,
                        output_path=test_json_path,
                    )
                    if "result" not in result:
                        # print(f"error: {result['message']}")
                        if "stderr" in result:
                            # print(f"error running semgrep for rule: { result['stderr']}")
                            error_info = result["stderr"]
                        else:
                            error_info = result["message"]
                    with open(test_json_path, "w") as f:
                        f.write(
                            json.dumps(
                                {
                                    "results": [],
                                    "errors": error_info,
                                }
                            )
                        )

                with open(test_json_path, "r") as f:
                    test_output = f.read()
                if test_output.strip() == "":
                    print(
                        "\033[31m" + f"Empty test output, rule: {rule_path}" + "\033[0m"
                    )
                    return 0
                test_output_json = json.loads(test_output)
                # there can be results and erros in same time 
                if test_output_json.get("results") or not test_output_json.get(
                    "errors"
                ):
                    # print(f"Rule works fine, no need to fix: {rule_path}")
                    continue

                # todo
                if remove_fix_pattern:
                    fixed_rule_content = fix_yaml(rule_content, rule_path)

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
                    fix_yaml_count += 1
                    # print(f"Fixed Semgrep rule saved to {fixed_rule_path}")
    print(f"Total rules: {total}, fixed rules: {fix_yaml_count}")


def simple_test_rule(rule_path, test_json_path, filepath="./temp/temp_code.c"):
    """
    simple test semgrep rule, save output to test_json_path
    Args:
        rule_path: path of semgrep rule
        test_json_path: path to save semgrep test output
        filepath: path of code file to test semgrep rule
    """
    # test rules grammar
    semgrep_runner = semgrep.SemgrepRunner()

    error_info = "no error info?"
    result = semgrep_runner.run_rule(
        rule_path=rule_path,
        target_path=filepath,
        output_path=test_json_path,
    )
    if "result" not in result:
        # print(f"error: {result['message']}")
        if "stderr" in result:
            # print(f"error running semgrep for rule: { result['stderr']}")
            error_info = result["stderr"]
        else:
            error_info = result["message"]
    with open(test_json_path, "w") as f:
        f.write(
            json.dumps(
                {
                    "results": [],
                    "errors": error_info,
                }
            )
        )


# get rules
def get_rule_data(rules_path="./rules/", test_output_result="./temp/semgrep/positive/", auto_test=True):
    data = []
    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith(".yaml"):
                idx = file.split("_")[-1].split(".")[0]
                rule_path = os.path.join(root, file)

                with open(rule_path, "r") as f:
                    rule_content = f.read()

                test_json_path = test_output_result + f"semgrep_output_{idx}.json"
                if auto_test and not os.path.exists(test_json_path):
                    print(f"Test output not found. Path: {test_json_path}")
                    simple_test_rule(
                        rule_path=rule_path,
                        test_json_path=test_json_path,
                    )
                with open(test_output_result + f"semgrep_output_{idx}.json", "r") as f:
                    test_output = f.read()
                if test_output.strip() == "":
                    print(
                        "\033[31m" + f"Empty test output, rule: {rule_path}" + "\033[0m"
                    )
                    return 0
                test_output_json = json.loads(test_output)

                data.append(
                    {
                        "idx": int(idx),
                        "rule_path": rule_path,
                        "semgrep_rule": rule_content,
                        "test_output": test_output_json,
                    }
                )
    return data

# only fix rules error
def get_rule_fix_batch(data, batch_path="./semgrep_fix.jsonl", model="qwen-plus"):
    prompt_template_fix = ChatPromptTemplate.from_messages(fix_rule_prompt)
    total = 0
    fix_num = 0
    jsonl_data = []
    for rule in data:
        total += 1
        # there can be results and erros in the same time. some errors are about Syntax error for code.
        if  rule["test_output"].get("results") or not rule["test_output"].get("errors"):
            # print(f"No errors for rule idx {rule['idx']}, skipping.")
            continue
        # some test func code is wrong, so we get Syntax error in semgrep output.
        errors_info=[]
        if type(rule["test_output"].get("errors")) is str:
            errors_info = rule["test_output"].get("errors")
        else:
            for err in rule["test_output"].get("errors", []):
                    # if (type(err['type']) is list) and err['type'][0]:
                    #     print(f"Rule idx {rule['idx']} error: PartialParsing")
                    if (type(err['type']) is str) and 'Rule' in err['type']:
                        errors_info.append(err)

        if not errors_info:
            continue

        message_fix = prompt_template_fix.invoke(
            {
                "semgrep_rule": rule["semgrep_rule"],
                "test_output": {"errors": errors_info},
            }
        )

        json_data = {
            "custom_id": f"{rule['idx']}",
            "method": "POST",
            "url": "/v1/chat/completions",
            "body": {
                "model": model,
                "messages": langchain_to_openai_messages(message_fix.to_messages()),
            },
        }
        jsonl_data.append(json_data)
        fix_num += 1
    print(f"Total rules: {total}. Total fix rules: {fix_num}")
    with jsonlines.open(batch_path, mode="w") as writer:
        for oneline in jsonl_data:
            writer.write(oneline)

def move_rules_byoutput(data, target_path="./rules_final/", positive=True, no_errors=True):
    '''
    Docstring for move_rules_byoutput
    
    :param data: from get_rule_data(), auto_test=False
    :param target_path: Description
    :param positive: Description
    :param no_errors: Description
    '''
    positive_num=0
    no_error_num=0

    for rule in data:
        source_path = Path(rule["rule_path"])
        dest_path = Path(target_path, *source_path.parts[1:])
        if  positive and rule["test_output"].get("results"):
            positive_num+=1
            create_directory(os.path.dirname(dest_path), print_info=False)
            shutil.copy2(source_path, dest_path)
        elif no_errors and not rule["test_output"].get("errors"):
            no_error_num+=1
            create_directory(os.path.dirname(dest_path), print_info=False)
            shutil.copy2(source_path, dest_path)
    print(f"Total rules: {len(data)}, Positive rules: {positive_num}, No error rules: {no_error_num}, all moved rules: {positive_num+no_error_num}")

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


def read_test_json(test_json_path):
    with open(test_json_path, "r") as f:
        result = json.load(f)
    total_rules = 0
    total = 0
    tp = set()
    fp = set()
    for cwe in result:

        result[cwe]["true_positive"] = set(result[cwe]["true_positive"])
        result[cwe]["false_positive"] = set(result[cwe]["false_positive"])
        print(
            f"CWE name:{cwe}. Total:{result[cwe]['total']}, true_positive:{len(result[cwe]['true_positive'])},false_positive:{len(result[cwe]['false_positive'])}, rule num:{result[cwe]['rules_num']}"
        )
        tp.update(result[cwe]["true_positive"])
        fp.update(result[cwe]["false_positive"])
        total_rules += result[cwe]["rules_num"]
        total += result[cwe]["total"]

    print(
        f"test total:{total}, rule num:{total_rules}, true_positive:{len(tp)},false_positive:{len(fp)}, Precision:{len(tp)/(len(tp)+len(fp))}"
    )


def read_cwe_status(cwe_status):
    first = list(cwe_status.keys())[0]
    key = "true_positive" if "true_positive" in cwe_status[first] else "true_negative"
    error = "p_error" if "p_error" in cwe_status[first] else "n_error"
    total = 0
    tp = 0
    p_error = 0
    for cwe in cwe_status:
        total += cwe_status[cwe]["total"]
        tp += len(cwe_status[cwe][key])
        p_error += len(cwe_status[cwe][error])
    print(f"Total samples: {total}, True : {tp}, Run Errors: {p_error}")
    for cwe in cwe_status:
        print(
            f"CWE-{cwe}: Total: {cwe_status[cwe]['total']}, True : {len(cwe_status[cwe][key])}, Run Errors: {len(cwe_status[cwe][error])}"
        )


def move_rules_bystatus(
    cwe_status,
    test_type="true_positive",
    rules_path="./rules/",
    target_path="./rules_selected/",
):
    create_directory(target_path)
    for cwe in cwe_status:
        source_dir = os.path.join(rules_path, cwe)
        dest_dir = os.path.join(target_path, cwe)
        create_directory(dest_dir)
        for file in os.listdir(source_dir):
            idx = file.split("_")[-1].split(".")[0]
            if file.endswith(".yaml") and (int(idx) in cwe_status[cwe][test_type]):
                source_file = os.path.join(source_dir, file)
                dest_file = os.path.join(dest_dir, file)
                shutil.copy2(source_file, dest_file)
        print(f"Moved rules for CWE-{cwe} to {dest_dir}")


def test_devign(rule_filename="rules_fixed_negative"):
    result=test_rules_batch(
    rule_path=f"./{rule_filename}/",
    dataset=load_devign("./data/devign/function.json"),
    cvs_name=f"semgrep_{rule_filename}_devign.cvs"
    )
    for cwe in result:
        result[cwe]['positive_path']= list(result[cwe]['positive_path'])
        result[cwe]['error']= list(result[cwe]['error'])

    with open(f"./test_{rule_filename}_devign_batch.json", "w") as f:
        json.dump(result, f, indent=4)
    read_test_json(f"./test_{rule_filename}_devign_batch.json")
    print_metrics_from_csv(f'./result/semgrep_{rule_filename}_devign.cvs')

def test_primevul_test():
    result=test_rules_batch(
    rule_path="./rules_fixed_negative/",
    dataset=load_primevul("./data/primevul/primevul_test.jsonl"),
    cvs_name="semgrep_rules_fixed_negative_primevul_test.cvs"
    )
    for cwe in result:
        result[cwe]['positive_path']= list(result[cwe]['positive_path'])
        result[cwe]['error']= list(result[cwe]['error'])

    with open("./test_rules_fixed_negative_primevul_test_batch.json", "w") as f:
        json.dump(result, f, indent=4)
    read_test_json("./test_rules_fixed_negative_primevul_test_batch.json")
    print_metrics_from_csv('./result/semgrep_rules_fixed_negative_primevul_test.cvs')

if __name__ == "__main__":
    # generate
    # args = parse_args()
    # model=ChatQwen(model="qwen3-max", temperature=0.1)
    # print(generate_semgrep_rules(model, args.dataset))
    # print(f"Total semgrep rules: {rule_num(path='./rules_selected/')}")
    # genertate_rule_batch(load_primevul())
    # get_semgrep_rules_from_batch_response(
    #     batch_response_path="./temp/semgrep_1583_result.jsonl",
    #     raw_data=load_primevul(),
    #     output_rules_path="./rules/",
    # )

    # vaildate and fix
    # vaildate_rules()
    # cwe_status = test_rule_positive()
    # with open("./cwe_status.json", "w") as f:
    #     json.dump(cwe_status, f, indent=4)
    # fix_rule(ChatOllama(model="gemma3:27b"), './rules_qwen-plus/')
    # get_rule_fix_batch(
    #     data=get_rule_data(),
    #     batch_path="./semgrep_fix_batch.jsonl",
    #     model="qwen-plus"
    # )
    # get_semgrep_rules_from_batch_response(batch_response_path='./temp/batch_result/semgrep_fix_batch_result.jsonl',
    #     raw_data=load_primevul(),
    #     output_rules_path="./rules_fixed/")
    
    # cwe_status = test_rule_positive("./rules_fixed/", output_path="./temp/semgrep/fixed/", strict=False)
    # with open("./cwe_fixed_status.json", "w") as f:
    #     json.dump(cwe_status, f, indent=4)

    # with open("./cwe_fixed_status.json", "r") as f:
    #     cwe_status= json.load(f)
    # move_rules_bystatus(
    #     cwe_status=cwe_status,
    #     rules_path="./rules_fixed/",
    #     target_path="./rules_fixed_selected/"
    # )
    # with open("./cwe_fixed_status.json", "r") as f:
    #     cwe_status = json.load(f)
    # read_cwe_status(cwe_status)
    # print(rule_num(path="./rules_fixed_selected/"))
    # data=get_rule_data(auto_test=True)
    
    # move_rules_byoutput(data=data, target_path="./rules_fixed_selected/", positive=True, no_errors=False)
    # print(rule_num(path="./rules_fixed_selected/"))


    # test with negative sample in train dataset and move
    # cwe_negative_status=test_rule_negative('./rules_fixed_selected/')
    # with open("./cwe_fixed_negative_status.json", "w") as f:
    #     json.dump(cwe_negative_status, f, indent=4)
    # move_rules_bystatus(
    #     cwe_status=json.load(open("./cwe_fixed_negative_status.json", "r")),
    #     test_type="true_negative",
    #     rules_path="./rules_fixed_selected/",
    #     target_path="./rules_fixed_negative/"
    # )
    # semgrep.SemgrepRunner.read_semgrep_output('./temp/semgrep/negative/')
    # with open("./cwe_negative_status.json", "r") as f:
    #     cwe_status = json.load(f)
    # read_cwe_status(cwe_status)

    # test each rule on dataset
    # results = test_each_rule_on_dataset('./rules_selected/', load_primevul("./data/primevul/primevul_test_paired.jsonl"))

    # test with test dataset
    # result=test_rules_batch(
    #     rule_path="./rules_fixed_negative/",
    #     dataset=load_primevul(),
    #     cvs_name="semgrep_rules_fixed_negative_primevul_train.cvs"
    # )
    # for cwe in result:
    #     result[cwe]['positive_path']= list(result[cwe]['positive_path'])
    #     result[cwe]['error']= list(result[cwe]['error'])

    # with open("./test_rules_fixed_negative_primevul_train_batch.json", "w") as f:
    #     json.dump(result, f, indent=4)
    # read_test_json("./test_rules_fixed_negative_primevul_train_batch.json")
    # print_metrics_from_csv('./result/semgrep_rules_fixed_negative_primevul_train.cvs')
    
    test_devign()


    # result=test_cwe_rules(
    #     rule_path="./rules_selected/",
    #     dataset=load_primevul("./data/primevul/primevul_test_paired.jsonl"),
    #     # cvs_name="semgrep_cwe_rules_negative_primevul.cvs"
    # )
    # for cwe in result:
    #     result[cwe]['positive_path']= list(result[cwe]['positive_path'])
    #     result[cwe]['error']= list(result[cwe]['error'])
    # with open("./test_cwe_rules.json", "w") as f:
    #     json.dump(result, f, indent=4)

    # read_test_json("./test_rules_batch.json")

    # print_metrics_from_csv('./result/semgrep_primevul.cvs')
