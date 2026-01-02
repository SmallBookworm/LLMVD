from data_process.utils.loader import load_primevul
from data_process.utils.process import get_cwe_idx_dict, list_by_idx
import json
import jsonlines
import random
import pandas as pd


def generate_train_data(dataset, output_path="./models/data/train_data.json"):
    result = []
    for sample in dataset:
        one_data = {
            "instruction": "Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or improper input validation. Respond only with 'VULNERABLE' or 'SAFE'.",
            "input": sample["func"],
            "output": "VULNERABLE" if sample["target"] == 1 else "SAFE",
        }
        result.append(one_data)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=4)
    print(f"Success to save train data to {output_path}.")
    return result


# chatML format
def generate_chatml_train_data(
    dataset, output_path="./models/data/chatml_train_data.jsonl"
):
    result = []
    for sample in dataset:
        messages = [
            {
                "role": "system",
                "content": "You are a code security expert who analyzes the given code to detect the security vulnerability.",
            },
            {
                "role": "user",
                "content": f"Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or improper input validation.\n```c\n{sample['func']}\n```",
            },
            {
                "role": "assistant",
                "content": "VULNERABLE" if sample["target"] == 1 else "SAFE",
            },
        ]
        one_data = {"messages": messages}
        result.append(one_data)

    with jsonlines.open(output_path, mode="w") as writer:
        for item in result:
            writer.write(item)
    print(f"Success to save chatML train data to {output_path}.")
    return result


# divide dataset by token length
def divide_data_by_length(dataset, tokenizer, max_length=2048):
    """
    divide dataset into short and long based on token length

    :param max_length: maximum token length
    """
    short_data = []
    long_data = []
    for sample in dataset:
        input_text = sample["func"] if "func" in sample else ""
        # instruction_text = sample['instruction'] if 'instruction' in sample else ''
        # full_text = instruction_text + '\n' + input_text
        tokenized = tokenizer(input_text, return_tensors="pt")
        if tokenized["input_ids"].shape[1] <= max_length:
            short_data.append(sample)
        else:
            long_data.append(sample)
    return short_data, long_data

#generate train data by cvs result
# temp_df = pd.DataFrame(
#             {
#                 "Idx": idx,
#                 "CWE": cwe,
#                 "Code": [sample["func"]],
#                 "Label": [sample["target"]],
#                 "Prediction": [prediction], 1/0
#                 "Response": [str(res)],
#             }
#         )
def get_train_data_by_cvs_result(data, 
    cvs_path="./result/semgrep_rules_fixed_negative_primevul_train.cvs"
):
    df = pd.read_csv(cvs_path)
    filtered_data = []
    for i in range(len(data)):
        sample = data[i]
        semgrep_result = df[df['Idx'] == int(sample['idx'])]
        if not semgrep_result.empty:
            prediction = semgrep_result['Prediction'].values[0]
            if prediction == 0:  # only keep SAFE samples
                filtered_data.append(sample)
    print(f"Filtered data length from {len(data)} to {len(filtered_data)} based on CVS results.")
    return filtered_data



# get train data by cwe_status.json
def get_train_data_by_cwe_status(
    cwe_status_path="./cwe_status.json", test_type="true_negative"
):
    with open(cwe_status_path, "r") as f:
        cwe_status = json.load(f)

    dataset = load_primevul("./data/primevul/primevul_train_paired.jsonl")

    filtered_data = []
    all_idx = []
    for cwe in cwe_status:
        all_idx.extend(cwe_status[cwe][test_type])
    # add samples that not matches cwe_status[cwe][test_type]

    for i in range(0, len(dataset), 2):
        sample = dataset[i]
        if int(sample["idx"]) not in all_idx:
            filtered_data.append(sample)
            filtered_data.append(dataset[i + 1])  # add the paired sample

    return filtered_data


# get fix number of train data by sample
def get_train_data_by_sample(dataset, num_samples=10):
    if num_samples >= len(dataset):
        print("num_samples >= dataset length, return full dataset")
        return dataset

    return random.sample(dataset, num_samples)


# split dataset
def split_dataset(dataset_path="./models/data/devign_32768_data.json", split_num=2):
    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    block_size = int(len(dataset) / split_num)
    for i in range(split_num):
        start_idx = i * block_size
        end_idx = (i + 1) * block_size if i != split_num - 1 else len(dataset)
        split_data = dataset[start_idx:end_idx]
        output_path = dataset_path.replace(".json", f"_part{i}.json")
        with open(output_path, "w") as f:
            json.dump(split_data, f, indent=4)
        print(f"Success to save split data to {output_path}.")
