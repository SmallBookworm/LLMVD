from models.generate_train_data import generate_train_data, generate_chatml_train_data, divide_data_by_length, get_train_data_by_cwe_status, split_dataset, get_train_data_by_cvs_result
from data_process.utils.loader import load_primevul, load_devign, load_reveal
from getresdata_csv import print_metrics_from_csv
import json

from transformers import AutoTokenizer, AutoModelForCausalLM
import os

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/"

def get_rules_idx(rules_path):
    rule_files = []
    for root, _, files in os.walk(rules_path):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                rule_files.append(file)
    rules_idx = []
    for rule_file in rule_files:
        idx = rule_file.split("_")[-1].split(".")[0]
        rules_idx.append(int(idx))
    return rules_idx

def validate_negative_data(negative_data, rules_path="./rules_fixed_negative/"):
    rules_idx=get_rules_idx(rules_path)
    print(f"rules_idx length: {len(rules_idx)}")
    for data in negative_data:
        data_idx = data['idx']
        if data_idx in rules_idx:
            print(f"Found same idx in rules: {data_idx}")
    print(f"negative_data length: {len(negative_data)}")

'''
primevul
32768
dataset length: 7570,8
Success to save train data to ./models/data/primevul_train_paired_data.json.
json length: 7570
dataset length: 7578
4096
dataset length: 7020,558
Success to save train data to ./models/data/primevul_train_paired_4096_data.json.
json length: 7020
dataset length: 7578

devign
32768
json length: 27309
'''
def generate_negative_data():
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    negative_data=get_train_data_by_cwe_status(cwe_status_path='./cwe_fixed_negative_status.json', test_type="true_negative")
    # res = generate_chatml_train_data(load_primevul(), output_path='./models/data/chatml_train_data.jsonl')
    # limit data to 4096 tokens
    max_token_length = 4096
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(negative_data, tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/primevul_fixed_negative_4096_data.json')
    # generate_train_data(load_primevul('./data/primevul/primevul_test_paired.jsonl'), output_path='./models/data/primevul_test_paired_data.json')
    with open('./models/data/primevul_fixed_negative_4096_data.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")

    validate_negative_data(negative_data, rules_path="./rules_fixed_negative/")

def generate_primevul_test_data():
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    # limit data to 32768 tokens
    max_token_length = 32768
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(load_primevul('./data/primevul/primevul_test_paired.jsonl'), tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/primevul_test_paired_32768_data.json')
    with open('./models/data/primevul_test_paired_32768_data.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")

    print(f"data length: {len(load_primevul('./data/primevul/primevul_test_paired.jsonl'))}")

def generate_devign_data():
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    # res = generate_chatml_train_data(load_primevul(), output_path='./models/data/chatml_train_data.jsonl')
    # limit data to 32768 tokens
    max_token_length = 32768
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(load_devign('./data/devign/function.json'), tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/devign_32768_data.json')
    with open('./models/data/devign_32768_data.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")

    print(f"data length: {len(load_devign('./data/devign/function.json'))}")

def generate_cvs_data():
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"
    result=get_train_data_by_cvs_result(data=load_primevul('./data/primevul/primevul_train_paired.jsonl'), cvs_path='./result/semgrep_rules_fixed_negative_primevul_train.cvs')
    # limit data to 32768 tokens
    max_token_length = 32768
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(result, tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/primevul_fixed_negative_train_data_by_cvs.json')
    with open('./models/data/primevul_fixed_negative_train_data_by_cvs.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")

def generate_reveal_data():
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    # limit data to 32768 tokens
    max_token_length = 32768
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(load_reveal('./data/reveal/'), tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/reveal_32768_data.json')
    with open('./models/data/reveal_32768_data.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")

    print(f"data length: {len(load_reveal('./data/reveal/'))}")
# {"messages": [{"role": "system", "content": "You are a helpful assistant"}, {"role": "user", "content": "谁在文艺复兴时期绘制人体?"}, {"role": "assistant", "content": "文艺复兴时期是一个关于艺术、文化和学术的复兴运动，在这个时期，许多艺术家都绘制了人体。"}]}
if __name__ == "__main__":
    # split_dataset(dataset_path="./models/data/devign_32768_data.json", split_num=2)
    # with open('./models/data/devign_32768_data_part1.json', 'r') as f:
    #     data = json.load(f)
    # print(f"json length: {len(data)}")
    # generate_primevul_test_data()
    # generate_cvs_data()
    
    # generate_reveal_data()
    split_dataset(dataset_path="./models/data/reveal_32768_data.json", split_num=2)
    with open('./models/data/reveal_32768_data_part0.json', 'r') as f:
        data1 = json.load(f)
    print(f"0json length: {len(data1)}")
    with open('./models/data/reveal_32768_data_part1.json', 'r') as f:
        data2 = json.load(f)
    print(f"1json length: {len(data2)}")