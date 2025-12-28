from models.generate_train_data import generate_train_data, generate_chatml_train_data, divide_data_by_length, get_train_data_by_cwe_status
from data_process.utils.loader import load_primevul
import json

from transformers import AutoTokenizer, AutoModelForCausalLM
import os

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/"

'''
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
'''

# {"messages": [{"role": "system", "content": "You are a helpful assistant"}, {"role": "user", "content": "谁在文艺复兴时期绘制人体?"}, {"role": "assistant", "content": "文艺复兴时期是一个关于艺术、文化和学术的复兴运动，在这个时期，许多艺术家都绘制了人体。"}]}
if __name__ == "__main__":
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    # res = generate_chatml_train_data(load_primevul(), output_path='./models/data/chatml_train_data.jsonl')
    # limit data to 4096 tokens
    max_token_length = 4096
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(load_primevul(), tokenizer, max_length=max_token_length)
    print(f"dataset length: {len(short_res)},{len(long_res)}")
    generate_train_data(short_res, output_path='./models/data/primevul_train_paired_4096_data.json')
    # generate_train_data(load_primevul('./data/primevul/primevul_test_paired.jsonl'), output_path='./models/data/primevul_test_paired_data.json')
    with open('./models/data/primevul_train_paired_4096_data.json', 'r') as f:
        data = json.load(f)
    print(f"json length: {len(data)}")
    print(f"dataset length: {len(load_primevul('./data/primevul/primevul_train_paired.jsonl'))}")
    for sample in long_res:
        print(f"{sample['cwe']}")