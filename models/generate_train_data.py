from data_process.utils.loader import load_primevul
from data_process.utils.process import get_cwe_idx_dict, list_by_idx
import json
import jsonlines
import random

def generate_train_data(dataset, output_path='./models/data/train_data.json'):
    result=[]
    for sample in dataset:
        one_data = {
            "instruction": "Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or improper input validation. Respond only with 'VULNERABLE' or 'SAFE'.",
            "input": sample['func'],
            "output": "VULNERABLE" if sample['target']==1 else "SAFE",
        }
        result.append(one_data)
    
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=4)
    print(f'Success to save train data to {output_path}.')
    return result

#chatML format
def generate_chatml_train_data(dataset, output_path='./models/data/chatml_train_data.jsonl'):
    result = []
    for sample in dataset:
        messages = [
            {"role": "system", "content": "You are a code security expert who analyzes the given code to detect the security vulnerability."},
            {"role": "user", "content": f"Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or improper input validation.\n```c\n{sample['func']}\n```"},
            {"role": "assistant", "content": "VULNERABLE" if sample['target'] == 1 else "SAFE"}
        ]
        one_data = {"messages": messages}
        result.append(one_data)
    
    with jsonlines.open(output_path, mode='w') as writer:
        for item in result:
            writer.write(item)
    print(f'Success to save chatML train data to {output_path}.')
    return result

# divide dataset by token length
def divide_data_by_length(dataset, tokenizer, max_length=2048):
    '''
    divide dataset into short and long based on token length
    
    :param max_length: maximum token length
    '''
    short_data = []
    long_data = []
    for sample in dataset:
        input_text = sample['func'] if 'func' in sample else ''
        # instruction_text = sample['instruction'] if 'instruction' in sample else ''
        # full_text = instruction_text + '\n' + input_text
        tokenized = tokenizer(input_text, return_tensors='pt')
        if tokenized['input_ids'].shape[1] <= max_length:
            short_data.append(sample)
        else:
            long_data.append(sample)
    return short_data, long_data

# get train data by cwe_status.json 
def get_train_data_by_cwe_status(cwe_status_path='./cwe_status.json', test_type="true_negative"):
    with open(cwe_status_path, 'r') as f:
        cwe_status = json.load(f)
    
    dataset = load_primevul('./data/primevul/primevul_train_paired.jsonl')
    idx_dict = list_by_idx(dataset)
    cwe_index_dict = get_cwe_idx_dict(dataset)

    filtered_data = []
    for cwe in cwe_status:
        for idx in cwe_status[cwe][test_type]:
            # add random one that matches cwe
            cwe_index_dict[cwe].remove(idx)
            for i in range(len(dataset)):
                sample = dataset[i]
                if sample['cwe'][0] == cwe and (sample['idx'] == idx):
                    if i % 2 == 1:
                        filtered_data.append(sample)
                        filtered_data.append(dataset[i-1])
                        print('error sample added')
                    else:
                        filtered_data.append(sample)
                        filtered_data.append(dataset[i+1])  # add the paired sample
        # sample_data =get_train_data_by_sample(cwe_index_dict[cwe], num_samples=len(cwe_status[cwe][test_type]))
        # for sample_idx in sample_data:
        #     for i in range(len(dataset)):
        #         sample = dataset[i]
        #         if sample['cwe'][0] == cwe and (sample['idx'] == sample_idx):
        #             if i % 2 == 1:
        #                 filtered_data.append(sample)
        #                 filtered_data.append(dataset[i-1])
        #             else:
        #                 filtered_data.append(sample)
        #                 filtered_data.append(dataset[i+1])  # add the paired sample
    return filtered_data

# get fix number of train data by sample
def get_train_data_by_sample(dataset, num_samples=10):
    if num_samples >= len(dataset):
        print("num_samples >= dataset length, return full dataset")
        return dataset

    return random.sample(dataset, num_samples)