from data_process.utils.loader import load_primevul
import json
import jsonlines

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
