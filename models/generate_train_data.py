from data_process.utils.loader import load_primevul
import json

def generate_train_data(dataset, output_path='./models/data/train_data.json'):
    result=[]
    for sample in dataset:
        one_data = {
            "instruction": "Analyze the following C code for security vulnerabilities such as buffer overflows, use-after-free, or information leaks. Respond only with 'VULNERABLE' or 'SAFE'.",
            "input": sample['func'],
            "output": "VULNERABLE" if sample['target']==1 else "SAFE",
        }
        result.append(one_data)
    
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=4)
    print(f'Success to save train data to {output_path}.')
    return result


