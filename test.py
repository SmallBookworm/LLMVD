import json
from data_process.utils.loader import load_devign, load_primevul
from getresdata_csv import print_metrics_from_csv

import tools.joern as joern
import tools.semgrep as semgrep

import pandas as pd

from typing import Literal

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_huggingface import ChatHuggingFace, HuggingFacePipeline
from langchain_ollama import ChatOllama

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

import argparse
import getpass
import os
import re

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/LLM-Research/"

if not os.environ.get("OPENAI_API_KEY"):
  os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter API key for OpenAI: ")


def parse_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="dataset name")
    parser.add_argument("--model_name", default="gemma3:27b", type=str,
                        help="The model to be used.")
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




# system_template = '''You are a senior security analyst specializing in static code analysis. Your task is to: 
# 1. Identify vulnerabilities from OWASP Top 10/CWE lists 
# 2. Classify severity (Critical/High/Medium/Low) 
# 3. Provide remediation guidance 
# 4. Highlight false positives'''


system_template = "You are a code security expert who analyzes the given code to detect the security vulnerability."

prompt_template = ChatPromptTemplate.from_messages(
    [("system", system_template), ("user", "Detect whether the following code contains vulnerabilities:\n\n{code}")]
)

class VulResult(BaseModel):
    """Result of vulnerability discovery."""

    # reason: str = Field(description="The reason of the detection result.")
    # vulnerability: str = Field(description="The type of vulnerability. (If the code is secure, give 'none' )") 
    label: Literal[0, 1] = Field(
        description="Vulnerability status indicator, only 0 or 1 (0: secure, 1: vulnerable)"
    )

def main(llm):
    args = parse_args()
    csv_path=f'{args.output}/{args.dataset}'
    csvfile=f'{csv_path}/{args.model_name}.csv'
    create_directory(csv_path)

    
    structured_llm = llm.with_structured_output(VulResult, include_raw=True)
    chain = prompt_template | structured_llm
    #devign
    data=load_devign(f'./data/{args.dataset}/function.json')
    for i, sample in enumerate(data):
        res=chain.invoke({'code':sample['code']})
        prediction=0
        if res['parsing_error']:
            print(res)
            prediction=500
        else:
            prediction=res['parsed'].label
        temp_df = pd.DataFrame({'Index': i, 'Code': [sample['code']], 'Label': [sample['label']], 'Prediction': [prediction],
                                    'Response': [str(res['raw'])]})
        temp_df.to_csv(csvfile, index=False, mode='w' if i == 0 else 'a', header=i == 0)

        
    print_metrics_from_csv(csvfile)
    
def local_model():
    args = parse_args()

    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"]+args.base_model, padding_side='left')
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.pad_token_id = tokenizer.eos_token_id
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = AutoModelForCausalLM.from_pretrained(
        os.environ["MODEL_PATH"]+args.base_model,
        load_in_8bit=True,
        dtype=torch.float16,
        device_map="auto",
        pad_token_id=tokenizer.eos_token_id
    )
    print("Base model loaded!")

    pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, max_new_tokens=128)
    hf = HuggingFacePipeline(pipeline=pipe)
    # tokenizer.chat_template
    # chat_model = ChatHuggingFace(llm=hf)

    ai_msg = hf.invoke("Who are you?")
    print(ai_msg)
    
def save_code(code, filepath='./temp/temp_code.c'):
    with open(filepath, 'w') as f:
        f.write(code)

def test_joernrun():
    data=load_devign(f'./data/devign/function.json')
    for i, sample in enumerate(data):
        if i>0:
            break
        print( 'label:', sample['label'])
        filepath=f'./temp/temp_code_{i}.c'
        # save_code(sample['code'], filepath)
        joern.parse_file(filepath, output=f'cpg{i}.bin', language='c')
        joern_runner = joern.JoernRunner(cpg_path=f'./temp/cpg{i}.bin')
        result = joern_runner.run_script(script_path='./tools/joern_scripts/base_slice.sc')
        if 'result' in result:
            print(result["result"])
        else:
            print(result.get('error', 'No result or error found'))

def test_scan():
    data=load_devign(f'./data/devign/function.json')
    for i, sample in enumerate(data):
        if i>0:
            break
        print( 'label:', sample['label'])
        filepath=f'./temp/temp_code_{i}.c'
        save_code(sample['code'], filepath)
        joern.scan_file(filepath)

def read_joernscan():
    log_text=joern.scan_file('./temp/temp_code.c')
    print('1A')

    pattern = r'^Result:\s*([0-9]+(?:\.[0-9]+)?)\s*:\s*(.*?):\s*([^:\s]+):(\d+):(\S+)$'
    results = []
    for line in log_text.splitlines():
        match = re.match(pattern, line.strip())
        if match:
            score = float(match.group(1))
            title = match.group(2).strip()
            filepath = match.group(3)
            line_number = int(match.group(4))
            function_name = match.group(5)
            results.append({
                "score": score,
                "title": title,
                "filepath": filepath,
                "line_number": line_number,
                "function_name": function_name
            })

    # 打印结果
    for r in results:
        print(r)

def test_semgreprun():
    data=load_devign(f'./data/devign/function.json')
    for i, sample in enumerate(data):
        if i>0:
            break
        print( 'label:', sample['label'])
        filepath=f'./temp/temp_code_{i}.c'
        save_code(sample['code'], filepath)
        semgrep_runner = semgrep.SemgrepRunner()
        result = semgrep_runner.run_rule(
            rule_path='./tools/semgrep_rules',
            target_path=filepath,
            output_path=f'./temp/semgrep_output_{i}.json'
        )
        if 'result' in result:
            print(result["result"].stdout)
        else:
            print(result.get('error', 'No result or error found'))

test_messages=[("user",'''You are a C language security expert. Please generate a Semgrep rule (in YAML format) based on the following vulnerability patch information:

Vulnerability type: Buffer Overflow (CWE-120)
Affected function: process_data()
Vulnerable code (before fix):
c
memcpy(buffer, input, size);

Fixed code:
c
if (size > sizeof(buffer)) return -1;
memcpy(buffer, input, size);

Goal: Detect all calls to memcpy that do not validate the destination buffer size beforehand.
Language: C

Output only the Semgrep rule in YAML format.
''') ]


def generate_semgrep_rules():
    args = parse_args()


    model=ChatOllama(model=args.model_name)
    prompt_template_rules = ChatPromptTemplate.from_messages(
        [("system", "You are a code security expert specializing in generating Semgrep rules for vulnerability detection."),
         ("user", '''Generate a Semgrep rule in YAML format to detect the vulnerable pattern described below. 
Output ONLY the Semgrep rule in YAML format.

Guidelines:
- Focus on the key difference between vulnerable and fixed code.
- Use `pattern` or `pattern-either` with minimal, precise code snippets.
- Include `message`, `severity`, and `languages: [c]`.
- Avoid matching entire functions; match only the risky expression or condition.

Vulnerability Details:
- CWE: {cwe}
- CVE: {cve}
- Description: {cve_desc}
- Commit message: {commit_message}
- Commit URl: {commit_url}
Vulnerable code (before fix):
{vul_code}

Fixed code:
{fix_code}

Language: C
''')]
    )
    if args.dataset=='devign':
        data=load_devign(f'./data/devign/function.json')
    elif args.dataset=='primevul_train_paired':
        data=load_primevul()
    total=0
    for i in range(0, len(data), 2):

        
        
        message_generate=prompt_template_rules.invoke({
            'cwe': data[i].get('cwe', 'N/A'),
            'cve': data[i].get('cve', 'N/A'),
            'cve_desc': data[i].get('cve_desc', 'N/A'),
            'commit_message': data[i].get('commit_message', 'N/A'),
            'commit_url': data[i].get('commit_url', 'N/A'),
            'vul_code': data[i]['func'],
            'fix_code': data[i+1]['func']
        })
        #test
        if data[i]['commit_url']==data[i+1]['commit_url']:
            continue
        else:
            print(data[i]['target'],'mismatch',data[i+1]['target'])
            total+=1

        create_directory('./temp/test_generate')
        messages_path=f'./temp/test_generate/semgrep_generate_{data[i]['idx']}.text'
        with open(messages_path, 'w') as f:
            f.write(message_generate.to_messages()[-1].content)
        print(f'Semgrep generate messages saved to {messages_path}')

        message_rules=model.invoke(message_generate)
        if message_rules:
            rule_text=message_rules.content
            # 使用正则表达式去掉开头的 ```yaml 和结尾的 ```
            cleaned_yaml = re.sub(r'^```yaml\s*\n?', '', rule_text, flags=re.MULTILINE)
            cleaned_yaml = re.sub(r'\n?```$', '', cleaned_yaml, flags=re.MULTILINE)
            directory=f'./rules/{data[i]['cwe'][0]}'
            create_directory(directory)
            rule_path=f'{directory}/semgrep_rule_{data[i]['idx']}.yaml'
            with open(rule_path, 'w') as f:
                f.write(cleaned_yaml)
            print(f'Semgrep rule saved to {rule_path}')
    return total

def write_dataset_to_files(dataset, max=0, base_path='./temp/dataset/'):
    create_directory(base_path)

    for i in range(0, min(len(dataset), max), 2):
        sample_path = os.path.join(base_path, str(i))
        create_directory(sample_path)
        sample = dataset[i]
        file_path = os.path.join(sample_path, f'sample_{i}_label_{sample["idx"]}.json')
        data=[sample]
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        c_filepath = os.path.join(sample_path, f'sample_{i}_label_{sample["idx"]}.cpp')
        with open(c_filepath, 'w') as f:
            f.write(sample['func'])
        
        file_path_2 = os.path.join(sample_path, f'sample_{i+1}_label_{dataset[i+1]["idx"]}.json')
        data_2=[dataset[i+1]]
        with open(file_path_2, 'w') as f:
            json.dump(data_2, f, indent=4)
        c_filepath_2 = os.path.join(sample_path, f'sample_{i+1}_label_{dataset[i+1]["idx"]}.cpp')
        with open(c_filepath_2, 'w') as f:
            f.write(dataset[i+1]['func'])
    print(f'Dataset samples saved to {base_path}')

if __name__ == "__main__":
   write_dataset_to_files(load_primevul(), 100)

