from data_process.utils.loader import load_devign, load_primevul
from getresdata_csv import print_metrics_from_csv

import tools.joern as joern
import tools.semgrep as semgrep

import pandas as pd

from typing import Literal

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama

from prompts.generate_rule import Semgrep_rule

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


def generate_semgrep_rules():
    args = parse_args()


    model=ChatOllama(model=args.model_name)
    prompt_template_rules = ChatPromptTemplate.from_messages(Semgrep_rule)
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
            total+=1
    return total

if __name__ == "__main__":
   print(generate_semgrep_rules()) 

