from data_process.utils.loader import load_devign
from getresdata_csv import print_metrics_from_csv
import pandas as pd

from typing import Literal

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama

import argparse
import getpass
import os

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

def main():
    args = parse_args()
    csv_path=f'{args.output}/{args.dataset}'
    csvfile=f'{csv_path}/{args.model_name}.csv'
    create_directory(csv_path)

    llm = ChatOllama(model=args.model_name)
    structured_llm = llm.with_structured_output(VulResult, include_raw=True)
    chain = prompt_template | structured_llm
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
        if i>100:
            break
        
    print_metrics_from_csv(csvfile)
    
    
    

    
    


if __name__ == "__main__":
    main()
