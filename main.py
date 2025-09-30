from data_process.utils.loader import load_devign
from typing import Optional

from pydantic import BaseModel, Field
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate

import getpass
import os

if not os.environ.get("OPENAI_API_KEY"):
  os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter API key for OpenAI: ")





# system_template = '''You are a senior security analyst specializing in static code analysis. Your task is to: 
# 1. Identify vulnerabilities from OWASP Top 10/CWE lists 
# 2. Classify severity (Critical/High/Medium/Low) 
# 3. Provide remediation guidance 
# 4. Highlight false positives'''


system_template = "You are a code security expert who analyzes the given code to detect the security vulnerability."

prompt_template = ChatPromptTemplate.from_messages(
    [("system", system_template), ("user", "Analyze this code:\n\n{code}")]
)

class VulResult(BaseModel):
    """Result of vulnerability discovery."""

    # reason: str = Field(description="The reason of the detection result.")
    vulnerability: str = Field(description="The type of vulnerability. (If the code is secure, give 'none' )") 
    label: Optional[int] = Field(
        default=None, description="Vulnerability status indicator, only o or 1 (0: secure, 1: vulnerable)"
    )

def main():
    llm = init_chat_model("gemma3:27b", model_provider="openai", base_url="http://localhost:11434/v1")
    structured_llm = llm.with_structured_output(VulResult, include_raw=True)
    chain = prompt_template | structured_llm
    data=load_devign('./data/devign/function.json')
    res=chain.invoke({'code':data[2]['code']})
    print(res)
    print("wtf")
    print(res['parsed'])
    print(data[2]['label'])

    
    


if __name__ == "__main__":
    main()
