from transformers import AutoTokenizer, AutoModelForCausalLM
import os

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/"

def try_qwen():
    # Load model directly


    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct")
    model = AutoModelForCausalLM.from_pretrained(os.environ["MODEL_PATH"] + "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct")
    messages = [
        {"role": "user", "content": "Who are you?"},
    ]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    outputs = model.generate(**inputs, max_new_tokens=128)
    print(tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1]:]))

if __name__ == "__main__":
    try_qwen()