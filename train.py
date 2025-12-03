from models.generate_train_data import generate_train_data, generate_chatml_train_data, divide_data_by_length
from data_process.utils.loader import load_primevul


from transformers import AutoTokenizer, AutoModelForCausalLM
import os

os.environ["MODEL_PATH"] = "/home/peng/.cache/modelscope/hub/models/"


# {"messages": [{"role": "system", "content": "You are a helpful assistant"}, {"role": "user", "content": "谁在文艺复兴时期绘制人体?"}, {"role": "assistant", "content": "文艺复兴时期是一个关于艺术、文化和学术的复兴运动，在这个时期，许多艺术家都绘制了人体。"}]}
if __name__ == "__main__":
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct"

    # res = generate_chatml_train_data(load_primevul(), output_path='./models/data/chatml_train_data.jsonl')
    tokenizer = AutoTokenizer.from_pretrained(os.environ["MODEL_PATH"] + model_name)
    short_res, long_res = divide_data_by_length(load_primevul(), tokenizer, max_length=2048)
    print(len(short_res), len(long_res))
    generate_train_data(short_res, output_path='./models/data/2048_train_data.json')