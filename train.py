from models.generate_train_data import generate_train_data, generate_chatml_train_data
from data_process.utils.loader import load_primevul
import jsonlines

# {"messages": [{"role": "system", "content": "You are a helpful assistant"}, {"role": "user", "content": "谁在文艺复兴时期绘制人体?"}, {"role": "assistant", "content": "文艺复兴时期是一个关于艺术、文化和学术的复兴运动，在这个时期，许多艺术家都绘制了人体。"}]}
if __name__ == "__main__":
    res = generate_chatml_train_data(load_primevul(), output_path='./models/data/chatml_train_data.jsonl')
    print(len(res))
