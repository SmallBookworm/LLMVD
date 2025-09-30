import openai
import json
import pandas as pd

openai.api_key = "YOUR_OPENAI_API_KEY"

def get_chatgpt_response(instruction, code):
    prompt = (
        f"Below is an instruction that describes a task, paired with an input that provides further context. "
        f"Write a response that appropriately completes the request.\n\n"
        f"### Instruction:\n{instruction}\n\n### Input:\n{code}\n\n### Response:"
    )
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",  # or "gpt-4"
        messages=[{"role": "user", "content": prompt}],
        max_tokens=8,
        temperature=0
    )
    return response.choices[0].message['content'].strip()

def main():
    with open("your_dataset.json", "r") as f:
        data = json.load(f)

    results = []
    for i, example in enumerate(data):
        instruction = example["instruction"]
        code = example["input"]
        label = example["output"]
        response = get_chatgpt_response(instruction, code)
        prediction = response[0] if response else ""
        prediction_result = 1 if prediction == '1' else 0
        label_result = 1 if label == '1' else 0
        results.append({
            "Index": i,
            "Code": code,
            "Label": label_result,
            "Prediction": prediction_result,
            "Response": response
        })

    df = pd.DataFrame(results)
    df.to_csv("chatgpt_results.csv", index=False)

if __name__ == "__main__":
    main()