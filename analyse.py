import jsonlines

def load_generated_jsonl(file_path):
    data = []
    with jsonlines.open(file_path, mode="r") as reader:
        for obj in reader:
            data.append(obj)
    return data

# Accuracy, Precision, Recall, F1 Score, FPR
def statistics_on_generated_jsonl(data):
    total = len(data)
    fail_generate_count=0
    true_positive=0
    false_positive=0
    true_negative=0
    false_negative=0
    
    # VULNERABLE or SAFE ("VULNERABLE\n" "SAFE\n" in label)
    for item in data:
        label = 1 if "VULNERABLE" in item.get("label") else 0
        if item.get("predict") == "VULNERABLE":
            prediction = 1
        elif item.get("predict") == "SAFE":
            prediction = 0
        else:
            fail_generate_count += 1
            continue
        if label == 1 and prediction == 1:
            true_positive += 1
        elif label == 0 and prediction == 1:
            false_positive += 1
        elif label == 0 and prediction == 0:
            true_negative += 1
        elif label == 1 and prediction == 0:
            false_negative += 1
    
    real_total = true_positive + false_positive + true_negative + false_negative
    accuracy = (true_positive + true_negative) / real_total if real_total > 0 else 0
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = false_positive / (false_positive + true_negative) if (false_positive + true_negative) > 0 else 0

    print(f"Total items: {total}")
    print(f"Failed generations: {fail_generate_count}")
    print(f"True Positives: {true_positive}, False Positives: {false_positive}, True Negatives: {true_negative}, False Negatives: {false_negative}")
    print(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}, FPR: {fpr:.4f}")

    return {
        "total": total,
        "failed_generations": fail_generate_count,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr
    }

if __name__ == "__main__":
    data = load_generated_jsonl("../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2025-12-29-21-01-14-train_paired-sft_fixed_negative/generated_predictions.jsonl")
    print(f"jsonl length: {len(data)}")
    statistics_on_generated_jsonl(data)