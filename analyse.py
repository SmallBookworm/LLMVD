import jsonlines
import pandas as pd


def load_generated_jsonl(file_path):
    data = []
    with jsonlines.open(file_path, mode="r") as reader:
        for obj in reader:
            data.append(obj)
    return data


# Accuracy, Precision, Recall, F1 Score, FPR
def statistics_on_generated_jsonl(data_list=[]):
    total = 0
    fail_generate_count = 0
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0

    # VULNERABLE or SAFE ("VULNERABLE\n" "SAFE\n" in label)
    for data in data_list:
        total += len(data)
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
    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) > 0
        else 0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) > 0
        else 0
    )
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0
    )
    fpr = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative) > 0
        else 0
    )

    print(f"Total items: {total}")
    print(f"Failed generations: {fail_generate_count}")
    print(
        f"True Positives: {true_positive}, False Positives: {false_positive}, True Negatives: {true_negative}, False Negatives: {false_negative}"
    )
    print(
        f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}, FPR: {fpr:.4f}"
    )

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
        "fpr": fpr,
    }


def statistics_on_jsonl_and_csv(csv_path, data_list=[]):
    total = 0
    fail_generate_count = 0
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0

    df = pd.read_csv(csv_path)

    for index, row in df.iterrows():
        idx = row["Idx"]
        prediction = row["Prediction"]
        label = row["Label"]

        if prediction == 1:
            total += 1
            if label == 1:
                true_positive += 1
            else:
                false_positive += 1
        else:
            continue

    print(f"total from csv: {total}")

    for data in data_list:
        total += len(data)
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
    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) > 0
        else 0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) > 0
        else 0
    )
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0
    )
    fpr = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative) > 0
        else 0
    )

    print(f"Total items: {total}")
    print(f"Failed generations: {fail_generate_count}")
    print(
        f"True Positives: {true_positive}, False Positives: {false_positive}, True Negatives: {true_negative}, False Negatives: {false_negative}"
    )
    print(
        f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}, FPR: {fpr:.4f}"
    )

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
        "fpr": fpr,
    }


if __name__ == "__main__":
    data0 = load_generated_jsonl(
        "../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2026-01-01-22-27-40-cvs-sft_fixed_negative/generated_predictions.jsonl"
    )
    # print(f"jsonl length: {len(data0)}")
    # statistics_on_generated_jsonl([data0])
    statistics_on_jsonl_and_csv(
        csv_path="./result/semgrep_rules_fixed_negative_primevul_train.cvs",
        data_list=[data0],
    )
