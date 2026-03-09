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
            elif "SAFE" in item.get("predict"):
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


# analyse jsonl and csv results (only count positive prediction in csv)
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

# only approve positive for same prediction in two jsonl files
# dotaset1 longer than dataset2
def prediction_approve_between_jsonl(
    data1,
    data2,
):
    total = 0
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    problem_count=0

    j=0
    for i in range(len(data2)):
        j=i
        for k in range(i, len(data1)):
            if data1[k].get("prompt") in data2[i].get("prompt"):
                j=k
                break
        if data1[j].get("prompt") not in data2[i].get("prompt"):
            print("Different prompt!")
            problem_count+=1
            continue
        total+=1
        if data1[j].get("predict") == "VULNERABLE" and data1[j].get("predict") == data2[i].get("predict"):
            if "VULNERABLE" in data1[j].get("label"):
                true_positive += 1
            else:
                false_positive += 1
        else:
            if "VULNERABLE" in data1[j].get("label"):
                false_negative += 1
            else:
                true_negative += 1

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
    print(f"Problem count (different prompts): {problem_count}")
    print(f"Total items: {total},real total{real_total}")
    print(
        f"True Positives: {true_positive}, False Positives: {false_positive}, True Negatives: {true_negative}, False Negatives: {false_negative}"
    )
    print(
        f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}, FPR: {fpr:.4f}"
    )

    return {
        "total": total,
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
# only approve negative for same prediction in two jsonl files
# dotaset1 longer than dataset2
def prediction_reject_between_jsonl(
    data1,
    data2,
):    
    total = 0
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    problem_count=0
    j=0
    for i in range(len(data2)):
        j=i
        for k in range(i, len(data1)):
            if data1[k].get("prompt") in data2[i].get("prompt"):
                j=k
                break
        if data1[j].get("prompt") not in data2[i].get("prompt"):
            print("Different prompt!")
            problem_count+=1
            continue
        total+=1
        if data1[j].get("predict") == "SAFE" and data1[j].get("predict") == data2[i].get("predict"):
            if "SAFE" in data1[j].get("label"):
                true_negative += 1
            else:
                false_negative += 1
        else:
            if "SAFE" in data1[j].get("label"):
                false_positive += 1
            else:
                true_positive += 1
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
    print(f"Problem count (different prompts): {problem_count}")
    print(f"Total items: {total},real total{real_total}")
    print(
        f"True Positives: {true_positive}, False Positives: {false_positive}, True Negatives: {true_negative}, False Negatives: {false_negative}"
    )
    print(
        f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}, FPR: {fpr:.4f}"
    )
    return {
        "total": total,
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


def change_csv_to_jsonl(csv_path):
    df = pd.read_csv(csv_path)
    data=[]
    for index, row in df.iterrows():
        item = {
            "idx": row["Idx"],
            "label": 'VULNERABLE' if row["Label"] == 1 else 'SAFE',
            "predict": 'VULNERABLE' if row["Prediction"] == 1 else 'SAFE',
            "prompt": row["Code"]
        }
        data.append(item)
    return data

if __name__ == "__main__":

    data0 = load_generated_jsonl(
        "../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2026-01-21-21-40-37-primevul_test_part0-sft_after/generated_predictions.jsonl"
    )
    data1 = load_generated_jsonl(
        "../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2026-01-21-21-40-37-primevul_test_part1-sft_after/generated_predictions.jsonl"
    )
    # data2=change_csv_to_jsonl("./result/semgrep_rules_fixed_negative_primevul_test_paired.cvs")
    # print(f"1json length: {len(data1)},2json length: {len(data2)}")
    # print(data2[10])
    # print(data1[10])
    # print(f"jsonl length: {len(data0)}")
    # statistics_on_generated_jsonl([data0,data1])
    # statistics_on_jsonl_and_csv(
    #     csv_path="./result/semgrep_rules_fixed_negative_primevul_train.cvs",
    #     data_list=[data0],
    # )
    # prediction_approve_between_jsonl(data2, data1)
    # statistics_on_jsonl_and_csv(
    #     csv_path="./result/semgrep_rules_fixed_negative_precision_primevul_test_paired.cvs",
    #     data_list=[data0],
    # )
    data0 = load_generated_jsonl(
        "../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2026-01-01-14-16-14-devign_32768_data_part0-origin/generated_predictions.jsonl"
    )
    data1 = load_generated_jsonl(
        "../LLaMA-Factory/saves/Qwen2.5-Coder-7B-Instruct/lora/eval_2026-01-01-14-16-14-devign_32768_data_part1-origin/generated_predictions.jsonl"
    )
    data2=change_csv_to_jsonl("./result/semgrep_rules_fixed_negative_precision_devign.cvs")
    prediction_reject_between_jsonl(data2, data0+data1)
