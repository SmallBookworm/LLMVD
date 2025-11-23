import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np

def fpr_score(y_true, y_pred):
    y_true, y_pred = np.array(y_true, dtype=np.int32), np.array(y_pred, dtype=np.int32)
    FP = sum((y_true == 0) & (y_pred == 1))
    TN = sum((y_true == 0) & (y_pred == 0))
    if (FP + TN) == 0:
        return 0.
    else:
        return FP / (FP + TN)

def print_metrics_from_csv(csv_path):
    df = pd.read_csv(csv_path)

    # 确保 Label 和 Prediction 是整数类型
    # 注意：你的 CSV 中 Label 可能是字符串 '0'/'1'，Prediction 是整数 0/1
    y_true = df['Label'].apply(lambda x: 1 if str(x).strip() == '1' else 0).tolist()
    y_pred = df['Prediction'].astype(int).tolist()

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fpr_score(y_true, y_pred)

    print(f'Length: {len(y_pred)}, positive samples num:{sum(y_true)}, negative samples num:{len(y_true)-sum(y_true)}, true_positive:{sum((np.array(y_true)==1)&(np.array(y_pred)==1))}, false_positive:{sum((np.array(y_true)==0)&(np.array(y_pred)==1))}')
    print(f'Accuracy: {accuracy:.4f}')
    print(f'Precision: {precision:.4f}')
    print(f'Recall: {recall:.4f}')
    print(f'FPR: {fpr:.4f}')
    print(f'F1: {f1:.4f}')

if __name__ == "__main__":
    csv_path = '/home/peng/project/LLM4CVD/outputs/llama3_lora/reveal_0-512/results.csv'  # 替换为你的 CSV 路径
    print_metrics_from_csv(csv_path)