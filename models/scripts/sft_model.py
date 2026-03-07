from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification

data_files = {
    "train": "./data/primevul/primevul_train_paired.jsonl",
    "val": "./data/primevul/primevul_valid_paired.jsonl",
    "test": "./data/primevul/primevul_test_paired.jsonl"
}


dataset = load_dataset("json", data_files=data_files)


model_name = "/home/peng/.cache/modelscope/hub/models/microsoft/codebert-base"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

# 查看分类头是否可训练
print(model.classifier)  # 应为 True

def tokenize_function(examples):
    # PrimeVul 使用 'func' 字段作为代码输入
    return tokenizer(
        examples["func"],
        truncation=True,
        padding="max_length",
        max_length=512,
        return_tensors="pt"
    )

tokenized_datasets = dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["func"]  # 不需要原始文本了
)

# 将标签列重命名为 'labels'（Trainer 要求）
tokenized_datasets = tokenized_datasets.rename_column("target", "labels")

# 设置 PyTorch 格式
tokenized_datasets.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])

from transformers import TrainingArguments, Trainer
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score
import numpy as np

def compute_metrics(eval_pred):
    predictions, labels = eval_pred
    preds = np.argmax(predictions, axis=1)
    return {
        "f1": f1_score(labels, preds),
        "accuracy": accuracy_score(labels, preds),
        "precision": precision_score(labels, preds),
        "recall": recall_score(labels, preds),
        "fpr": np.sum((preds == 1) & (labels == 0)) / np.sum(labels == 0)  # False Positive Rate
    }

training_args = TrainingArguments(
    output_dir="./codebert-primevul-local",
    eval_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=3,
    weight_decay=0.01,
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True,
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets["train"],
    eval_dataset=tokenized_datasets["val"],
    compute_metrics=compute_metrics,
)

# 微调
trainer.train()

# 在测试集上评估
test_results = trainer.evaluate(eval_dataset=tokenized_datasets["test"])
print("Test Results:", test_results)