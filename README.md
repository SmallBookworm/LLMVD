# run:
local_huggingface_model: .venv/bin/python main.py --dataset devign --base_model Meta-Llama-3-8B

ollama: .venv/bin/python main.py --dataset devign

# metrics
Accuracy: 0.6364
Precision: 0.6667
Recall: 0.6667
FPR: 0.4000
F1: 0.6667