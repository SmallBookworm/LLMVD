from models.generate_train_data import generate_train_data
from data_process.utils.loader import load_primevul

if __name__ == "__main__":
    res=generate_train_data(load_primevul())
    print(len(res))
