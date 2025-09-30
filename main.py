from data_process.utils.loader import load_devign


def main():
    data=load_devign('./data/devign/function.json')
    print('length:'+str(len(data)))
    


if __name__ == "__main__":
    main()
