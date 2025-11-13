from data_process.utils.loader import load_primevul
from data_process.utils.process import list_by_cwe


if __name__ == "__main__":
    data = load_primevul()
    list=list_by_cwe(data)
    total=0
    all=0
    for cwe in list:
        if len(list[cwe])>90:
            total+=1
            all+=len(list[cwe])
            print(f"CWE-{cwe}: ")
    print('cwe length:', len(list))
    print('cwe with more than 10 samples:', total)
    print('average samples per cwe:', all)