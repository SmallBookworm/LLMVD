from data_process.utils.loader import load_primevul
from data_process.utils.process import list_by_cwe
import pathlib
from statsmodels.stats.proportion import proportion_confint


def get_cwe_statistics(data, length_threshold=90):
    cwe_list = list_by_cwe(data)
    total_cwe = len(cwe_list)
    cwe_with_more_than_t_samples = sum(
        1 for cwe in cwe_list if len(cwe_list[cwe]) > length_threshold
    )
    average_samples_per_cwe = (
        sum(len(cwe_list[cwe]) for cwe in cwe_list) / total_cwe if total_cwe > 0 else 0
    )

    return {
        "total_cwe": total_cwe,
        f"cwe_with_more_than_{length_threshold}_samples": cwe_with_more_than_t_samples,
        "average_samples_per_cwe": average_samples_per_cwe,
        "list": cwe_list,
    }


def get_rules_statistics(path="./rules/"):
    rule_dict = {}
    rule_path = pathlib.Path(path)
    for cwe_dir in rule_path.iterdir():
        if cwe_dir.is_dir() and cwe_dir.name.startswith("CWE-"):
            cwe_id = cwe_dir.name
            rule_files = list(cwe_dir.glob("*.yaml"))
            rule_dict[cwe_id] = rule_files
    return rule_dict


if __name__ == "__main__":
    data=load_primevul()
    cwe_list =list_by_cwe(data)
    rule_dict = get_rules_statistics('./rules_fixed_negative/')
    total_rules = sum(len(rule_dict[cwe]) for cwe in rule_dict)
    total_samples = sum(len(cwe_list[cwe]) for cwe in cwe_list)
    average_percentage = total_rules / total_samples
    for cwe in cwe_list:
        samples_num=len(cwe_list[cwe])
        if cwe in rule_dict:
            rules_num=len(rule_dict[cwe])
            ci = proportion_confint(rules_num, samples_num, method='wilson')
            if samples_num>10 and ci[1] <average_percentage:
                print(f"{cwe}: {samples_num} samples, {rules_num} rules. percentage: {(rules_num/samples_num)*100 if rules_num>0 else 'N/A'}%. Wilson 95% CI: {ci}")
        else:
            print(f"{cwe}: {samples_num} samples, 0 rules. Wilson 95% CI: {proportion_confint(0, samples_num, method='wilson')}")
    print(f'Total: {total_samples} samples, {total_rules} rules. average percentage:{average_percentage*100 if total_samples>0 else "N/A"}%')
    print(f"total CWEs with rules: {len(rule_dict)}, total CWEs in dataset: {len(cwe_list)}")
