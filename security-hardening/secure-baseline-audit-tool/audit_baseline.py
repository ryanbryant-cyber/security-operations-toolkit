import csv
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

CONFIG_FILE = (
    BASE_DIR
    / "sample-data"
    / "windows_configuration.json"
)

BASELINE_FILE = (
    BASE_DIR
    / "baseline"
    / "windows_security_baseline.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "baseline_audit_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "baseline_audit_results.csv"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_equals(actual, expected):
    return actual == expected


def evaluate_minimum(actual, expected):
    return actual >= expected


def evaluate_maximum(actual, expected):
    return actual <= expected


def evaluate_range(actual, minimum, maximum):
    return minimum <= actual <= maximum


def evaluate_control(control, configuration):
    field = control["field"]
    operator = control["operator"]

    actual_value = configuration.get(field)

    if actual_value is None:
        return {
            "status": "REVIEW",
            "actual_value": None,
            "reason": "Configuration field was not present in the system snapshot."
        }

    if operator == "equals":
        passed = evaluate_equals(
            actual_value,
            control["expected_value"]
        )

        return {
            "status": "PASS" if passed else "FAIL",
            "actual_value": actual_value,
            "reason": (
                "Observed value matches baseline."
                if passed
                else "Observed value does not match baseline."
            )
        }

    if operator == "minimum":
        passed = evaluate_minimum(
            actual_value,
            control["expected_value"]
        )

        return {
            "status": "PASS" if passed else "FAIL",
            "actual_value": actual_value,
            "reason": (
                "Observed value meets or exceeds the required minimum."
                if passed
                else "Observed value is below the required minimum."
            )
        }

    if operator == "maximum":
        passed = evaluate_maximum(
            actual_value,
            control["expected_value"]
        )

        return {
            "status": "PASS" if passed else "FAIL",
            "actual_value": actual_value,
            "reason": (
                "Observed value is within the permitted maximum."
                if passed
                else "Observed value exceeds the permitted maximum."
            )
        }

    if operator == "range":
        passed = evaluate_range(
            actual_value,
            control["minimum_value"],
            control["maximum_value"]
        )

        return {
            "status": "PASS" if passed else "FAIL",
            "actual_value": actual_value,
            "reason": (
                "Observed value is within the approved range."
                if passed
                else "Observed value falls outside the approved range."
            )
        }

    if operator == "review_if_true":
        if actual_value is True:
            return {
                "status": "REVIEW",
                "actual_value": actual_value,
                "reason": (
                    "Setting is enabled and requires analyst review "
                    "to confirm business justification and safeguards."
                )
            }

        return {
            "status": "PASS",
            "actual_value": actual_value,
            "reason": "Setting is disabled."
        }

    if operator == "conditional_equals":
        condition = control["condition"]

        condition_field = condition["field"]
        condition_expected = condition["equals"]

        condition_actual = configuration.get(
            condition_field
        )

        if condition_actual != condition_expected:
            return {
                "status": "NOT_APPLICABLE",
                "actual_value": actual_value,
                "reason": (
                    f"Conditional control not applicable because "
                    f"{condition_field} is {condition_actual}."
                )
            }

        passed = evaluate_equals(
            actual_value,
            control["expected_value"]
        )

        return {
            "status": "PASS" if passed else "FAIL",
            "actual_value": actual_value,
            "reason": (
                "Conditional requirement is satisfied."
                if passed
                else "Conditional requirement is not satisfied."
            )
        }

    return {
        "status": "REVIEW",
        "actual_value": actual_value,
        "reason": f"Unsupported operator: {operator}"
    }


def build_expected_description(control):
    operator = control["operator"]

    if operator == "equals":
        return str(control["expected_value"])

    if operator == "minimum":
        return f">= {control['expected_value']}"

    if operator == "maximum":
        return f"<= {control['expected_value']}"

    if operator == "range":
        return (
            f"{control['minimum_value']} "
            f"through {control['maximum_value']}"
        )

    if operator == "review_if_true":
        return "Review if enabled"

    if operator == "conditional_equals":
        condition = control["condition"]

        return (
            f"{control['expected_value']} when "
            f"{condition['field']} = "
            f"{condition['equals']}"
        )

    return "Unknown"


def audit_system(system_data, baseline_data):
    configuration = system_data[
        "security_configuration"
    ]

    results = []

    for control in baseline_data["controls"]:
        evaluation = evaluate_control(
            control,
            configuration
        )

        result = {
            "control_id": control["control_id"],
            "name": control["name"],
            "category": control["category"],
            "field": control["field"],
            "operator": control["operator"],
            "expected": build_expected_description(
                control
            ),
            "actual": evaluation["actual_value"],
            "status": evaluation["status"],
            "severity": control["severity"],
            "reason": evaluation["reason"],
            "remediation": control["remediation"]
        }

        results.append(result)

    return results


def summarize_results(results):
    summary = {
        "total_controls": len(results),
        "pass": 0,
        "fail": 0,
        "review": 0,
        "not_applicable": 0
    }

    for result in results:
        status = result["status"]

        if status == "PASS":
            summary["pass"] += 1
        elif status == "FAIL":
            summary["fail"] += 1
        elif status == "REVIEW":
            summary["review"] += 1
        elif status == "NOT_APPLICABLE":
            summary["not_applicable"] += 1

    return summary


def export_json(
    system_data,
    baseline_data,
    results,
    summary
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "system": system_data["system"],
        "baseline": {
            "name": baseline_data[
                "baseline_name"
            ],
            "version": baseline_data[
                "baseline_version"
            ]
        },
        "summary": summary,
        "results": results
    }

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )


def export_csv(results):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "control_id",
        "name",
        "category",
        "field",
        "expected",
        "actual",
        "status",
        "severity",
        "reason",
        "remediation"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:
            writer.writerow({
                field: result[field]
                for field in fieldnames
            })


def print_results(
    system_data,
    results,
    summary
):
    system = system_data["system"]

    print()
    print("=" * 86)
    print("SECURE BASELINE AUDIT TOOL")
    print("=" * 86)

    print(
        f"Host: {system['hostname']} | "
        f"{system['operating_system']} | "
        f"{system['business_function']}"
    )

    print("-" * 86)

    for result in results:
        print(
            f"{result['status']:<14} "
            f"{result['control_id']} | "
            f"{result['name']} | "
            f"{result['severity']}"
        )

    print("=" * 86)
    print(
        f"Total Controls:  "
        f"{summary['total_controls']}"
    )
    print(
        f"PASS:            "
        f"{summary['pass']}"
    )
    print(
        f"FAIL:            "
        f"{summary['fail']}"
    )
    print(
        f"REVIEW:          "
        f"{summary['review']}"
    )
    print(
        f"NOT APPLICABLE:  "
        f"{summary['not_applicable']}"
    )
    print("=" * 86)

    print(
        f"JSON report: {JSON_OUTPUT}"
    )

    print(
        f"CSV report:  {CSV_OUTPUT}"
    )

    print("=" * 86)


def main():
    system_data = load_json(
        CONFIG_FILE
    )

    baseline_data = load_json(
        BASELINE_FILE
    )

    results = audit_system(
        system_data,
        baseline_data
    )

    summary = summarize_results(
        results
    )

    export_json(
        system_data,
        baseline_data,
        results,
        summary
    )

    export_csv(results)

    print_results(
        system_data,
        results,
        summary
    )


if __name__ == "__main__":
    main()
