import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


SIGNIN_FILE = Path("sample-logs/signin_logs.csv")
PROCESS_FILE = Path("sample-logs/process_events.csv")
PRIVILEGED_FILE = Path("sample-logs/privileged_activity.csv")
NETWORK_FILE = Path("sample-logs/network_events.csv")

EXPECTATIONS_FILE = Path(
    "expected-results/hunt_expectations.json"
)

OUTPUT_DIR = Path("output")
OUTPUT_FILE = OUTPUT_DIR / "hunt_validation_results.json"


def load_csv(path):
    """Load a CSV file into a list of dictionaries."""
    with open(
        path,
        "r",
        encoding="utf-8",
        newline=""
    ) as csv_file:
        return list(csv.DictReader(csv_file))


def parse_time(value):
    """Convert ISO-8601 UTC text into datetime."""
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def seconds_between(later, earlier):
    """Return elapsed seconds between two timestamps."""
    return int(
        (
            parse_time(later)
            - parse_time(earlier)
        ).total_seconds()
    )


def short_account(upn):
    """Convert user@domain into short account name."""
    return upn.split("@", 1)[0]


def to_bool(value):
    """Convert CSV true/false text into Python bool."""
    return str(value).lower() == "true"


def hunt_01(signins):
    """Repeated failed sign-ins."""
    grouped = defaultdict(list)

    for row in signins:
        if str(row["ResultType"]) == "0":
            continue

        key = (
            row["UserPrincipalName"],
            row["IPAddress"]
        )

        grouped[key].append(row)

    findings = []

    for (identity, ip), rows in grouped.items():
        if len(rows) < 3:
            continue

        rows = sorted(
            rows,
            key=lambda x: parse_time(
                x["TimeGenerated"]
            )
        )

        findings.append({
            "identity": identity,
            "source_ip": ip,
            "failed_attempts": len(rows),
            "first_failure": rows[0]["TimeGenerated"],
            "last_failure": rows[-1]["TimeGenerated"]
        })

    return findings


def hunt_02(signins):
    """Successful sign-in after repeated failures."""
    failures = hunt_01(signins)
    findings = []

    for failure in failures:
        for row in signins:
            if str(row["ResultType"]) != "0":
                continue

            if (
                row["UserPrincipalName"]
                != failure["identity"]
            ):
                continue

            if row["IPAddress"] != failure["source_ip"]:
                continue

            elapsed = seconds_between(
                row["TimeGenerated"],
                failure["last_failure"]
            )

            if 0 <= elapsed <= 300:
                findings.append({
                    "identity": failure["identity"],
                    "source_ip": failure["source_ip"],
                    "failed_attempts":
                        failure["failed_attempts"],
                    "last_failure":
                        failure["last_failure"],
                    "success_time":
                        row["TimeGenerated"],
                    "seconds_after_last_failure":
                        elapsed
                })

    return findings


def hunt_03(signins):
    """Successful dormant-account activity."""
    findings = []

    for row in signins:
        if row["AccountStatus"].lower() != "dormant":
            continue

        if str(row["ResultType"]) != "0":
            continue

        findings.append({
            "identity": row["UserPrincipalName"],
            "source_ip": row["IPAddress"],
            "success_time": row["TimeGenerated"],
            "account_status": row["AccountStatus"],
            "device_compliant":
                to_bool(row["DeviceCompliant"]),
            "conditional_access":
                row["ConditionalAccessStatus"]
        })

    return findings


def suspicious_powershell(processes):
    """Return PowerShell events with suspicious arguments."""
    indicators = (
        "-encodedcommand",
        "-enc",
        "-executionpolicy bypass",
        "invoke-webrequest",
        "downloadstring"
    )

    findings = []

    for row in processes:
        if row["ProcessName"].lower() != "powershell.exe":
            continue

        command = row["CommandLine"].lower()

        if any(
            indicator in command
            for indicator in indicators
        ):
            findings.append(row)

    return findings


def hunt_04(processes):
    """Suspicious PowerShell activity."""
    findings = []

    for row in suspicious_powershell(processes):
        findings.append({
            "identity": row["AccountName"],
            "device": row["DeviceName"],
            "time": row["TimeGenerated"]
        })

    return findings


def hunt_05(signins, processes):
    """Dormant sign-in followed by suspicious PowerShell."""
    dormant = hunt_03(signins)
    powershell = suspicious_powershell(processes)

    findings = []

    for signin in dormant:
        account = short_account(signin["identity"])

        for process in powershell:
            if process["AccountName"] != account:
                continue

            elapsed = seconds_between(
                process["TimeGenerated"],
                signin["success_time"]
            )

            if 0 <= elapsed <= 300:
                findings.append({
                    "identity": signin["identity"],
                    "signin_time":
                        signin["success_time"],
                    "process_time":
                        process["TimeGenerated"],
                    "seconds_between": elapsed
                })

    return findings


def suspicious_role_changes(privileged):
    """Return ungoverned Contributor role changes."""
    findings = []

    valid_operations = {
        "add member to role",
        "role assignment modified"
    }

    for row in privileged:
        if row["ActivityStatus"].lower() != "success":
            continue

        if row["OperationName"].lower() not in valid_operations:
            continue

        if row["RoleName"].lower() == "none":
            continue

        missing_justification = (
            row["Justification"].strip() == ""
        )

        missing_ticket = (
            row["TicketNumber"].strip() == ""
            or row["TicketNumber"].upper() == "NONE"
        )

        if not (
            missing_justification
            or missing_ticket
        ):
            continue

        findings.append(row)

    return findings


def hunt_06(privileged):
    """Ungoverned privileged role assignments."""
    findings = []

    for row in suspicious_role_changes(privileged):
        findings.append({
            "identity": row["TargetUser"],
            "operation": row["OperationName"],
            "role": row["RoleName"],
            "time": row["TimeGenerated"]
        })

    return findings


def hunt_07(signins, processes, privileged):
    """Dormant sign-in -> PowerShell -> Contributor role."""
    dormant = hunt_03(signins)
    powershell = suspicious_powershell(processes)

    role_changes = [
        row
        for row in suspicious_role_changes(privileged)
        if row["RoleName"].lower() == "contributor"
    ]

    findings = []

    for signin in dormant:
        account = short_account(signin["identity"])

        for process in powershell:
            if process["AccountName"] != account:
                continue

            signin_to_process = seconds_between(
                process["TimeGenerated"],
                signin["success_time"]
            )

            if not 0 <= signin_to_process <= 300:
                continue

            for role in role_changes:
                if short_account(
                    role["TargetUser"]
                ) != account:
                    continue

                process_to_role = seconds_between(
                    role["TimeGenerated"],
                    process["TimeGenerated"]
                )

                if not 0 <= process_to_role <= 300:
                    continue

                findings.append({
                    "identity": account,
                    "signin_to_process_seconds":
                        signin_to_process,
                    "process_to_role_seconds":
                        process_to_role,
                    "role_operation":
                        role["OperationName"]
                })

    return findings


def hunt_08(
    signins,
    processes,
    privileged,
    network
):
    """Dormant chain followed by allowed network activity."""
    dormant = hunt_03(signins)
    powershell = suspicious_powershell(processes)

    role_changes = [
        row
        for row in suspicious_role_changes(privileged)
        if row["RoleName"].lower() == "contributor"
    ]

    network_activity = [
        row
        for row in network
        if row["Action"].lower() == "allow"
        and int(row["DestinationPort"]) in (443, 8443)
    ]

    findings = []

    for signin in dormant:
        account = short_account(signin["identity"])

        for process in powershell:
            if process["AccountName"] != account:
                continue

            signin_to_process = seconds_between(
                process["TimeGenerated"],
                signin["success_time"]
            )

            if not 0 <= signin_to_process <= 300:
                continue

            for role in role_changes:
                if short_account(
                    role["TargetUser"]
                ) != account:
                    continue

                process_to_role = seconds_between(
                    role["TimeGenerated"],
                    process["TimeGenerated"]
                )

                if not 0 <= process_to_role <= 300:
                    continue

                for net in network_activity:
                    if net["AccountName"] != account:
                        continue

                    role_to_network = seconds_between(
                        net["TimeGenerated"],
                        role["TimeGenerated"]
                    )

                    if not 0 <= role_to_network <= 300:
                        continue

                    findings.append({
                        "role_time":
                            role["TimeGenerated"],
                        "network_time":
                            net["TimeGenerated"],
                        "destination_ip":
                            net["DestinationIP"],
                        "destination_port":
                            int(net["DestinationPort"])
                    })

    return findings


def finance_core_sequence(
    signins,
    processes,
    network
):
    """Build the expected Finance-account core sequence."""
    failures = [
        row
        for row in signins
        if row["UserPrincipalName"].lower()
        == "finance.user@northstar.example"
        and str(row["ResultType"]) != "0"
    ]

    successes = [
        row
        for row in signins
        if row["UserPrincipalName"].lower()
        == "finance.user@northstar.example"
        and str(row["ResultType"]) == "0"
        and row["IPAddress"] == "198.51.100.24"
    ]

    processes_finance = sorted(
        [
            row
            for row in processes
            if row["AccountName"].lower()
            == "finance.user"
            and row["ProcessName"].lower()
            in ("powershell.exe", "cmd.exe")
        ],
        key=lambda x: parse_time(
            x["TimeGenerated"]
        )
    )

    suspicious_ps = [
        row
        for row in suspicious_powershell(processes)
        if row["AccountName"].lower()
        == "finance.user"
    ]

    blocked_smb = [
        row
        for row in network
        if row["AccountName"].lower()
        == "finance.user"
        and int(row["DestinationPort"]) == 445
        and row["Action"].lower() == "deny"
    ]

    unusual_8443 = [
        row
        for row in network
        if row["AccountName"].lower()
        == "finance.user"
        and int(row["DestinationPort"]) == 8443
    ]

    failures = sorted(
        failures,
        key=lambda x: parse_time(
            x["TimeGenerated"]
        )
    )

    success = successes[0]

    return {
        "identity":
            "finance.user@northstar.example",
        "failed_attempts":
            len(failures),
        "last_failure":
            failures[-1]["TimeGenerated"],
        "success_time":
            success["TimeGenerated"],
        "seconds_failure_to_success":
            seconds_between(
                success["TimeGenerated"],
                failures[-1]["TimeGenerated"]
            ),
        "first_follow_on_process":
            processes_finance[0]["TimeGenerated"],
        "suspicious_powershell":
            suspicious_ps[0]["TimeGenerated"],
        "blocked_smb":
            blocked_smb[0]["TimeGenerated"],
        "unusual_8443_connection":
            unusual_8443[0]["TimeGenerated"]
    }


def hunt_09(
    signins,
    processes,
    network
):
    """Count Finance multi-source join expansion."""
    failure_groups = hunt_01(signins)

    failure = next(
        item
        for item in failure_groups
        if item["identity"].lower()
        == "finance.user@northstar.example"
    )

    success = next(
        row
        for row in signins
        if row["UserPrincipalName"].lower()
        == "finance.user@northstar.example"
        and row["IPAddress"] == failure["source_ip"]
        and str(row["ResultType"]) == "0"
    )

    finance_processes = [
        row
        for row in processes
        if row["AccountName"].lower()
        == "finance.user"
        and row["ProcessName"].lower()
        in ("powershell.exe", "cmd.exe")
        and 0 <= seconds_between(
            row["TimeGenerated"],
            success["TimeGenerated"]
        ) <= 300
    ]

    finance_network = [
        row
        for row in network
        if row["AccountName"].lower()
        == "finance.user"
    ]

    findings = []

    for process in finance_processes:
        for net in finance_network:
            elapsed = seconds_between(
                net["TimeGenerated"],
                process["TimeGenerated"]
            )

            if 0 <= elapsed <= 300:
                findings.append({
                    "process_time":
                        process["TimeGenerated"],
                    "network_time":
                        net["TimeGenerated"],
                    "destination_ip":
                        net["DestinationIP"],
                    "destination_port":
                        int(net["DestinationPort"])
                })

    return findings


def hunt_10_categories(
    signins,
    processes,
    privileged,
    network
):
    """Calculate expected summary category counts."""

    finance_authentication = len(
        hunt_02(signins)
    )

    dormant_multi_stage = len(
        hunt_07(
            signins,
            processes,
            privileged
        )
    )

    powershell_findings = len(
        hunt_04(processes)
    )

    privilege_findings = len(
        [
            row
            for row in suspicious_role_changes(privileged)
            if row["RoleName"].lower()
            == "contributor"
        ]
    )

    interesting_ips = {
        "203.0.113.77",
        "203.0.113.88",
        "203.0.113.90",
        "203.0.113.91"
    }

    network_findings = len([
        row
        for row in network
        if (
            int(row["DestinationPort"])
            in (445, 8443)
            or row["DestinationIP"]
            in interesting_ips
        )
    ])

    return {
        "finance_authentication_finding":
            finance_authentication,
        "dormant_multi_stage_findings":
            dormant_multi_stage,
        "suspicious_powershell_findings":
            powershell_findings,
        "privileged_role_findings":
            privilege_findings,
        "high_interest_network_findings":
            network_findings
    }


def finding_exists(expected, actual_rows):
    """Check whether expected fields exist in an actual row."""
    return any(
        all(
            actual.get(key) == value
            for key, value in expected.items()
        )
        for actual in actual_rows
    )


def main():
    signins = load_csv(SIGNIN_FILE)
    processes = load_csv(PROCESS_FILE)
    privileged = load_csv(PRIVILEGED_FILE)
    network = load_csv(NETWORK_FILE)

    with open(
        EXPECTATIONS_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        expectations = json.load(file)

    actual_results = {
        "01": hunt_01(signins),
        "02": hunt_02(signins),
        "03": hunt_03(signins),
        "04": hunt_04(processes),
        "05": hunt_05(
            signins,
            processes
        ),
        "06": hunt_06(privileged),
        "07": hunt_07(
            signins,
            processes,
            privileged
        ),
        "08": hunt_08(
            signins,
            processes,
            privileged,
            network
        ),
        "09": hunt_09(
            signins,
            processes,
            network
        )
    }

    validation_results = []

    print("=== SENTINEL KQL HUNT VALIDATION ===\n")

    passed = 0

    for hunt in expectations["hunts"]:
        hunt_id = hunt["hunt_id"]

        if hunt_id == "10":
            actual_categories = hunt_10_categories(
                signins,
                processes,
                privileged,
                network
            )

            expected_categories = hunt[
                "expected_categories"
            ]

            actual_rows = sum(
                actual_categories.values()
            )

            row_match = (
                actual_rows
                == hunt["expected_rows"]
            )

            detail_match = (
                actual_categories
                == expected_categories
            )

            actual_detail = actual_categories

        elif hunt_id == "09":
            actual = actual_results[hunt_id]

            actual_rows = len(actual)

            row_match = (
                actual_rows
                == hunt["expected_rows"]
            )

            core = finance_core_sequence(
                signins,
                processes,
                network
            )

            expected_core = hunt[
                "expected_core_sequence"
            ]

            detail_match = (
                core == expected_core
            )

            actual_detail = {
                "join_rows": actual_rows,
                "core_sequence": core
            }

        else:
            actual = actual_results[hunt_id]

            actual_rows = len(actual)

            row_match = (
                actual_rows
                == hunt["expected_rows"]
            )

            expected_findings = hunt.get(
                "expected_findings",
                []
            )

            detail_match = all(
                finding_exists(
                    expected,
                    actual
                )
                for expected in expected_findings
            )

            actual_detail = actual

        status = (
            "PASS"
            if row_match and detail_match
            else "REVIEW"
        )

        if status == "PASS":
            passed += 1

        print(
            f"[{status}] Hunt {hunt_id} | "
            f"{hunt['title']} | "
            f"Expected rows: {hunt['expected_rows']} | "
            f"Actual rows: {actual_rows}"
        )

        validation_results.append({
            "hunt_id": hunt_id,
            "title": hunt["title"],
            "status": status,
            "expected_rows":
                hunt["expected_rows"],
            "actual_rows":
                actual_rows,
            "row_count_match":
                row_match,
            "detail_match":
                detail_match,
            "actual_results":
                actual_detail
        })

    OUTPUT_DIR.mkdir(exist_ok=True)

    report = {
        "lab":
            "Microsoft Sentinel KQL Threat Hunting Lab",
        "validation_method":
            (
                "Local Python validation against "
                "synthetic source CSV datasets. "
                "KQL was not executed locally."
            ),
        "summary": {
            "hunts_validated":
                len(validation_results),
            "hunts_passed":
                passed,
            "hunts_for_review":
                len(validation_results) - passed
        },
        "results":
            validation_results
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as output_file:
        json.dump(
            report,
            output_file,
            indent=4
        )

    print("\n=== VALIDATION SUMMARY ===")
    print(
        f"Hunts validated:   "
        f"{len(validation_results)}"
    )
    print(f"Hunts passed:      {passed}")
    print(
        f"Hunts for review:  "
        f"{len(validation_results) - passed}"
    )
    print(
        f"Validation report: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
