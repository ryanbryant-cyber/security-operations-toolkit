import csv
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

PROCESS_FILE = (
    BASE_DIR
    / "sample-data"
    / "processes.csv"
)

COMMAND_FILE = (
    BASE_DIR
    / "sample-data"
    / "command_lines.csv"
)

NETWORK_FILE = (
    BASE_DIR
    / "sample-data"
    / "network_connections.csv"
)

MODULE_FILE = (
    BASE_DIR
    / "sample-data"
    / "loaded_modules.csv"
)

MEMORY_FILE = (
    BASE_DIR
    / "sample-data"
    / "memory_regions.csv"
)

RULES_FILE = (
    BASE_DIR
    / "rules"
    / "forensic_rules.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "memory_forensics_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "memory_forensics_findings.csv"
)


def load_csv(path):
    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def to_bool(value):
    return str(value).strip().lower() == "true"


def is_external_ip(ip):
    return (
        ip
        and ip != "0.0.0.0"
        and not ip.startswith("10.")
    )


def assign_priority(score, thresholds):
    if score >= thresholds["HIGH"]:
        return "HIGH"

    if score >= thresholds["MODERATE"]:
        return "MODERATE"

    return "LOW"


def add_indicator(
    indicators,
    category,
    name,
    points,
    evidence
):
    indicators.append({
        "category": category,
        "indicator": name,
        "points": points,
        "evidence": evidence
    })


def find_process(processes, pid):
    for process in processes:
        if process["pid"] == str(pid):
            return process

    return None


def child_processes(processes, parent_pid):
    return [
        process
        for process in processes
        if process["ppid"] == str(parent_pid)
    ]


def build_process_chain(processes):
    suspicious_chain = []

    word = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "winword.exe"
        ),
        None
    )

    powershell = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "powershell.exe"
        ),
        None
    )

    rundll32 = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "rundll32.exe"
        ),
        None
    )

    cmd = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "cmd.exe"
        ),
        None
    )

    for process in [
        word,
        powershell,
        rundll32,
        cmd
    ]:
        if process is not None:
            suspicious_chain.append({
                "pid": process["pid"],
                "ppid": process["ppid"],
                "process_name": process[
                    "process_name"
                ],
                "user": process["user"],
                "timestamp": process[
                    "timestamp"
                ]
            })

    return suspicious_chain


def analyze_process_relationships(
    processes,
    rules,
    indicators
):
    score = 0

    relationship_rules = rules[
        "process_relationships"
    ]

    office_names = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe"
    }

    powershell = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "powershell.exe"
        ),
        None
    )

    rundll32 = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "rundll32.exe"
        ),
        None
    )

    cmd = next(
        (
            process
            for process in processes
            if process["process_name"].lower()
            == "cmd.exe"
        ),
        None
    )

    if powershell:
        parent = find_process(
            processes,
            powershell["ppid"]
        )

        if (
            parent
            and parent["process_name"].lower()
            in office_names
        ):
            rule = relationship_rules[
                "office_spawns_powershell"
            ]

            score += rule["points"]

            add_indicator(
                indicators,
                "Process Relationship",
                "Office process spawned PowerShell",
                rule["points"],
                (
                    f"{parent['process_name']} PID "
                    f"{parent['pid']} spawned "
                    f"powershell.exe PID "
                    f"{powershell['pid']}."
                )
            )

    if rundll32 and powershell:
        if rundll32["ppid"] == powershell["pid"]:
            rule = relationship_rules[
                "powershell_spawns_rundll32"
            ]

            score += rule["points"]

            add_indicator(
                indicators,
                "Process Relationship",
                "PowerShell spawned rundll32",
                rule["points"],
                (
                    f"powershell.exe PID "
                    f"{powershell['pid']} spawned "
                    f"rundll32.exe PID "
                    f"{rundll32['pid']}."
                )
            )

    if cmd and powershell:
        if cmd["ppid"] == powershell["pid"]:
            rule = relationship_rules[
                "powershell_spawns_cmd"
            ]

            score += rule["points"]

            add_indicator(
                indicators,
                "Process Relationship",
                "PowerShell spawned command shell",
                rule["points"],
                (
                    f"powershell.exe PID "
                    f"{powershell['pid']} spawned "
                    f"cmd.exe PID {cmd['pid']}."
                )
            )

    return score


def analyze_command_lines(
    commands,
    rules,
    indicators
):
    score = 0

    command_rules = rules[
        "command_line_indicators"
    ]

    all_command_text = " ".join(
        command["command_line"]
        for command in commands
    ).lower()

    powershell_command = next(
        (
            command
            for command in commands
            if command["process_name"].lower()
            == "powershell.exe"
        ),
        None
    )

    if powershell_command:
        command_line = powershell_command[
            "command_line"
        ].lower()

        encoded_rule = command_rules[
            "encoded_command"
        ]

        if any(
            pattern.lower() in command_line
            for pattern in encoded_rule["patterns"]
        ):
            score += encoded_rule["points"]

            add_indicator(
                indicators,
                "Command Line",
                "Encoded PowerShell command",
                encoded_rule["points"],
                powershell_command["command_line"]
            )

        bypass_rule = command_rules[
            "execution_policy_bypass"
        ]

        if any(
            pattern.lower() in command_line
            for pattern in bypass_rule["patterns"]
        ):
            score += bypass_rule["points"]

            add_indicator(
                indicators,
                "Command Line",
                "PowerShell execution policy bypass",
                bypass_rule["points"],
                powershell_command["command_line"]
            )

        profile_rule = command_rules[
            "no_profile"
        ]

        if any(
            pattern.lower() in command_line
            for pattern in profile_rule["patterns"]
        ):
            score += profile_rule["points"]

            add_indicator(
                indicators,
                "Command Line",
                "PowerShell launched without profile",
                profile_rule["points"],
                powershell_command["command_line"]
            )

    discovery_rule = command_rules[
        "discovery_commands"
    ]

    matched_patterns = [
        pattern
        for pattern
        in discovery_rule["patterns"]
        if pattern.lower() in all_command_text
    ]

    if (
        len(matched_patterns)
        >= discovery_rule["minimum_matches"]
    ):
        score += discovery_rule["points"]

        add_indicator(
            indicators,
            "Command Line",
            "Multiple discovery commands",
            discovery_rule["points"],
            (
                "Matched discovery patterns: "
                + ", ".join(matched_patterns)
            )
        )

    return score


def analyze_modules(
    modules,
    rules,
    indicators
):
    score = 0

    module_rules = rules[
        "module_indicators"
    ]

    suspicious_modules = []

    for module in modules:
        module_path = module["module_path"]
        unsigned = (
            module["signed"].strip().lower()
            == "no"
        )

        user_writable = (
            "\\users\\" in module_path.lower()
            or "\\appdata\\local\\temp\\"
            in module_path.lower()
        )

        if unsigned:
            suspicious_modules.append(module)

    if suspicious_modules:
        rule = module_rules["unsigned_module"]

        score += rule["points"]

        add_indicator(
            indicators,
            "Loaded Module",
            "Unsigned module loaded",
            rule["points"],
            "; ".join(
                (
                    f"{module['module_name']} in "
                    f"{module['process_name']}"
                )
                for module in suspicious_modules
            )
        )

    writable_modules = [
        module
        for module in modules
        if (
            "\\users\\"
            in module["module_path"].lower()
            or "\\appdata\\local\\temp\\"
            in module["module_path"].lower()
        )
    ]

    if writable_modules:
        rule = module_rules[
            "user_writable_module_path"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Loaded Module",
            "Module loaded from user-writable path",
            rule["points"],
            "; ".join(
                module["module_path"]
                for module in writable_modules
            )
        )

    temp_unsigned = [
        module
        for module in modules
        if (
            module["signed"].strip().lower()
            == "no"
            and "\\appdata\\local\\temp\\"
            in module["module_path"].lower()
            and module["module_name"].lower()
            .endswith(".dll")
        )
    ]

    if temp_unsigned:
        rule = module_rules[
            "unsigned_temp_dll"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Loaded Module",
            "Unsigned DLL loaded from Temp",
            rule["points"],
            "; ".join(
                module["module_path"]
                for module in temp_unsigned
            )
        )

    return score


def analyze_network(
    connections,
    rules,
    indicators
):
    score = 0

    network_rules = rules[
        "network_indicators"
    ]

    rundll_connections = [
        connection
        for connection in connections
        if (
            connection["process_name"].lower()
            == "rundll32.exe"
            and connection["direction"].lower()
            == "outbound"
            and is_external_ip(
                connection["remote_ip"]
            )
        )
    ]

    if rundll_connections:
        rule = network_rules[
            "external_connection_from_rundll32"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Network",
            "External connection from rundll32",
            rule["points"],
            "; ".join(
                (
                    f"{connection['remote_ip']}:"
                    f"{connection['remote_port']}"
                )
                for connection
                in rundll_connections
            )
        )

    powershell_connections = [
        connection
        for connection in connections
        if (
            connection["process_name"].lower()
            == "powershell.exe"
            and connection["direction"].lower()
            == "outbound"
            and is_external_ip(
                connection["remote_ip"]
            )
        )
    ]

    if powershell_connections:
        rule = network_rules[
            "external_connection_from_powershell"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Network",
            "External connection from PowerShell",
            rule["points"],
            "; ".join(
                (
                    f"{connection['remote_ip']}:"
                    f"{connection['remote_port']}"
                )
                for connection
                in powershell_connections
            )
        )

    uncommon_rule = network_rules[
        "uncommon_destination_port"
    ]

    uncommon_connections = [
        connection
        for connection in connections
        if int(connection["remote_port"] or 0)
        in uncommon_rule["ports"]
    ]

    if uncommon_connections:
        score += uncommon_rule["points"]

        add_indicator(
            indicators,
            "Network",
            "Higher-interest destination port",
            uncommon_rule["points"],
            "; ".join(
                (
                    f"{connection['process_name']} → "
                    f"{connection['remote_ip']}:"
                    f"{connection['remote_port']}"
                )
                for connection
                in uncommon_connections
            )
        )

    smb_rule = network_rules[
        "attempted_internal_smb"
    ]

    smb_attempts = [
        connection
        for connection in connections
        if (
            int(connection["remote_port"] or 0)
            == smb_rule["port"]
            and connection["state"]
            == smb_rule["state"]
        )
    ]

    if smb_attempts:
        score += smb_rule["points"]

        add_indicator(
            indicators,
            "Network",
            "Attempted internal SMB communication",
            smb_rule["points"],
            "; ".join(
                (
                    f"{connection['process_name']} → "
                    f"{connection['remote_ip']}:445 "
                    f"({connection['state']})"
                )
                for connection in smb_attempts
            )
        )

    return score


def analyze_memory_regions(
    regions,
    rules,
    indicators
):
    score = 0

    memory_rules = rules[
        "memory_indicators"
    ]

    rwx_regions = [
        region
        for region in regions
        if (
            region["protection"]
            == memory_rules[
                "private_rwx_region"
            ]["protection"]
            and to_bool(
                region["private_memory"]
            )
        )
    ]

    if rwx_regions:
        rule = memory_rules[
            "private_rwx_region"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Memory Region",
            "Private RWX memory",
            rule["points"],
            "; ".join(
                (
                    f"{region['process_name']} PID "
                    f"{region['pid']} at "
                    f"{region['region_start']}"
                )
                for region in rwx_regions
            )
        )

    unbacked_exec = [
        region
        for region in regions
        if (
            to_bool(region["private_memory"])
            and to_bool(region["executable"])
            and not region["backing_file"].strip()
            and region["protection"] != "RWX"
        )
    ]

    if unbacked_exec:
        rule = memory_rules[
            "private_executable_unbacked_region"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Memory Region",
            "Private executable memory without backing file",
            rule["points"],
            "; ".join(
                (
                    f"{region['process_name']} PID "
                    f"{region['pid']} at "
                    f"{region['region_start']} "
                    f"({region['protection']})"
                )
                for region in unbacked_exec
            )
        )

    return score


def build_timeline(
    processes,
    commands,
    connections,
    modules,
    regions
):
    timeline = []

    interesting_processes = {
        "winword.exe",
        "powershell.exe",
        "rundll32.exe",
        "cmd.exe",
        "whoami.exe",
        "ipconfig.exe",
        "net.exe"
    }

    for process in processes:
        if process["process_name"].lower() in interesting_processes:
            timeline.append({
                "timestamp": process["timestamp"],
                "source": "Process",
                "event": (
                    f"{process['process_name']} "
                    f"started as PID {process['pid']}"
                )
            })

    for connection in connections:
        if connection["process_name"].lower() in {
            "powershell.exe",
            "rundll32.exe",
            "cmd.exe"
        }:
            timeline.append({
                "timestamp": connection["timestamp"],
                "source": "Network",
                "event": (
                    f"{connection['process_name']} → "
                    f"{connection['remote_ip']}:"
                    f"{connection['remote_port']} "
                    f"({connection['state']})"
                )
            })

    for module in modules:
        if module["module_name"].lower() == "financehelper.dll":
            timeline.append({
                "timestamp": module["timestamp"],
                "source": "Module",
                "event": (
                    f"{module['module_name']} loaded by "
                    f"{module['process_name']}"
                )
            })

    for region in regions:
        if (
            region["process_name"].lower()
            == "rundll32.exe"
            and to_bool(region["private_memory"])
            and to_bool(region["executable"])
        ):
            timeline.append({
                "timestamp": region["timestamp"],
                "source": "Memory",
                "event": (
                    f"{region['process_name']} contained "
                    f"{region['protection']} private "
                    f"executable memory at "
                    f"{region['region_start']}"
                )
            })

    timeline.sort(
        key=lambda item: item["timestamp"]
    )

    return timeline


def analyze():
    processes = load_csv(PROCESS_FILE)
    commands = load_csv(COMMAND_FILE)
    connections = load_csv(NETWORK_FILE)
    modules = load_csv(MODULE_FILE)
    regions = load_csv(MEMORY_FILE)
    rules = load_json(RULES_FILE)

    indicators = []

    score = 0

    score += analyze_process_relationships(
        processes,
        rules,
        indicators
    )

    score += analyze_command_lines(
        commands,
        rules,
        indicators
    )

    score += analyze_modules(
        modules,
        rules,
        indicators
    )

    score += analyze_network(
        connections,
        rules,
        indicators
    )

    score += analyze_memory_regions(
        regions,
        rules,
        indicators
    )

    final_score = min(
        score,
        rules["maximum_score"]
    )

    priority = assign_priority(
        final_score,
        rules["priority_thresholds"]
    )

    process_chain = build_process_chain(
        processes
    )

    timeline = build_timeline(
        processes,
        commands,
        connections,
        modules,
        regions
    )

    finding = {
        "finding_id": "MEM-INV-001",
        "finding_type": (
            "Correlated Suspicious Memory Activity"
        ),
        "host": "NFG-FIN-WS07",
        "user": "finance.user",
        "risk_score": final_score,
        "investigation_priority": priority,
        "confidence_statement": rules[
            "confidence_language"
        ][priority],
        "indicator_count": len(indicators),
        "indicators": indicators,
        "process_chain": process_chain,
        "timeline": timeline,
        "analyst_assessment": (
            "Multiple independent forensic artifacts "
            "converge on a suspicious process chain "
            "involving Microsoft Word, PowerShell, "
            "rundll32.exe, discovery commands, outbound "
            "network communication, an unsigned DLL "
            "loaded from a user-writable Temp directory, "
            "and private executable memory. The evidence "
            "supports high-priority investigation but "
            "does not independently prove malware, "
            "command-and-control, process injection, or "
            "successful lateral movement."
        ),
        "guardrails": rules[
            "analyst_guardrails"
        ]
    }

    return finding


def export_results(finding):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "summary": {
            "findings": 1,
            "high_priority_findings": (
                1
                if finding[
                    "investigation_priority"
                ] == "HIGH"
                else 0
            )
        },
        "finding": finding
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

    fieldnames = [
        "finding_id",
        "finding_type",
        "host",
        "user",
        "risk_score",
        "investigation_priority",
        "indicator_count",
        "analyst_assessment"
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

        writer.writerow({
            field: finding[field]
            for field in fieldnames
        })


def print_results(finding):
    print()
    print("=" * 92)
    print("WINDOWS MEMORY FORENSICS INVESTIGATION LAB")
    print("=" * 92)

    print(
        f"Finding:  {finding['finding_id']}"
    )

    print(
        f"Host:     {finding['host']}"
    )

    print(
        f"User:     {finding['user']}"
    )

    print(
        f"Score:    {finding['risk_score']}"
    )

    print(
        f"Priority: "
        f"{finding['investigation_priority']}"
    )

    print(
        f"Indicators: "
        f"{finding['indicator_count']}"
    )

    print("-" * 92)

    for indicator in finding["indicators"]:
        print(
            f"[{indicator['category']}] "
            f"{indicator['indicator']} "
            f"(+{indicator['points']})"
        )

    print("-" * 92)

    print(
        "Analyst Assessment:"
    )

    print(
        finding["analyst_assessment"]
    )

    print("=" * 92)

    print(
        f"JSON report: {JSON_OUTPUT}"
    )

    print(
        f"CSV report:  {CSV_OUTPUT}"
    )

    print("=" * 92)


def main():
    finding = analyze()

    export_results(
        finding
    )

    print_results(
        finding
    )


if __name__ == "__main__":
    main()