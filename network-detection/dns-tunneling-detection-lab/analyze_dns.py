import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DNS_FILE = (
    BASE_DIR
    / "sample-data"
    / "dns_queries.csv"
)

RULES_FILE = (
    BASE_DIR
    / "rules"
    / "dns_detection_rules.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "dns_detection_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "dns_detection_summary.csv"
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
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def parse_time(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def assign_priority(score, thresholds):
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"

    if score >= thresholds["HIGH"]:
        return "HIGH"

    if score >= thresholds["MODERATE"]:
        return "MODERATE"

    return "LOW"


def add_indicator(
    indicators,
    name,
    points,
    evidence
):
    indicators.append({
        "indicator": name,
        "points": points,
        "evidence": evidence
    })


def get_subdomain_label(query_name, parent_domain):
    suffix = "." + parent_domain.lower()
    query = query_name.lower()

    if query.endswith(suffix):
        return query[
            : -len(suffix)
        ].rstrip(".")

    return ""


def encoded_looking(label, rules):
    pattern = rules["encoded_pattern"]

    if len(label) < pattern["minimum_label_length"]:
        return False

    allowed = set(
        pattern["allowed_characters"].lower()
    )

    characters = [
        char
        for char in label.lower()
        if char.isalnum()
    ]

    if not characters:
        return False

    matching = sum(
        1
        for char in characters
        if char in allowed
    )

    ratio = (
        matching
        / len(characters)
    )

    return (
        ratio
        >= rules["thresholds"][
            "encoded_pattern_minimum_ratio"
        ]
    )


def group_dns_events(events):
    grouped = defaultdict(list)

    for event in events:
        key = (
            event["source_host"],
            event["source_ip"],
            event["parent_domain"]
        )

        grouped[key].append(event)

    for key in grouped:
        grouped[key].sort(
            key=lambda item: parse_time(
                item["timestamp"]
            )
        )

    return grouped


def average_interval_seconds(events):
    if len(events) < 2:
        return None

    differences = []

    for index in range(
        1,
        len(events)
    ):
        current = parse_time(
            events[index]["timestamp"]
        )

        previous = parse_time(
            events[index - 1]["timestamp"]
        )

        differences.append(
            (
                current
                - previous
            ).total_seconds()
        )

    if not differences:
        return None

    return round(
        sum(differences)
        / len(differences),
        2
    )


def analyze_group(
    source_host,
    source_ip,
    parent_domain,
    events,
    rules
):
    thresholds = rules["thresholds"]
    weights = rules["risk_weights"]

    indicators = []
    score = 0

    labels = [
        get_subdomain_label(
            event["query_name"],
            parent_domain
        )
        for event in events
    ]

    labels = [
        label
        for label in labels
        if label
    ]

    unique_labels = set(labels)

    query_count = len(events)

    txt_count = sum(
        1
        for event in events
        if event["query_type"].upper()
        == "TXT"
    )

    long_labels = [
        label
        for label in labels
        if len(label)
        >= thresholds[
            "long_subdomain_length"
        ]
    ]

    encoded_labels = [
        label
        for label in labels
        if encoded_looking(
            label,
            rules
        )
    ]

    unique_ratio = (
        round(
            len(unique_labels)
            / len(labels),
            4
        )
        if labels
        else 0
    )

    encoded_ratio = (
        round(
            len(encoded_labels)
            / len(labels),
            4
        )
        if labels
        else 0
    )

    long_ratio = (
        round(
            len(long_labels)
            / len(labels),
            4
        )
        if labels
        else 0
    )

    avg_interval = average_interval_seconds(
        events
    )

    start_time = events[0]["timestamp"]
    end_time = events[-1]["timestamp"]

    window_seconds = int(
        (
            parse_time(end_time)
            - parse_time(start_time)
        ).total_seconds()
    )

    # --------------------------------------------------
    # HIGH QUERY FREQUENCY
    # --------------------------------------------------

    if (
        query_count
        >= thresholds[
            "minimum_queries_to_parent_domain"
        ]
        and avg_interval is not None
        and avg_interval
        <= thresholds[
            "high_frequency_average_seconds"
        ]
    ):
        points = weights[
            "high_query_frequency"
        ]

        score += points

        add_indicator(
            indicators,
            "High query frequency",
            points,
            (
                f"{query_count} queries were observed "
                f"with an average interval of "
                f"{avg_interval} seconds."
            )
        )

    # --------------------------------------------------
    # LONG SUBDOMAIN LABELS
    # --------------------------------------------------

    if (
        query_count
        >= thresholds[
            "minimum_queries_to_parent_domain"
        ]
        and long_labels
    ):
        points = weights[
            "long_subdomain_labels"
        ]

        score += points

        add_indicator(
            indicators,
            "Long subdomain labels",
            points,
            (
                f"{len(long_labels)} of "
                f"{len(labels)} subdomain labels "
                f"were at least "
                f"{thresholds['long_subdomain_length']} "
                "characters long."
            )
        )

    # --------------------------------------------------
    # HIGH UNIQUE SUBDOMAIN RATIO
    # --------------------------------------------------

    if (
        query_count
        >= thresholds[
            "minimum_queries_to_parent_domain"
        ]
        and unique_ratio
        >= thresholds[
            "unique_subdomain_ratio"
        ]
    ):
        points = weights[
            "high_unique_subdomain_ratio"
        ]

        score += points

        add_indicator(
            indicators,
            "High unique-subdomain ratio",
            points,
            (
                f"Unique-subdomain ratio was "
                f"{unique_ratio:.0%}."
            )
        )

    # --------------------------------------------------
    # MULTIPLE TXT QUERIES
    # --------------------------------------------------

    if (
        txt_count
        >= thresholds[
            "txt_query_count"
        ]
    ):
        points = weights[
            "multiple_txt_queries"
        ]

        score += points

        add_indicator(
            indicators,
            "Multiple TXT queries",
            points,
            (
                f"{txt_count} TXT queries were "
                "observed for the parent domain."
            )
        )

    # --------------------------------------------------
    # ENCODED-LOOKING SUBDOMAINS
    # --------------------------------------------------

    if (
        query_count
        >= thresholds[
            "minimum_queries_to_parent_domain"
        ]
        and encoded_ratio
        >= thresholds[
            "encoded_pattern_minimum_ratio"
        ]
    ):
        points = weights[
            "encoded_looking_subdomains"
        ]

        score += points

        add_indicator(
            indicators,
            "Encoded-looking subdomains",
            points,
            (
                f"{encoded_ratio:.0%} of observed "
                "subdomain labels matched the "
                "configured hexadecimal-looking pattern."
            )
        )

    # --------------------------------------------------
    # SINGLE PARENT-DOMAIN CONCENTRATION
    # --------------------------------------------------

    if (
        query_count
        >= thresholds[
            "minimum_queries_to_parent_domain"
        ]
    ):
        points = weights[
            "single_parent_domain_concentration"
        ]

        score += points

        add_indicator(
            indicators,
            "Single parent-domain concentration",
            points,
            (
                f"{query_count} queries were concentrated "
                f"on {parent_domain}."
            )
        )

    final_score = min(
        score,
        rules["maximum_score"]
    )

    priority = assign_priority(
        final_score,
        rules["priority_thresholds"]
    )

    return {
        "source_host": source_host,
        "source_ip": source_ip,
        "parent_domain": parent_domain,
        "first_query": start_time,
        "last_query": end_time,
        "window_seconds": window_seconds,
        "query_count": query_count,
        "txt_query_count": txt_count,
        "unique_subdomain_count": len(
            unique_labels
        ),
        "unique_subdomain_ratio": (
            unique_ratio
        ),
        "long_subdomain_count": len(
            long_labels
        ),
        "long_subdomain_ratio": long_ratio,
        "encoded_subdomain_count": len(
            encoded_labels
        ),
        "encoded_subdomain_ratio": (
            encoded_ratio
        ),
        "average_query_interval_seconds": (
            avg_interval
        ),
        "risk_score": final_score,
        "priority": priority,
        "indicator_count": len(
            indicators
        ),
        "indicators": indicators,
        "recommended_actions": rules[
            "recommended_actions"
        ][priority],
        "analyst_assessment": (
            "Multiple DNS behavioral indicators "
            "are present and warrant investigation "
            "for possible DNS tunneling or covert "
            "communications. The DNS telemetry alone "
            "does not prove command-and-control, "
            "data exfiltration, or the contents of "
            "any information that may have been "
            "transported."
            if priority
            in {
                "CRITICAL",
                "HIGH",
                "MODERATE"
            }
            else (
                "Observed DNS behavior remains "
                "within the configured low-priority "
                "range and is retained for baseline "
                "comparison."
            )
        ),
        "analyst_guardrails": rules[
            "analyst_guardrails"
        ]
    }


def analyze_dns(events, rules):
    grouped = group_dns_events(
        events
    )

    analyses = []

    for (
        source_host,
        source_ip,
        parent_domain
    ), group in grouped.items():

        analyses.append(
            analyze_group(
                source_host,
                source_ip,
                parent_domain,
                group,
                rules
            )
        )

    analyses.sort(
        key=lambda item: (
            -item["risk_score"],
            item["source_host"],
            item["parent_domain"]
        )
    )

    return analyses


def build_findings(analyses):
    findings = []

    counter = 1

    for analysis in analyses:
        if analysis["priority"] == "LOW":
            continue

        finding = dict(analysis)

        finding["finding_id"] = (
            f"DNS-{counter:03d}"
        )

        finding["finding_type"] = (
            "Possible DNS Tunneling Activity"
        )

        findings.append(finding)

        counter += 1

    return findings


def build_summary(
    events,
    analyses,
    findings
):
    hosts = {
        event["source_host"]
        for event in events
    }

    parent_domains = {
        event["parent_domain"]
        for event in events
    }

    return {
        "dns_event_count": len(events),
        "hosts_analyzed": len(hosts),
        "parent_domains_analyzed": len(
            parent_domains
        ),
        "behavior_groups_analyzed": len(
            analyses
        ),
        "findings": len(findings),
        "critical_findings": sum(
            1
            for finding in findings
            if finding["priority"]
            == "CRITICAL"
        ),
        "high_findings": sum(
            1
            for finding in findings
            if finding["priority"]
            == "HIGH"
        ),
        "moderate_findings": sum(
            1
            for finding in findings
            if finding["priority"]
            == "MODERATE"
        )
    }


def export_json(
    summary,
    analyses,
    findings
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "summary": summary,
        "behavior_analysis": analyses,
        "findings": findings
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


def export_csv(findings):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "finding_id",
        "finding_type",
        "source_host",
        "source_ip",
        "parent_domain",
        "query_count",
        "txt_query_count",
        "unique_subdomain_ratio",
        "encoded_subdomain_ratio",
        "average_query_interval_seconds",
        "risk_score",
        "priority",
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

        for finding in findings:
            writer.writerow({
                field: finding[field]
                for field in fieldnames
            })


def print_results(
    summary,
    findings
):
    print()
    print("=" * 92)
    print(
        "DNS TUNNELING DETECTION "
        "& TRIAGE LAB"
    )
    print("=" * 92)

    print(
        f"DNS events:              "
        f"{summary['dns_event_count']}"
    )

    print(
        f"Hosts analyzed:          "
        f"{summary['hosts_analyzed']}"
    )

    print(
        f"Parent domains analyzed: "
        f"{summary['parent_domains_analyzed']}"
    )

    print(
        f"Behavior groups:         "
        f"{summary['behavior_groups_analyzed']}"
    )

    print(
        f"Findings:                "
        f"{summary['findings']}"
    )

    print("-" * 92)

    if not findings:
        print(
            "No higher-priority DNS findings."
        )

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['priority']:<8} | "
            f"Score {finding['risk_score']:>3} | "
            f"{finding['source_host']} | "
            f"{finding['parent_domain']}"
        )

        print(
            f"          "
            f"Queries: {finding['query_count']} | "
            f"TXT: {finding['txt_query_count']} | "
            f"Unique: "
            f"{finding['unique_subdomain_ratio']:.0%} | "
            f"Encoded: "
            f"{finding['encoded_subdomain_ratio']:.0%} | "
            f"Avg Interval: "
            f"{finding['average_query_interval_seconds']}s"
        )

        print(
            f"          "
            f"Indicators: "
            f"{finding['indicator_count']}"
        )

    print("=" * 92)

    print(
        f"JSON report: "
        f"{JSON_OUTPUT}"
    )

    print(
        f"CSV report:  "
        f"{CSV_OUTPUT}"
    )

    print("=" * 92)


def main():
    events = load_csv(
        DNS_FILE
    )

    rules = load_json(
        RULES_FILE
    )

    analyses = analyze_dns(
        events,
        rules
    )

    findings = build_findings(
        analyses
    )

    summary = build_summary(
        events,
        analyses,
        findings
    )

    export_json(
        summary,
        analyses,
        findings
    )

    export_csv(
        findings
    )

    print_results(
        summary,
        findings
    )


if __name__ == "__main__":
    main()
