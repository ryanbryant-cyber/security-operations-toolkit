import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

SESSION_FILE = (
    BASE_DIR
    / "sample-data"
    / "session_events.csv"
)

WEB_FILE = (
    BASE_DIR
    / "sample-data"
    / "web_traffic.csv"
)

RULES_FILE = (
    BASE_DIR
    / "rules"
    / "detection_rules.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "activity_analysis_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "security_findings.csv"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_csv(path):
    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def parse_time(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def to_bool(value):
    return str(value).strip().lower() == "true"


def assign_severity(score, thresholds):
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"

    if score >= thresholds["HIGH"]:
        return "HIGH"

    if score >= thresholds["MODERATE"]:
        return "MODERATE"

    return "LOW"


# --------------------------------------------------
# SESSION HIJACKING ANALYSIS
# --------------------------------------------------

def analyze_sessions(events, rules):
    grouped = defaultdict(list)

    for event in events:
        grouped[event["session_id"]].append(event)

    findings = []

    for session_id, session_events in grouped.items():
        session_events.sort(
            key=lambda item: parse_time(
                item["timestamp"]
            )
        )

        login_event = next(
            (
                event
                for event in session_events
                if event["event_type"] == "login"
                and event["outcome"] == "success"
            ),
            None
        )

        if login_event is None:
            continue

        baseline_ip = login_event["source_ip"]
        baseline_agent = login_event["user_agent"]
        login_time = parse_time(
            login_event["timestamp"]
        )

        anomalous_events = [
            event
            for event in session_events
            if (
                event["source_ip"] != baseline_ip
                or event["user_agent"] != baseline_agent
            )
        ]

        indicators = []
        score = 0

        weights = rules["risk_weights"]

        source_ip_change = any(
            event["source_ip"] != baseline_ip
            for event in session_events
        )

        if source_ip_change:
            points = weights["source_ip_change"]
            score += points

            indicators.append({
                "indicator": "Source IP change",
                "points": points,
                "evidence": (
                    f"Session changed from {baseline_ip} "
                    "to another source IP."
                )
            })

        user_agent_change = any(
            event["user_agent"] != baseline_agent
            for event in session_events
        )

        if user_agent_change:
            points = weights["user_agent_change"]
            score += points

            indicators.append({
                "indicator": "User-agent change",
                "points": points,
                "evidence": (
                    f"Session changed from {baseline_agent} "
                    "to a different user agent."
                )
            })

        mfa_not_verified = any(
            not to_bool(event["mfa_verified"])
            for event in anomalous_events
        )

        if mfa_not_verified:
            points = weights["mfa_not_verified"]
            score += points

            indicators.append({
                "indicator": "MFA not verified on anomalous origin",
                "points": points,
                "evidence": (
                    "One or more events from the anomalous "
                    "origin did not show MFA verification."
                )
            })

        rapid_change = False
        rapid_seconds = None

        if anomalous_events:
            first_anomaly_time = parse_time(
                anomalous_events[0]["timestamp"]
            )

            rapid_seconds = int(
                (
                    first_anomaly_time
                    - login_time
                ).total_seconds()
            )

            rapid_change = (
                rapid_seconds
                <= rules["rapid_transition_seconds"]
            )

        if rapid_change:
            points = weights["rapid_origin_change"]
            score += points

            indicators.append({
                "indicator": "Rapid origin change",
                "points": points,
                "evidence": (
                    f"Anomalous origin appeared "
                    f"{rapid_seconds} seconds after login."
                )
            })

        sensitive_anomalous = [
            event
            for event in anomalous_events
            if to_bool(event["sensitive_action"])
        ]

        if sensitive_anomalous:
            points = weights[
                "sensitive_action_from_anomalous_origin"
            ]
            score += points

            resources = sorted({
                event["resource"]
                for event in sensitive_anomalous
            })

            indicators.append({
                "indicator": (
                    "Sensitive action from anomalous origin"
                ),
                "points": points,
                "evidence": (
                    "Sensitive resources accessed: "
                    + ", ".join(resources)
                )
            })

        concurrent_origin_reuse = False

        if anomalous_events:
            first_anomaly = parse_time(
                anomalous_events[0]["timestamp"]
            )

            last_anomaly = parse_time(
                anomalous_events[-1]["timestamp"]
            )

            window_seconds = rules[
                "concurrent_session_window_seconds"
            ]

            concurrent_origin_reuse = any(
                event["source_ip"] == baseline_ip
                and event["user_agent"] == baseline_agent
                and parse_time(event["timestamp"]) > first_anomaly
                and parse_time(event["timestamp"]) <= last_anomaly
                and (
                    parse_time(event["timestamp"])
                    - first_anomaly
                ).total_seconds() <= window_seconds
                for event in session_events
            )

        if concurrent_origin_reuse:
            points = weights[
                "concurrent_origin_reuse"
            ]
            score += points

            indicators.append({
                "indicator": "Concurrent origin reuse",
                "points": points,
                "evidence": (
                    "The original source resumed activity "
                    "while the anomalous origin was also "
                    "using the same session identifier."
                )
            })

        final_score = min(score, 100)

        severity = assign_severity(
            final_score,
            rules["severity_thresholds"]
        )

        if severity == "LOW":
            continue

                anomalous_ips = sorted({
            event["source_ip"]
            for event in anomalous_events
        })

        anomalous_agents = sorted({
            event["user_agent"]
            for event in anomalous_events
        })

        findings.append({
            "finding_id": (
                f"HIJACK-{session_id.replace('SESSION-', '', 1)}"
            ),
            "finding_type": (
                "Suspected Session Hijacking"
            ),
            "user": login_event["user"],
            "session_id": session_id,
            "baseline_source_ip": baseline_ip,
            "baseline_user_agent": baseline_agent,
            "anomalous_source_ips": anomalous_ips,
            "anomalous_user_agents": anomalous_agents,
            "risk_score": final_score,
            "severity": severity,
            "indicators": indicators,
            "containment_recommendations": rules[
                "containment_recommendations"
            ],
            "analyst_assessment": (
                "The session shows multiple behavioral "
                "anomalies consistent with suspected "
                "session hijacking, including origin "
                "changes and continued use of the same "
                "session identifier. The telemetry does "
                "not establish how the session token was "
                "obtained."
            )
        })
            "user": login_event["user"],
            "session_id": session_id,
            "baseline_source_ip": baseline_ip,
            "baseline_user_agent": baseline_agent,
            "anomalous_source_ips": anomalous_ips,
            "anomalous_user_agents": anomalous_agents,
            "risk_score": final_score,
            "severity": severity,
            "indicators": indicators,
            "containment_recommendations": rules[
                "containment_recommendations"
            ],
            "analyst_assessment": (
                "The session shows multiple behavioral "
                "anomalies consistent with suspected "
                "session hijacking, including origin "
                "changes and continued use of the same "
                "session identifier. The telemetry does "
                "not establish how the session token was "
                "obtained."
            )
        })

    return findings


# --------------------------------------------------
# DDoS ANALYSIS
# --------------------------------------------------

def group_web_events_by_minute(events):
    grouped = defaultdict(list)

    for event in events:
        minute = event["timestamp"][:16]

        grouped[minute].append(event)

    return dict(
        sorted(grouped.items())
    )


def total_requests(events):
    return sum(
        int(event["requests_per_minute"])
        for event in events
    )


def calculate_weighted_response(events):
    requests = total_requests(events)

    if requests == 0:
        return 0

    weighted_total = sum(
        int(event["requests_per_minute"])
        * int(event["avg_response_ms"])
        for event in events
    )

    return round(
        weighted_total / requests,
        2
    )


def calculate_error_ratio(events, error_codes):
    requests = total_requests(events)

    if requests == 0:
        return 0

    error_requests = sum(
        int(event["requests_per_minute"])
        for event in events
        if int(event["status_code"])
        in error_codes
    )

    return round(
        error_requests / requests,
        4
    )


def calculate_endpoint_concentration(events):
    total = total_requests(events)

    if total == 0:
        return 0, None

    endpoint_counts = defaultdict(int)

    for event in events:
        endpoint_counts[event["endpoint"]] += int(
            event["requests_per_minute"]
        )

    endpoint, count = max(
        endpoint_counts.items(),
        key=lambda item: item[1]
    )

    return round(count / total, 4), endpoint


def analyze_ddos(events, rules):
    grouped = group_web_events_by_minute(
        events
    )

    minutes = list(grouped.keys())

    baseline_count = rules[
        "baseline_minutes"
    ]

    baseline_minutes = minutes[
        :baseline_count
    ]

    baseline_totals = [
        total_requests(grouped[minute])
        for minute in baseline_minutes
    ]

    baseline_average = round(
        sum(baseline_totals)
        / len(baseline_totals),
        2
    )

    findings = []

    for minute in minutes[baseline_count:]:
        minute_events = grouped[minute]

        request_count = total_requests(
            minute_events
        )

        if baseline_average == 0:
            multiplier = 0
        else:
            multiplier = round(
                request_count / baseline_average,
                2
            )

        source_count = len({
            event["source_ip"]
            for event in minute_events
        })

        concentration, target_endpoint = (
            calculate_endpoint_concentration(
                minute_events
            )
        )

        error_ratio = calculate_error_ratio(
            minute_events,
            rules["error_status_codes"]
        )

        response_ms = calculate_weighted_response(
            minute_events
        )

        score = 0
        indicators = []

        weights = rules["risk_weights"]

        if (
            multiplier
            >= rules[
                "volume_multiplier_threshold"
            ]
        ):
            points = weights[
                "traffic_volume_spike"
            ]
            score += points

            indicators.append({
                "indicator": "Traffic volume spike",
                "points": points,
                "evidence": (
                    f"Traffic reached {multiplier}x "
                    "the established baseline."
                )
            })

        if (
            multiplier
            >= rules[
                "critical_volume_multiplier"
            ]
        ):
            points = weights[
                "critical_volume_spike"
            ]
            score += points

            indicators.append({
                "indicator": (
                    "Critical traffic volume spike"
                ),
                "points": points,
                "evidence": (
                    f"Traffic exceeded the "
                    f"{rules['critical_volume_multiplier']}x "
                    "critical-volume threshold."
                )
            })

        if (
            source_count
            >= rules[
                "minimum_distributed_sources"
            ]
        ):
            points = weights[
                "distributed_source_activity"
            ]
            score += points

            indicators.append({
                "indicator": (
                    "Distributed source activity"
                ),
                "points": points,
                "evidence": (
                    f"{source_count} distinct sources "
                    "contributed traffic during the minute."
                )
            })

        if (
            concentration
            >= rules[
                "endpoint_concentration_threshold"
            ]
        ):
            points = weights[
                "endpoint_concentration"
            ]
            score += points

            indicators.append({
                "indicator": (
                    "Endpoint concentration"
                ),
                "points": points,
                "evidence": (
                    f"{concentration:.0%} of requests "
                    f"targeted {target_endpoint}."
                )
            })

        if (
            error_ratio
            >= rules["high_error_ratio"]
        ):
            points = weights[
                "error_response_increase"
            ]
            score += points

            indicators.append({
                "indicator": (
                    "Error response increase"
                ),
                "points": points,
                "evidence": (
                    f"{error_ratio:.0%} of requests "
                    "received monitored error responses."
                )
            })

        if (
            response_ms
            >= rules[
                "degraded_response_ms"
            ]
        ):
            points = weights[
                "response_time_degradation"
            ]
            score += points

            indicators.append({
                "indicator": (
                    "Response-time degradation"
                ),
                "points": points,
                "evidence": (
                    f"Weighted average response time "
                    f"reached {response_ms} ms."
                )
            })

        final_score = min(score, 100)

        severity = assign_severity(
            final_score,
            rules["severity_thresholds"]
        )

        if severity == "LOW":
            continue

        findings.append({
            "finding_id": (
                "DDOS-"
                + minute.replace(":", "")
            ),
            "finding_type": (
                "Suspected Distributed "
                "Denial-of-Service Activity"
            ),
            "minute": minute,
            "baseline_requests_per_minute": (
                baseline_average
            ),
            "observed_requests_per_minute": (
                request_count
            ),
            "baseline_multiplier": multiplier,
            "distinct_sources": source_count,
            "target_endpoint": target_endpoint,
            "endpoint_concentration": concentration,
            "error_ratio": error_ratio,
            "weighted_response_ms": response_ms,
            "risk_score": final_score,
            "severity": severity,
            "indicators": indicators,
            "containment_recommendations": rules[
                "containment_recommendations"
            ],
            "analyst_assessment": (
                "Traffic volume, source distribution, "
                "endpoint concentration, error responses, "
                "and latency degradation support a "
                "suspected distributed denial-of-service "
                "finding. The telemetry alone does not "
                "establish the intent or ownership of "
                "every participating source."
            )
        })

    return {
        "baseline_minutes": baseline_minutes,
        "baseline_totals": baseline_totals,
        "baseline_average": baseline_average,
        "findings": findings
    }


# --------------------------------------------------
# EXPORT / REPORTING
# --------------------------------------------------

def export_json(
    session_findings,
    ddos_analysis
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "summary": {
            "session_findings": len(
                session_findings
            ),
            "ddos_findings": len(
                ddos_analysis["findings"]
            ),
            "total_findings": (
                len(session_findings)
                + len(ddos_analysis["findings"])
            )
        },
        "session_hijacking_analysis": {
            "findings": session_findings
        },
        "ddos_analysis": ddos_analysis
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


def export_csv(
    session_findings,
    ddos_findings
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "finding_id",
        "finding_type",
        "severity",
        "risk_score",
        "subject",
        "time_window",
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

        for finding in session_findings:
            writer.writerow({
                "finding_id": finding[
                    "finding_id"
                ],
                "finding_type": finding[
                    "finding_type"
                ],
                "severity": finding[
                    "severity"
                ],
                "risk_score": finding[
                    "risk_score"
                ],
                "subject": finding[
                    "user"
                ],
                "time_window": finding[
                    "session_id"
                ],
                "indicator_count": len(
                    finding["indicators"]
                ),
                "analyst_assessment": finding[
                    "analyst_assessment"
                ]
            })

        for finding in ddos_findings:
            writer.writerow({
                "finding_id": finding[
                    "finding_id"
                ],
                "finding_type": finding[
                    "finding_type"
                ],
                "severity": finding[
                    "severity"
                ],
                "risk_score": finding[
                    "risk_score"
                ],
                "subject": finding[
                    "target_endpoint"
                ],
                "time_window": finding[
                    "minute"
                ],
                "indicator_count": len(
                    finding["indicators"]
                ),
                "analyst_assessment": finding[
                    "analyst_assessment"
                ]
            })


def print_results(
    session_findings,
    ddos_analysis
):
    print()
    print("=" * 92)
    print(
        "SESSION HIJACKING & DDoS "
        "DETECTION AND CONTAINMENT LAB"
    )
    print("=" * 92)

    print()
    print("SESSION ANALYSIS")
    print("-" * 92)

    if not session_findings:
        print("No session findings detected.")

    for finding in session_findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['user']} | "
            f"Score: {finding['risk_score']} | "
            f"{finding['severity']} | "
            f"Indicators: "
            f"{len(finding['indicators'])}"
        )

    print()
    print("DDoS BASELINE")
    print("-" * 92)

    print(
        "Baseline minute totals: "
        + ", ".join(
            str(value)
            for value
            in ddos_analysis[
                "baseline_totals"
            ]
        )
    )

    print(
        f"Average baseline: "
        f"{ddos_analysis['baseline_average']} "
        "requests/minute"
    )

    print()
    print("DDoS ANALYSIS")
    print("-" * 92)

    if not ddos_analysis["findings"]:
        print("No DDoS findings detected.")

    for finding in ddos_analysis["findings"]:
        print(
            f"{finding['finding_id']} | "
            f"{finding['minute']} | "
            f"{finding['observed_requests_per_minute']} req/min | "
            f"{finding['baseline_multiplier']}x baseline | "
            f"Score: {finding['risk_score']} | "
            f"{finding['severity']}"
        )

    total = (
        len(session_findings)
        + len(ddos_analysis["findings"])
    )

    print()
    print("=" * 92)

    print(
        f"Session findings: {len(session_findings)}"
    )

    print(
        f"DDoS findings:    "
        f"{len(ddos_analysis['findings'])}"
    )

    print(
        f"Total findings:   {total}"
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
    rules = load_json(
        RULES_FILE
    )

    session_events = load_csv(
        SESSION_FILE
    )

    web_events = load_csv(
        WEB_FILE
    )

    session_findings = analyze_sessions(
        session_events,
        rules["session_hijacking"]
    )

    ddos_analysis = analyze_ddos(
        web_events,
        rules["ddos_detection"]
    )

    export_json(
        session_findings,
        ddos_analysis
    )

    export_csv(
        session_findings,
        ddos_analysis["findings"]
    )

    print_results(
        session_findings,
        ddos_analysis
    )


if __name__ == "__main__":
    main()
