import csv
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DATA_FILE = (
    BASE_DIR
    / "sample-data"
    / "email_cases.json"
)

MODEL_FILE = (
    BASE_DIR
    / "rules"
    / "phishing_risk_model.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "phishing_analysis_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "phishing_analysis_summary.csv"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def add_indicator(indicators, name, points, evidence):
    indicators.append({
        "indicator": name,
        "points": points,
        "evidence": evidence
    })


def score_email(email, model):
    score = 0
    indicators = []

    auth = email["authentication"]
    sender = email["sender_context"]
    body = email["body_indicators"]

    # Authentication checks
    if auth["spf"].lower() == "fail":
        points = model["authentication"]["spf_fail"]
        score += points

        add_indicator(
            indicators,
            "SPF failure",
            points,
            "SPF authentication result was fail."
        )

    if auth["dkim"].lower() == "fail":
        points = model["authentication"]["dkim_fail"]
        score += points

        add_indicator(
            indicators,
            "DKIM failure",
            points,
            "DKIM authentication result was fail."
        )

    if auth["dmarc"].lower() == "fail":
        points = model["authentication"]["dmarc_fail"]
        score += points

        add_indicator(
            indicators,
            "DMARC failure",
            points,
            "DMARC authentication result was fail."
        )

    elif auth["dmarc"].lower() == "none":
        points = model["authentication"]["dmarc_none"]
        score += points

        add_indicator(
            indicators,
            "No DMARC enforcement result",
            points,
            "DMARC result was none."
        )

    # Sender context
    if (
        sender["external_sender"]
        and not sender["known_sender"]
    ):
        points = model["sender_context"][
            "external_unknown_sender"
        ]
        score += points

        add_indicator(
            indicators,
            "External unknown sender",
            points,
            "Message originated from an external sender not marked as known."
        )

    if sender["display_name_impersonation"]:
        points = model["sender_context"][
            "display_name_impersonation"
        ]
        score += points

        add_indicator(
            indicators,
            "Display-name impersonation",
            points,
            "Sender display name appears to impersonate a trusted organization or role."
        )

    if not sender["from_reply_to_domain_match"]:
        points = model["sender_context"][
            "reply_to_domain_mismatch"
        ]
        score += points

        add_indicator(
            indicators,
            "Reply-To domain mismatch",
            points,
            "From and Reply-To domains do not align."
        )

    if not sender["from_return_path_domain_match"]:
        points = model["sender_context"][
            "return_path_domain_mismatch"
        ]
        score += points

        add_indicator(
            indicators,
            "Return-Path domain mismatch",
            points,
            "From and Return-Path domains do not align."
        )

    # Body indicators
    body_mapping = [
        (
            "urgency_language",
            "urgency_language",
            "Urgency language"
        ),
        (
            "credential_request",
            "credential_request",
            "Credential request"
        ),
        (
            "financial_request",
            "financial_request",
            "Financial request"
        ),
        (
            "threatening_language",
            "threatening_language",
            "Threatening language"
        ),
        (
            "security_alert_theme",
            "security_alert_theme",
            "Security-alert theme"
        )
    ]

    for field, model_key, label in body_mapping:
        if body[field]:
            points = model["body_indicators"][model_key]
            score += points

            add_indicator(
                indicators,
                label,
                points,
                f"{label} was present in the message context."
            )

    # URL analysis
    for url in email["urls"]:
        if not url["domain_matches_sender"]:
            points = model["url_indicators"][
                "sender_domain_mismatch"
            ]
            score += points

            add_indicator(
                indicators,
                "URL domain mismatch",
                points,
                (
                    f"URL domain {url['domain']} "
                    "does not match the sender domain."
                )
            )

        if not url["uses_https"]:
            points = model["url_indicators"][
                "non_https_url"
            ]
            score += points

            add_indicator(
                indicators,
                "Non-HTTPS URL",
                points,
                f"URL uses HTTP rather than HTTPS: {url['url']}"
            )

    # Attachment analysis
    for attachment in email["attachments"]:
        if attachment["file_type"].upper() == "HTML":
            points = model["attachment_indicators"][
                "html_attachment"
            ]
            score += points

            add_indicator(
                indicators,
                "HTML attachment",
                points,
                f"HTML attachment observed: {attachment['filename']}"
            )

        if attachment["contains_external_form"]:
            points = model["attachment_indicators"][
                "external_form"
            ]
            score += points

            add_indicator(
                indicators,
                "Attachment contains external form",
                points,
                (
                    f"{attachment['filename']} contains "
                    "an external form."
                )
            )

        if attachment["macro_enabled"]:
            points = model["attachment_indicators"][
                "macro_enabled"
            ]
            score += points

            add_indicator(
                indicators,
                "Macro-enabled attachment",
                points,
                f"Macro-enabled attachment: {attachment['filename']}"
            )

        if attachment["executable"]:
            points = model["attachment_indicators"][
                "executable_attachment"
            ]
            score += points

            add_indicator(
                indicators,
                "Executable attachment",
                points,
                f"Executable attachment: {attachment['filename']}"
            )

    final_score = min(
        score,
        model["maximum_score"]
    )

    return final_score, indicators


def assign_disposition(score, thresholds):
    if score >= thresholds["MALICIOUS"]:
        return "MALICIOUS"

    if score >= thresholds["SUSPICIOUS"]:
        return "SUSPICIOUS"

    return "BENIGN"


def extract_domain(address):
    if "@" not in address:
        return None

    return address.rsplit("@", 1)[1].lower()


def extract_iocs(email):
    iocs = []

    headers = email["headers"]

    email_fields = [
        ("from_address", "Sender Email"),
        ("reply_to", "Reply-To Email"),
        ("return_path", "Return-Path Email")
    ]

    seen = set()

    for field, label in email_fields:
        value = headers[field]

        key = ("email", value.lower())

        if key not in seen:
            seen.add(key)

            iocs.append({
                "type": "email",
                "value": value,
                "source": label
            })

        domain = extract_domain(value)

        if domain:
            key = ("domain", domain)

            if key not in seen:
                seen.add(key)

                iocs.append({
                    "type": "domain",
                    "value": domain,
                    "source": label
                })

    sending_ip = headers["sending_ip"]

    key = ("ip", sending_ip)

    if key not in seen:
        seen.add(key)

        iocs.append({
            "type": "ip",
            "value": sending_ip,
            "source": "Sending IP"
        })

    for url in email["urls"]:
        key = ("url", url["url"])

        if key not in seen:
            seen.add(key)

            iocs.append({
                "type": "url",
                "value": url["url"],
                "source": "Message URL"
            })

        key = ("domain", url["domain"].lower())

        if key not in seen:
            seen.add(key)

            iocs.append({
                "type": "domain",
                "value": url["domain"].lower(),
                "source": "Message URL"
            })

    for attachment in email["attachments"]:
        sha256 = attachment["sha256"].lower()

        key = ("sha256", sha256)

        if key not in seen:
            seen.add(key)

            iocs.append({
                "type": "sha256",
                "value": sha256,
                "source": attachment["filename"]
            })

    return iocs


def build_analyst_assessment(
    email,
    score,
    disposition,
    indicators
):
    case_id = email["case_id"]

    if disposition == "MALICIOUS":
        return (
            f"{case_id} contains multiple high-risk phishing indicators "
            f"and received a risk score of {score}. "
            "The combined authentication failures, sender anomalies, "
            "message content, URL characteristics, or attachment behavior "
            "support a MALICIOUS disposition."
        )

    if disposition == "SUSPICIOUS":
        return (
            f"{case_id} contains indicators that warrant additional "
            f"analyst investigation and received a risk score of {score}. "
            "Available evidence is concerning but does not independently "
            "establish confirmed malicious activity."
        )

    return (
        f"{case_id} received a risk score of {score}. "
        "The available synthetic evidence does not contain enough "
        "risk indicators to support a suspicious or malicious disposition."
    )


def analyze_cases(dataset, model):
    results = []

    for email in dataset["emails"]:
        score, indicators = score_email(
            email,
            model
        )

        disposition = assign_disposition(
            score,
            model["disposition_thresholds"]
        )

        iocs = extract_iocs(email)

        result = {
            "case_id": email["case_id"],
            "received_time": email["received_time"],
            "recipient": email["recipient"],
            "subject": email["headers"]["subject"],
            "from_display_name": email["headers"][
                "from_display_name"
            ],
            "from_address": email["headers"][
                "from_address"
            ],
            "sending_ip": email["headers"][
                "sending_ip"
            ],
            "spf": email["authentication"]["spf"],
            "dkim": email["authentication"]["dkim"],
            "dmarc": email["authentication"]["dmarc"],
            "risk_score": score,
            "disposition": disposition,
            "risk_indicators": indicators,
            "extracted_iocs": iocs,
            "analyst_assessment": build_analyst_assessment(
                email,
                score,
                disposition,
                indicators
            )
        }

        results.append(result)

    return results


def summarize_results(results):
    summary = {
        "total_cases": len(results),
        "malicious": 0,
        "suspicious": 0,
        "benign": 0
    }

    for result in results:
        disposition = result["disposition"]

        if disposition == "MALICIOUS":
            summary["malicious"] += 1
        elif disposition == "SUSPICIOUS":
            summary["suspicious"] += 1
        elif disposition == "BENIGN":
            summary["benign"] += 1

    return summary


def export_json(dataset, model, results, summary):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report = {
        "dataset_name": dataset["dataset_name"],
        "risk_model": model["model_name"],
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
        "case_id",
        "received_time",
        "recipient",
        "subject",
        "from_address",
        "sending_ip",
        "spf",
        "dkim",
        "dmarc",
        "risk_score",
        "disposition",
        "indicator_count",
        "ioc_count",
        "risk_indicators",
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

        for result in results:
            indicator_names = [
                item["indicator"]
                for item in result["risk_indicators"]
            ]

            writer.writerow({
                "case_id": result["case_id"],
                "received_time": result["received_time"],
                "recipient": result["recipient"],
                "subject": result["subject"],
                "from_address": result["from_address"],
                "sending_ip": result["sending_ip"],
                "spf": result["spf"],
                "dkim": result["dkim"],
                "dmarc": result["dmarc"],
                "risk_score": result["risk_score"],
                "disposition": result["disposition"],
                "indicator_count": len(
                    result["risk_indicators"]
                ),
                "ioc_count": len(
                    result["extracted_iocs"]
                ),
                "risk_indicators": " | ".join(
                    indicator_names
                ),
                "analyst_assessment": result[
                    "analyst_assessment"
                ]
            })


def print_results(results, summary):
    print()
    print("=" * 86)
    print("PHISHING EMAIL INVESTIGATION LAB")
    print("=" * 86)

    for result in results:
        print(
            f"{result['case_id']} | "
            f"Score: {result['risk_score']:>3} | "
            f"{result['disposition']:<10} | "
            f"Indicators: {len(result['risk_indicators']):>2} | "
            f"IOCs: {len(result['extracted_iocs']):>2}"
        )

    print("=" * 86)

    print(
        f"Total Cases:  "
        f"{summary['total_cases']}"
    )

    print(
        f"MALICIOUS:    "
        f"{summary['malicious']}"
    )

    print(
        f"SUSPICIOUS:   "
        f"{summary['suspicious']}"
    )

    print(
        f"BENIGN:       "
        f"{summary['benign']}"
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
    dataset = load_json(DATA_FILE)
    model = load_json(MODEL_FILE)

    results = analyze_cases(
        dataset,
        model
    )

    summary = summarize_results(results)

    export_json(
        dataset,
        model,
        results,
        summary
    )

    export_csv(results)

    print_results(
        results,
        summary
    )


if __name__ == "__main__":
    main()
