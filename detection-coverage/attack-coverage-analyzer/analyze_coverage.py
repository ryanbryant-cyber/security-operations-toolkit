import csv
import json
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

CATALOG_FILE = (
    BASE_DIR
    / "sample-data"
    / "detection_catalog.csv"
)

MODEL_FILE = (
    BASE_DIR
    / "rules"
    / "coverage_model.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "attack_coverage_results.json"
)

TECHNIQUE_CSV = (
    OUTPUT_DIR
    / "technique_coverage.csv"
)

TACTIC_CSV = (
    OUTPUT_DIR
    / "tactic_coverage.csv"
)

PRIORITY_CSV = (
    OUTPUT_DIR
    / "engineering_priorities.csv"
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


def split_values(value):
    if not value:
        return []

    return [
        item.strip()
        for item in value.split("|")
        if item.strip()
    ]


def coverage_rating(score, thresholds):
    if score >= thresholds["STRONG"]:
        return "STRONG"

    if score >= thresholds["MODERATE"]:
        return "MODERATE"

    if score >= thresholds["LOW"]:
        return "LOW"

    return "GAP"


def technique_detections(
    catalog,
    technique_id
):
    return [
        detection
        for detection in catalog
        if detection["technique_id"]
        == technique_id
    ]


def average_confidence(detections):
    if not detections:
        return 0

    values = [
        float(item["confidence"])
        for item in detections
    ]

    return round(
        sum(values) / len(values),
        2
    )


def score_technique(
    detections,
    model
):
    if not detections:
        return {
            "score": 0,
            "breakdown": {
                "detection_presence": 0,
                "validated_detection_points": 0,
                "data_source_diversity_points": 0,
                "detection_type_diversity_points": 0,
                "active_detection_points": 0,
                "confidence_points": 0,
                "needs_review_penalty": 0,
                "experimental_penalty": 0
            }
        }

    scoring = model[
        "coverage_scoring"
    ]

    validated = [
        detection
        for detection in detections
        if detection["validation_status"]
        == "Validated"
    ]

    needs_review = [
        detection
        for detection in detections
        if detection["validation_status"]
        == "Needs Review"
    ]

    active = [
        detection
        for detection in detections
        if detection["detection_status"]
        == "Active"
    ]

    experimental = [
        detection
        for detection in detections
        if detection["detection_status"]
        == "Experimental"
    ]

    unique_sources = {
        detection["data_source"]
        for detection in detections
    }

    unique_types = {
        detection["detection_type"]
        for detection in detections
    }

    presence_points = scoring[
        "detection_presence"
    ]["points"]

    validated_points = min(
        len(validated)
        * scoring[
            "validated_detection"
        ][
            "points_per_detection"
        ],
        scoring[
            "validated_detection"
        ][
            "maximum_points"
        ]
    )

    source_points = min(
        len(unique_sources)
        * scoring[
            "data_source_diversity"
        ][
            "points_per_unique_source"
        ],
        scoring[
            "data_source_diversity"
        ][
            "maximum_points"
        ]
    )

    type_points = min(
        len(unique_types)
        * scoring[
            "detection_type_diversity"
        ][
            "points_per_unique_type"
        ],
        scoring[
            "detection_type_diversity"
        ][
            "maximum_points"
        ]
    )

    active_ratio = (
        len(active)
        / len(detections)
    )

    active_points = round(
        active_ratio
        * scoring[
            "active_detection_bonus"
        ][
            "maximum_points"
        ],
        2
    )

    confidence_average = (
        average_confidence(
            detections
        )
    )

    confidence_points = round(
        (
            confidence_average
            / 100
        )
        * scoring[
            "confidence_score"
        ][
            "maximum_points"
        ],
        2
    )

    review_penalty = min(
        len(needs_review)
        * scoring[
            "needs_review_penalty"
        ][
            "points_per_detection"
        ],
        scoring[
            "needs_review_penalty"
        ][
            "maximum_penalty"
        ]
    )

    experimental_penalty = min(
        len(experimental)
        * scoring[
            "experimental_penalty"
        ][
            "points_per_detection"
        ],
        scoring[
            "experimental_penalty"
        ][
            "maximum_penalty"
        ]
    )

    raw_score = (
        presence_points
        + validated_points
        + source_points
        + type_points
        + active_points
        + confidence_points
        - review_penalty
        - experimental_penalty
    )

    final_score = round(
        max(
            0,
            min(
                model[
                    "maximum_coverage_score"
                ],
                raw_score
            )
        ),
        2
    )

    return {
        "score": final_score,
        "breakdown": {
            "detection_presence": (
                presence_points
            ),
            "validated_detection_points": (
                validated_points
            ),
            "data_source_diversity_points": (
                source_points
            ),
            "detection_type_diversity_points": (
                type_points
            ),
            "active_detection_points": (
                active_points
            ),
            "confidence_points": (
                confidence_points
            ),
            "needs_review_penalty": (
                -review_penalty
            ),
            "experimental_penalty": (
                -experimental_penalty
            )
        }
    }


def engineering_priority(
    coverage,
    technique_priority
):
    if (
        coverage == "GAP"
        and technique_priority == "Critical"
    ):
        return "CRITICAL"

    if (
        coverage == "GAP"
        and technique_priority == "High"
    ):
        return "HIGH"

    if (
        coverage == "LOW"
        and technique_priority == "Critical"
    ):
        return "HIGH"

    if (
        coverage == "GAP"
        and technique_priority
        == "Moderate"
    ):
        return "MODERATE"

    if coverage == "LOW":
        return "REVIEW"

    return "MAINTAIN"


def redundancy_status(
    detections,
    model
):
    rules = model[
        "redundancy_analysis"
    ]

    if (
        len(detections)
        < rules["review_threshold"]
    ):
        return {
            "review_required": False,
            "classification": (
                "No Redundancy Review"
            ),
            "notes": (
                "Detection count is below the "
                "redundancy review threshold."
            )
        }

    sources = {
        detection["data_source"]
        for detection in detections
    }

    types = {
        detection["detection_type"]
        for detection in detections
    }

    resilient = (
        len(sources)
        >= rules[
            "strong_overlap_minimum_data_sources"
        ]
        and len(types)
        >= rules[
            "strong_overlap_minimum_detection_types"
        ]
    )

    if resilient:
        classification = (
            "Layered Coverage - Review Alert Overlap"
        )

        notes = (
            "Multiple detections use diverse telemetry "
            "or analytic types. Maintain layered coverage "
            "while reviewing duplicate alerting."
        )

    else:
        classification = (
            "Potential Duplicate Coverage"
        )

        notes = (
            "Multiple detections exist but may not "
            "provide sufficiently independent coverage. "
            "Review telemetry and detection logic."
        )

    return {
        "review_required": True,
        "classification": classification,
        "notes": notes
    }


def analyze_techniques(
    catalog,
    model
):
    results = []

    for technique in model[
        "priority_techniques"
    ]:
        detections = technique_detections(
            catalog,
            technique["technique_id"]
        )

        score_result = score_technique(
            detections,
            model
        )

        score = score_result[
            "score"
        ]

        rating = coverage_rating(
            score,
            model[
                "coverage_thresholds"
            ]
        )

        validated_count = sum(
            1
            for detection in detections
            if detection[
                "validation_status"
            ]
            == "Validated"
        )

        review_count = sum(
            1
            for detection in detections
            if detection[
                "validation_status"
            ]
            == "Needs Review"
        )

        experimental_count = sum(
            1
            for detection in detections
            if detection[
                "detection_status"
            ]
            == "Experimental"
        )

        active_count = sum(
            1
            for detection in detections
            if detection[
                "detection_status"
            ]
            == "Active"
        )

        unique_sources = sorted({
            detection["data_source"]
            for detection in detections
        })

        unique_types = sorted({
            detection["detection_type"]
            for detection in detections
        })

        detection_ids = [
            detection["detection_id"]
            for detection in detections
        ]

        redundancy = redundancy_status(
            detections,
            model
        )

        results.append({
            "technique_id": technique[
                "technique_id"
            ],
            "technique": technique[
                "technique"
            ],
            "tactics": split_values(
                technique["tactic"]
            ),
            "technique_priority": technique[
                "priority"
            ],
            "detection_count": len(
                detections
            ),
            "validated_detection_count": (
                validated_count
            ),
            "needs_review_count": (
                review_count
            ),
            "experimental_count": (
                experimental_count
            ),
            "active_detection_count": (
                active_count
            ),
            "data_sources": unique_sources,
            "detection_types": unique_types,
            "average_confidence": (
                average_confidence(
                    detections
                )
            ),
            "coverage_score": score,
            "coverage_rating": rating,
            "engineering_priority": (
                engineering_priority(
                    rating,
                    technique["priority"]
                )
            ),
            "score_breakdown": (
                score_result[
                    "breakdown"
                ]
            ),
            "detection_ids": (
                detection_ids
            ),
            "redundancy_review": (
                redundancy
            ),
            "recommendation": model[
                "recommendation_templates"
            ][rating]
        })

    return results


def tactic_rating(
    average_score,
    model
):
    rules = model[
        "tactic_analysis"
    ]

    if (
        average_score
        >= rules[
            "strong_average_threshold"
        ]
    ):
        return "STRONG"

    if (
        average_score
        >= rules[
            "moderate_average_threshold"
        ]
    ):
        return "MODERATE"

    if (
        average_score
        >= rules[
            "low_average_threshold"
        ]
    ):
        return "LOW"

    return "GAP"


def analyze_tactics(
    technique_results,
    model
):
    tactic_map = defaultdict(list)

    for technique in technique_results:
        for tactic in technique[
            "tactics"
        ]:
            tactic_map[tactic].append(
                technique
            )

    results = []

    for tactic in sorted(
        tactic_map
    ):
        techniques = tactic_map[
            tactic
        ]

        average_score = round(
            sum(
                item["coverage_score"]
                for item in techniques
            )
            / len(techniques),
            2
        )

        gaps = [
            item
            for item in techniques
            if item["coverage_rating"]
            == "GAP"
        ]

        low = [
            item
            for item in techniques
            if item["coverage_rating"]
            == "LOW"
        ]

        strong = [
            item
            for item in techniques
            if item["coverage_rating"]
            == "STRONG"
        ]

        results.append({
            "tactic": tactic,
            "priority_technique_count": (
                len(techniques)
            ),
            "average_coverage_score": (
                average_score
            ),
            "coverage_rating": (
                tactic_rating(
                    average_score,
                    model
                )
            ),
            "strong_techniques": (
                len(strong)
            ),
            "low_techniques": (
                len(low)
            ),
            "gap_techniques": (
                len(gaps)
            ),
            "technique_ids": [
                item["technique_id"]
                for item in techniques
            ]
        })

    return results


def engineering_priority_rank(value):
    ranks = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MODERATE": 2,
        "REVIEW": 1,
        "MAINTAIN": 0
    }

    return ranks.get(
        value,
        0
    )


def build_engineering_priorities(
    technique_results
):
    priorities = [
        {
            "technique_id": item[
                "technique_id"
            ],
            "technique": item[
                "technique"
            ],
            "technique_priority": item[
                "technique_priority"
            ],
            "coverage_rating": item[
                "coverage_rating"
            ],
            "coverage_score": item[
                "coverage_score"
            ],
            "engineering_priority": item[
                "engineering_priority"
            ],
            "recommendation": item[
                "recommendation"
            ]
        }
        for item in technique_results
        if item[
            "engineering_priority"
        ]
        != "MAINTAIN"
    ]

    priorities.sort(
        key=lambda item: (
            -engineering_priority_rank(
                item[
                    "engineering_priority"
                ]
            ),
            item[
                "coverage_score"
            ],
            item[
                "technique_id"
            ]
        )
    )

    return priorities


def build_redundancy_review(
    technique_results
):
    return [
        {
            "technique_id": item[
                "technique_id"
            ],
            "technique": item[
                "technique"
            ],
            "detection_count": item[
                "detection_count"
            ],
            "data_sources": item[
                "data_sources"
            ],
            "detection_types": item[
                "detection_types"
            ],
            "coverage_rating": item[
                "coverage_rating"
            ],
            "classification": item[
                "redundancy_review"
            ][
                "classification"
            ],
            "notes": item[
                "redundancy_review"
            ][
                "notes"
            ]
        }
        for item in technique_results
        if item[
            "redundancy_review"
        ][
            "review_required"
        ]
    ]


def build_summary(
    catalog,
    techniques,
    tactics,
    priorities,
    redundancy
):
    return {
        "catalog_detection_count": len(
            catalog
        ),
        "priority_technique_count": len(
            techniques
        ),
        "strong_techniques": sum(
            1
            for item in techniques
            if item["coverage_rating"]
            == "STRONG"
        ),
        "moderate_techniques": sum(
            1
            for item in techniques
            if item["coverage_rating"]
            == "MODERATE"
        ),
        "low_techniques": sum(
            1
            for item in techniques
            if item["coverage_rating"]
            == "LOW"
        ),
        "coverage_gaps": sum(
            1
            for item in techniques
            if item["coverage_rating"]
            == "GAP"
        ),
        "validated_detections": sum(
            1
            for item in catalog
            if item[
                "validation_status"
            ]
            == "Validated"
        ),
        "detections_needing_review": sum(
            1
            for item in catalog
            if item[
                "validation_status"
            ]
            == "Needs Review"
        ),
        "experimental_detections": sum(
            1
            for item in catalog
            if item[
                "detection_status"
            ]
            == "Experimental"
        ),
        "tactics_analyzed": len(
            tactics
        ),
        "engineering_priorities": len(
            priorities
        ),
        "redundancy_reviews": len(
            redundancy
        )
    }


def export_json(report):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

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


def export_technique_csv(
    techniques
):
    fieldnames = [
        "technique_id",
        "technique",
        "tactics",
        "technique_priority",
        "detection_count",
        "validated_detection_count",
        "needs_review_count",
        "experimental_count",
        "active_detection_count",
        "data_source_count",
        "detection_type_count",
        "average_confidence",
        "coverage_score",
        "coverage_rating",
        "engineering_priority",
        "detection_ids",
        "recommendation"
    ]

    with open(
        TECHNIQUE_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for item in techniques:
            writer.writerow({
                "technique_id": item[
                    "technique_id"
                ],
                "technique": item[
                    "technique"
                ],
                "tactics": " | ".join(
                    item["tactics"]
                ),
                "technique_priority": item[
                    "technique_priority"
                ],
                "detection_count": item[
                    "detection_count"
                ],
                "validated_detection_count": (
                    item[
                        "validated_detection_count"
                    ]
                ),
                "needs_review_count": item[
                    "needs_review_count"
                ],
                "experimental_count": item[
                    "experimental_count"
                ],
                "active_detection_count": item[
                    "active_detection_count"
                ],
                "data_source_count": len(
                    item["data_sources"]
                ),
                "detection_type_count": len(
                    item["detection_types"]
                ),
                "average_confidence": item[
                    "average_confidence"
                ],
                "coverage_score": item[
                    "coverage_score"
                ],
                "coverage_rating": item[
                    "coverage_rating"
                ],
                "engineering_priority": item[
                    "engineering_priority"
                ],
                "detection_ids": " | ".join(
                    item["detection_ids"]
                ),
                "recommendation": item[
                    "recommendation"
                ]
            })


def export_tactic_csv(
    tactics
):
    fieldnames = [
        "tactic",
        "priority_technique_count",
        "average_coverage_score",
        "coverage_rating",
        "strong_techniques",
        "low_techniques",
        "gap_techniques",
        "technique_ids"
    ]

    with open(
        TACTIC_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for item in tactics:
            writer.writerow({
                "tactic": item[
                    "tactic"
                ],
                "priority_technique_count": (
                    item[
                        "priority_technique_count"
                    ]
                ),
                "average_coverage_score": (
                    item[
                        "average_coverage_score"
                    ]
                ),
                "coverage_rating": item[
                    "coverage_rating"
                ],
                "strong_techniques": item[
                    "strong_techniques"
                ],
                "low_techniques": item[
                    "low_techniques"
                ],
                "gap_techniques": item[
                    "gap_techniques"
                ],
                "technique_ids": " | ".join(
                    item["technique_ids"]
                )
            })


def export_priority_csv(
    priorities
):
    fieldnames = [
        "technique_id",
        "technique",
        "technique_priority",
        "coverage_rating",
        "coverage_score",
        "engineering_priority",
        "recommendation"
    ]

    with open(
        PRIORITY_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for item in priorities:
            writer.writerow(item)


def print_results(report):
    summary = report["summary"]

    print()
    print("=" * 96)
    print(
        "MITRE ATT&CK DETECTION COVERAGE "
        "& GAP ANALYSIS TOOL"
    )
    print("=" * 96)

    print(
        f"Detection catalog:      "
        f"{summary['catalog_detection_count']}"
    )

    print(
        f"Priority techniques:    "
        f"{summary['priority_technique_count']}"
    )

    print(
        f"STRONG coverage:        "
        f"{summary['strong_techniques']}"
    )

    print(
        f"MODERATE coverage:      "
        f"{summary['moderate_techniques']}"
    )

    print(
        f"LOW coverage:           "
        f"{summary['low_techniques']}"
    )

    print(
        f"Coverage GAPs:          "
        f"{summary['coverage_gaps']}"
    )

    print(
        f"Validated detections:   "
        f"{summary['validated_detections']}"
    )

    print(
        f"Needs review:           "
        f"{summary['detections_needing_review']}"
    )

    print(
        f"Experimental:           "
        f"{summary['experimental_detections']}"
    )

    print(
        f"Redundancy reviews:     "
        f"{summary['redundancy_reviews']}"
    )

    print("-" * 96)
    print("HIGH-PRIORITY ENGINEERING ITEMS")
    print("-" * 96)

    priorities = report[
        "engineering_priorities"
    ]

    if not priorities:
        print(
            "No engineering priorities identified."
        )

    for item in priorities:
        print(
            f"{item['engineering_priority']:<8} | "
            f"{item['technique_id']} | "
            f"{item['technique']:<35} | "
            f"{item['coverage_rating']:<8} | "
            f"Score {item['coverage_score']}"
        )

    print("-" * 96)
    print("REDUNDANCY / OVERLAP REVIEW")
    print("-" * 96)

    redundancy = report[
        "redundancy_review"
    ]

    if not redundancy:
        print(
            "No redundancy reviews identified."
        )

    for item in redundancy:
        print(
            f"{item['technique_id']} | "
            f"{item['technique']:<25} | "
            f"Detections: "
            f"{item['detection_count']} | "
            f"{item['classification']}"
        )

    print("=" * 96)

    print(
        f"JSON report:      "
        f"{JSON_OUTPUT}"
    )

    print(
        f"Technique CSV:    "
        f"{TECHNIQUE_CSV}"
    )

    print(
        f"Tactic CSV:       "
        f"{TACTIC_CSV}"
    )

    print(
        f"Priority CSV:     "
        f"{PRIORITY_CSV}"
    )

    print("=" * 96)


def main():
    catalog = load_csv(
        CATALOG_FILE
    )

    model = load_json(
        MODEL_FILE
    )

    techniques = analyze_techniques(
        catalog,
        model
    )

    tactics = analyze_tactics(
        techniques,
        model
    )

    priorities = (
        build_engineering_priorities(
            techniques
        )
    )

    redundancy = (
        build_redundancy_review(
            techniques
        )
    )

    summary = build_summary(
        catalog,
        techniques,
        tactics,
        priorities,
        redundancy
    )

    report = {
        "model_name": model[
            "model_name"
        ],
        "summary": summary,
        "technique_coverage": techniques,
        "tactic_coverage": tactics,
        "engineering_priorities": priorities,
        "redundancy_review": redundancy,
        "analyst_guardrails": model[
            "analyst_guardrails"
        ]
    }

    export_json(
        report
    )

    export_technique_csv(
        techniques
    )

    export_tactic_csv(
        tactics
    )

    export_priority_csv(
        priorities
    )

    print_results(
        report
    )


if __name__ == "__main__":
    main()
