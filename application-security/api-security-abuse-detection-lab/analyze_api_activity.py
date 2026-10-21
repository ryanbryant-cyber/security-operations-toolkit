import json

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

SAMPLE_DATA_DIR = (
    BASE_DIR
    / "sample-data"
)

CONFIG_DIR = (
    BASE_DIR
    / "config"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

USERS_FILE = (
    SAMPLE_DATA_DIR
    / "users.json"
)

AUTHORIZED_OBJECTS_FILE = (
    SAMPLE_DATA_DIR
    / "authorized_objects.json"
)

API_REQUESTS_FILE = (
    SAMPLE_DATA_DIR
    / "api_requests.json"
)

POLICY_FILE = (
    CONFIG_DIR
    / "detection_policy.json"
)

NORMALIZED_OUTPUT = (
    OUTPUT_DIR
    / "normalized_api_events.json"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def normalize_text(value):
    if value is None:
        return None

    text = str(
        value
    ).strip()

    if not text:
        return None

    return text


def normalize_timestamp(value):
    text = normalize_text(
        value
    )

    if text is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        parsed = parsed.astimezone(
            timezone.utc
        )

        return (
            parsed
            .isoformat()
            .replace(
                "+00:00",
                "Z"
            )
        )

    except ValueError:
        return None


def build_user_lookup(
    users
):
    return {
        user[
            "user"
        ].lower(): user
        for user in users
    }


def identify_resource_type(
    endpoint
):
    if endpoint is None:
        return "unknown"

    if endpoint.startswith(
        "/api/accounts/"
    ):
        return "accounts"

    if endpoint.startswith(
        "/api/invoices/"
    ):
        return "invoices"

    if endpoint.startswith(
        "/api/reports/"
    ):
        return "reports"

    if endpoint.startswith(
        "/api/admin/"
    ):
        return "admin"

    if endpoint.startswith(
        "/api/auth/"
    ):
        return "authentication"

    return "other"


def source_ip_is_expected(
    source_ip,
    user_record
):
    if user_record is None:
        return False

    expected_ips = user_record.get(
        "expected_source_ips",
        []
    )

    return (
        source_ip
        in expected_ips
    )


def object_is_authorized(
    user,
    resource_type,
    object_id,
    authorized_objects
):
    if object_id is None:
        return None

    if resource_type not in {
        "accounts",
        "invoices",
        "reports"
    }:
        return None

    resource_permissions = (
        authorized_objects.get(
            resource_type,
            {}
        )
    )

    allowed_objects = (
        resource_permissions.get(
            user,
            []
        )
    )

    return (
        object_id
        in allowed_objects
    )


def normalize_event(
    raw_event,
    user_lookup,
    authorized_objects
):
    user = normalize_text(
        raw_event.get(
            "user"
        )
    )

    if user is not None:
        user = user.lower()

    user_record = (
        user_lookup.get(
            user
        )
        if user
        else None
    )

    endpoint = normalize_text(
        raw_event.get(
            "endpoint"
        )
    )

    resource_type = (
        identify_resource_type(
            endpoint
        )
    )

    object_id = normalize_text(
        raw_event.get(
            "object_id"
        )
    )

    source_ip = normalize_text(
        raw_event.get(
            "source_ip"
        )
    )

    role = None
    department = None

    if user_record:
        role = user_record.get(
            "role"
        )

        department = (
            user_record.get(
                "department"
            )
        )

    normalized = {
        "timestamp": (
            normalize_timestamp(
                raw_event.get(
                    "timestamp"
                )
            )
        ),

        "request_id": (
            normalize_text(
                raw_event.get(
                    "request_id"
                )
            )
        ),

        "source_ip": source_ip,

        "source_ip_expected": (
            source_ip_is_expected(
                source_ip,
                user_record
            )
        ),

        "user": user,

        "role": role,

        "department": (
            department
        ),

        "token_id": (
            normalize_text(
                raw_event.get(
                    "token_id"
                )
            )
        ),

        "http_method": (
            normalize_text(
                raw_event.get(
                    "http_method"
                )
            )
        ),

        "endpoint": endpoint,

        "resource_type": (
            resource_type
        ),

        "object_id": object_id,

        "object_in_expected_scope": (
            object_is_authorized(
                user,
                resource_type,
                object_id,
                authorized_objects
            )
            if user
            else None
        ),

        "response_status": (
            raw_event.get(
                "response_status"
            )
        ),

        "response_bytes": (
            raw_event.get(
                "response_bytes"
            )
        ),

        "user_agent": (
            normalize_text(
                raw_event.get(
                    "user_agent"
                )
            )
        ),

        "authentication_result": (
            normalize_text(
                raw_event.get(
                    "authentication_result"
                )
            )
        ),

        "authorization_result": (
            normalize_text(
                raw_event.get(
                    "authorization_result"
                )
            )
        )
    }

    if normalized[
        "http_method"
    ]:
        normalized[
            "http_method"
        ] = normalized[
            "http_method"
        ].upper()

    if normalized[
        "authentication_result"
    ]:
        normalized[
            "authentication_result"
        ] = normalized[
            "authentication_result"
        ].lower()

    if normalized[
        "authorization_result"
    ]:
        normalized[
            "authorization_result"
        ] = normalized[
            "authorization_result"
        ].lower()

    return normalized


def normalize_events(
    api_requests,
    users,
    authorized_objects
):
    user_lookup = (
        build_user_lookup(
            users
        )
    )

    normalized_events = []

    for raw_event in api_requests:
        normalized_events.append(
            normalize_event(
                raw_event,
                user_lookup,
                authorized_objects
            )
        )

    return normalized_events


def export_normalized_events(
    events
):
    report = {
        "event_count": len(
            events
        ),
        "events": events
    }

    with open(
        NORMALIZED_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )


def print_summary(
    events
):
    unexpected_ip_events = sum(
        1
        for event in events
        if (
            event[
                "user"
            ]
            and not event[
                "source_ip_expected"
            ]
        )
    )

    out_of_scope_objects = sum(
        1
        for event in events
        if event[
            "object_in_expected_scope"
        ]
        is False
    )

    print()
    print("=" * 78)

    print(
        "API SECURITY ANALYSIS "
        "FOUNDATION"
    )

    print("=" * 78)

    print(
        f"Normalized API events:      "
        f"{len(events)}"
    )

    print(
        f"Unexpected-source events:   "
        f"{unexpected_ip_events}"
    )

    print(
        f"Out-of-scope object events: "
        f"{out_of_scope_objects}"
    )

    print("=" * 78)

    print(
        f"Normalized dataset: "
        f"{NORMALIZED_OUTPUT}"
    )

    print("=" * 78)


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    users = load_json(
        USERS_FILE
    )

    authorized_objects = (
        load_json(
            AUTHORIZED_OBJECTS_FILE
        )
    )

    api_requests = load_json(
        API_REQUESTS_FILE
    )

    load_json(
        POLICY_FILE
    )

    normalized_events = (
        normalize_events(
            api_requests,
            users,
            authorized_objects
        )
    )

    export_normalized_events(
        normalized_events
    )

    print_summary(
        normalized_events
    )


if __name__ == "__main__":
    main()
