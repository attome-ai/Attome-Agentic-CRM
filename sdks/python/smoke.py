"""S3-T1: the Python SDK against a Prism mock of the SDK document.

Usage: python sdks/python/smoke.py http://127.0.0.1:4010

Prism answers from the document's schemas and refuses a request the
document does not allow (a missing API key, a PATCH without If-Match), so a
pass means the generated client and Attome's layer send what the API
declares and read what it answers.
"""

import sys
import uuid

from attome_sdk.client import IDEMPOTENCY_HEADER, AttomeClient
from attome_sdk.exceptions import ApiException
from attome_sdk.models.execute_query_request import ExecuteQueryRequest


def main(base_url: str) -> None:
    client = AttomeClient(base_url, "pk_smoke", "secret", retries=0)
    record_id = str(uuid.uuid4())

    listed = list(client.records("account", page_size=10, max_pages=2))
    assert isinstance(listed, list)

    client.get("account", record_id)

    created = client.create("account", {"name": "Smoke"})
    assert created.id is not None and created.row_version is not None

    updated = client.update("account", record_id, 1, {"name": "Smoke 2"})
    assert updated.data is not None

    client.delete("account", record_id)

    answer = client.query(ExecuteQueryRequest(entity="account", page_size=5))
    assert answer.data is not None and answer.metadata is not None

    assert IDEMPOTENCY_HEADER == "x-idempotency-key"

    anonymous = AttomeClient(base_url, retries=0)
    try:
        list(anonymous.records("account", max_pages=1))
    except ApiException as error:
        assert error.status == 401, error.status
    else:
        raise AssertionError("a call without an API key was accepted")

    print("python sdk smoke: ok")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4010")
