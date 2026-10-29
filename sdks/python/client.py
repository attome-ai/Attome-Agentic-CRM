"""Attome's layer over the generated Python client (S3-T1).

Copied into the generated package as ``attome_sdk.client`` by the build
(``sdks/README.md``). It adds what every caller needs and the generator does
not know about the Attome API:

- **Auth:** ``Authorization: ApiKey <public_key>:<secret>``.
- **Retries:** 429, 502, 503 and 504 are tried again (honouring
  ``Retry-After``), for every method; a write is safe to repeat because of
  its idempotency key.
- **Idempotency:** each write sends one ``x-idempotency-key``, the same on
  every retry of that call, so the server applies it once.
- **Paging:** ``records()`` follows ``next_cursor`` to the end.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterator, Optional

import urllib3

from attome_sdk.api.entity_api import EntityApi
from attome_sdk.api.query_api import QueryApi
from attome_sdk.api_client import ApiClient
from attome_sdk.configuration import Configuration

RETRY_STATUSES = (429, 502, 503, 504)
IDEMPOTENCY_HEADER = "x-idempotency-key"


class AttomeClient:
    """One deployment, one API key."""

    def __init__(
        self,
        base_url: str,
        public_key: Optional[str] = None,
        secret: Optional[str] = None,
        retries: int = 3,
        backoff: float = 0.5,
    ) -> None:
        config = Configuration(host=base_url.rstrip("/"))
        if public_key is not None and secret is not None:
            config.api_key["api_key"] = f"ApiKey {public_key}:{secret}"
        config.retries = urllib3.Retry(
            total=retries,
            backoff_factor=backoff,
            status_forcelist=RETRY_STATUSES,
            allowed_methods=None,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.api_client = ApiClient(config)
        self.entities = EntityApi(self.api_client)
        self.queries = QueryApi(self.api_client)

    @staticmethod
    def _write_headers() -> Dict[str, str]:
        return {IDEMPOTENCY_HEADER: str(uuid.uuid4())}

    def records(
        self,
        entity: str,
        page_size: int = 200,
        max_pages: Optional[int] = None,
        **params: Any,
    ) -> Iterator[Any]:
        """Every record of ``entity`` the key may read, page after page."""
        cursor: Optional[str] = None
        pages = 0
        while True:
            page = self.entities.list_records(
                entity, page_size=page_size, cursor=cursor, **params
            )
            yield from page.items
            pages += 1
            cursor = page.next_cursor
            if not cursor or (max_pages is not None and pages >= max_pages):
                return

    def get(self, entity: str, record_id: str, **params: Any) -> Any:
        return self.entities.get_record(entity, record_id, **params)

    def create(self, entity: str, fields: Dict[str, Any]) -> Any:
        return self.entities.create_record(
            entity, request_body=fields, _headers=self._write_headers()
        )

    def update(
        self, entity: str, record_id: str, row_version: int, fields: Dict[str, Any]
    ) -> Any:
        """Changes ``fields``; refused (409) when the record changed since
        ``row_version`` was read."""
        return self.entities.update_record(
            entity,
            record_id,
            if_match=f'"{row_version}"',
            request_body=fields,
            _headers=self._write_headers(),
        )

    def delete(self, entity: str, record_id: str) -> None:
        self.entities.delete_record(entity, record_id, _headers=self._write_headers())

    def query(self, request: Any) -> Any:
        return self.queries.execute(request)
