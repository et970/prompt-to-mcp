"""Persistence for :class:`McpRecord` provisioning results."""

from __future__ import annotations

import abc

from ..models import McpRecord


class RecordStore(abc.ABC):
    @abc.abstractmethod
    async def put(self, record: McpRecord) -> None: ...

    @abc.abstractmethod
    async def get(self, mcp_id: str) -> McpRecord | None: ...

    @abc.abstractmethod
    async def list(self, limit: int = 50) -> list[McpRecord]: ...

    @abc.abstractmethod
    async def delete(self, mcp_id: str) -> None: ...


class MemoryRecordStore(RecordStore):
    def __init__(self) -> None:
        self._records: dict[str, McpRecord] = {}

    async def put(self, record: McpRecord) -> None:
        self._records[record.id] = record

    async def get(self, mcp_id: str) -> McpRecord | None:
        return self._records.get(mcp_id)

    async def list(self, limit: int = 50) -> list[McpRecord]:
        return list(self._records.values())[:limit]

    async def delete(self, mcp_id: str) -> None:
        self._records.pop(mcp_id, None)


class FirestoreRecordStore(RecordStore):
    COLLECTION = "p2m_mcps"

    def __init__(self, project_id: str, database: str = "(default)") -> None:
        from google.cloud import firestore

        self._db = firestore.AsyncClient(project=project_id, database=database)

    async def put(self, record: McpRecord) -> None:
        await (
            self._db.collection(self.COLLECTION)
            .document(record.id)
            .set(record.model_dump(mode="json"))
        )

    async def get(self, mcp_id: str) -> McpRecord | None:
        snap = await self._db.collection(self.COLLECTION).document(mcp_id).get()
        return McpRecord.model_validate(snap.to_dict()) if snap.exists else None

    async def list(self, limit: int = 50) -> list[McpRecord]:
        out: list[McpRecord] = []
        async for snap in self._db.collection(self.COLLECTION).limit(limit).stream():
            out.append(McpRecord.model_validate(snap.to_dict()))
        return out

    async def delete(self, mcp_id: str) -> None:
        await self._db.collection(self.COLLECTION).document(mcp_id).delete()
