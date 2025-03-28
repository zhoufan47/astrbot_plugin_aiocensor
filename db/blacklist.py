import time
import uuid
import sqlite3

from ..common.types import BlacklistEntry, DBError  # type: ignore


class BlacklistMixin:
    """黑名单相关功能"""

    _db: sqlite3.Connection | None

    def _create_tables(self) -> None:
        """
        创建黑名单表。

        Raises:
            DBError: 数据库未初始化或创建表失败。
        """
        if not self._db:
            raise DBError("数据库未初始化")
        try:
            self._db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id TEXT PRIMARY KEY,
                identifier TEXT UNIQUE NOT NULL,
                reason TEXT,
                updated_at INTEGER NOT NULL
            )""")
            self._db.commit()
        except sqlite3.Error as e:
            self._db.rollback()
            raise DBError(f"创建黑名单表失败: {e!s}")

    def add_blacklist_entry(
        self, identifier: str, reason: str | None = None
    ) -> str:
        """
        添加一个黑名单条目。

        Args:
            identifier: 黑名单标识符，通常是用户ID或群组ID。
            reason: 添加到黑名单的原因，可选。

        Returns:
            新添加的黑名单条目的ID。

        Raises:
            DBError: 数据库未初始化或添加条目失败。
        """
        if not self._db:
            raise DBError("数据库未初始化或连接已关闭")
        entry_id = str(uuid.uuid4())
        current_time = int(time.time())
        try:
            cursor = self._db.cursor()
            cursor.execute(
                "INSERT INTO blacklist (id, identifier, reason, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(identifier) DO UPDATE SET reason = ?, updated_at = ? RETURNING id",
                (entry_id, identifier, reason, current_time, reason, current_time),
            )
            result = cursor.fetchone()
            self._db.commit()
            cursor.close()
            return result[0] if result else entry_id
        except sqlite3.Error as e:
            self._db.rollback()
            raise DBError(f"添加黑名单条目失败：{e!s}")

    def get_blacklist_entries(
        self, limit: int = 100, offset: int = 0
    ) -> list[BlacklistEntry]:
        """
        获取黑名单条目列表。

        Args:
            limit: 返回的最大条目数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            黑名单条目列表。

        Raises:
            DBError: 数据库未初始化或获取条目失败。
        """
        if not self._db:
            raise DBError("数据库未初始化或连接已关闭")
        try:
            cursor = self._db.execute(
                "SELECT id, identifier, reason, updated_at FROM blacklist ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [
                BlacklistEntry(
                    id=row[0], identifier=row[1], reason=row[2], updated_at=row[3]
                )
                for row in rows
            ]
        except sqlite3.Error as e:
            raise DBError(f"获取黑名单条目失败：{e!s}")

    def get_blacklist_entries_count(self) -> int:
        """
        获取黑名单条目的总数。

        Returns:
            黑名单条目的总数。

        Raises:
            DBError: 数据库未初始化或获取条目总数失败。
        """
        if not self._db:
            raise DBError("数据库未初始化或连接已关闭")
        try:
            cursor = self._db.execute("SELECT COUNT(*) FROM blacklist")
            result = cursor.fetchone()
            cursor.close()
            return result[0] if result else 0
        except sqlite3.Error as e:
            raise DBError(f"获取黑名单条目总数失败：{e!s}")

    def search_blacklist(
        self, search_term: str, limit: int = 100, offset: int = 0
    ) -> list[BlacklistEntry]:
        """
        搜索黑名单条目。

        Args:
            search_term: 搜索关键词，将在标识符和原因字段中进行搜索。
            limit: 返回的最大条目数，默认为100。
            offset: 偏移量，用于分页，默认为0。

        Returns:
            符合搜索条件的黑名单条目列表。

        Raises:
            DBError: 数据库未初始化或搜索条目失败。
        """
        if not self._db:
            raise DBError("数据库未初始化或连接已关闭")
        search_pattern = f"%{search_term}%"
        try:
            cursor = self._db.execute(
                "SELECT id, identifier, reason, updated_at FROM blacklist WHERE identifier LIKE ? OR reason LIKE ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (search_pattern, search_pattern, limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [
                BlacklistEntry(
                    id=row[0], identifier=row[1], reason=row[2], updated_at=row[3]
                )
                for row in rows
            ]
        except sqlite3.Error as e:
            raise DBError(f"搜索黑名单条目失败：{e!s}")

    def delete_blacklist_entry(self, entry_id: str) -> bool:
        """
        删除一个黑名单条目。

        Args:
            entry_id: 要删除的黑名单条目的ID。

        Returns:
            如果删除成功返回True，否则返回False。

        Raises:
            DBError: 数据库未初始化或删除条目失败。
        """
        if not self._db:
            raise DBError("数据库未初始化或连接已关闭")
        try:
            cursor = self._db.cursor()
            cursor.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
            deleted = cursor.rowcount > 0
            self._db.commit()
            cursor.close()
            return deleted
        except sqlite3.Error as e:
            self._db.rollback()
            raise DBError(f"删除黑名单条目失败：{e!s}")
