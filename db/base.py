import sqlite3

from ..common.types import DBError  # type: ignore


class BaseDBMixin:
    """基础数据库Mixin"""

    def __init__(self, db_path: str):
        """
        初始化数据库Mixin。

        Args:
            db_path: 数据库文件的路径。
        """
        self._db_path: str = db_path
        self._db: sqlite3.Connection | None = None

    def __enter__(self) -> "BaseDBMixin":
        """
        同步上下文管理器入口。

        Returns:
            返回自身实例。
        """
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        同步上下文管理器出口。

        Args:
            exc_type: 异常类型。
            exc_val: 异常值。
            exc_tb: 异常回溯信息。
        """
        self.close()

    def initialize(self) -> None:
        """初始化数据库连接和表结构。"""
        try:
            self._db = sqlite3.connect(self._db_path)
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._create_tables()
        except sqlite3.Error as e:
            if self._db:
                self._db.close()
                self._db = None
            raise DBError(f"无法连接到数据库: {e!s}")
        except Exception as e:
            if self._db:
                self._db.close()
                self._db = None
            raise DBError(f"初始化数据库失败: {e!s}")

    def _create_tables(self):
        """
        创建数据库表结构。

        Raises:
            NotImplementedError: 如果子类没有实现此方法。
        """
        raise NotImplementedError

    def close(self) -> None:
        """关闭数据库连接。"""
        if self._db:
            try:
                self._db.close()
                self._db = None
            except sqlite3.Error as e:
                raise DBError(f"关闭数据库连接失败：{e!s}")
