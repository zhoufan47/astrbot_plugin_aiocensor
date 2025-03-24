import asyncio
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

import jwt
from hypercorn.asyncio import serve
from hypercorn.config import Config
from quart import Quart, Response, jsonify, request, send_from_directory

from astrbot.api import logger

from .db import DBManager  # type:ignore


class WebUIServer:
    """AIOCENSOR Web UI类"""

    def __init__(
        self,
        password: str,
        secret_key: str,
    ):
        data_path = os.path.join(os.getcwd(), "data", "aiocensor")
        if not os.path.exists(data_path):
            os.makedirs(data_path)
        self._db_mgr = DBManager(os.path.join(data_path, "censor.db"))
        self._app = Quart(__name__, static_folder="static", static_url_path="")
        self._password = password
        self._secret_key = secret_key
        self._server_task: asyncio.Task | None = None
        self._setup_app()

    def _setup_app(self):
        """配置Quart应用实例"""

        async def format_response(
            data: dict[str, Any] | None = None,
            message: str = "",
            status_code: int = 200,
        ) -> tuple[Response, int]:
            """格式化API响应

            Args:
                data: 响应数据
                message: 响应消息
                status_code: HTTP状态码

            Returns:
                格式化的JSON响应和状态码
            """
            response = {"success": status_code < 400, "message": message}
            if data is not None:
                response.update(data)
            return jsonify(response), status_code

        def generate_tokens() -> tuple[str, str]:
            """生成JWT访问令牌和刷新令牌

            Returns:
                访问令牌和刷新令牌
            """
            access_token = jwt.encode(
                {
                    "role": "admin",
                    "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
                },
                self._secret_key,
                algorithm="HS256",
            )
            refresh_token = jwt.encode(
                {
                    "role": "admin",
                    "exp": datetime.now(timezone.utc) + timedelta(days=30),
                },
                self._secret_key,
                algorithm="HS256",
            )
            return access_token, refresh_token

        def verify_token(token: str) -> dict[str, Any] | None:
            """验证JWT令牌

            Args:
                token: JWT令牌字符串

            Returns:
                解码后的令牌载荷，如果令牌无效则返回None
            """
            try:
                payload = jwt.decode(token, self._secret_key, algorithms=["HS256"])
                return payload
            except jwt.ExpiredSignatureError:
                return None
            except jwt.InvalidTokenError:
                return None

        def clean_input(text: str) -> str:
            """预处理输入文本，去除空格

            Args:
                text: 输入文本

            Returns:
                处理后的文本
            """
            if text:
                return text.strip()
            return ""

        def token_required(func):
            """验证请求中的令牌的装饰器"""

            @wraps(func)
            async def decorated(*args, **kwargs):
                auth_header = request.headers.get("Authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    return await format_response(
                        message="缺少或无效的令牌", status_code=401
                    )

                token = auth_header.split(" ")[1].strip()
                payload = verify_token(token)
                if not payload:
                    return await format_response(
                        message="令牌无效或已过期", status_code=401
                    )

                request.auth = payload
                return await func(*args, **kwargs)

            return decorated

        @self._app.route("/api/login", methods=["POST"])
        async def login() -> tuple[Response, int]:
            """处理用户登录并发放令牌"""
            try:
                data = await request.get_json()
                if not data:
                    return await format_response(
                        message="无效的请求数据", status_code=400
                    )

                password = data.get("password", "")
                password = clean_input(password)

                if not password:
                    return await format_response(message="缺少密码", status_code=400)

                expected_password = self._password
                if password != expected_password:
                    logger.warning("无效的登录尝试，密码错误")
                    return await format_response(message="密码错误", status_code=401)

                access_token, refresh_token = generate_tokens()
                return await format_response(
                    data={"access_token": access_token, "refresh_token": refresh_token},
                    message="登录成功",
                )
            except Exception as e:
                logger.error(f"登录错误: {e!s}")
                return await format_response(message="登录失败", status_code=500)

        @self._app.route("/api/refresh", methods=["POST"])
        async def refresh() -> tuple[Response, int]:
            """使用刷新令牌获取新的访问令牌"""
            try:
                data = await request.get_json()
                if not data:
                    return await format_response(
                        message="无效的请求数据", status_code=400
                    )

                refresh_token = data.get("refresh_token", "")
                refresh_token = clean_input(refresh_token)

                if not refresh_token:
                    return await format_response(
                        message="缺少刷新令牌", status_code=400
                    )

                payload = verify_token(refresh_token)
                if not payload:
                    return await format_response(
                        message="无效的刷新令牌", status_code=401
                    )

                access_token, new_refresh_token = generate_tokens()
                return await format_response(
                    data={
                        "access_token": access_token,
                        "refresh_token": new_refresh_token,
                    },
                    message="刷新成功",
                )
            except Exception:
                return await format_response(message="刷新令牌失败", status_code=500)

        @self._app.route("/api/audit-logs", methods=["GET"])
        @token_required
        async def get_audit_logs() -> tuple[Response, int]:
            """获取审计日志列表"""
            try:
                args = request.args
                limit = int(args.get("limit", 10))
                offset = int(args.get("offset", 0))
                search = args.get("search")

                async with self._db_mgr:
                    if search:
                        logs = await self._db_mgr.get_audit_logs(
                            search_term=search,
                            limit=limit,
                            offset=offset,
                        )
                        total = await self._db_mgr.get_audit_logs_count()
                    else:
                        logs = await self._db_mgr.get_audit_logs(
                            limit=limit, offset=offset
                        )
                        total = await self._db_mgr.get_audit_logs_count()

                return await format_response(
                    data={
                        "logs": [
                            {
                                "id": log.id,
                                "content": log.result.message.content,
                                "user_id": log.result.extra["user_id_str"],
                                "source": log.result.message.source,
                                "systemJudgment": log.result.risk_level.name,
                                "reason": str(log.result.reason),
                                "time": log.result.message.timestamp,
                            }
                            for log in logs
                        ],
                        "total": total,
                    }
                )
            except Exception as e:
                logger.error(f"获取审计日志失败: {e!s}")
                return await format_response(message="获取日志失败", status_code=500)

        @self._app.route("/api/audit-logs/<string:log_id>/dispose", methods=["POST"])
        @token_required
        async def dispose_log(log_id: str) -> tuple[Response, int]:
            """处理审计日志的处置操作"""
            try:
                log_id = clean_input(log_id)
                data = await request.get_json()
                if not data:
                    return await format_response(
                        message="无效的请求数据", status_code=400
                    )

                actions = data.get("actions", [])
                for action in actions:
                    if action == "block":
                        async with self._db_mgr:
                            log = await self._db_mgr.get_audit_log(log_id)
                            if not log:
                                return await format_response(
                                    message="找不到指定的审核日志", status_code=404
                                )

                            if (
                                not log.result.extra
                                or "user_id_str" not in log.result.extra
                            ):
                                return await format_response(
                                    message="审核日志中缺少用户ID信息", status_code=400
                                )

                            user_id = log.result.extra["user_id_str"]
                            reason = f"根据审核日志 {log_id} 添加"

                            existing = await self._db_mgr.search_blacklist(user_id)
                            if any(entry.identifier == user_id for entry in existing):
                                continue

                            await self._db_mgr.add_blacklist_entry(user_id, reason)
                    elif action == "dispose":
                        return await format_response(
                            message="功能未实现", status_code=400 #TODO:实现控制台处置
                        )
                    else:
                        return await format_response(
                            message="无效的操作", status_code=400
                        )
                return await format_response(message="处置成功", status_code=200)
            except Exception as e:
                logger.error(f"处置失败 {log_id}: {e!s}",exc_info=True)
                return await format_response(message="处置失败", status_code=500)

        @self._app.route("/api/audit-logs/<string:log_id>/ignore", methods=["POST"])
        @token_required
        async def ignore_log(log_id: str) -> tuple[Response, int]:
            """忽略（删除）审计日志"""
            try:
                log_id = clean_input(log_id)
                async with self._db_mgr:
                    if not await self._db_mgr.delete_audit_log(log_id):
                        return await format_response(
                            message="日志不存在", status_code=404
                        )
                    return await format_response(
                        message="已删除日志", data={"log_id": log_id}
                    )
            except Exception as e:
                logger.error(f"删除日志失败 {log_id}: {e!s}", exc_info=True)
                return await format_response(message="删除日志失败", status_code=500)

        @self._app.route("/api/blacklist", methods=["GET"])
        @token_required
        async def get_blacklist() -> tuple[Response, int]:
            """获取黑名单列表"""
            try:
                args = request.args
                limit = int(args.get("limit", 10))
                offset = int(args.get("offset", 0))
                search = args.get("search")

                async with self._db_mgr:
                    if search:
                        entries = await self._db_mgr.get_blacklist_entries(
                            search, limit=limit, offset=offset
                        )
                        total = await self._db_mgr.get_blacklist_entries_count()
                    else:
                        entries = await self._db_mgr.get_blacklist_entries(
                            limit=limit, offset=offset
                        )
                        total = await self._db_mgr.get_blacklist_entries_count()

                return await format_response(
                    data={
                        "records": [
                            {
                                "id": entry.id,
                                "user": entry.identifier,
                                "reason": entry.reason,
                            }
                            for entry in entries
                        ],
                        "total": total,
                    }
                )
            except Exception as e:
                logger.error(f"获取黑名单失败: {e!s}")
                return await format_response(message="获取黑名单失败", status_code=500)

        @self._app.route("/api/blacklist", methods=["POST"])
        @token_required
        async def add_to_blacklist() -> tuple[Response, int]:
            """添加条目到黑名单"""
            try:
                data = await request.get_json()
                if not data:
                    return await format_response(
                        message="无效的请求数据", status_code=400
                    )

                user_id = data.get("userId", "")
                reason = data.get("reason", "")

                user_id = clean_input(user_id)
                reason = clean_input(reason)

                if not user_id or not reason:
                    return await format_response(
                        message="缺少必要参数", status_code=400
                    )

                async with self._db_mgr:
                    existing = await self._db_mgr.search_blacklist(user_id)
                    if any(entry.identifier == user_id for entry in existing):
                        return await format_response(
                            message="用户已在黑名单中", status_code=409
                        )

                    record_id = await self._db_mgr.add_blacklist_entry(user_id, reason)
                    return await format_response(
                        data={"id": record_id, "user": user_id, "reason": reason},
                        message="已添加至黑名单",
                        status_code=201,
                    )
            except Exception as e:
                logger.error(f"添加黑名单失败: {e!s}")
                return await format_response(message="添加黑名单失败", status_code=500)

        @self._app.route("/api/blacklist/<string:record_id>", methods=["DELETE"])
        @token_required
        async def delete_blacklist(record_id: str) -> tuple[Response, int]:
            """从黑名单中删除条目"""
            try:
                record_id = clean_input(record_id)
                async with self._db_mgr:
                    if not await self._db_mgr.delete_blacklist_entry(record_id):
                        return await format_response(
                            message="黑名单记录不存在", status_code=404
                        )
                    return await format_response(
                        data={"record_id": record_id}, message="已移出黑名单"
                    )
            except Exception as e:
                logger.error(f"移除黑名单失败: {e!s}", exc_info=True)
                return await format_response(message="移除黑名单失败", status_code=500)

        @self._app.route("/api/sensitive-words", methods=["GET"])
        @token_required
        async def get_sensitive_words() -> tuple[Response, int]:
            """获取敏感词列表"""
            try:
                args = request.args
                limit = int(args.get("limit", 10))
                offset = int(args.get("offset", 0))
                search = args.get("search")

                async with self._db_mgr:
                    if search:
                        words = await self._db_mgr.get_sensitive_words(
                            search, limit=limit, offset=offset
                        )
                        total = len(await self._db_mgr.get_sensitive_words(search))
                    else:
                        words = await self._db_mgr.get_sensitive_words(
                            limit=limit, offset=offset
                        )
                        total = await self._db_mgr.get_sensitive_words_count()

                return await format_response(
                    data={
                        "words": [
                            {
                                "id": word.id,
                                "word": word.word,
                                "updatedAt": word.updated_at,
                            }
                            for word in words
                        ],
                        "total": total,
                    }
                )
            except Exception as e:
                logger.error(f"获取敏感词失败: {e!s}")
                return await format_response(message="获取敏感词失败", status_code=500)

        @self._app.route("/api/sensitive-words", methods=["POST"])
        @token_required
        async def add_sensitive_word() -> tuple[Response, int]:
            """添加敏感词"""
            try:
                data = await request.get_json()
                if not data:
                    return await format_response(
                        message="无效的请求数据", status_code=400
                    )

                word = data.get("word", "")
                word = clean_input(word)

                if not word:
                    return await format_response(
                        message="缺少敏感词内容", status_code=400
                    )

                async with self._db_mgr:
                    existing = await self._db_mgr.get_sensitive_words(word)
                    if any(entry.word == word for entry in existing):
                        return await format_response(
                            message="敏感词已存在", status_code=409
                        )

                    word_id = await self._db_mgr.add_sensitive_word(word)
                    return await format_response(
                        data={"id": word_id, "word": word},
                        message="敏感词添加成功",
                        status_code=201,
                    )
            except Exception as e:
                logger.error(f"添加敏感词失败: {e!s}")
                return await format_response(message="添加敏感词失败", status_code=500)

        @self._app.route("/api/sensitive-words/<string:word_id>", methods=["DELETE"])
        @token_required
        async def delete_sensitive_word(word_id: str) -> tuple[Response, int]:
            """删除敏感词"""
            try:
                word_id = clean_input(word_id)
                async with self._db_mgr:
                    if not await self._db_mgr.delete_sensitive_word(word_id):
                        return await format_response(
                            message="敏感词不存在", status_code=404
                        )
                    return await format_response(
                        data={"word_id": word_id}, message="敏感词删除成功"
                    )
            except Exception as e:
                logger.error(f"删除敏感词失败: {e!s}")
                return await format_response(message="删除敏感词失败", status_code=500)

        @self._app.route("/", strict_slashes=False)
        async def serve_root():
            """提供前端静态文件"""
            return await send_from_directory(self._app.static_folder, "index.html")

    async def start(self, host: str, port: int):
        """启动HTTP服务"""
        config = Config()
        config.bind = [f"{host}:{port}"]
        self._server_task = asyncio.create_task(serve(self._app, config))
        logger.info(f"AIOCENSOR WebUI 服务已启动于 {host}:{port}")

        try:
            await self._server_task
        except asyncio.CancelledError:
            logger.info("请求关闭服务")
        finally:
            await self.close()

    async def close(self):
        """关闭资源"""
        if self._server_task:
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass


def run_server(secret_key: str, password: str, host: str, port: int):
    """子进程入口"""
    server = WebUIServer(password, secret_key)
    asyncio.run(server.start(host, port))
