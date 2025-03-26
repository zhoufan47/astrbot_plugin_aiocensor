import os
import secrets
from multiprocessing import Process

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type:ignore

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image, Plain
from astrbot.api.provider import ProviderRequest
from astrbot.api.star import Context, Star, register
from astrbot.core.star.filter.event_message_type import EventMessageType

from .censor_flow import CensorFlow  # type:ignore
from .common import RiskLevel, admin_check, dispose_msg  # type:ignore
from .db import DBManager  # type:ignore
from .webui import run_server  # type:ignore


@register(
    "astrbot_plugin_aiocensor", "Raven95676", "Astrbot综合内容安全+群管插件", "v0.0.3"
)
class AIOCensor(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.web_ui_process = None

        # 初始化内容审查流
        self.censor_flow = CensorFlow(config)
        # 设置数据存储路径
        data_path = os.path.join(os.getcwd(), "data", "aiocensor")
        if not os.path.exists(data_path):
            os.makedirs(data_path)
        # 初始化数据库管理器
        self.db_mgr = DBManager(os.path.join(data_path, "censor.db"))

    async def initialize(self):
        """初始化组件"""
        logger.debug("初始化组件")
        # 如果webui配置中没有密钥，则生成一个随机密钥
        if not self.config["webui"].get("secret"):
            self.config["webui"]["secret"] = secrets.token_urlsafe(32)
            self.config.save_config()
        # 初始化数据库
        await self.db_mgr.initialize()
        # 获取黑名单并构建用户ID审查器
        black_list = await self.db_mgr.get_blacklist_entries()
        await self.censor_flow.userid_censor.build(
            {entry.identifier for entry in black_list}
        )
        # 如果文本审查器支持构建，则加载敏感词
        if hasattr(self.censor_flow.text_censor, "build"):
            sensitive_words = await self.db_mgr.get_sensitive_words()
            await self.censor_flow.text_censor.build(
                {entry.word for entry in sensitive_words}
            )

        # 注册定时任务，每5分钟检查一次数据库更新
        self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
        self.scheduler.add_job(
            self._update_censors,
            "interval",
            minutes=5,
            id="update_censors",
            misfire_grace_time=60,
        )
        self.scheduler.start()

        # 启动Web UI服务进程
        self.web_ui_process = Process(
            target=run_server,
            args=(
                self.config["webui"]["secret"],
                self.config["webui"]["password"],
                self.config["webui"].get("host", "0.0.0.0"),
                self.config["webui"].get("port", 9966),
            ),
            daemon=True,
        )
        self.web_ui_process.start()

    async def _handle_aiocqhttp_group_message(self, event, res):
        """处理aiocqhttp平台的群消息"""
        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
            AiocqhttpMessageEvent,
        )

        if not isinstance(event, AiocqhttpMessageEvent):
            return

        group_id = int(event.get_group_id())
        user_id = int(event.get_sender_id())
        self_id = int(event.get_self_id())
        message_id = int(event.message_obj.message_id)

        if await admin_check(user_id, group_id, self_id, event.bot):
            return  # 管理员跳过处置

        res.extra.update({
            "group_id": group_id,
            "user_id": user_id,
            "self_id": self_id,
            "message_id": message_id,
        })

        if res.risk_level == RiskLevel.Block and self.config.get("enable_group_msg_censor"):
            await dispose_msg(
                message_id=message_id,
                group_id=group_id,
                user_id=user_id,
                self_id=self_id,
                client=event.bot,
            )

    async def handle_message(self, event: AstrMessageEvent):
        """处理消息内容审查"""
        if self.config.get("enable_blacklist"):
            res = await self.censor_flow.submit_userid(
                event.get_sender_id(), event.unified_msg_origin
            )
            if res.risk_level == RiskLevel.Block:
                if self.config.get("enable_blacklist_log"):
                    await self.db_mgr.add_audit_log(res)
                event.stop_event()
                return

        # 遍历消息组件
        for comp in event.message_obj.message:
            if isinstance(comp, Plain):
                res = await self.censor_flow.submit_text(
                    comp.text, event.unified_msg_origin
                )
            elif isinstance(comp, Image) and self.config.get("enable_image_censor"):
                res = await self.censor_flow.submit_image(
                    comp.url, event.unified_msg_origin
                )
            else:
                continue

            if res.risk_level != RiskLevel.Pass:
                user_id_str = event.get_sender_id()
                res.extra = {"user_id_str": user_id_str}

                # 处理平台特定逻辑
                if event.get_platform_name() == "aiocqhttp" and event.get_group_id():
                    await self._handle_aiocqhttp_group_message(event, res)
                else:
                    logger.warning("非aiocqhttp平台的群消息，无法自动处置")

                await self.db_mgr.add_audit_log(res)
                if res.risk_level == RiskLevel.Block:
                    event.stop_event()
                break

    @filter.event_message_type(EventMessageType.ALL)
    async def is_baned(self, event: AstrMessageEvent):
        """黑名单判定"""
        if self.config.get("enable_blacklist"):
            res = await self.censor_flow.submit_userid(
                event.get_sender_id(), event.unified_msg_origin
            )
            if res.risk_level == RiskLevel.Block:
                if self.config.get("enable_blacklist_log"):
                    await self.db_mgr.add_audit_log(res)
                event.stop_event()

    @filter.on_decorating_result()
    async def on_decorating_result(self, event: AstrMessageEvent):
        """输出审核"""
        if self.config.get("enable_output_censor"):
            await self.handle_message(event)

    @filter.event_message_type(EventMessageType.GROUP_MESSAGE)
    async def group_censor(self, event: AstrMessageEvent):
        """群管功能"""
        if not self.config.get("enable_group_msg_censor"):
            return

        group_list = self.config.get("group_list", [])
        if group_list and event.get_group_id() not in group_list:
            return

        await self.handle_message(event)

    @filter.event_message_type(EventMessageType.PRIVATE_MESSAGE)
    async def private_censor(self, event: AstrMessageEvent):
        """私聊审核功能"""
        if self.config.get("enable_private_msg_censor"):
            await self.handle_message(event)

    @filter.on_llm_request()
    async def on_llm_request(self, request: ProviderRequest, event: AstrMessageEvent):
        """LLM 请求前的审核"""
        if not self.config.get("enable_llm_censor"):
            return
            
        res = await self.censor_flow.submit_text(
            request.prompt, event.unified_msg_origin
        )
        if res.risk_level != RiskLevel.Pass:
            await self.db_mgr.add_audit_log(res)
            event.stop_event()
            return

        for image_url in request.image_urls:
            res = await self.censor_flow.submit_image(
                image_url, event.unified_msg_origin
            )
            if res.risk_level != RiskLevel.Pass:
                await self.db_mgr.add_audit_log(res)
                event.stop_event()
                return

    async def terminate(self):
        """清理资源"""
        if hasattr(self, "scheduler"):
            self.scheduler.shutdown()

        if self.web_ui_process:
            self.web_ui_process.terminate()
            self.web_ui_process.join(5)

        await self.censor_flow.close()
        await self.db_mgr.close()

    async def _update_censors(self):
        """定期更新审查器数据"""
        try:
            black_list = await self.db_mgr.get_blacklist_entries()
            await self.censor_flow.userid_censor.build(
                {entry.identifier for entry in black_list}
            )

            if hasattr(self.censor_flow.text_censor, "build"):
                sensitive_words = await self.db_mgr.get_sensitive_words()
                await self.censor_flow.text_censor.build(
                    {entry.word for entry in sensitive_words}
                )

            logger.debug("审查器数据已更新")
        except Exception as e:
            logger.error(f"更新审查器数据失败: {e}")