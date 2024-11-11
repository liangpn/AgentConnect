import sys
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any
sys.path.append(str(Path(__file__).parent.parent.parent))

from agent_connect.meta_protocol.meta_protocol import MetaProtocol, ProtocolType
from agent_connect.meta_protocol.protocol_negotiator import NegotiationStatus
from agent_connect.utils.log_base import set_log_color_level
from agent_connect.utils.llm.base_llm import AzureLLM
from openai import AsyncAzureOpenAI
from tests.test_code.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config
)

# 模拟发送数据的回调函数
async def mock_send_callback(data: bytes) -> None:
    """模拟发送数据的回调函数"""
    logging.info(f"Mock sending data: {data}")

# 模拟获取能力信息的回调函数
async def mock_capability_info(requirement: str, 
                             input_description: str, 
                             output_description: str) -> str:
    """模拟获取能力信息的回调函数"""
    return """
    Capability Assessment:
    - Requirements: Can fully meet the specified requirements
    - Input Format: Can process all specified input fields
    - Output Format: Can generate all required output fields
    - No significant limitations or constraints identified
    """

def get_llm_instance() -> AzureLLM:
    """Return Azure OpenAI LLM instance"""
    validate_config()
    
    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )
    
    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

async def test_negotiate_protocol():
    """测试协议协商功能"""
    try:
        # 获取LLM实例
        llm = get_llm_instance()
        
        # 创建MetaProtocol实例
        meta_protocol = MetaProtocol(
            send_callback=mock_send_callback,
            get_capability_info_callback=mock_capability_info,
            llm=llm
        )

        # 定义测试用的协议需求
        requirement = """
        设计一个用于获取用户教育经历的 API 接口。
        - API 应该支持获取单个用户的教育经历信息
        - 教育经历信息应包含：学校名称、专业、学位、成就、开始时间、结束时间
        - 需要支持错误处理和参数验证
        """

        input_description = """
        输入参数应包含：
        - user_id: 用户ID (字符串)
        - include_details: 是否包含详细信息 (布尔值，可选)
        """

        output_description = """
        输出应包含：
        - 教育经历列表，每个教育经历包含：
          * institution: 学校名称
          * major: 专业
          * degree: 学位 (Bachelor/Master/Doctorate)
          * achievements: 成就
          * start_date: 开始时间 (YYYY-MM-DD)
          * end_date: 结束时间 (YYYY-MM-DD)
        - 支持分页和错误信息返回
        """

        # 启动协议协商协程
        negotiation_task = asyncio.create_task(
            meta_protocol.negotiate_protocol(
                requirement=requirement,
                input_description=input_description,
                output_description=output_description
            )
        )

        # 模拟接收协议协商消息
        async def simulate_negotiation_messages():
            # 等待一段时间，让negotiate_protocol先执行
            await asyncio.sleep(1)
            
            # 修改消息1的格式 - 简化协议定义并避免转义字符问题
            message1 = {
                "action": "protocolNegotiation",
                "sequenceId": 1,
                "candidateProtocols": {  # 直接使用字典而不是 JSON 字符串
                    "endpoints": [
                        {
                            "path": "/api/v1/education",
                            "method": "GET",
                            "parameters": {
                                "user_id": {"type": "string", "required": True},
                                "include_details": {"type": "boolean", "required": False}
                            }
                        }
                    ],
                    "schemas": {
                        "EducationExperience": {
                            "type": "object",
                            "properties": {
                                "institution": {"type": "string"},
                                "major": {"type": "string"},
                                "degree": {"type": "string", "enum": ["Bachelor", "Master", "Doctorate"]},
                                "achievements": {"type": "string"},
                                "start_date": {"type": "string", "format": "date"},
                                "end_date": {"type": "string", "format": "date"}
                            }
                        }
                    }
                },
                "status": NegotiationStatus.ACCEPTED.value
            }

            # 将消息编码为字节并添加协议类型头
            protocol_type_byte = bytes([ProtocolType.META.value << 6])
            message_bytes = protocol_type_byte + json.dumps(message1).encode('utf-8')
            
            # 模拟接收消息
            await meta_protocol.handle_meta_data(message_bytes)

        # 启动模拟消息接收协程
        message_task = asyncio.create_task(simulate_negotiation_messages())

        # 等待协议协商完成
        success, protocol = await negotiation_task
        await message_task

        # 验证协商结果
        if success:
            logging.info("协议协商成功!")
            logging.info(f"协商的协议内容: {protocol}")
        else:
            logging.error("协议协商失败!")

    except Exception as e:
        logging.error(f"测试过程中出现错误: {str(e)}", exc_info=True)
        raise

async def main():
    """主测试函数"""
    set_log_color_level(logging.INFO)
    await test_negotiate_protocol()

if __name__ == "__main__":
    asyncio.run(main()) 