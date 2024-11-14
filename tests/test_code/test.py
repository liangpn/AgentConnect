from textwrap import dedent
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
import json

protocol_doc = """
----------a
    b
    c
    d
    e
----------
"""

user_prompt = dedent('''
    Please generate a requester class based on the following protocol documentation:

    --[ protocol_doc ]--
    {protocol_doc}
    --[END]--
''').format(protocol_doc=protocol_doc).strip()

print(user_prompt)


import asyncio
from openai import AsyncAzureOpenAI
from tests.test_code.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT, 
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config
)

async def test_azure_openai():
    """测试访问 Azure OpenAI"""
    
    # 验证配置
    validate_config()
    
    # 创建 Azure OpenAI 客户端
    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )

    # 打印 Azure OpenAI 配置信息
    print("Azure OpenAI 配置信息:")
    print(f"API Key: {AZURE_OPENAI_API_KEY}")
    print(f"Endpoint: {AZURE_OPENAI_ENDPOINT}")
    print(f"Deployment: {AZURE_OPENAI_DEPLOYMENT}")
    print(f"Model Name: {AZURE_OPENAI_MODEL_NAME}")
    print("------------------------")
    
    try:
        # 发送请求
        response = await client.chat.completions.create(
            model=AZURE_OPENAI_MODEL_NAME,
            messages=[
                {"role": "system", "content": "你是一个有帮助的助手。"},
                {"role": "user", "content": "你好!"}
            ]
        )
        print(f"Azure OpenAI 响应: {response.choices[0].message.content}")
        
    except Exception as e:
        print(f"调用 Azure OpenAI 出错: {str(e)}")

# 运行测试
if __name__ == "__main__":
    asyncio.run(test_azure_openai())



