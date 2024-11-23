# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import importlib
import json
import os
import logging
from typing import Any, Dict, Tuple

import sys
g_current_dir: str = os.path.dirname(os.path.abspath(__file__))
sys.path.append(g_current_dir)
sys.path.append(g_current_dir + "/../../")

from agent_connect.utils.llm.base_llm import AzureLLM, BaseLLM
from agent_connect.utils.llm_output_processer import extract_code_from_llm_output
from agent_connect.simple_node import SimpleNegotiationNode
from openai import AsyncAzureOpenAI

from config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config
)

g_current_dir: str = os.path.dirname(os.path.abspath(__file__))

def generate_did_info(node: SimpleNegotiationNode, json_filename: str) -> None:
    """Generate or load DID information for a node
    
    Args:
        node: The SimpleNegotiationNode instance
        json_filename: Name of the JSON file to store DID info (e.g. "alice.json")
    """
    json_path: str = os.path.join(g_current_dir, json_filename)

    if os.path.exists(json_path):
        print(f"Loading existing DID information from {json_filename}")
        with open(json_path, "r") as f:
            info: Dict[str, str] = json.load(f)
        node.set_did_info(info["private_key_pem"], info["did"], info["did_document_json"])
    else:
        print(f"Generating new DID information for {json_filename}")
        private_key_pem: str
        did: str
        did_document_json: str
        private_key_pem, did, did_document_json = node.generate_did_document()
        node.set_did_info(private_key_pem, did, did_document_json)
        
        with open(json_path, "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)

def get_llm_instance() -> AzureLLM:
    """Return the Azure OpenAI LLM instance"""
    validate_config()
    
    client: AsyncAzureOpenAI = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )
    
    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

def load_bob_did() -> str:
    """Load Bob's DID from the JSON file"""
    bob_json_path: str = os.path.join(g_current_dir, "bob.json") 
    with open(bob_json_path, "r") as f:
        bob_info: Dict[str, str] = json.load(f)
    return bob_info["did"] 

async def generate_code_for_protocol_requester_interface(llm: BaseLLM, 
                                         interface_description: Dict[str, Any], 
                                         code_path: str) -> str:
    """根据接口描述生成协议接口代码
    
    Args:
        llm: LLM实例
        interface_description: 接口描述字典
        code_path: 生成代码的保存路径
        
    Returns:
        str: 生成的代码字符串
    """
    # 构建系统提示词
    system_prompt = """你是一个专业的Python开发者。
# 请根据接口描述生成异步函数代码。代码需要遵循以下要求:
1. 函数必须是异步函数(async def)
2. 函数名必须为call_requester_interface
3. 函数输入参数为RequesterBase实例
4. RequesterBase导入方法:from agent_connect.app_protocols import RequesterBase
5. 在函数中调用实例的send_request方法，并且根据方便描述，构造一个用于测试的合适的函数入参。
6. 返回send_request方法返回的字典
7. 代码需要类型提示
8. 遵循Google Python风格指南

# 输出格式
输出代码以三个反引号包裹，中间的代码是可以运行的Python代码。
示例如下：

```python
XXXX
```
"""

    # 构建用户提示词
    user_prompt = f"""请根据以下接口描述生成代码:
{json.dumps(interface_description, indent=2)}

生成的代码应该包含完整的异步函数定义、类型提示和注释。
"""

    # 调用LLM生成代码
    code = await llm.async_generate_response(system_prompt, user_prompt)

    print(f"Generated code: {code}")

    code = extract_code_from_llm_output(code)
    
    # Check if the directory exists, if not, create it
    directory = os.path.dirname(code_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if code_path:
        with open(code_path, "w") as f:
            f.write(code)
            
    # Dynamically load the Python code from the specified path
    spec = importlib.util.spec_from_file_location("requester_module", code_path)
    requester_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(requester_module)

    # Start a coroutine to call the function defined in the dynamically loaded module
    if hasattr(requester_module, 'call_requester_interface'):
        return requester_module.call_requester_interface
    else:
        print("Function 'call_requester_interface' not found in the loaded module.")
        return None

async def generate_code_for_protocol_provider_callback(
    llm: BaseLLM,
    callback_description: Dict[str, Any],
    code_path: str
) -> str:
    """根据回调函数描述生成provider回调处理函数代码
    
    Args:
        llm: LLM实例
        callback_description: 回调函数描述字典
        code_path: 生成代码的保存路径
        
    Returns:
        str: 生成的回调处理函数
    """
    # 构建系统提示词
    system_prompt = """你是一个专业的Python开发者。
# 请根据回调函数描述生成异步回调函数代码。代码需要遵循以下要求:
1. 函数必须是异步函数(async def)
2. 函数名必须为provider_callback
3. 函数参数需要与回调函数描述中的参数定义保持一致
4. 函数需要返回一个合适的响应数据,你可以自己构造测试数据
5. 代码需要类型提示
6. 遵循Google Python风格指南
7. 生成的回调函数应该包含基本的参数验证和错误处理

# 输出格式
输出代码以三个反引号包裹，中间的代码是可以运行的Python代码。
示例如下：

```python
XXXX
```
"""

    # 构建用户提示词
    user_prompt = f"""请根据以下回调函数描述生成代码:
{json.dumps(callback_description, indent=2)}

生成的代码应该包含完整的异步函数定义、类型提示和注释。
"""

    # 调用LLM生成代码
    code = await llm.async_generate_response(system_prompt, user_prompt)
    
    print(f"Generated callback code: {code}")
    
    code = extract_code_from_llm_output(code)
    
    # 确保目录存在
    directory = os.path.dirname(code_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # 保存生成的代码
    if code_path:
        with open(code_path, "w") as f:
            f.write(code)
            
    # 动态加载生成的代码
    spec = importlib.util.spec_from_file_location("provider_module", code_path)
    provider_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider_module)

    # 返回生成的回调函数
    if hasattr(provider_module, 'provider_callback'):
        return provider_module.provider_callback
    else:
        print("Function 'provider_callback' not found in the loaded module.")
        return None

