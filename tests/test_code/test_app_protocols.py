# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import os
import sys
import logging
import asyncio
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from agent_connect.app_protocols.app_protocols import AppProtocols
from agent_connect.utils.log_base import set_log_color_level

async def test_app_protocols():
    """测试 AppProtocols 功能"""
    try:
        # 获取测试协议目录的路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        test_protocol_path = os.path.join(current_dir, 'generated_code_test')
        
        # 初始化 AppProtocols 实例
        app_protocols = AppProtocols([test_protocol_path])
        
        # 测试协议加载
        education_protocol_hash = "sha256:2664c06c8ff8f26a56a3a7d8da81c32ab1365d4c8cc1501b887dde82e0067f40"
        
        # 获取 Requester 和 Provider 类
        requester_class = app_protocols.get_requester_by_hash(education_protocol_hash)
        provider_class = app_protocols.get_provider_by_hash(education_protocol_hash)
        
        if requester_class and provider_class:
            logging.info("成功加载协议类")
            logging.info(f"Requester class: {requester_class.__name__}")
            logging.info(f"Provider class: {provider_class.__name__}")
        else:
            logging.error("协议类加载失败")
            return
            
        # 测试协议文件哈希计算
        protocol_doc_path = os.path.join(
            test_protocol_path,
            'education_history_protocol',
            'protocol_document.md'
        )
        calculated_hash = app_protocols.calculate_file_hash(protocol_doc_path)
        logging.info(f"协议文件哈希值: {calculated_hash}")
        
        # 测试协议文件完整性验证
        protocol_dir = os.path.join(
            test_protocol_path,
            'education_history_protocol'
        )
        
        verification_result = app_protocols.verify_protocol_files(
            protocol_dir,
            {
                "files": {
                    "protocol_document": {
                        "file": "protocol_document.md",
                        "hash": "sha256:2664c06c8ff8f26a56a3a7d8da81c32ab1365d4c8cc1501b887dde82e0067f40"
                    },
                    "requester": {
                        "file": "requester.py",
                        "hash": "sha256:af4bb9b0faaee53f2e86ceb448ed6ecc50a89c99177732858c6007e0aff1f87b"
                    },
                    "provider": {
                        "file": "provider.py",
                        "hash": "sha256:9701d46940bfa68972675ca25198321daf77ee685fe73861141602bfd2c42ad1"
                    }
                }
            }
        )
        
        if verification_result:
            logging.info("协议文件完整性验证通过")
        else:
            logging.error("协议文件完整性验证失败")
            
        # 测试无效协议哈希
        invalid_hash = "sha256:invalid_hash_value"
        invalid_requester = app_protocols.get_requester_by_hash(invalid_hash)
        invalid_provider = app_protocols.get_provider_by_hash(invalid_hash)
        
        if invalid_requester is None and invalid_provider is None:
            logging.info("无效协议哈希处理正确")
        else:
            logging.error("无效协议哈希处理异常")

    except Exception as e:
        logging.error(f"测试过程中发生错误: {str(e)}", exc_info=True)
        raise

async def main():
    """主测试函数"""
    set_log_color_level(logging.INFO)
    await test_app_protocols()

if __name__ == "__main__":
    asyncio.run(main()) 