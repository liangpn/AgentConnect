# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import os
import logging
import sys
from typing import Any, Dict

g_current_dir: str = os.path.dirname(os.path.abspath(__file__))
sys.path.append(g_current_dir)
sys.path.append(g_current_dir + "/../../")

from agent_connect.simple_node import SimpleNegotiationNode, ProviderSession
from agent_connect.app_protocols import ProviderBase
from agent_connect.utils.log_base import set_log_color_level

from utils import generate_did_info, get_llm_instance

async def new_provider_negotiation_session_callback(provider_session: ProviderSession) -> None:
    """Process new negotiation sessions"""
    print(f"New negotiation session from DID: {provider_session.remote_did}")

    # note: check remote did permission
    
    # generate the protocol callback process code
    
    # 设置协议处理代码回调，并将代码和协议hash值保存，以便后面使用

    # wait for code generation to complete
    success: bool = await provider_session.code_generated()
    if success:
        print("Code generation completed successfully")
    else:
        print("Code generation failed")

async def main() -> None:
    # create the node for Bob
    bob_node: SimpleNegotiationNode = SimpleNegotiationNode(
        host_domain="localhost",
        llm=get_llm_instance(),
        host_port="8001",
        host_ws_path="/ws",
        protocol_code_path=os.path.join(g_current_dir, "protocol_code"),
        new_provider_session_callback=new_provider_negotiation_session_callback
    )

    # generate the DID information for Bob
    generate_did_info(bob_node, "bob.json")
    print(f"Bob's DID: {bob_node.simple_node.did}")

    # start the node
    bob_node.run()

    while True:
        # process other system tasks
        await asyncio.sleep(1)
    
    # finally stop the node
    await bob_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
