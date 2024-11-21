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

from agent_connect.simple_node import SimpleNegotiationNode, RequesterSession
from agent_connect.app_protocols import RequesterBase
from agent_connect.utils.log_base import set_log_color_level

from utils import generate_did_info, get_llm_instance, load_bob_did

# Define protocol requirements
requirement = """
Design an API interface for retrieving user education history.
- API should support retrieving education history for a single user
- Education history should include: school name, major, degree, achievements, start time, end time
- Must support error handling and parameter validation
"""

input_description = """
Input parameters should include:
- user_id: User ID (string)
- include_details: Whether to include detailed information (boolean, optional)
"""

output_description = """
Output should include:
- List of education history, each containing:
* institution: School name
* major: Major
* degree: Degree (Bachelor/Master/Doctorate)
* achievements: Achievements
* start_date: Start time (YYYY-MM-DD)
* end_date: End time (YYYY-MM-DD)
- Support for pagination and error message return
"""

async def main() -> None:
    # create the node for Alice
    alice_node: SimpleNegotiationNode = SimpleNegotiationNode(
        host_domain="localhost", 
        llm=get_llm_instance(),
        host_port="8000",
        host_ws_path="/ws",
        protocol_code_path=os.path.join(g_current_dir, "protocol_code")
    )

    # generate the DID information for Alice
    generate_did_info(alice_node, "alice.json")
    print(f"Alice's DID: {alice_node.simple_node.did}")

    # load the DID information for Bob
    bob_did: str = load_bob_did()

    # start the node
    alice_node.run()

    # connect to Bob, and negotiate the protocol
    requester_session: RequesterSession = await alice_node.connect_to_did(bob_did, 
                                                                          requirement, 
                                                                          input_description, 
                                                                          output_description)
    
    # get the requester instance and the interface description
    requester_instance: RequesterBase = requester_session.requester_instance
    interface_description: Dict[str, Any] = requester_session.send_request_description

    # notify the remote side that code generation has been completed, and wait for the remote side to confirm
    success: bool = await requester_session.code_generated()
    print(f"Code generated: {success}")
    print(f"Interface description: {interface_description}")

    while True:
        # process other system tasks
        await asyncio.sleep(1)

    # finally stop the node
    await alice_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
