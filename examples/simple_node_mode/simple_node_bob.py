# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import os
import logging

import sys  

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../../") 

from agent_connect.simple_node import SimpleNode, SimpleNodeSession
from agent_connect.utils.log_base import set_log_color_level

def generate_did_info(bob_node: SimpleNode):
    # Check if bob.json exists
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the current file's directory
    bob_json_path = os.path.join(current_dir, "bob.json")  # Construct the path to bob.json

    if os.path.exists(bob_json_path):
        print("Loading existing Bob DID information")
        with open(bob_json_path, "r") as f:
            bob_info = json.load(f)
        bob_node.set_did_info(bob_info["private_key_pem"], bob_info["did"], bob_info["did_document_json"])
    else:
        print("Generating new Bob DID information")
        private_key_pem, did, did_document_json = bob_node.generate_did_document()
        bob_node.set_did_info(private_key_pem, did, did_document_json)
        
        # Save Bob's DID information
        with open(bob_json_path, "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)

async def ws_new_session_callback(simple_session: SimpleNodeSession):
    print(f"New session established with DID: {simple_session.remote_did}")

async def main():
    # 使用新的接口创建节点，只指定ws路径
    bob_node = SimpleNode(
        host_domain="localhost", 
        new_session_callback=ws_new_session_callback,
        host_port="8001",
        host_ws_path="/ws"
    )
    
    generate_did_info(bob_node)

    print(f"Bob's DID: {bob_node.did}")

    # Start the node
    bob_node.run()
    
    # Read Alice's DID
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the current file's directory
    alice_json_path = os.path.join(current_dir, "alice.json")  # Construct the path to bob.json
    with open(alice_json_path, "r") as f:
        alice_info = json.load(f)
    alice_did = alice_info["did"]
    
    try:
        # Connect to Alice
        bob_session = await bob_node.connect_to_did(alice_did)

        # Send message to Alice
        message = "Hello Alice, I'm Bob!"
        success = await bob_session.send_message(message)
        if success:
            print(f"Successfully sent message to {alice_did}")
        else:
            print(f"Failed to send message to {alice_did}")
        
        # Wait for Alice's reply
        while True:
            reply = await bob_session.receive_message()
            reply = reply.decode('utf-8') if reply else None
            print(f"Received reply content: {reply}")

    except asyncio.CancelledError:
        print("Bob node is shutting down...")
    finally:
        await bob_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
