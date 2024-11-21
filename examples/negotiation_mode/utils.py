# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import json
import os
import logging
from typing import Any, Dict, Tuple

import sys
g_current_dir: str = os.path.dirname(os.path.abspath(__file__))
sys.path.append(g_current_dir)
sys.path.append(g_current_dir + "/../../")

from agent_connect.utils.llm.base_llm import AzureLLM
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