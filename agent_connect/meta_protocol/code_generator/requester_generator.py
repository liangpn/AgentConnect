# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

from textwrap import dedent
from typing import Dict, Tuple, Any, Optional
import logging
import traceback

from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase
from agent_connect.utils.llm.base_llm import BaseLLM

# Prompts for code generation
REQUESTER_CLASS_PROMPT = '''
You are a senior Python developer. Based on the protocol documentation and code requirements, please help me generate a protocol requester class.

# Protocol Requester Class Description
According to the protocol documentation, implement a protocol requester class that can construct request messages, send requests, process response messages, and return results based on the response messages.

# The base class for the protocol requester is defined as follows:
```
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable
import asyncio

class RequesterBase(ABC):
    """Base class for protocol requesters"""
    
    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self.received_messages: list[bytes] = []
        self.messages_event = asyncio.Event()
        
    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages
        
        Args:
            callback: Async function that takes binary data (bytes) as input and sends 
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback
    
    def handle_message(self, message: bytes) -> None:
        """Handle received message, called by the class user
        
        Args:
            message: Received binary message data
        """
        self.received_messages.append(message)
        self.messages_event.set()
```

# Please generate the requester class according to the following requirements:

1. The class must inherit from RequesterBase, import RequesterBase class using:
```
from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase
```
2. The class needs to implement a method to initiate a request protocol, with the following requirements:
  - Must be an async method
  - Parameters should include all data required by the requester according to the protocol documentation
  - This method will construct the request protocol, call self._send_callback to send the request protocol, then wait for the asyncio.Event until a response is received
  - After receiving the response message, process it according to the protocol documentation and return the processing result
  - Return value: [bool, Any], where bool indicates if the request was successful, Any is the data or result returned on success, recommended to use dict type
  - Add detailed docstrings for the method, including functionality, parameters, and return values. Each parameter and return value must be described in detail, including every field in the parameters and every field in the return value. If the return value is a dictionary or JSON, the fields or key-value pairs in the JSON must be described in detail to allow the caller to understand.
  - Must handle the following error cases:
    * Network timeout (set according to protocol documentation, default 15 seconds)
    * Message format errors
    * Parameter validation failures
  - Method example (pseudocode) as follows:
```
async def send_request(self, user_id: str, user_name: str) -> Tuple[bool, dict[str, Any]]:
    # Construct request protocol
    request_message = self._construct_request_message(user_id, user_name)

    # Send request protocol
    await self._send_callback(request_message)

    # Wait for response
    if not self.received_messages:
        try:
            # Wait for new message with timeout, timeout set according to protocol doc
            await asyncio.wait_for(self.messages_event.wait(), timeout=15)
            # Clear event for next wait
            self.messages_event.clear()
        except asyncio.TimeoutError:
            logging.error(f"Protocol negotiation timeout\nStack trace:\n{traceback.format_exc()}")
            return False, {}
        
    # Process response and return result
```
  - For self.received_messages and self.messages_event.wait(), always check if self.received_messages is empty first. If it is empty, call self.messages_event.wait() to wait for a message; otherwise, directly process self.received_messages.

3. Must implement the handle_message abstract method

4. Code requirements:
  - Follow Google Python Style Guide
  - Use type annotations
  - Include complete class and method documentation
  - Use logging module to record logs (in English)
  - Handle exceptions and edge cases properly
  - Ensure code testability and robustness
  - Internal method names should start with underscore (_)

# Output format
Output in the following format, code part should be directly runnable in Python file:
--[ module_name ]--
XXXX
--[END]--

--[ requester_code ]--
XXXX
--[END]--
'''

REQUESTER_DESCRIPTION_PROMPT = """
Generate a JSON description for the requester class that:
1. Follows the format in requester_description.json
2. Describes all methods and their parameters
3. Includes version information
Protocol Documentation:
{protocol_doc}
"""

async def _generate_requester_class(
    protocol_doc: str,
    llm: BaseLLM
) -> str:
    # Use REQUESTER_CLASS_PROMPT as system prompt
    system_prompt = REQUESTER_CLASS_PROMPT
    
    # Simple user prompt with protocol documentation
    user_prompt = dedent(f'''
        Please generate a requester class based on the following protocol documentation:

        --[ protocol_doc ]--
        {protocol_doc}
        --[END]--
    ''').strip()
    
    # Call OpenAI API
    content = await llm.async_generate_response(system_prompt, user_prompt)
    
    try:
        # Extract module_name and requester_code from content
        # Find module_name section
        module_name_start = content.find("--[ module_name ]--") + len("--[ module_name ]--")
        if module_name_start == -1:
            raise ValueError("Could not find module_name marker")
            
        module_name_end = content.find("--[END]--", module_name_start)
        if module_name_end == -1:
            raise ValueError("Could not find module_name end marker") 
            
        module_name = content[module_name_start:module_name_end].strip()

        # Find requester_code section
        requester_code_start = content.find("--[ requester_code ]--") + len("--[ requester_code ]--")
        if requester_code_start == -1:
            raise ValueError("Could not find requester_code marker")
            
        requester_code_end = content.find("--[END]--", requester_code_start)
        if requester_code_end == -1:
            raise ValueError("Could not find requester_code end marker")
            
        requester_code = content[requester_code_start:requester_code_end].strip()

        if not module_name or not requester_code:
            raise ValueError("Extracted module_name or requester_code is empty")

        return module_name, requester_code
        
    except Exception as e:
        logging.error(f"Failed to parse content: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return "", ""

async def _generate_requester_description(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> str:
   
    description_prompt = REQUESTER_DESCRIPTION_PROMPT.format(
        protocol_doc=protocol_doc
    )
    description_json = await llm.generate_code(description_prompt)
    return description_json

async def generate_requester_code(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> Tuple[str, str, str]:
   
    # Extract protocol name and create module name
    protocol_name = protocol_doc.get("name", "unknown_protocol")
    module_name = f"{protocol_name.lower()}_requester"
    
    # Generate requester class code and description
    requester_code = await _generate_requester_class(protocol_doc, llm)
    description_json = await _generate_requester_description(protocol_doc, llm)
    
    return module_name, requester_code, description_json
