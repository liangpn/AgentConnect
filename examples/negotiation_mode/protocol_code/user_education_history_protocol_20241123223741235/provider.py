import json
import logging
import traceback
from typing import Any, Dict, Optional, Awaitable, Callable
from agent_connect.app_protocols import ProviderBase
from jsonschema import validate, ValidationError

class ProtocolProvider(ProviderBase):
    """Protocol provider class for handling user education history retrieval"""

    def __init__(self) -> None:
        super().__init__()
        # Define the JSON schema for request validation
        self._request_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "messageType": {"type": "string", "const": "getUserEducationHistory"},
                "messageId": {"type": "string"},
                "userId": {"type": "string"},
                "includeDetails": {"type": "boolean", "default": False},
                "page": {"type": "integer", "minimum": 1},
                "pageSize": {"type": "integer", "minimum": 1, "default": 10}
            },
            "required": ["messageType", "messageId", "userId"],
            "additionalProperties": False
        }

    async def handle_message(self, message: bytes) -> None:
        """Handle received message and process user education history request

        Args:
            message: Received binary message data
        """
        try:
            # Decode message
            message_str = message.decode('utf-8')
            message_dict = json.loads(message_str)
            
            # Validate message format
            validate(instance=message_dict, schema=self._request_schema)
            
            message_id = message_dict["messageId"]

            # Prepare callback input
            callback_input_dict = {
                "userId": message_dict["userId"],
                "includeDetails": message_dict.get("includeDetails", False),
                "page": message_dict.get("page", 1),
                "pageSize": message_dict.get("pageSize", 10)
            }
            
            # Call protocol callback function to handle business logic
            if self._protocol_callback:
                result = await self._protocol_callback(callback_input_dict)
                
                # Construct response message
                response_message = self._construct_response_message(result, message_id)
                
                # Send response
                if self._send_callback:
                    await self._send_callback(response_message)
            else:
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error", message_id)
                await self._send_callback(error_message)
                
        except ValidationError as ve:
            logging.error(f"Validation error while handling message: {ve.message}")
            error_message = self._construct_error_message(422, str(ve), message_dict.get("messageId"))
            if self._send_callback:
                await self._send_callback(error_message)
        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(400, str(e), message_dict.get("messageId"))
            if self._send_callback:
                await self._send_callback(error_message)

    def _construct_response_message(self, result: dict, message_id: str) -> bytes:
        """Construct response message from callback result and include message ID"""
        response_dict = {
            "messageType": "getUserEducationHistory",
            "messageId": message_id,
            **result
        }
        return json.dumps(response_dict).encode('utf-8')

    def _construct_error_message(self, code: int, error_message: str, message_id: Optional[str]) -> bytes:
        """Construct error message to be sent as response"""
        error_response = {
            "messageType": "getUserEducationHistory",
            "messageId": message_id or '',
            "code": code,
            "error": {
                "code": code, 
                "message": error_message
            }
        }
        return json.dumps(error_response).encode('utf-8')