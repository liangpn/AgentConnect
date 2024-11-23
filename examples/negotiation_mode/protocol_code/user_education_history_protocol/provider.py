import logging
import traceback
from typing import Any, Awaitable, Callable, Dict, Optional
import json
from uuid import UUID
from agent_connect.app_protocols import ProviderBase


class EducationHistoryProtocolProvider(ProviderBase):
    """Protocol provider class for handling user education history retrieval."""
    
    def __init__(self) -> None:
        super().__init__()

    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.
        
        Args:
            message: Received binary message data
        """
        try:
            # Parse received message and convert to callback function dictionary parameters
            callback_input_dict, message_id = self._parse_message(message)
            logging.info(f"Message received with ID: {message_id}")

            # Call protocol callback function to handle business logic
            if self._protocol_callback:
                result = await self._protocol_callback(callback_input_dict)
                
                # Parse and construct response message based on callback return dictionary
                response_message = self._construct_response_message(result, message_id)
                
                # Send response
                if self._send_callback:
                    await self._send_callback(response_message)
                else:
                    logging.error("Send callback not set")
            else:
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error", message_id)
                await self._send_callback(error_message)
                
        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(400, str(e), message_id)
            await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> (Dict[str, Any], str):
        """Parse the received message and extract callback parameters and message ID.
        
        Args:
            message: Received binary message data
            
        Returns:
            Tuple: Parsed message dictionary and message ID
        """
        try:
            message_dict = json.loads(message.decode('utf-8'))

            # Validate message type
            if message_dict.get("messageType") != "retrieveUserEducationHistory":
                raise ValueError("Invalid message type")

            # Extract parameters into a dictionary
            callback_input_dict = {
                "userId": message_dict["userId"],
                "includeDetails": message_dict.get("includeDetails", False),
                "page": message_dict.get("page", 1),
                "pageSize": message_dict.get("pageSize", 10)
            }

            # Validate message ID
            message_id = message_dict["messageId"]
            UUID(message_id)  # Ensure it is a valid UUID

            return callback_input_dict, message_id
        except Exception as e:
            raise ValueError(f"Message format error: {e}")

    def _construct_response_message(self, result: Dict[str, Any], message_id: str) -> bytes:
        """Construct response message based on the callback result.
        
        Args:
            result: Result dictionary returned from protocol callback
            message_id: Message ID from the request
            
        Returns:
            Response binary message data
        """
        try:
            response = {
                "messageType": "retrieveUserEducationHistory",
                "messageId": message_id,
                "code": result["code"],
                "message": result["message"],
                "educationHistory": result.get("educationHistory", []),
                "pagination": result.get("pagination", {})
            }
            return json.dumps(response).encode('utf-8')
        except Exception as e:
            logging.error(f"Error constructing response message: {e}")
            raise

    def _construct_error_message(self, code: int, message: str, message_id: str) -> bytes:
        """Construct error message.
        
        Args:
            code: HTTP status code for the error
            message: Description of the error
            message_id: Message ID from the request
            
        Returns:
            Error binary message data
        """
        error_response = {
            "messageType": "retrieveUserEducationHistory",
            "messageId": message_id,
            "code": code,
            "message": message
        }
        return json.dumps(error_response).encode('utf-8')