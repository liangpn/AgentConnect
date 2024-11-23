import json
import logging
from typing import Any, Dict, Optional, Awaitable, Callable
from agent_connect.app_protocols import ProviderBase

class ProtocolProvider(ProviderBase):
    """Generic protocol provider class for handling protocol messages."""

    def __init__(self) -> None:
        super().__init__()

    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.
        If message is error, call send_callback to send error message.

        Args:
            message (bytes): Received binary message data
        """
        try:
            # Parse received message and convert to callback function dictionary parameters
            callback_input_dict, message_id = self._parse_message(message)

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
            logging.error(f"Failed to handle message: {str(e)}. Stack trace: {traceback.format_exc()}")
            error_message = self._construct_error_message(400, str(e), None)
            if self._send_callback:
                await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> (Dict[str, Any], Optional[str]):
        """Parse the incoming binary message into a dictionary with protocol data.

        Args:
            message (bytes): Received binary message data

        Returns:
            Tuple containing the parsed dictionary and optional message ID
        """
        try:
            message_str = message.decode("utf-8")
            parsed_message = json.loads(message_str)
            message_id = parsed_message.get("message_id")

            # Check for required general_field
            if "general_field" not in parsed_message:
                raise ValueError("Missing required field: general_field")

            return parsed_message, message_id
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            logging.error(f"Error parsing message: {str(e)}")
            raise ValueError("Message format error")

    def _construct_response_message(self, result: Dict[str, Any], message_id: Optional[str]) -> bytes:
        """Construct the response message to be sent back.

        Args:
            result (dict): Result dictionary from protocol callback
            message_id (Optional[str]): Message ID to include in the response if available

        Returns:
            bytes: Constructed binary response message
        """
        response = {"code": result["code"]}

        if "data" in result:
            response["data"] = result["data"]

        if result["code"] != 200 and "error_message" in result:
            response["error_message"] = result["error_message"]

        if message_id is not None:
            response["message_id"] = message_id

        return json.dumps(response).encode("utf-8")

    def _construct_error_message(self, code: int, error_message: str, message_id: Optional[str]) -> bytes:
        """Construct an error message for sending in case of failures.

        Args:
            code (int): HTTP-like status code
            error_message (str): Description of the error
            message_id (Optional[str]): Original message ID, if available

        Returns:
            bytes: Constructed binary error message
        """
        error_response = {
            "code": code,
            "error_message": error_message
        }

        if message_id is not None:
            error_response["message_id"] = message_id

        return json.dumps(error_response).encode("utf-8")