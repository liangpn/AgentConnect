import json
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from agent_connect.app_protocols import ProviderBase


class ProtocolProvider(ProviderBase):
    """Protocol provider class responsible for managing example protocol communication."""

    def __init__(self) -> None:
        super().__init__()

    async def handle_message(self, message: bytes) -> None:
        """Handle received message and manage protocol communication.

        Args:
            message: Received binary message data.
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
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error")
                await self._send_callback(error_message)
                
        except ValueError as ve:
            logging.error(f"Message format error: {str(ve)}")
            error_message = self._construct_error_message(400, f"Message format error: {str(ve)}")
            await self._send_callback(error_message)
        except KeyError as ke:
            logging.error(f"Parameter validation failure: missing {str(ke)}")
            error_message = self._construct_error_message(400, f"Parameter validation error: {str(ke)} required")
            await self._send_callback(error_message)
        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(500, "Internal server error")
            await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> tuple[Dict[str, Any], Optional[str]]:
        """Parse the received message bytes to a dictionary suitable for protocol callback.

        Args:
            message: Received binary message.

        Returns:
            tuple containing the parsed message dictionary and message ID if present.
        """
        try:
            message_dict = json.loads(message.decode('utf-8'))
            message_id = message_dict.get('message_id')
            return message_dict, message_id
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON message format") from e

    def _construct_response_message(self, result: Dict[str, Any], message_id: Optional[str]) -> bytes:
        """Construct a response message based on the protocol's return result and message_id.

        Args:
            result: Dictionary received from the protocol callback function.
            message_id: Original message ID if present, to attach to the response.

        Returns:
            Response message as bytes.
        """
        response = {
            'code': result.get('code'),
            'result': result.get('result'),
            'error_message': result.get('error_message'),
        }
        if message_id:
            response['message_id'] = message_id
        return json.dumps(response).encode('utf-8')

    def _construct_error_message(self, code: int, details: str) -> bytes:
        """Construct an error message in the protocol format.

        Args:
            code: HTTP status code for the error.
            details: Detailed error message.

        Returns:
            Error message as bytes.
        """
        error_response = {
            'code': code,
            'result': {
                'status': 'error',
                'details': details,
            }
        }
        return json.dumps(error_response).encode('utf-8')