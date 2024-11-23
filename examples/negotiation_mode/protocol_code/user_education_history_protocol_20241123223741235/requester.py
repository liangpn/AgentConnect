import json
import logging
from typing import Any, Dict, Optional
import asyncio

from agent_connect.app_protocols import RequesterBase

class ProtocolRequester(RequesterBase):
    """Requester class for retrieving user's education history."""

    async def send_request(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to retrieve user's education history.

        Args:
            input: Request input data, must include 'message_id' and 'user_id'.

        Returns:
            dict: Output data from the response message with 'code' indicating the status.
        """
        try:
            # Validate input
            self._validate_input(input)

            # Construct request protocol
            request_message = self._construct_request_message(input)
            logging.info(f"Sending request: {request_message}")

            # Send request protocol using callback
            await self._send_callback(bytes(request_message, encoding='utf-8'))

            # Wait for response with timeout
            if not self.received_messages:
                try:
                    await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                    self.messages_event.clear()
                except asyncio.TimeoutError:
                    logging.error("Protocol negotiation timeout.")
                    return {"code": 504, "error_message": "Protocol negotiation timeout"}

            # Process response
            response_message = self.received_messages.pop(0).decode('utf-8')
            return self._process_response(response_message)
        except ValueError as e:
            logging.error(f"Input validation failed: {e}")
            return {"code": 422, "error_message": str(e)}
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")
            return {"code": 500, "error_message": "Internal server error"}

    def _validate_input(self, input: Dict[str, Any]) -> None:
        """Validate input parameters for request."""
        required_keys = ["message_id", "user_id"]
        for key in required_keys:
            if key not in input:
                raise ValueError(f"Missing required field: {key}")

    def _construct_request_message(self, input: Dict[str, Any]) -> str:
        """Construct request message in JSON format."""
        request_data = {
            "messageType": "getUserEducationHistory",
            "messageId": input["message_id"],
            "userId": input["user_id"],
            "includeDetails": input.get("include_details", False),
            "page": input.get("page", 1),
            "pageSize": input.get("page_size", 10)
        }
        return json.dumps(request_data)

    def _process_response(self, response_message: str) -> Dict[str, Any]:
        """Process the response message and return the result.

        Args:
            response_message: JSON formatted response message as string.

        Returns:
            dict: Processed response with 'code' and data or error information.
        """
        try:
            response_data = json.loads(response_message)
            message_id = response_data.get("messageId")
            if response_data["code"] == 200:
                return {
                    "code": response_data["code"],
                    "data": {
                        "education_history": response_data["educationHistory"],
                        "pagination": response_data["pagination"]
                    }
                }
            else:
                logging.error(f"Request with messageId {message_id} failed with code {response_data['code']}")
                return {
                    "code": response_data.get("code", 500),
                    "error": response_data.get("error", {"code": 500, "message": "Unexpected error occurred"})
                }
        except json.JSONDecodeError:
            logging.error("Failed to decode response message")
            return {"code": 500, "error_message": "Failed to decode response message"}
        except KeyError as e:
            logging.error(f"Missing expected key in response: {e}")
            return {"code": 500, "error_message": f"Missing expected key in response: {str(e)}"}