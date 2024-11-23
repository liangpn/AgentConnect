import json
import logging
import traceback
import asyncio
import uuid
from typing import Any, Dict
from agent_connect.app_protocols import RequesterBase

class UserEducationHistoryRequest(RequesterBase):
    """Class to request user education history from the server."""

    async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
        """
        Send request to retrieve user's education history.

        Args:
            input (dict[str, Any]): Request input data including user_id, include_details, page, and page_size.

        Returns:
            dict[str, Any]: Request output data from response message. This includes status code, message, 
                            education history, and pagination details.
        """
        try:
            # Validate input parameters
            self._validate_input(input)

            # Construct request message
            request_message = self._construct_request_message(input)

            # Send request protocol
            await self._send_callback(request_message)

            # Wait for response
            response = await self._wait_for_response()

            # Process and return response
            return self._process_response(response)
            
        except (asyncio.TimeoutError, ValueError) as e:
            logging.error(f"Error during request: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return {"code": 504, "message": str(e)}

    def _validate_input(self, input: dict[str, Any]) -> None:
        """Validate input parameters."""
        if 'user_id' not in input:
            raise ValueError("Input must include 'user_id'.")

        input['include_details'] = input.get('include_details', False)
        input['page'] = input.get('page', 1)
        input['page_size'] = input.get('page_size', 10)

        if not isinstance(input['user_id'], str):
            raise ValueError("'user_id' must be a string.")

        if not isinstance(input['include_details'], bool):
            raise ValueError("'include_details' must be a boolean.")

        if not isinstance(input['page'], int) or input['page'] < 1:
            raise ValueError("'page' must be an integer of at least 1.")

        if not isinstance(input['page_size'], int) or input['page_size'] < 1:
            raise ValueError("'page_size' must be an integer of at least 1.")

    def _construct_request_message(self, input: dict[str, Any]) -> bytes:
        """Construct the request message using input parameters."""
        request_message = {
            "messageType": "retrieveUserEducationHistory",
            "messageId": str(uuid.uuid4()),
            "userId": input['user_id'],
            "includeDetails": input['include_details'],
            "page": input['page'],
            "pageSize": input['page_size']
        }
        logging.info(f"Constructed request message: {request_message}")
        return json.dumps(request_message).encode('utf-8')

    async def _wait_for_response(self) -> bytes:
        """Wait for response message with specified timeout."""
        if not self.received_messages:
            try:
                await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                self.messages_event.clear()
            except asyncio.TimeoutError:
                raise asyncio.TimeoutError("Protocol negotiation timeout.")

        return self.received_messages.pop(0)

    def _process_response(self, response: bytes) -> dict[str, Any]:
        """Process the received response message."""
        try:
            response_data = json.loads(response.decode('utf-8'))
            logging.info(f"Received response: {response_data}")

            if 'code' not in response_data:
                return {"code": 500, "message": "Invalid response format, missing 'code'."}

            return response_data

        except json.JSONDecodeError:
            logging.error("Response message format error.")
            return {"code": 400, "message": "Invalid response message format."}