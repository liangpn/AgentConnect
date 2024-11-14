import json
import logging
import asyncio
import uuid
from typing import Tuple, Any, Dict, Optional
from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase

class UserEducationRequester(RequesterBase):
    """Protocol requester for retrieving user education background information."""

    async def send_request(
        self,
        user_id: str,
        include_details: bool = False,
        page: int = 1,
        page_size: int = 10
    ) -> Tuple[bool, Dict[str, Any]]:
        """Send a request to retrieve educational background of a user.

        Args:
            user_id (str): Unique identifier for the user.
            include_details (bool): Optional; whether to include detailed info. Default is False.
            page (int): Optional; pagination page number. Default is 1.
            page_size (int): Optional; number of items per page. Default is 10.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: Success status and response data.
                - If successful, the response data will be in dictionary format.
                - In case of failure, an appropriate error dictionary will be returned.
        
        Raises:
            ValueError: If input parameters fail validation.

        """
        # Validate and construct the request message
        try:
            if not user_id:
                raise ValueError("user_id is required.")
            
            if page < 1 or page_size < 1:
                raise ValueError("page and page_size must be positive integers.")
            
            message_id = str(uuid.uuid4())
            request_message = self._construct_request_message(
                message_id, user_id, include_details, page, page_size
            )
        except ValueError as e:
            logging.error(f"Parameter validation failed: {str(e)}")
            return False, {"error": str(e)}

        # Send request protocol
        if self._send_callback is None:
            logging.error("Send callback not set.")
            return False, {"error": "Send callback not set."}

        try:
            await self._send_callback(request_message)
        except Exception as e:
            logging.error(f"Failed to send request: {str(e)}")
            return False, {"error": "Failed to send request due to network error."}

        # Wait for response
        try:
            await asyncio.wait_for(self.messages_event.wait(), timeout=15)
            self.messages_event.clear()

            if not self.received_messages:
                logging.error("No response received.")
                return False, {"error": "No response received."}

            response_message = self.received_messages.pop(0)
            return self._process_response(response_message)
        except asyncio.TimeoutError:
            logging.error("Protocol negotiation timeout")
            return False, {"error": "Request timed out."}

    def _construct_request_message(self, message_id: str, user_id: str, include_details: bool, page: int, page_size: int) -> bytes:
        """Constructs the request message in JSON format.
        
        Args:
            message_id (str): Unique message identifier.
            user_id (str): User ID for which data is requested.
            include_details (bool): Whether detailed information is requested.
            page (int): Page number for pagination.
            page_size (int): Items per page for pagination.

        Returns:
            bytes: JSON-encoded request message in binary format.
        """
        request_data = {
            "messageType": "getUserEducation",
            "messageId": message_id,
            "userId": user_id,
            "includeDetails": include_details,
            "page": page,
            "pageSize": page_size
        }
        return json.dumps(request_data).encode('utf-8')

    def _process_response(self, response_message: bytes) -> Tuple[bool, Dict[str, Any]]:
        """Process the received response message.

        Args:
            response_message (bytes): Received response message in binary format.

        Returns:
            Tuple[bool, Dict[str, Any]]: Success status and response data.
                - If successful, the data field will contain the educational background details.
                - In case of failure, the error information will be given.
        """
        try:
            response_data = json.loads(response_message.decode('utf-8'))
            if 'error' in response_data:
                logging.error(f"Error in response: {response_data['error']['message']}")
                return False, response_data['error']
            
            return True, response_data.get('data', {})
        
        except json.JSONDecodeError:
            logging.error("Failed to decode response message.")
            return False, {"error": "Invalid response format."}

    def handle_message(self, message: bytes) -> None:
        """Handle received message, called by the class user.

        Args:
            message (bytes): Received binary message data.
        """
        self.received_messages.append(message)
        self.messages_event.set()