import asyncio
import logging
import json
import uuid
from typing import Any, Dict, Optional
from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase


class EducationProtocolRequester(RequesterBase):
    """Class for sending requests to retrieve educational background information for a single user."""

    async def send_request(self, user_id: str, include_details: bool = False,
                           page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """Send request to get user educational background information.

        Args:
            user_id: Unique user identifier.
            include_details: Flag to include detailed information.
            page: Page number for paginated results.
            page_size: Number of items per page.

        Returns:
            Dictionary containing the HTTP status code, data or error information.
        
        Raises:
            ValueError: If the provided parameters are invalid.
        """
        
        if not self._is_valid_uuid(user_id):
            logging.error("Invalid user_id format: Must be a valid UUID.")
            return {"code": 400, "error": {"message": "Invalid user_id format", "details": "The user_id must be a valid UUID."}}

        if page < 1 or page_size < 1:
            logging.error("Invalid pagination parameters.")
            return {"code": 400, "error": {"message": "Invalid pagination parameters", "details": "Page and page_size must be greater than 0"}}

        request_message = self._construct_request_message(user_id, include_details, page, page_size)

        if not self._send_callback:
            logging.error("Send callback is not set.")
            return {"code": 500, "error": {"message": "Internal Server Error", "details": "Send callback not set."}}

        try:
            await self._send_callback(json.dumps(request_message).encode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to send request message: {e}")
            return {"code": 500, "error": {"message": "Internal Server Error", "details": str(e)}}

        if not self.received_messages:
            try:
                await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                self.messages_event.clear()
            except asyncio.TimeoutError:
                logging.error("Protocol negotiation timeout")
                return {"code": 504, "error": {"message": "Protocol negotiation timeout"}}

        response_message = self.received_messages.pop(0).decode('utf-8')

        try:
            response = json.loads(response_message)
            return self._process_response(response)
        except json.JSONDecodeError:
            logging.error("Response message format error")
            return {"code": 500, "error": {"message": "Response message format error"}}

    def _construct_request_message(self, user_id: str, include_details: bool, page: int, page_size: int) -> Dict[str, Any]:
        """Constructs the request message according to the protocol documentation."""
        message = {
            "messageType": "getUserEducation",
            "messageId": str(uuid.uuid4()),
            "userId": user_id,
            "includeDetails": include_details,
            "page": page,
            "pageSize": page_size
        }
        return message

    @staticmethod
    def _is_valid_uuid(value: str) -> bool:
        """Validates whether the given string is a valid UUID."""
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False
    
    def _process_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Processes the response message and extracts relevant data or errors."""
        if "code" not in response:
            logging.error("Response message missing 'code' field")
            return {"code": 500, "error": {"message": "Response message missing 'code' field"}}

        if response.get("code") == 200:
            return {
                "code": 200,
                "data": response.get("data", []),
                "pagination": response.get("pagination", {})
            }
        else:
            return {
                "code": response.get("code"),
                "error": response.get("error", {"message": "Unknown error"})
            }