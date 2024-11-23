import logging
from typing import Any, Dict, Awaitable, Callable
import asyncio
from agent_connect.app_protocols import RequesterBase


class Requester(RequesterBase):
    """A class to send requests based on the sample protocol."""

    async def send_request(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Send a generic request and receive the response.
        
        Args:
            input: A dictionary containing 'endpoint' as the API endpoint, 'payload' 
                   as the data to be sent, and 'headers' as the HTTP headers.
        
        Returns:
            A dictionary containing a status 'code', 'data' from the response, and an 
            'error_message' if an error occurred.
        """
        try:
            # Construct request protocol
            request_message = self._construct_request_message(input)

            # Send request protocol
            await self._send_callback(request_message)

            # Wait for response
            if not self.received_messages:
                try:
                    await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                    self.messages_event.clear()
                except asyncio.TimeoutError:
                    logging.error("Protocol negotiation timeout")
                    return {"code": 504, "error_message": "Protocol negotiation timeout"}
            
            # Process the first received message
            response_message = self.received_messages.pop(0)
            response = self._process_response_message(response_message)

            if 'code' not in response:
                logging.error("Invalid response format, missing 'code'")
                return {"code": 500, "error_message": "Invalid response format"}
            return response

        except Exception as e:
            logging.exception("An unexpected error occurred")
            return {"code": 500, "error_message": str(e)}
    
    def _construct_request_message(self, input: Dict[str, Any]) -> bytes:
        """Constructs the request message from input data.
        
        Args:
            input: A dictionary with request parameters including endpoint, payload, and headers.
        
        Returns:
            A bytes object containing the serialized request message.
        """
        try:
            endpoint = input['endpoint']
            payload = input['payload']
            headers = input['headers']

            # Validate headers field
            if not isinstance(headers, dict) or 'Authorization' not in headers or 'Content-Type' not in headers:
                raise ValueError("Invalid headers format: must include 'Authorization' and 'Content-Type'")
            
            # Here, you would serialize your input to bytes according to your protocol
            request_message = f"{endpoint} {headers} {payload}".encode('utf-8')
            return request_message
        except KeyError as e:
            logging.error(f"Missing required input parameter: {e}")
            raise ValueError(f"Missing required input parameter: {e}")

    def _process_response_message(self, message: bytes) -> Dict[str, Any]:
        """Processes the response message and extracts the relevant data.
        
        Args:
            message: The received response message in bytes.
        
        Returns:
            A dictionary representation of the response data.
        """
        try:
            # Assuming the response is JSON encoded, modify this according to your actual protocol
            response_str = message.decode('utf-8')
            response_data = eval(response_str)  # Replace eval with secure parsing for actual implementation

            if not isinstance(response_data, dict) or 'code' not in response_data:
                raise ValueError("Invalid response message format")
            
            return response_data
        except Exception as e:
            logging.error(f"Error processing response message: {e}")
            return {"code": 500, "error_message": "Error processing response message"}