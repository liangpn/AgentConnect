from agent_connect.app_protocols import RequesterBase
from typing import Any, Dict
import asyncio
import logging
import traceback

class ProtocolRequester(RequesterBase):
    """Requester class for the protocol."""
    
    async def send_request(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Send request message.
        
        Constructs and sends a request message using the provided input data, 
        waits for a response, and processes the response to return a result.
        
        Args:
            input: Request input data as a dictionary.
        
        Returns:
            A dictionary containing the response code and other response 
            data if available.
        """
        logging.debug("Start constructing request protocol message")
        request_message = self._construct_request_message(input)
        
        if self._send_callback is None:
            error_message = "Send callback is not set."
            logging.error(error_message)
            return {"code": 500, "error_message": error_message}

        try:
            logging.info("Sending request message")
            await self._send_callback(request_message)

            logging.info("Waiting for response message")
            if not self.received_messages:
                await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                self.messages_event.clear()

            response_message = self.received_messages.pop(0)
            logging.debug("Response message received")
            response = self._process_response_message(response_message)
            return response

        except asyncio.TimeoutError:
            logging.error(f"Protocol negotiation timeout\nStack trace:\n{traceback.format_exc()}")
            return {"code": 504, "error_message": "Protocol negotiation timeout"}

        except Exception as e:
            logging.error(f"Error occurred during request or response processing: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return {"code": 500, "error_message": str(e)}

    def _construct_request_message(self, input: Dict[str, Any]) -> bytes:
        """Constructs the request message from input data.
        
        Args:
            input: Request input data as a dictionary.
        
        Returns:
            Request message in bytes format.
        """
        # Construct the protocol-specific message here
        logging.debug("Request message constructed successfully.")
        return b"request_message"

    def _process_response_message(self, message: bytes) -> Dict[str, Any]:
        """Processes the response message to extract results.
        
        Args:
            message: Response message in bytes format.
        
        Returns:
            A dictionary containing the extracted information including the status code.
        """
        # Process the protocol-specific message here
        logging.debug("Processing response message.")
        
        if not message:
            logging.error("Empty message received")
            return {"code": 400, "error_message": "Empty response message"}

        # Assume the response contains a valid code field in the message
        return {"code": 200}  # Example, replace with actual message handling logic