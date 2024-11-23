from agent_connect.app_protocols import RequesterBase
from typing import Dict, Any

async def call_requester_interface(requester: RequesterBase) -> Dict[str, Any]:
    """Calls the requester interface to retrieve user's education history.

    Args:
        requester: An instance of RequesterBase used to send requests.

    Returns:
        A dictionary containing the response from send_request, including code, 
        message, education_history, and pagination details.
    """
    # Constructing the parameters for the request
    params = {
        "user_id": "123456789",  # Example user_id
        "include_details": True,  # Include detailed information
        "page": 1,                # Starting page for pagination
        "page_size": 10           # Number of records per page
    }

    # Asynchronously sending the request and returning the response
    response = await requester.send_request(params)
    return response