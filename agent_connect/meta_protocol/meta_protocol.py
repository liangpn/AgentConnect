import json
import random
import string
from enum import Enum
from typing import Optional, Dict, Any

from agent_connect.meta_protocol.protocol_negotiator import NegotiationStatus



class ProtocolType(Enum):
    """Protocol type enum"""
    META = 0        # Meta protocol for negotiation
    APPLICATION = 1 # Application protocol for data transfer
    NATURAL = 2     # Natural language protocol
    VERIFICATION = 3 # Verification protocol


class MetaProtocol:
    """Meta protocol implementation for protocol negotiation"""
    
    def __init__(self):
        self.max_negotiation_rounds = 10
        self.timeout_seconds = 15

    # TODO: When a protocol negotiation request comes in, the first step should be to check if existing protocols meet the requirements
    async def negotiate_protocol(self, requirement: str, 
                                 input_description: str, 
                                 output_description: str) -> Dict[str, Any]:
        """Negotiate protocol based on requirements and I/O descriptions
        
        Args:
            requirement: Natural language description of protocol requirements
            input_description: Natural language description of expected input format
            output_description: Natural language description of expected output format
            
        Returns:
            Protocol negotiation result as dictionary
        """
        pass
        
    def encode_protocol_header(self, protocol_type: ProtocolType) -> bytes:
        """Encode protocol header
        
        Args:
            protocol_type: Protocol type enum value
            
        Returns:
            Encoded header bytes
        """
        # Protocol type uses first 2 bits, remaining 6 bits are reserved
        header = protocol_type.value << 6
        return bytes([header])
        
    def decode_protocol_header(self, header_byte: bytes) -> ProtocolType:
        """Decode protocol header
        
        Args:
            header_byte: Header byte to decode
            
        Returns:
            Decoded protocol type
        """
        protocol_type = header_byte[0] >> 6
        return ProtocolType(protocol_type)

    def create_protocol_negotiation_message(
        self,
        sequence_id: int,
        candidate_protocols: str,
        modification_summary: Optional[str] = None,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, Any]:
        """Create protocol negotiation message
        
        Args:
            sequence_id: Negotiation sequence ID
            candidate_protocols: Candidate protocols description
            modification_summary: Optional modification summary
            status: Negotiation status
            
        Returns:
            Protocol negotiation message dict
        """
        message = {
            "action": "protocolNegotiation",
            "sequenceId": sequence_id,
            "candidateProtocols": candidate_protocols,
            "status": status.value
        }
        if modification_summary:
            message["modificationSummary"] = modification_summary
        return message

    def create_code_generation_message(self, success: bool = True) -> Dict[str, str]:
        """Create code generation message
        
        Args:
            success: Whether code generation succeeded
            
        Returns:
            Code generation message dict
        """
        return {
            "action": "codeGeneration",
            "status": "generated" if success else "error"
        }

    def create_test_cases_message(
        self,
        test_cases: str,
        modification_summary: Optional[str] = None,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, Any]:
        """Create test cases negotiation message
        
        Args:
            test_cases: Test cases description
            modification_summary: Optional modification summary
            status: Negotiation status
            
        Returns:
            Test cases message dict
        """
        message = {
            "action": "testCasesNegotiation",
            "testCases": test_cases,
            "status": status.value
        }
        if modification_summary:
            message["modificationSummary"] = modification_summary
        return message

    def create_fix_error_message(
        self,
        error_description: str,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, str]:
        """Create fix error negotiation message
        
        Args:
            error_description: Error description
            status: Negotiation status
            
        Returns:
            Fix error message dict
        """
        return {
            "action": "fixErrorNegotiation",
            "errorDescription": error_description,
            "status": status.value
        }

    def create_natural_language_message(
        self,
        message: str,
        is_request: bool = True
    ) -> Dict[str, str]:
        """Create natural language negotiation message
        
        Args:
            message: Natural language message content
            is_request: Whether this is a request message
            
        Returns:
            Natural language message dict
        """
        # Generate random 16 char message ID
        message_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        return {
            "action": "naturalLanguageNegotiation",
            "type": "REQUEST" if is_request else "RESPONSE",
            "messageId": message_id,
            "message": message
        }














