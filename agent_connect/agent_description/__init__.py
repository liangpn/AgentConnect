"""
Agent Description模块，提供JSON文档的签名生成和验证功能。
"""

from .proof import generate_proof, verify_proof

__all__ = ['generate_proof', 'verify_proof']
