"""
src package - LLM Security Gateway modules
Makes the src directory a Python package and exposes key classes
"""

from .custom_recognizers import (
    CustomAPIKeyRecognizer,
    CustomInternalIDRecognizer,
    ContextAwarePhoneRecognizer,
    CompositeEmailDomainRecognizer,
    CreditCardRecognizer  
)

from .injection_detector import InjectionDetector
from .pii_detector import PIIDetector
from .policy_engine import PolicyEngine, PolicyAction
from .gateway import LLMSecurityGateway

# Optional bonus import
try:
    from .llm_integration import OllamaLLM, LLMSecurityGatewayWithLLM
    __all__ = [
        'CustomAPIKeyRecognizer',
        'CustomInternalIDRecognizer',
        'ContextAwarePhoneRecognizer',
        'CompositeEmailDomainRecognizer',
        'InjectionDetector',
        'CreditCardRecognizer',  
        'PIIDetector',
        'PolicyEngine',
        'PolicyAction',
        'LLMSecurityGateway',
        'OllamaLLM',
        'LLMSecurityGatewayWithLLM'
    ]
except ImportError:
    __all__ = [
        'CustomAPIKeyRecognizer',
        'CustomInternalIDRecognizer',
        'ContextAwarePhoneRecognizer',
        'CompositeEmailDomainRecognizer',
        'InjectionDetector',
        'PIIDetector',
        'PolicyEngine',
        'PolicyAction',
        'LLMSecurityGateway'
    ]

__version__ = '1.0.0'