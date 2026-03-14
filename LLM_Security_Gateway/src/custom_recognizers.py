"""
Custom PII recognizers for Presidio
Implements: custom recognizer, context-aware scoring, composite entity detection, confidence calibration
"""

from presidio_analyzer import PatternRecognizer, Pattern
import re

class CustomAPIKeyRecognizer(PatternRecognizer):
    """Custom recognizer for API keys and secrets"""
    
    def __init__(self):
        patterns = [
            Pattern(
                name="api_key_pattern",
                regex=r"[A-Za-z0-9]{20,40}",
                score=0.7
            ),
            Pattern(
                name="sk_api_key",
                regex=r"sk-[A-Za-z0-9]{32,}",
                score=0.9
            ),
            Pattern(
                name="aws_key",
                regex=r"AKIA[0-9A-Z]{16}",
                score=0.95
            )
        ]
        
        super().__init__(
            supported_entity="API_KEY",
            patterns=patterns,
            context=["api", "key", "token", "secret", "access", "sk-"]
        )


class CustomInternalIDRecognizer(PatternRecognizer):
    """Custom recognizer for internal employee IDs"""
    
    def __init__(self):
        patterns = [
            Pattern(
                name="employee_id",
                regex=r"EMP-\d{5}",
                score=0.85
            ),
            Pattern(
                name="internal_id",
                regex=r"ID-\d{6}[A-Z]{2}",
                score=0.8
            )
        ]
        
        super().__init__(
            supported_entity="INTERNAL_ID",
            patterns=patterns,
            context=["employee", "id", "internal", "emp", "staff"]
        )


class ContextAwarePhoneRecognizer(PatternRecognizer):
    """
    Context-aware phone number recognizer
    Demonstrates context-aware scoring
    """
    
    def __init__(self):
        patterns = [
            Pattern(
                name="phone_pattern_1",
                regex=r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
                score=0.6
            ),
            Pattern(
                name="phone_pattern_intl",
                regex=r"\+\d{1,3}\s?\(?\d{1,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
                score=0.7
            )
        ]
        
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=patterns,
            context=["phone", "call", "mobile", "cell", "tel", "contact", "whatsapp"]
        )
    
    def analyze(self, text, entities, nlp_artifacts=None):
        """Override analyze to add context awareness"""
        results = super().analyze(text, entities, nlp_artifacts)
        
        for result in results:
            # Check for context words nearby
            start = max(0, result.start - 30)
            end = min(len(text), result.end + 30)
            surrounding = text[start:end].lower()
            
            context_words = ["phone", "call", "mobile", "cell", "whatsapp", 
                            "telephone", "contact", "reach"]
            
            for word in context_words:
                if word in surrounding:
                    result.score = min(1.0, result.score + 0.2)
                    break
        
        return results


class CompositeEmailDomainRecognizer(PatternRecognizer):
    """
    Composite entity detection for emails with domain analysis
    Demonstrates composite entity detection
    """
    
    def __init__(self):
        patterns = [
            Pattern(
                name="email",
                regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                score=0.7
            )
        ]
        
        self.suspicious_domains = [
            "tempmail", "throwaway", "mailinator", "guerrillamail",
            "10minute", "yopmail", "disposable"
        ]
        
        super().__init__(
            supported_entity="EMAIL_ADDRESS",
            patterns=patterns,
            context=["email", "mail", "@"]
        )
    
    def analyze(self, text, entities, nlp_artifacts=None):
        results = super().analyze(text, entities, nlp_artifacts)
        
        for result in results:
            email = text[result.start:result.end].lower()
            domain = email.split('@')[-1] if '@' in email else ""
            
            for susp in self.suspicious_domains:
                if susp in domain:
                    result.score = min(1.0, result.score + 0.15)
                    break
            
            if any(word in email for word in ['admin', 'root', 'support']):
                result.score = min(1.0, result.score + 0.1)
        
        return results


class CreditCardRecognizer(PatternRecognizer):
    """Enhanced credit card recognizer for detecting various credit card formats"""
    
    def __init__(self):
        patterns = [
            Pattern(
                name="credit_card_visa",
                regex=r"4[0-9]{12}(?:[0-9]{3})?",
                score=0.8
            ),
            Pattern(
                name="credit_card_mastercard",
                regex=r"5[1-5][0-9]{14}",
                score=0.8
            ),
            Pattern(
                name="credit_card_amex",
                regex=r"3[47][0-9]{13}",
                score=0.8
            ),
            Pattern(
                name="credit_card_discover",
                regex=r"6(?:011|5[0-9]{2})[0-9]{12}",
                score=0.8
            ),
            Pattern(
                name="credit_card_dashes",
                regex=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                score=0.9
            ),
            Pattern(
                name="credit_card_spaces",
                regex=r"\b\d{4}\s+\d{4}\s+\d{4}\s+\d{4}\b",
                score=0.9
            ),
            Pattern(
                name="credit_card_with_text",
                regex=r"(?:credit|card|cc)[:\s]*(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})",
                score=0.95
            )
        ]
        
        # Context words that increase confidence
        context_words = [
            "credit", "card", "cc", "amex", "visa", "mastercard", 
            "discover", "jcb", "payment", "charge", "bill"
        ]
        
        super().__init__(
            supported_entity="CREDIT_CARD",
            patterns=patterns,
            context=context_words
        )
    
    def analyze(self, text, entities, nlp_artifacts=None):
        """Override analyze to add context awareness"""
        results = super().analyze(text, entities, nlp_artifacts)
        
        for result in results:
            # Boost score if there are context words nearby
            start = max(0, result.start - 30)
            end = min(len(text), result.end + 30)
            surrounding = text[start:end].lower()
            
            context_words = ["credit", "card", "cc", "payment", "charge"]
            for word in context_words:
                if word in surrounding:
                    result.score = min(1.0, result.score + 0.1)
                    break
        
        return results