"""
PII Detection Module using Microsoft Presidio
Implements custom recognizers and anonymization
"""

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import yaml
import time
from typing import Dict, List, Tuple, Optional
from .custom_recognizers import (
    CustomAPIKeyRecognizer,
    CustomInternalIDRecognizer,
    ContextAwarePhoneRecognizer,
    CompositeEmailDomainRecognizer,
    CreditCardRecognizer  # ADD THIS LINE
)

class PIIDetector:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        registry = RecognizerRegistry()
        registry.add_recognizer(CreditCardRecognizer())  # Now this will work
        registry.add_recognizer(CustomAPIKeyRecognizer())
        registry.add_recognizer(CustomInternalIDRecognizer())
        registry.add_recognizer(ContextAwarePhoneRecognizer())
        registry.add_recognizer(CompositeEmailDomainRecognizer())
        
       s
        
        self.analyzer = AnalyzerEngine(
            registry=registry,
            default_score_threshold=self.config['thresholds']['pii_confidence']
        )
        
        self.anonymizer = AnonymizerEngine()
        self.entities_to_mask = self.config['entities_to_mask']
        
    def analyze_pii(self, text: str) -> Tuple[List, float]:
        """
        Analyze text for PII
        Returns: (results, latency_ms)
        """
        start_time = time.time()
        
        results = self.analyzer.analyze(
            text=text,
            language='en',
            entities=self.entities_to_mask,
            score_threshold=self.config['thresholds']['pii_confidence']
        )
        
        latency = (time.time() - start_time) * 1000
        return results, latency
    
    def anonymize_pii(self, text: str, results: List, 
                     operator: str = "replace") -> Tuple[str, float]:
        """
        Anonymize detected PII
        Returns: (anonymized_text, latency_ms)
        """
        start_time = time.time()
        
        operators = self._get_operators(operator)
        
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        
        latency = (time.time() - start_time) * 1000
        return anonymized.text, latency
    
    def _get_operators(self, default_operator: str) -> Dict:
        """Get operator configuration for different entity types"""
        if default_operator == "mask":
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "EMAIL_ADDRESS": OperatorConfig("mask", {
                    "masking_char": "*",
                    "chars_to_mask": 5,
                    "from_end": False
                }),
                "PHONE_NUMBER": OperatorConfig("mask", {
                    "masking_char": "#",
                    "chars_to_mask": 7,
                    "from_end": True
                }),
                "CREDIT_CARD": OperatorConfig("replace", 
                                             {"new_value": "[CREDIT CARD REDACTED]"}),
                "PERSON": OperatorConfig("replace", {"new_value": "[NAME]"}),
                "API_KEY": OperatorConfig("replace", {"new_value": "[API KEY REDACTED]"}),
                "INTERNAL_ID": OperatorConfig("replace", {"new_value": "[INTERNAL ID]"})
            }
        elif default_operator == "redact":
            operators = {
                "DEFAULT": OperatorConfig("redact", {})
            }
        else:
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": f"<{default_operator}>"})
            }
        
        return operators
    
    def analyze_with_context(self, text: str, context: Optional[str] = None) -> Dict:
        """Analyze with additional context for better accuracy"""
        results, analysis_latency = self.analyze_pii(text)
        
        grouped = {}
        for result in results:
            entity = result.entity_type
            if entity not in grouped:
                grouped[entity] = []
            grouped[entity].append({
                'text': text[result.start:result.end],
                'confidence': result.score,
                'start': result.start,
                'end': result.end
            })
        
        return {
            'results': results,
            'grouped': grouped,
            'total_count': len(results),
            'entity_types': list(set(r.entity_type for r in results)),
            'latency_ms': analysis_latency
        }