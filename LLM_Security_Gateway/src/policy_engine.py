"""
Policy Decision Engine
Implements configurable policy decisions (Allow/Mask/Block)
"""

import yaml
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime

class PolicyAction(Enum):
    ALLOW = "allow"
    MASK = "mask"
    BLOCK = "block"

class PolicyEngine:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.default_action = PolicyAction(self.config['policies']['default'])
        self.high_risk_action = PolicyAction(self.config['policies']['high_risk'])
        
        self.entity_sensitivity = {
            "CREDIT_CARD": 5,
            "SSN": 5,
            
            "API_KEY": 5,
            "INTERNAL_ID": 5,
            "PERSON": 4,
            "EMAIL_ADDRESS": 4,
            "PHONE_NUMBER": 4,
            "LOCATION": 3,
            "DATE_TIME": 3,
            "ORGANIZATION": 2,
            "AGE": 1,
            "DEFAULT": 1
        }
    
    def decide(self, 
              injection_result: Dict,
              pii_results: List,
              user_role: str = "standard") -> Dict:
        """
        Make policy decision based on injection score and PII detected
        """
        injection_score = injection_result['overall']
        is_injection = injection_result.get('is_injection', False)
        
        print(f"DEBUG Policy: Injection score = {injection_score:.3f}, is_injection = {is_injection}")
        
        # CRITICAL: Block high injection scores immediately
        if is_injection or injection_score >= 0.5:
            print(f"DEBUG Policy: BLOCKING due to injection score {injection_score:.3f}")
            return self._make_decision(
                action=PolicyAction.BLOCK,
                reason=f"Injection detected (score: {injection_score:.2f})",
                details={
                    'injection_score': injection_score,
                    'matched_patterns': injection_result.get('matched_patterns', []),
                    'risk_level': injection_result.get('risk_level', 'UNKNOWN')
                }
            )
        
        # Calculate PII risk for non-injection cases
        pii_risk_score = self._calculate_pii_risk(pii_results)
        sensitive_entities = self._get_sensitive_entities(pii_results)
        
        print(f"DEBUG Policy: PII risk = {pii_risk_score:.3f}, sensitive = {sensitive_entities}")
        
        # Mask if sensitive PII found
        if sensitive_entities or pii_risk_score >= 0.4:
            print(f"DEBUG Policy: MASKING due to PII")
            return self._make_decision(
                action=PolicyAction.MASK,
                reason=f"Sensitive PII detected: {', '.join(sensitive_entities[:3]) if sensitive_entities else 'PII found'}",
                details={
                    'injection_score': injection_score,
                    'pii_risk_score': pii_risk_score,
                    'sensitive_entities': sensitive_entities
                }
            )
        
        # Default allow for safe queries
        print(f"DEBUG Policy: ALLOWING - no risks detected")
        return self._make_decision(
            action=PolicyAction.ALLOW,
            reason="No risks detected",
            details={
                'injection_score': injection_score,
                'pii_risk_score': pii_risk_score
            }
        )
    
    def _calculate_pii_risk(self, pii_results: List) -> float:
        """Calculate overall risk score from PII detection"""
        if not pii_results:
            return 0.0
        
        total_risk = 0.0
        for result in pii_results:
            sensitivity = self.entity_sensitivity.get(
                result.entity_type, 
                self.entity_sensitivity['DEFAULT']
            )
            risk_contribution = result.score * (sensitivity / 5.0)
            total_risk += risk_contribution
        
        return min(total_risk / len(pii_results), 1.0)
    
    def _get_sensitive_entities(self, pii_results: List) -> List[str]:
        """Get list of sensitive entity types detected"""
        sensitive = []
        for result in pii_results:
            if self.entity_sensitivity.get(result.entity_type, 1) >= 4:
                sensitive.append(result.entity_type)
        return list(set(sensitive))
    
    def _make_decision(self, action: PolicyAction, 
                      reason: str, details: Dict) -> Dict:
        """Format decision output"""
        return {
            'action': action.value,
            'reason': reason,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_allowed_operations(self, action: PolicyAction) -> Dict:
        """Get allowed operations based on action"""
        if action == PolicyAction.ALLOW:
            return {
                'can_proceed': True,
                'requires_anonymization': False,
                'requires_logging': False
            }
        elif action == PolicyAction.MASK:
            return {
                'can_proceed': True,
                'requires_anonymization': True,
                'requires_logging': True
            }
        else:  # BLOCK
            return {
                'can_proceed': False,
                'requires_anonymization': False,
                'requires_logging': True
            }