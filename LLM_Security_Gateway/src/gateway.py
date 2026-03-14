"""
Main LLM Security Gateway
Orchestrates all components and implements the pipeline
"""

import yaml
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from .injection_detector import InjectionDetector
from .pii_detector import PIIDetector
from .policy_engine import PolicyEngine, PolicyAction

class LLMSecurityGateway:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.injection_detector = InjectionDetector(config_path)
        self.pii_detector = PIIDetector(config_path)
        self.policy_engine = PolicyEngine(config_path)
        
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'masked_requests': 0,
            'allowed_requests': 0,
            'total_latency_ms': 0,
            'injection_detections': 0,
            'pii_detections': 0
        }
    
    def process(self, 
                user_input: str, 
                user_role: str = "standard",
                context: Optional[str] = None) -> Dict[str, Any]:
        """
        Process user input through security pipeline
        """
        start_time = time.time()
        
        result = {
            'original_input': user_input,
            'timestamp': datetime.now().isoformat(),
            'user_role': user_role,
            'pipeline': []
        }
        
        # Step 1: Injection Detection
        step_start = time.time()
        injection_result = self.injection_detector.calculate_injection_score(user_input)
        injection_latency = (time.time() - step_start) * 1000
        
        result['pipeline'].append({
            'step': 'injection_detection',
            'result': injection_result,
            'latency_ms': injection_latency
        })
        
        if injection_result['is_injection']:
            self.metrics['injection_detections'] += 1
        
        # Step 2: PII Analysis
        step_start = time.time()
        pii_results, pii_analysis_latency = self.pii_detector.analyze_pii(user_input)
        
        result['pipeline'].append({
            'step': 'pii_analysis',
            'result': {
                'count': len(pii_results),
                'entities': [
                    {
                        'type': r.entity_type,
                        'text': user_input[r.start:r.end],
                        'confidence': r.score
                    } for r in pii_results
                ]
            },
            'latency_ms': pii_analysis_latency
        })
        
        if pii_results:
            self.metrics['pii_detections'] += 1
        
        # Step 3: Policy Decision
        step_start = time.time()
        decision = self.policy_engine.decide(
            injection_result=injection_result,
            pii_results=pii_results,
            user_role=user_role
        )
        decision_latency = (time.time() - step_start) * 1000
        
        result['pipeline'].append({
            'step': 'policy_decision',
            'result': decision,
            'latency_ms': decision_latency
        })
        
        # Step 4: Apply Policy
        step_start = time.time()
        output = self._apply_policy(user_input, pii_results, decision)
        application_latency = (time.time() - step_start) * 1000
        
        result['pipeline'].append({
            'step': 'policy_application',
            'result': output,
            'latency_ms': application_latency
        })
        
        total_latency = (time.time() - start_time) * 1000
        result['total_latency_ms'] = total_latency
        
        self._update_metrics(decision['action'], total_latency)
        
        result['summary'] = {
            'action_taken': decision['action'],
            'reason': decision['reason'],
            'injection_score': injection_result['overall'],
            'pii_count': len(pii_results),
            'total_latency_ms': total_latency
        }
        
        return result
    
    def _apply_policy(self, user_input: str, pii_results: List, decision: Dict) -> Dict:
        """Apply policy decision to input"""
        action = decision['action']
        
        print(f"DEBUG Gateway: Applying policy action: {action}")
        
        if action == PolicyAction.BLOCK.value:
            return {
                'status': 'blocked',
                'output': None,
                'message': 'Request blocked by security policy',
                'reason': decision['reason']
            }
        
        elif action == PolicyAction.MASK.value:
            anonymized, latency = self.pii_detector.anonymize_pii(
                user_input, 
                pii_results,
                operator="mask"
            )
            
            return {
                'status': 'masked',
                'output': anonymized,
                'message': 'PII has been masked',
                'anonymization_latency_ms': latency
            }
        
        else:  # ALLOW
            return {
                'status': 'allowed',
                'output': user_input,
                'message': 'Request allowed'
            }
    
    def _update_metrics(self, action: str, latency: float):
        """Update gateway metrics"""
        self.metrics['total_requests'] += 1
        
        if action == 'block':
            self.metrics['blocked_requests'] += 1
        elif action == 'mask':
            self.metrics['masked_requests'] += 1
        else:
            self.metrics['allowed_requests'] += 1
        
        self.metrics['total_latency_ms'] += latency
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        if self.metrics['total_requests'] > 0:
            avg_latency = self.metrics['total_latency_ms'] / self.metrics['total_requests']
        else:
            avg_latency = 0
        
        return {
            **self.metrics,
            'avg_latency_ms': avg_latency,
            'block_rate': self.metrics['blocked_requests'] / max(self.metrics['total_requests'], 1),
            'mask_rate': self.metrics['masked_requests'] / max(self.metrics['total_requests'], 1)
        }
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'masked_requests': 0,
            'allowed_requests': 0,
            'total_latency_ms': 0,
            'injection_detections': 0,
            'pii_detections': 0
        }