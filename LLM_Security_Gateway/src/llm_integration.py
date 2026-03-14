"""
Bonus: Local LLM Integration with Ollama
"""

import requests
import time
from typing import Dict, Any
from .gateway import LLMSecurityGateway

class OllamaLLM:
    def __init__(self, model_name: str = "llama2", base_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
        
    def generate(self, prompt: str, max_tokens: int = 100) -> Dict[str, Any]:
        """Generate response from local LLM"""
        start_time = time.time()
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens
            }
        }
        
        try:
            response = requests.post(self.api_url, json=payload)
            response.raise_for_status()
            result = response.json()
            
            latency = (time.time() - start_time) * 1000
            
            return {
                'success': True,
                'response': result.get('response', ''),
                'latency_ms': latency,
                'model': self.model_name
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'latency_ms': (time.time() - start_time) * 1000
            }
    
    def check_availability(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except:
            return False


class LLMSecurityGatewayWithLLM(LLMSecurityGateway):
    def __init__(self, config_path: str = "config/config.yaml", use_llm: bool = True):
        super().__init__(config_path)
        self.use_llm = use_llm
        if use_llm:
            self.llm = OllamaLLM()
    
    def process_with_llm(self, user_input: str, **kwargs):
        """Process and forward to LLM if allowed"""
        security_result = self.process(user_input, **kwargs)
        
        if security_result['summary']['action_taken'] == 'block':
            return {
                **security_result,
                'llm_response': None,
                'llm_latency_ms': 0,
                'message': 'Request blocked by security policy'
            }
        
        processed_input = security_result['pipeline'][-1]['result']['output']
        
        if self.use_llm and self.llm.check_availability():
            llm_start = time.time()
            llm_result = self.llm.generate(processed_input)
            llm_latency = (time.time() - llm_start) * 1000
            
            return {
                **security_result,
                'llm_response': llm_result.get('response'),
                'llm_latency_ms': llm_latency,
                'total_with_llm_ms': security_result['total_latency_ms'] + llm_latency
            }
        else:
            return {
                **security_result,
                'llm_response': None,
                'llm_latency_ms': 0,
                'message': 'LLM not available'
            }