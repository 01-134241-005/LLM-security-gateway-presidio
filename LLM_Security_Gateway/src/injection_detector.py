"""
Injection Detection Module
Implements scoring mechanism for prompt injection and jailbreak attempts
"""

import re
import yaml
from typing import Dict, List, Tuple

class InjectionDetector:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.injection_patterns = self.config['injection_patterns']
        self.threshold = self.config['thresholds']['injection_score']
        
        # ENHANCED PATTERNS WITH ROLE-PLAY SPECIFIC PATTERNS
        self.jailbreak_patterns = [
            # Critical patterns (weight 1.0)
            (r"ignore\s+(?:all\s+)?(?:previous|above|prior|my|the)\s+instructions?", 1.0),
            (r"ignore\s+(?:all\s+)?(?:rules?|guidelines?|policies?)", 1.0),
            (r"system\s+prompt", 0.9),
            (r"DAN|jailbreak|bypass", 1.0),
            (r"do\s+anything\s+now", 1.0),
            
            # ROLE-PLAY PATTERNS (weights 0.7-0.9)
            (r"act\s+as\s+(?:if\s+)?(?:a|an|the)", 0.8),
            (r"act\s+like\s+(?:a|an|the)", 0.8),
            (r"pretend\s+(?:to\s+be|that|you'?re|you\s+are)", 0.9),
            (r"you\s+are\s+(?:now|actually|really)\s+", 0.8),
            (r"role[- ]?play", 0.9),
            (r"take\s+on\s+the\s+role", 0.8),
            (r"play\s+the\s+role", 0.8),
            (r"imagine\s+(?:that\s+)?you\s+are", 0.7),
            (r"simulate\s+being", 0.7),
            (r"from\s+now\s+on\s+you\s+are", 0.9),
            (r"hypothetical\s+scenario", 0.6),
            
            # Hacker specific
            (r"hacker|hack(?:ing)?", 0.8),
            (r"malicious", 0.6),
            
            # Extraction attempts
            (r"what\s+are\s+your\s+(?:instructions|rules|guidelines)", 0.8),
            (r"reveal\s+your\s+(?:instructions|prompt|system)", 0.9),
            (r"print\s+your\s+(?:instructions|prompt)", 0.8),
            (r"show\s+your\s+(?:instructions|prompt|system)", 0.8),
            (r"no\s+(?:rules|restrictions|limits)", 0.8),
        ]
        
    def calculate_injection_score(self, text: str) -> Dict:
        """
        Calculate injection score based on multiple factors
        """
        text_lower = text.lower()
        
        # Score 1: Pattern matching
        pattern_score = 0.0
        matched_patterns = []
        
        print(f"\nDEBUG: Analyzing text: {text[:50]}...")
        
        for pattern, weight in self.jailbreak_patterns:
            if re.search(pattern, text_lower):
                pattern_score += weight
                matched_patterns.append(pattern)
                print(f"DEBUG: ✓ Matched: {pattern} (weight: {weight})")
        
        pattern_score = min(pattern_score, 1.0)
        
        # Score 2: Role-play specific keyword detection
        roleplay_score = self._detect_roleplay(text_lower)
        
        # Score 3: Suspicious structure
        structure_score = self._analyze_structure(text)
        
        # Score 4: Keyword density
        keyword_score = self._analyze_keywords(text_lower)
        
        # Score 5: Command verb detection
        command_score = self._analyze_commands(text_lower)
        
        # Combine scores with roleplay-specific boost
        scores = {
            'pattern_match': pattern_score,
            'roleplay': roleplay_score,
            'structure': structure_score,
            'keyword_density': keyword_score,
            'commands': command_score
        }
        
        # Adjusted weights
        weights = {
            'pattern_match': 0.4,
            'roleplay': 0.3,      # New weight for roleplay
            'structure': 0.1,
            'keyword_density': 0.1,
            'commands': 0.1
        }
        
        overall = sum(scores[k] * weights[k] for k in scores)
        
        # Debug output
        print(f"DEBUG: Pattern score: {pattern_score:.3f}")
        print(f"DEBUG: Roleplay score: {roleplay_score:.3f}")
        print(f"DEBUG: Structure score: {structure_score:.3f}")
        print(f"DEBUG: Keyword score: {keyword_score:.3f}")
        print(f"DEBUG: Command score: {command_score:.3f}")
        print(f"DEBUG: Overall score: {overall:.3f}")
        print(f"DEBUG: Threshold: {self.threshold}")
        
        return {
            'overall': overall,
            'detailed': scores,
            'matched_patterns': matched_patterns,
            'is_injection': overall > self.threshold,
            'risk_level': self.get_risk_level(overall)
        }
    
    def _detect_roleplay(self, text_lower: str) -> float:
        """Specifically detect role-play attacks"""
        roleplay_phrases = [
            'act as', 'act like', 'pretend', 'role play', 'roleplay',
            'you are now', 'you are actually', 'imagine you are',
            'take on the role', 'play the role', 'simulate',
            'hacker', 'dan', 'do anything now'
        ]
        
        score = 0.0
        for phrase in roleplay_phrases:
            if phrase in text_lower:
                score += 0.2
                print(f"DEBUG: Roleplay phrase detected: '{phrase}'")
        
        return min(score, 1.0)
    
    def _analyze_commands(self, text_lower: str) -> float:
        """Analyze command verbs"""
        command_verbs = [
            'ignore', 'forget', 'disregard', 'bypass', 'override',
            'reveal', 'show', 'print', 'tell', 'output', 'display',
            'act', 'pretend', 'simulate', 'roleplay', 'become',
            'hack', 'bypass'
        ]
        
        words = text_lower.split()
        command_count = sum(1 for word in words if word in command_verbs)
        
        if len(words) == 0:
            return 0.0
        
        return min(command_count / 3, 1.0)
    
    def _analyze_structure(self, text: str) -> float:
        """Analyze text structure for injection patterns"""
        score = 0.0
        
        # Check for command-like structures
        commands = re.findall(r'\b(?:act|pretend|simulate|roleplay|become)\b', text.lower())
        if commands:
            score += 0.2 * len(commands)
        
        # Check for multiple sentences with imperatives
        sentences = re.split(r'[.!?]+', text)
        imperative_count = 0
        for s in sentences:
            if re.search(r'^\s*(act|pretend|simulate|roleplay|ignore|forget|bypass|show|tell|do)\s', s.lower()):
                imperative_count += 1
        
        if len(sentences) > 0:
            score += 0.2 * (imperative_count / len(sentences))
        
        return min(score, 1.0)
    
    def _analyze_keywords(self, text_lower: str) -> float:
        """Analyze keyword density"""
        injection_keywords = [
            'ignore', 'bypass', 'override', 'forget', 'disregard',
            'pretend', 'imagine', 'suppose', 'consider', 'what if',
            'act', 'role', 'simulate', 'hypothetical', 'scenario',
            'hacker', 'malicious', 'attack', 'jailbreak', 'dan'
        ]
        
        words = text_lower.split()
        word_count = len(words)
        if word_count == 0:
            return 0.0
        
        keyword_count = 0
        for kw in injection_keywords:
            if kw in text_lower:
                keyword_count += text_lower.count(kw)
        
        density = keyword_count / word_count
        return min(density * 15, 1.0)
    
    def get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "SAFE"