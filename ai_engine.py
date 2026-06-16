"""
ai_engine.py — AI Threat Analysis Engine for AI-NIDS
Uses Ollama (local Llama 3) to analyze security alerts and provide
threat explanations, risk assessments, and mitigation recommendations.
"""

import requests
import json


class AIEngine:
    """Interface to Ollama/Llama 3 for AI-powered threat analysis."""

    def __init__(self, model="llama3", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip('/')

    def is_available(self):
        """Check if Ollama is running and the model is available."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '').split(':')[0] for m in models]
                return self.model in model_names
            return False
        except (requests.ConnectionError, requests.Timeout):
            return False

    def _build_prompt(self, alert_data):
        """Construct a structured prompt for threat analysis."""
        prompt = f"""You are a cybersecurity threat analyst. Analyze the following network intrusion detection alert and provide a detailed security analysis.

ALERT DETAILS:
- Signature: {alert_data.get('signature', 'Unknown')}
- Source IP: {alert_data.get('src_ip', 'Unknown')}
- Destination IP: {alert_data.get('dest_ip', 'Unknown')}
- Source Port: {alert_data.get('src_port', 'N/A')}
- Destination Port: {alert_data.get('dest_port', 'N/A')}
- Protocol: {alert_data.get('protocol', 'Unknown')}
- Severity: {alert_data.get('severity', 'Unknown')} (1=Critical, 2=High, 3=Medium, 4=Low)
- Category: {alert_data.get('category', 'Unknown')}
- Timestamp: {alert_data.get('timestamp', 'Unknown')}

Provide your analysis in the following format:

THREAT EXPLANATION:
[Explain what this alert means, what type of attack or suspicious activity it indicates, and why it was triggered]

RISK LEVEL:
[Critical / High / Medium / Low]

ATTACK CATEGORY:
[Classify the type of attack — e.g., Reconnaissance, Brute Force, Malware, DoS, Data Exfiltration, etc.]

POTENTIAL IMPACT:
[Describe the potential damage if this threat is not addressed]

RECOMMENDATIONS:
- [Specific mitigation action 1]
- [Specific mitigation action 2]
- [Specific mitigation action 3]
- [Specific mitigation action 4]

INCIDENT SUMMARY:
[One-paragraph summary suitable for an incident report]"""

        return prompt

    def analyze_alert(self, alert_data):
        """
        Send an alert to Llama 3 for analysis.
        Returns a dict with the parsed analysis sections.
        """
        if not self.is_available():
            return {
                'success': False,
                'error': f'Ollama is not running or model "{self.model}" is not available. '
                         f'Please start Ollama and run: ollama pull {self.model}',
                'analysis_text': None,
                'threat_level': None,
                'recommendations': None
            }

        prompt = self._build_prompt(alert_data)

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 1024
                    }
                },
                timeout=120
            )

            if response.status_code != 200:
                return {
                    'success': False,
                    'error': f'Ollama API error: {response.status_code}',
                    'analysis_text': None,
                    'threat_level': None,
                    'recommendations': None
                }

            result = response.json()
            analysis_text = result.get('response', '')

            # Parse sections from the analysis
            parsed = self._parse_analysis(analysis_text)
            parsed['success'] = True
            parsed['error'] = None
            parsed['analysis_text'] = analysis_text

            return parsed

        except requests.Timeout:
            return {
                'success': False,
                'error': 'AI analysis timed out. The model may be loading. Please try again.',
                'analysis_text': None,
                'threat_level': None,
                'recommendations': None
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'AI analysis error: {str(e)}',
                'analysis_text': None,
                'threat_level': None,
                'recommendations': None
            }

    def _parse_analysis(self, text):
        """Parse the structured analysis text into sections."""
        sections = {
            'threat_explanation': '',
            'threat_level': '',
            'attack_category': '',
            'potential_impact': '',
            'recommendations': '',
            'incident_summary': ''
        }

        current_section = None
        section_map = {
            'THREAT EXPLANATION:': 'threat_explanation',
            'RISK LEVEL:': 'threat_level',
            'ATTACK CATEGORY:': 'attack_category',
            'POTENTIAL IMPACT:': 'potential_impact',
            'RECOMMENDATIONS:': 'recommendations',
            'INCIDENT SUMMARY:': 'incident_summary'
        }

        lines = text.split('\n')
        for line in lines:
            stripped = line.strip()

            # Check if this line is a section header
            matched = False
            for header, key in section_map.items():
                if stripped.upper().startswith(header.rstrip(':')):
                    current_section = key
                    # If content is on the same line as header
                    remainder = stripped[len(header):].strip()
                    if remainder:
                        sections[current_section] = remainder
                    matched = True
                    break

            if not matched and current_section:
                if stripped:
                    if sections[current_section]:
                        sections[current_section] += '\n' + line
                    else:
                        sections[current_section] = stripped

        # Clean up threat level to just the level word
        if sections['threat_level']:
            level = sections['threat_level'].strip().lower()
            for valid in ['critical', 'high', 'medium', 'low']:
                if valid in level:
                    sections['threat_level'] = valid.capitalize()
                    break

        return sections
