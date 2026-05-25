import json
import os
from groq import Groq

# WARNING: Putting keys in code is for local testing only!
# Never commit this file to a version control system like Git.
API_KEY = "your_key_here"

# Initialize the Groq client with your hardcoded key
client = Groq(api_key=API_KEY)

def load_false_positives(filepath="fp_alerts.json"):
    """Loads the classified False Positives."""
    if not os.path.exists(filepath):
        print(f"[-] Error: {filepath} not found.")
        return []
    with open(filepath, 'r') as f:
        return json.load(f)

def generate_honeypot_strategy(alert):
    """Uses LLM to design a specific honeypot strategy based on a False Positive."""
    
    endpoint = alert.get('endpoint', '/unknown')
    vuln_type = alert.get('alert_type', 'Unknown Vulnerability')
    evidence = alert.get('evidence', '')

    prompt = f"""
    You are an expert Cybersecurity Deception Architect.
    A DevSecOps scanner incorrectly flagged a False Positive on our web application.
    We want to turn this False Positive into an active Honeypot.

    Scanner Alert Details:
    - Endpoint: {endpoint}
    - Suspected Vulnerability: {vuln_type}
    - Scanner Evidence: {evidence}

    Task: Design a JSON configuration for a Flask Web Honeypot.
    Include a 'Honeytoken' (fake credentials) that links this trap to an SSH honeypot.

    Respond ONLY with a valid JSON object matching this exact structure:
    {{
        "endpoint": "{endpoint}",
        "vulnerability_simulated": "{vuln_type}",
        "persona": "Description of the fake server persona",
        "fake_db_schema": {{"tables": ["list", "of", "fake", "tables"]}},
        "honeytoken": {{
            "ssh_username": "a_plausible_admin_username",
            "ssh_password": "a_complex_password",
            "leak_context": "How the attacker discovers this token"
        }},
        "llm_system_prompt": "Instructions for the honeypot to respond convincingly to attackers."
    }}
    """

    print(f"[*] Asking Llama-3 to design a strategy for {vuln_type} on {endpoint}...")
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.1-8b-instant",
        temperature=0.7,
        response_format={"type": "json_object"}
    )
    
    strategy_json = chat_completion.choices[0].message.content
    return json.loads(strategy_json)

def main():
    fp_alerts = load_false_positives()
    if not fp_alerts:
        return

    target_alert = fp_alerts[0]
    strategy = generate_honeypot_strategy(target_alert)
    
    if strategy:
        with open("honeypot_strategies.json", 'w') as f:
            json.dump([strategy], f, indent=4)
        print("\n[+] Success! Deception Strategy generated.")

if __name__ == "__main__":
    main()