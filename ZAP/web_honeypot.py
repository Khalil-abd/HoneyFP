import json
import logging
import uuid
import time
import os
import requests
from flask import Flask, request, Response

app = Flask(__name__)

# --- CONFIGURATION ---
# REMARQUE : Utilise des variables d'environnement pour tes clés API en production
GROQ_API_KEY = "your_api_key_here"
GROQ_MODEL = "llama-3.1-8b-instant"
STRATEGIES_FILE = 'honeypot_strategies.json'
INTERACTIONS_LOG = 'hacker_interactions.jsonl'
HONEYTOKEN_FILE = 'leaked_honeytokens.json'

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# --- LOAD STRATEGIES ---
def load_strategies():
    if not os.path.exists(STRATEGIES_FILE):
        return []
    with open(STRATEGIES_FILE, 'r') as f:
        return json.load(f)

# --- LLM ENGINE (GROQ) ---
def get_llm_response(prompt, attack_payload):
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Attaque reçue : {attack_payload}"}
        ],
        "temperature": 0.3
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        logger.error(f"Erreur LLM : {e}")
        return "Internal Server Error"

# --- CORE HANDLER ---
def handle_attack(strategy):
    payload = request.get_data(as_text=True) or request.args.to_dict()
    
    # 1. Génération de réponse via LLM
    response_text = get_llm_response(strategy['llm_system_prompt'], str(payload))
    
    # 2. Vérification fuite de Honeytoken
    honeytoken = strategy.get('honeytoken', {})
    leaked = False
    if honeytoken.get('ssh_password') in response_text:
        leaked = True
        with open(HONEYTOKEN_FILE, 'a') as f:
            f.write(json.dumps({"ip": request.remote_addr, "token": honeytoken}) + "\n")
            
    # 3. Logging de l'interaction
    with open(INTERACTIONS_LOG, 'a') as f:
        f.write(json.dumps({
            "timestamp": time.time(),
            "ip": request.remote_addr,
            "endpoint": strategy['endpoint'],
            "attack": payload,
            "response": response_text,
            "leak": leaked
        }) + "\n")
        
    return Response(response_text, mimetype='text/plain')

# --- DYNAMIC ROUTING ---
strategies = load_strategies()
for s in strategies:
    app.add_url_rule(s['endpoint'], endpoint=str(uuid.uuid4()), 
                     view_func=lambda s=s: handle_attack(s), 
                     methods=['GET', 'POST'])

if __name__ == '__main__':
    logger.info("Honeypot Web activé et prêt.")
    app.run(host='0.0.0.0', port=5000)