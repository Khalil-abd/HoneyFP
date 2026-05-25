import json

def classify_alert(alert):
    """Simple rule-based FP classifier."""
    try:
        risk = int(alert.get("riskcode", 0))
    except (ValueError, TypeError):
        risk = 0
        
    try:
        confidence = int(alert.get("confidence", 0))
    except (ValueError, TypeError):
        confidence = 0
    
    # High confidence + high risk = likely true positive
    if risk >= 3 and confidence >= 3:
        return "true_positive", 0.85
    # Low confidence scanner alerts = likely false positive  
    if confidence <= 1:
        return "false_positive", 0.90
    # Medium risk with medium confidence = uncertain
    if risk == 2:
        return "false_positive", 0.65
        
    return "false_positive", 0.75

def parse_and_classify_zap_report(raw_file_path, output_file_path):
    print(f"[*] Lecture du rapport brut ZAP : {raw_file_path}...")
    
    with open(raw_file_path, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    standardized_alerts = []
    
    # Parcourir les sites scannés
    for site in raw_data.get("site", []):
        # On ignore le bruit (la télémétrie Microsoft Edge)
        if "microsoft.com" in site.get("@host", ""):
            continue
            
        for alert in site.get("alerts", []):
            alert_name = alert.get("name", "")
            
            # On filtre sur les vulnérabilités qui nous intéressent pour le PoC
            if alert_name in ["Injection SQL", "Private IP Disclosure"]:
                
                # --- NOUVELLE LOGIQUE DE CLASSIFICATION ---
                classification, conf = classify_alert(alert)
                
                instance = alert.get("instances", [{}])[0]
                
                # Formatage standardisé
                formatted_alert = {
                    "alert_id": f"ZAP-{alert.get('pluginid')}",
                    "alert_type": alert_name,
                    "endpoint": instance.get("uri", ""),
                    "parameter": instance.get("param", ""),
                    "evidence": instance.get("evidence", ""),
                    "description": alert.get("desc", "").replace("<p>", "").replace("</p>", ""),
                    "classification": classification,
                    "confidence": conf,
                    "source": "OWASP ZAP DAST"
                }
                
                standardized_alerts.append(formatted_alert)

    # Sauvegarder le résultat propre
    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(standardized_alerts, f, indent=4, ensure_ascii=False)
        
    print(f"[+] Classification terminée ! {len(standardized_alerts)} alertes traitées.")
    print(f"[+] Fichier standardisé sauvegardé sous : {output_file_path}")

if __name__ == "__main__":
    parse_and_classify_zap_report("2026-05-17-ZAP-Report-.json", "alerts.json")