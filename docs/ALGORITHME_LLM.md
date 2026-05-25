# Algorithme — Comment le LLM apprend des False Positives

> **Note importante.** Le terme "entraînement" est employé ici dans un sens
> large. HoneyFP n'effectue pas (encore) de fine-tuning du LLM par descente
> de gradient. Le mécanisme principal est de l'**in-context learning** :
> les False Positives classifiés sont injectés dans le prompt du LLM, qui
> les utilise comme grounding pour générer une stratégie de déception.
> Cette section documente honnêtement (1) **ce que l'algorithme actuel
> fait réellement**, puis (2) **la boucle d'entraînement complète** qui
> peut être ajoutée pour passer à un vrai apprentissage en ligne.

---

## 1. Vue d'ensemble

```
Données brutes ──▶ Classification ──▶ Curation ──▶ In-context generation ──▶ Validation ──▶ Déploiement
   (ZAP scan)       (Iso-Forest)      (top-K       (Architect LLM)           (Pydantic)
                                       FP dedupe)
                                                                                    │
                                                                                    ▼
                                                                              Runtime mutation
                                                                              (Responder LLM)
                                                                                    │
                                                                                    ▼
                                                                            interactions.jsonl
                                                                                    │
       ┌────────────────────────────────────────────────────────────────────────────┘
       │  BOUCLE DE FEEDBACK (proposée)
       ▼
   Re-ranking ──▶ Few-shot enrichi ──▶ Architect amélioré ──▶ Nouveau blueprint
```

Le système combine quatre techniques d'IA :

| Stage | Technique | Rôle |
|---|---|---|
| 1 — Classification | Isolation Forest (scikit-learn) | Séparer TP / FP dans les alertes ZAP |
| 2 — Curation | Top-K + déduplication par (endpoint, vuln_type) | Réduire le coût de prompt |
| 3 — Génération | LLM en mode JSON (Groq Llama-3.1) | Synthétiser une stratégie par FP |
| 4 — Mutation runtime | LLM local (Ollama llama3.2:3b) | Mutiler les réponses HTTP à chaque attaque |

---

## 2. Algorithme actuel (in-context learning)

### Notation

- `A = {a_1, ..., a_n}` : ensemble d'alertes ZAP brutes (n ≈ 172 dans notre dataset)
- `F ⊆ A` : sous-ensemble classifié False Positive (avec un score de confiance)
- `D = {d_1, ..., d_k}` : ensemble dédupliqué de couples (endpoint, vuln_type)
- `B` : Deception Blueprint (objet Pydantic structuré)
- `B = (persona, fake_db, traps, honeytokens, breadcrumbs)`
- `T_i` : i-ème trap, avec `T_i = (path, method, vuln_family, decoy_template, llm_mutation_prompt, source_fp_id)`

### Stage 1 — Classification non supervisée des FP

```
ALGORITHM ClassifyAlerts(raw_zap_report)
─────────────────────────────────────────
INPUT  : raw_zap_report (JSON ZAP)
OUTPUT : F = liste d'alertes étiquetées "False Positive"

1.  A ← parse_zap(raw_zap_report)                    # rule-based extraction
2.  X ← extract_features(A)                          # risk_level, confidence,
                                                       endpoint_freq
3.  model ← IsolationForest(contamination=0.15)
4.  y ← model.fit_predict(X)
5.  FOR each a_i in A:
6.      IF y_i == +1  (anomaly score positif = "normal")
7.          label(a_i) ← "False Positive"
8.      ELSE
9.          label(a_i) ← "True Positive"
10. F ← {a_i in A | label(a_i) == "False Positive"}
11. RETURN F
```

Pourquoi non supervisé ? Parce qu'on n'a pas de ground truth FP/TP labellisée
en pratique. L'Isolation Forest isole les points "atypiques" — l'hypothèse
est qu'un FP est une alerte typique (haute fréquence, basse confiance) tandis
qu'un vrai TP est une anomalie statistique.

### Stage 2 — Curation des FP pour le prompt

```
ALGORITHM CurateFPs(F, K=5)
─────────────────────────────
INPUT  : F (FP set), K (top-K à garder)
OUTPUT : D (liste compacte pour le prompt)

1.  counter ← {}
2.  bucket  ← {}
3.  FOR each f in F:
4.      key ← (f.endpoint, f.alert_type)
5.      counter[key] ← counter[key] + 1
6.      IF key not in bucket:
7.          bucket[key] ← f
8.  top ← K plus fréquents (key, count) dans counter
9.  D ← []
10. FOR each (key, count) in top:
11.     a ← bucket[key]
12.     a_trimmed ← garder uniquement {alert_id, alert_type, endpoint,
                                       parameter, evidence}
13.     a_trimmed.occurrences ← count
14.     D.append(a_trimmed)
15. RETURN D
```

Justifications :
- **Dédup par (endpoint, vuln_type)** : 172 FP avec beaucoup de doublons →
  ~12 combinaisons uniques. Inutile de payer le LLM N fois pour la même
  chose.
- **Top-K** : on garde les FP les plus fréquents car ils représentent les
  zones les plus susceptibles d'attirer un attaquant.
- **Trim des champs** : on jette `description`, `cweid`, `wascid`, etc.
  car non utiles pour la génération. Réduit le prompt de ~70%.

### Stage 3 — In-context generation du Blueprint

```
ALGORITHM ArchitectGenerate(D)
────────────────────────────────
INPUT  : D (curated FPs)
OUTPUT : B (Deception Blueprint)

1.  prompt_sys  ← ARCHITECT_SYSTEM_PROMPT
2.  prompt_user ← ARCHITECT_USER_TEMPLATE.format(fp_json=D)
3.  raw_json ← LLM.complete(
                  model     = "llama-3.1-8b-instant",
                  system    = prompt_sys,
                  user      = prompt_user,
                  json_mode = True,
                  temp      = 0.6,
                  max_toks  = 2500
              )
4.  data ← json.loads(raw_json)
5.  TRY:
6.      B ← DeceptionBlueprint.model_validate(data)     # strict Pydantic
7.  CATCH ValidationError:
8.      B ← RepairBlueprint(data, D)                    # defensive normaliser
9.  RETURN B
```

Le LLM ne "voit" pas un dataset d'entraînement ; il voit **chaque FP comme
exemple** et synthétise une stratégie cohérente *au moment du prompt*. C'est
le pattern dit **few-shot in-context learning** (Brown et al. 2020) : le
modèle généralise à partir de quelques exemples placés dans le contexte,
sans mise à jour des poids.

#### Le mécanisme de "repair" — robustesse face aux hallucinations

```
ALGORITHM RepairBlueprint(raw_data, D)
─────────────────────────────────────────
INPUT  : raw_data (dict potentiellement invalide), D (FPs sources)
OUTPUT : B (blueprint validé)

1.  persona ← validate_or_default(raw_data.persona, DEFAULT_PERSONA)
2.  FOR each table_t in raw_data.fake_db:
3.      normalise sql_type:
            "FLOAT"  → "REAL"
            "VARCHAR" → "TEXT"
            "INT"    → "INTEGER"
            ...
4.  tables ← safe_validate(FakeTable, normalised_tables)
5.  FOR each trap_t in raw_data.traps:
6.      IF trap_t.vuln_family not in VALID_FAMILIES:
7.          trap_t.vuln_family ← "generic_500"
8.      set defaults for missing fields
9.  traps ← safe_validate(TrapEndpoint, normalised_traps)
10. IF no SSH honeytoken in raw_data.honeytokens:
11.     inject default ssh_credentials token
12. tokens ← safe_validate(Honeytoken, ...)
13. crumbs ← safe_validate(Breadcrumb, raw_data.breadcrumbs)
14. B ← DeceptionBlueprint(persona, tables, traps, tokens, crumbs, ...)
15. RETURN B
```

C'est essentiel : le LLM hallucine régulièrement (sql_type="FLOAT" qui
n'existe pas en SQLite, breadcrumb sans `path`, etc.). Le repair garantit
que chaque génération produit un blueprint *exécutable*.

### Stage 4 — Mutation runtime (per-attack)

```
ALGORITHM RespondToAttack(trap, payload, attacker_profile)
─────────────────────────────────────────────────────────
INPUT  : trap (TrapEndpoint), payload (string), profile (string)
OUTPUT : body (string) — corps HTTP servi à l'attaquant

1.  cache_key ← hash(trap.path + profile + payload[:200])
2.  IF cache_key in LRU_cache:
3.      RETURN LRU_cache[cache_key]                    # économise le LLM
4.  system_prompt ← trap.llm_mutation_prompt
                    + "\n\nAttacker profile: " + profile
                    + "\nNever break the fourth wall."
5.  user_prompt ← "Endpoint: " + trap.path
                  + "\nVuln family: " + trap.vuln_family
                  + "\nPayload: " + payload
6.  TRY:
7.      body ← LLM_local.complete(
                  model     = "llama3.2:3b",
                  system    = system_prompt,
                  user      = user_prompt,
                  temp      = 0.4,
                  max_toks  = 320
              )
8.  CATCH connection_error:
9.      body ← trap.decoy_template.replace("{payload}", payload[:200])
10. LRU_cache[cache_key] ← body
11. RETURN body
```

Le runtime LLM joue le rôle de **acteur en costume** : il a déjà reçu
un *system prompt* précis (designé par l'Architect) qui lui dit "tu es
MySQL, ne réponds qu'avec un corps d'erreur SQL". Il n'a pas besoin de
re-raisonner sur la stratégie, juste d'incarner le rôle.

---

## 3. Boucle de feedback proposée (apprentissage en ligne)

L'algorithme ci-dessus est **stateless** : chaque blueprint est généré
indépendamment, sans tirer parti des attaques passées. Voici la boucle
fermée que l'on peut greffer pour transformer HoneyFP en système qui
**apprend des attaquants réels**.

### Stage 5 — Re-ranking des FP par engagement attaquant

```
ALGORITHM RerankFPsByEngagement(F, interactions_log)
─────────────────────────────────────────────────────
INPUT  : F (FPs classifiés), interactions_log (JSONL)
OUTPUT : F_ranked (FPs réordonnés par engagement)

1.  engagement ← {}                                    # par alert_id
2.  FOR each line in interactions_log:
3.      record ← parse(line)
4.      IF record.is_trap == True:
5.          trap ← lookup_trap(record.path)
6.          engagement[trap.source_fp_alert_id] += 1
7.          IF record.honeytoken_id != null:
8.              engagement[trap.source_fp_alert_id] += 10  # gros bonus
9.  FOR each f in F:
10.     f.engagement_score ← engagement.get(f.alert_id, 0)
11.     f.priority ← 0.5 * f.confidence + 0.5 * normalise(f.engagement_score)
12. F_ranked ← sort(F, by=priority, desc=True)
13. RETURN F_ranked
```

Idée clé : un FP qui n'a jamais été visité par un attaquant n'est pas
intéressant à instrumenter. Un FP dont le trap a déclenché un honeytoken
leak est extrêmement précieux — on veut le garder en priorité dans les
prochains blueprints.

### Stage 6 — Construction de few-shot examples à partir de l'historique

```
ALGORITHM BuildFewShotPool(past_blueprints, interactions_log, top_n=3)
──────────────────────────────────────────────────────────────────────
INPUT  : past_blueprints (liste), interactions_log (JSONL), top_n
OUTPUT : pool (liste de paires (FP, strategy) jugées efficaces)

1.  pool ← []
2.  FOR each bp in past_blueprints:
3.      FOR each trap in bp.traps:
4.          attack_count ← count of interactions where path==trap.path
                            and is_trap==True
5.          leak_count   ← count of honeytoken_leaks where endpoint==trap.path
6.          score        ← attack_count + 5 * leak_count
7.          IF score > 0:
8.              pool.append({
                  "fp"       : lookup_fp(trap.source_fp_alert_id),
                  "strategy" : strip_to_relevant_fields(trap),
                  "score"    : score
              })
9.  pool ← sort(pool, by=score, desc=True)[:top_n]
10. RETURN pool
```

Ce pool sert ensuite à enrichir le prompt de l'Architect :

```
ALGORITHM ArchitectGenerateEnriched(D, few_shot_pool)
──────────────────────────────────────────────────────
1.  examples_block ← format_as_json_examples(few_shot_pool)
2.  user_prompt ← (
        "Here are examples of past trap designs that effectively caught attackers:\n"
        + examples_block
        + "\nNow apply the same style to these new FPs:\n"
        + json.dumps(D)
    )
3.  raw_json ← LLM.complete(... user=user_prompt ...)
4.  ... (suite identique à Stage 3)
```

C'est de l'**in-context learning amélioré par historique** — on
s'approche de la RAG (Retrieval-Augmented Generation) : le LLM apprend
des patterns qui ont *concrètement* attrapé des attaquants.

### Stage 7 — Fine-tuning supervisé (optionnel, hors free tier)

Quand on accumule suffisamment d'exemples `(FP, strategy, outcome)`, on
peut passer à du vrai entraînement supervisé :

```
ALGORITHM SupervisedFinetune(triples)
──────────────────────────────────────
INPUT  : triples = [(FP, strategy, outcome_score), ...]
OUTPUT : modèle fine-tuné

1.  dataset ← []
2.  FOR each (fp, strat, score) in triples WHERE score > threshold:
3.      example ← {
            "prompt"     : format_architect_prompt([fp]),
            "completion" : json.dumps(strat)
        }
4.      dataset.append(example)
5.  base_model ← load("llama-3.1-8b")
6.  finetuned ← LoRA_finetune(
                  base_model,
                  dataset,
                  epochs       = 3,
                  lr           = 1e-5,
                  rank         = 16,
                  target_layers = ["q_proj", "v_proj"]
              )
7.  RETURN finetuned
```

À utiliser quand on a > 500 exemples positifs (le LLM "apprend" alors
le style sans avoir besoin du prompt verbose).

### Stage 8 — Boucle complète

```
LOOP every D days (e.g. weekly):
    1.  pull last D days of interactions.jsonl + honeytoken_leaks.jsonl
    2.  F_ranked ← RerankFPsByEngagement(F, interactions_log)
    3.  D_new   ← CurateFPs(F_ranked, K=5)
    4.  few_shot_pool ← BuildFewShotPool(past_blueprints, interactions_log)
    5.  B_new ← ArchitectGenerateEnriched(D_new, few_shot_pool)
    6.  deploy(B_new)
    7.  archive(B_new, timestamp, parent_metrics)
END LOOP
```

Cette boucle transforme HoneyFP d'un système "one-shot" en un **système
adaptatif** dont la qualité de déception **augmente avec le temps** à
mesure que de vrais attaquants l'éprouvent.

---

## 4. Synthèse — Tableau récapitulatif

| Stage | Algorithme | Type d'IA | Coût | Statut |
|---|---|---|---|---|
| 1 | Classification FP | ML non supervisé (Isolation Forest) | CPU | Implémenté |
| 2 | Curation top-K | Tri / dédup | CPU | Implémenté |
| 3 | Génération Blueprint | LLM in-context (Groq Llama-3.1) | 1 call / blueprint | Implémenté |
| 4 | Repair défensif | Validation + heuristiques | CPU | Implémenté |
| 5 | Mutation runtime | LLM in-context (Ollama llama3.2) | 1 call / attaque (cached) | Implémenté |
| 6 | Re-ranking par engagement | Statistique sur logs | CPU | **Proposé** |
| 7 | Few-shot pool historique | Retrieval | CPU | **Proposé** |
| 8 | Génération enrichie | LLM in-context + RAG | 1 call / blueprint | **Proposé** |
| 9 | Fine-tuning supervisé | LoRA sur Llama 8B | GPU (~$10) | **Proposé** |

---

## 5. Référence aux fichiers du projet

| Stage | Fichier |
|---|---|
| 1 | `ZAP/parse_zap.py`, `ZAP/advanced_fp_classifier.py` |
| 2 | `honeypot/architect/architect.py` (fonction `deduplicate_fps`) |
| 3 | `honeypot/architect/architect.py` (fonction `generate_blueprint`) + `prompts.py` |
| 4 | `honeypot/architect/architect.py` (fonction `_repair_blueprint`) |
| 5 | `honeypot/runtime/responder.py` |
| 6-9 | Non implémentés — voir section "Roadmap" du README |
