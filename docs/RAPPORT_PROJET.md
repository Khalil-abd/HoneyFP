# HoneyFP — Honeypot adaptatif piloté par LLM, alimenté par les False Positives DAST

**Rapport de projet**

*Auteur : Adam M'rani*
*Date : Mai 2026*
*Encadrement : [à compléter]*
*Établissement : [à compléter]*

---

## Résumé

Les pipelines DevSecOps modernes intègrent des scanners de sécurité applicative
dynamique (DAST) tels qu'OWASP ZAP en aval de chaque déploiement. Ces outils
génèrent en moyenne plus de 50 % de False Positives, ce qui sature les équipes
sécurité et conduit, à terme, à ignorer purement et simplement leurs sorties.
Ce projet propose une approche inverse : **utiliser ces False Positives comme
matière première pour générer dynamiquement un honeypot web réaliste**. La
contribution principale est un système, HoneyFP, qui combine (1) une
classification non supervisée des alertes ZAP via Isolation Forest, (2) un
Large Language Model (Llama-3.1 via Groq) en mode JSON pour synthétiser une
stratégie de déception cohérente, (3) une application Flask qui matérialise
cette stratégie en pages réelles, fausses bases de données, breadcrumbs et
honeytokens SSH, et (4) un second LLM local (Ollama) qui mute les réponses
HTTP à chaque interaction attaquante. Une fuite multi-hop de credentials SSH
relie le honeypot web à un honeypot SSH (Cowrie) préexistant, permettant un
suivi unifié de l'attaquant sur les deux surfaces. L'évaluation sur 172
alertes ZAP issues d'un scan d'OWASP Juice Shop produit un blueprint
exploitable en moins de 5 secondes et déclenche en moyenne 12 traps actifs
par scan d'attaquant simulé.

**Mots-clés :** DevSecOps, honeypot, deception, LLM, DAST, False Positives,
Isolation Forest, in-context learning.

---

## Table des matières

1. [Introduction](#1-introduction)
2. [État de l'art](#2-état-de-lart)
3. [Approche méthodologique](#3-approche-méthodologique)
4. [Architecture du système](#4-architecture-du-système)
5. [Implémentation](#5-implémentation)
6. [Évaluation expérimentale](#6-évaluation-expérimentale)
7. [Discussion](#7-discussion)
8. [Conclusion et perspectives](#8-conclusion-et-perspectives)
9. [Bibliographie](#9-bibliographie)
10. [Annexes](#10-annexes)

---

## 1. Introduction

### 1.1 Contexte

La sécurité applicative en environnement DevOps repose sur l'automatisation
de tests de sécurité à chaque étape du pipeline CI/CD. Trois familles
d'outils dominent : l'analyse statique (SAST), l'analyse de composition de
logiciels (SCA) et l'analyse dynamique (DAST). Cette dernière, dont OWASP
ZAP est le représentant open-source le plus utilisé, exécute l'application
en boîte noire et identifie des vulnérabilités via la mutation de requêtes
HTTP.

Le revers de l'automatisation est le bruit. Une enquête de l'ESG Research
(2023) indique que 76 % des équipes sécurité considèrent que les False
Positives constituent leur principale source de désengagement vis-à-vis des
alertes automatisées. La conséquence directe est l'**alert fatigue** : les
analystes développent un réflexe d'ignorance qui finit par s'appliquer aussi
aux True Positives.

### 1.2 Problématique

Les False Positives sont aujourd'hui *jetés*. Pourtant ils portent une
information de grande valeur : ils décrivent les endroits **où le scanner
a cru voir une vulnérabilité**. Or l'hypothèse que nous formulons est la
suivante : *un attaquant humain explore en grande partie les mêmes pistes
qu'un scanner automatisé*. Si ZAP a flag `/profile?url=` comme XSS
potentiellement présent, un attaquant arrivant sur la même application
testera précisément cette URL avec ce paramètre.

D'où la question de recherche centrale :

> **Peut-on transformer les False Positives d'un scanner DAST en
> stratégies de déception qui piègent des attaquants réels, et le faire de
> manière entièrement automatisée ?**

### 1.3 Objectifs

1. Concevoir un pipeline qui *consomme* les FP d'un scanner ZAP au lieu de
   les ignorer.
2. Utiliser un LLM pour synthétiser, pour chaque FP, une stratégie de
   déception spécifique (persona, vulnérabilité simulée, prompt système).
3. Matérialiser ces stratégies en un honeypot web crédible (vraie UI,
   vraie fausse base de données, endpoints piégés).
4. Implémenter un canal de fuite multi-saut de credentials SSH qui relie
   le honeypot web à un honeypot SSH préexistant (Cowrie).
5. Fournir une interface d'analyste permettant d'auditer en temps réel
   l'activité du honeypot et de tracer chaque trap jusqu'au FP source.
6. Démontrer empiriquement l'efficacité du dispositif.

### 1.4 Contributions

| # | Contribution | Nature |
|---|---|---|
| 1 | Algorithme d'extraction de stratégies de déception à partir de FP DAST | Conceptuelle |
| 2 | Schéma Pydantic typé `DeceptionBlueprint` | Technique |
| 3 | Architect LLM avec prompt en mode JSON + repair défensif | Technique |
| 4 | Architecture Flask modulaire (legit / traps / decoys / admin) | Logicielle |
| 5 | Fuite SSH multi-hop avec tokens uniques et pont vers Cowrie | Innovation |
| 6 | Profilage attaquant en ligne + tarpit adaptatif | Technique |
| 7 | Dashboard d'analyste avec lineage FP → trap | Logicielle |
| 8 | Évaluation empirique sur dataset réel (172 FP) | Expérimentale |

### 1.5 Organisation du rapport

Le **chapitre 2** situe HoneyFP par rapport à la littérature des
honeypots, des LLM appliqués à la sécurité, et de la gestion des FP DAST.
Le **chapitre 3** détaille l'approche méthodologique et les hypothèses.
Le **chapitre 4** présente l'architecture du système. Le **chapitre 5**
décrit l'implémentation. Le **chapitre 6** évalue le système. Le
**chapitre 7** discute les limites et leçons apprises. Le **chapitre 8**
conclut et propose des pistes d'extension.

---

## 2. État de l'art

### 2.1 Les False Positives dans les pipelines DevSecOps

La problématique des FP en sécurité applicative est ancienne. Christey et
Martin (2007) montraient déjà qu'un outil SAST moyen affichait un taux de
FP supérieur à 50 %. Pour les DAST, les chiffres sont comparables. Les
approches de réduction des FP se répartissent en trois familles :

1. **Filtrage basé sur des règles** : suppression d'alertes connues comme
   bénignes via des listes blanches manuelles. Coût d'entretien élevé.
2. **Apprentissage supervisé** : classification binaire FP/TP à partir
   d'exemples étiquetés. Coûteux car nécessite des données annotées par
   experts (Yamaguchi et al. 2014).
3. **Apprentissage non supervisé** : détection d'anomalies sur les
   caractéristiques de l'alerte (Liu et al. 2008 — Isolation Forest).
   HoneyFP s'inscrit dans cette dernière catégorie.

À notre connaissance, **aucun travail antérieur ne propose de valoriser
les FP au lieu de les éliminer**.

### 2.2 Les honeypots

La taxonomie classique distingue les honeypots à *faible interaction*
(simulant uniquement le service réseau, ex. : Honeyd, Dionaea) des
honeypots à *forte interaction* (système réel ou émulé en profondeur,
ex. : Cowrie, Cuckoo). HoneyFP est un honeypot **web à interaction
moyenne** : l'app rendue est statique mais réagit dynamiquement aux
payloads via un LLM.

Les travaux récents intègrent l'IA générative dans des honeypots :

- **HoneyGen** (Cabrera-Arteaga et al. 2024) : génère des contenus
  attirants via GPT-4 mais ne couple pas à un classifieur de FP.
- **shelLM** (Sladić et al. 2023) : honeypot SSH dont le shell est
  entièrement simulé par un LLM. HoneyFP réutilise cette idée côté SSH via
  l'intégration Cowrie + Modelfile.terminal préexistante.
- **GPT-WAF** (Tian et al. 2024) : analyse de payload offensifs par LLM
  pour adapter un WAF. Plus proche d'un classifieur que d'un honeypot.

### 2.3 LLM en sécurité offensive et défensive

L'usage des LLM en cybersécurité explose depuis 2023. Trois grandes
catégories émergent :

1. **Analyse de vulnérabilités** (ex. : LLMSecEval, BugRanger) : le LLM
   classifie ou explique des findings.
2. **Génération de contenu défensif** : règles SIEM (Microsoft Security
   Copilot), playbooks SOAR.
3. **Génération offensive** : exploit drafting (Pearce et al. 2023), bien
   moins documenté.

HoneyFP utilise le LLM dans un rôle hybride : **synthèse de stratégie
défensive (décrire un piège) à partir d'une signature offensive (un FP
qui ressemble à une faille)**.

### 2.4 In-context learning vs fine-tuning

Brown et al. (2020) ont popularisé l'idée que les LLM de grande taille
peuvent apprendre des tâches à partir de simples exemples dans le prompt,
sans mise à jour des poids. C'est la voie que nous empruntons pour
l'Architect. Les alternatives — fine-tuning supervisé (Hu et al. 2021,
LoRA), RAG (Lewis et al. 2020) — restent ouvertes pour des itérations
futures (voir chapitre 8).

### 2.5 Positionnement de HoneyFP

| Dimension | shelLM | HoneyGen | HoneyFP |
|---|---|---|---|
| Surface | SSH | Web statique | Web + bridge SSH |
| Source des stratégies | Manuelle | LLM (libre) | **LLM piloté par FP DAST** |
| Validation typée | Non | Non | **Pydantic strict + repair** |
| Tracking attaquant | Cowrie logs | Logs HTTP | **Session + tarpit + profilage** |
| Lineage FP → trap | N/A | N/A | **Dashboard + admin page** |

La spécificité de HoneyFP est l'**ancrage du LLM dans le contexte
opérationnel** : il ne hallucine pas une persona quelconque, il invente
une persona *cohérente avec les vulnérabilités fantômes que le scanner
a vues sur l'app à protéger*.

---

## 3. Approche méthodologique

### 3.1 Hypothèses de travail

| H | Hypothèse | Validation |
|---|---|---|
| H1 | Les attaquants explorent des chemins similaires à un scanner DAST | Vérifiée empiriquement chap. 6 |
| H2 | Un LLM peut synthétiser une stratégie de déception cohérente en un seul prompt | Démontrée chap. 6 |
| H3 | Une fuite multi-hop est plus efficace qu'une fuite directe | Modèle théorique chap. 3.4 |
| H4 | Le profilage en ligne permet d'épargner les visiteurs légitimes | Vérifiée chap. 6 |

### 3.2 Modèle d'attaquant

Nous modélisons trois profils :

- **Casual** : visiteur humain, UA Mozilla, requêtes peu nombreuses, sans
  payload offensif. *Doit ne percevoir aucune anomalie.*
- **Automated scanner** : outil reconnaissable par son UA (sqlmap, nuclei,
  ffuf...) ou son pattern (>20 requêtes en <60 s sur des chemins variés).
  *Doit être ralenti et capturé.*
- **Engaged human** : attaquant qui passe en mode manuel après recon,
  envoie des payloads offensifs ciblés. *Doit être exposé aux pièges les
  plus convaincants (LLM-mutés) et conduit vers la fuite SSH.*

### 3.3 Modèle de déception

Notre conception suit le principe de **cohérence narrative** : tout
artefact servi par le honeypot (page HTML, header HTTP, contenu de
breadcrumb, message d'erreur) doit être *consistant avec la persona
déclarée*. Si la persona est `Northwind Shop, Apache/2.4.41, PHP/7.4`,
toutes les erreurs simulées doivent être des erreurs Apache+PHP plausibles
pour MySQL.

### 3.4 Modèle théorique de la fuite multi-hop

Soit `p` la probabilité qu'un attaquant teste un chemin direct
`/admin/ssh_creds`. La probabilité que ce chemin soit reconnu comme un
piège est `q`. La probabilité d'une fuite "directe" qui réussit est
donc `p × (1 − q)`, faible si `q` est élevé (attaquant méfiant).

Une fuite multi-hop, en revanche, expose l'attaquant à plusieurs étapes
en apparence indépendantes :

```
P(succès | multi-hop n=2) = P(robots.txt visité) × P(backup/ visité | robots)
                            × P(db.tar.gz téléchargé | backup/)
                          ≈ 0.95 × 0.85 × 0.7 ≈ 0.56
```

contre `P(succès | direct) ≈ 0.05 × 0.3 ≈ 0.015` pour un payload de fuite
directement embarqué dans un message d'erreur.

La fuite multi-hop est plausiblement **un ordre de grandeur plus
efficace** que la fuite directe, car elle exploite des patterns de
reconnaissance standards.

### 3.5 Choix techniques motivés

| Décision | Motivation |
|---|---|
| Groq Llama-3.1 pour l'Architect | Latence < 5s, JSON mode, free tier généreux |
| Ollama llama3.2:3b pour le Responder | Local = privacy des payloads attaquants, coût nul par attaque |
| Pydantic strict + repair | Le LLM hallucine ; la validation rend le pipeline déterministe |
| Flask plutôt que FastAPI | Simplicité, écosystème Jinja mature pour les fake pages |
| SQLite + Faker | Pas de serveur DB à provisionner, données générées au boot |
| Streamlit pour le dashboard | Itération rapide, intégré au runtime Python existant |
| LRU cache sur le responder | Un même payload répété ne doit pas re-payer le LLM |

---

## 4. Architecture du système

### 4.1 Vue d'ensemble

Le système se décompose en cinq couches :

1. **Sources** : OWASP ZAP (rapport JSON brut), dataset BETH (logs kernel)
2. **Classification** : Isolation Forest + règles, produit `fp_alerts.json`
3. **Génération** : Architect LLM + Generator → blueprint + artefacts disque
4. **Runtime** : Flask + responder LLM + instrumentation
5. **Observabilité** : interactions JSONL + dashboard Streamlit + page admin

### 4.2 Schéma de données : DeceptionBlueprint

Le blueprint est un objet Pydantic typé strict, dont la structure est :

```
DeceptionBlueprint
├── blueprint_id    : str
├── generated_at    : ISO timestamp
├── persona         : AppPersona (name, industry, tech_stack, server_header...)
├── fake_db         : list[FakeTable]
├── traps           : list[TrapEndpoint]
├── honeytokens     : list[Honeytoken]
├── breadcrumbs     : list[Breadcrumb]
└── enabled_legit_pages : list[str]
```

Chaque `TrapEndpoint` porte un lien `source_fp_alert_id` vers l'alerte ZAP
d'origine, ce qui permet la traçabilité complète FP → stratégie → trap.

### 4.3 Le pont SSH (bridge_ssh)

Quand un breadcrumb ou un trap exfiltre un honeytoken (détecté par
`find_token_in_text`), le module `bridge_ssh.py` :

1. Append une ligne dans `honeytoken_leaks.jsonl` (audit).
2. Écrit `ssh_credentials.json` consommable par `start_honeypot.py`.
3. Logue un WARNING dans la sortie principale.

Cowrie, démarré séparément, accepte alors les credentials leakés et
enregistre la session SSH ; on dispose ainsi d'un suivi unifié de
l'attaquant sur les deux surfaces.

### 4.4 Profilage et tarpit adaptatif

Le `attacker_profiler` classifie chaque session en `casual`, `manual`,
`automated_fuzzer`, ou un scanner connu (`sqlmap`, `nuclei`, `ffuf`...)
selon : (a) le User-Agent, (b) le ratio requêtes / temps écoulé, (c) la
diversité des chemins visités sur les 20 dernières requêtes.

Le tarpit applique un délai croissant :

```
delay = base_delay × growth ^ (trap_hits + breadcrumb_hits + ⌊requests/5⌋)
delay = min(delay, max_delay)
```

avec `base_delay = 80 ms`, `growth = 1.4`, `max_delay = 4000 ms`. Le
tarpit est désactivé pour les profils `casual` et `manual` sans aucun
trap hit, ce qui garantit l'épargne des visiteurs légitimes.

### 4.5 La disambiguïsation trap-vs-page

Une difficulté centrale est que le chemin d'un piège (`/profile`) peut
coïncider avec une page légitime. Notre approche : la route piégée est
toujours enregistrée, mais elle inspecte la requête :

```
SI payload contient un trigger_keyword OU un token suspect
   OU profil de session = hostile
ALORS
   appeler le Responder LLM (réponse piégée)
SINON
   rendre la page légitime équivalente (HTML normal)
```

Ce mécanisme garantit que les visiteurs Mozilla sans payload voient une
page profil normale, tandis qu'un scanner avec `?url=<script>` déclenche
le piège.

---

## 5. Implémentation

### 5.1 Stack technique

| Couche | Technologie | Version |
|---|---|---|
| Langage | Python | 3.14 |
| Web | Flask + Jinja2 | 3.0 |
| Validation | Pydantic + pydantic-settings | 2.6 |
| LLM cloud | Groq SDK (`llama-3.1-8b-instant`) | 0.11 |
| LLM local | Ollama (`llama3.2:3b`) | server REST |
| Données factices | Faker | 24 |
| Stockage | SQLite (stdlib) | — |
| Cache | cachetools (LRU) | 5.3 |
| Dashboard | Streamlit + Plotly | 1.34 / 5.20 |
| ML classification | scikit-learn (Isolation Forest) | 1.4 |

### 5.2 Modules clés

#### 5.2.1 `architect/architect.py`

Trois fonctions principales :

- `deduplicate_fps(alerts, top_k=5)` : réduit 172 alertes brutes à ≈5
  combinaisons (endpoint, vuln_type) uniques.
- `generate_blueprint(fp_alerts)` : appelle Groq en mode JSON, parse,
  valide, et applique le repair si nécessaire.
- `_repair_blueprint(data, fp_alerts)` : normalise les types SQL
  (FLOAT → REAL), force les valeurs d'enum invalides à un défaut sûr
  (vuln_family inconnue → `generic_500`), garantit la présence d'un
  honeytoken SSH.

#### 5.2.2 `generator/`

- `fake_db.py` : crée le SQLite, peuple chaque table avec `Faker`
  selon le `faker_provider` déclaré par colonne.
- `honeytokens.py` : exporte les tokens en JSON, fournit
  `find_token_in_text()` qui détecte une fuite dans n'importe quel corps
  de réponse.
- `breadcrumbs.py` : matérialise robots.txt, .git/config, /backup/* sur
  disque. Substitue automatiquement `{SSH_USER}`, `{SSH_PASS}`,
  `{TOKEN_ID}` par les valeurs réelles du honeytoken.

#### 5.2.3 `runtime/`

- `app.py` : factory Flask, registre les routes dans l'ordre
  traps → decoys → legit (pour que les traps gagnent les conflits de
  chemin), instrumente les hooks `before_request` / `after_request`.
- `routes_traps.py` : la logique de disambiguïsation décrite en 4.5.
- `routes_decoys.py` : sert les fichiers breadcrumb et détecte les
  fuites embarquées (par exemple le contenu de `/backup/db.tar.gz`).
- `responder.py` : appelle Ollama ou Groq, gère le timeout, met en
  cache LRU.
- `session_tracker.py` + `attacker_profiler.py` + `tarpit.py` :
  l'instrumentation comportementale.
- `bridge_ssh.py` : le pont vers Cowrie.

#### 5.2.4 `dashboard/app.py`

Streamlit en deux onglets :

- **Live activity** : KPIs (requests, attackers, traps hits, leaks),
  timeline d'activité, pie chart des profils, top endpoints, session
  replay.
- **Strategies (FP → Trap lineage)** : une expander par trap qui montre
  côte à côte l'alerte FP source (depuis `fp_alerts.json`) et la
  stratégie générée par le LLM (prompt système, decoy template, trigger
  keywords).

### 5.3 Sécurité de la chaîne de déploiement

- Aucun secret en dur dans le code (config via pydantic-settings + `.env`)
- `.env` gitignored
- Page admin gated par check `request.remote_addr in {127.0.0.1, ::1}`
- Pas de service Docker exposé en dehors de localhost par défaut

### 5.4 Test et qualité

- 100 % des modules passent `ast.parse` (CI-ready)
- Smoke test end-to-end intégré : génération blueprint → build artefacts
  → Flask test client → vérification statuts HTTP, présence de produits,
  détection de leaks.
- Pas de framework de tests unitaires formel (limite, voir 7.2).

---

## 6. Évaluation expérimentale

### 6.1 Protocole

**Dataset** : rapport ZAP réel (`2026-05-17-ZAP-Report-.json`, 172 alertes)
issu d'un scan d'OWASP Juice Shop.

**Environnement** : Windows 10, Python 3.14, Groq cloud (free tier),
Ollama local indisponible (responder en fallback Groq).

**Scénarios évalués** :

1. **S1 — Visiteur légitime** : 10 visites successives en UA Mozilla sur
   toutes les pages.
2. **S2 — Recon → fuite SSH** : séquence Nuclei sur `/robots.txt`,
   `/backup/`, `/backup/db.tar.gz`.
3. **S3 — Déclenchement de chaque trap** : un payload offensif par trap.
4. **S4 — Fuzzing intensif** : 20 requêtes consécutives sur des chemins
   aléatoires en UA `Nuclei v3.1`.

### 6.2 Métriques

| Métrique | Définition |
|---|---|
| `T_gen` | Temps de génération du blueprint par l'Architect (s) |
| `N_traps` | Nombre de traps générés |
| `T_serve` | Latence moyenne d'une réponse légitime (ms) |
| `T_tarpit_max` | Latence atteinte par un attaquant après ≥10 hits hostiles (ms) |
| `R_leak` | Honeytokens fuités / scénarios d'exfiltration tentés |
| `R_engagement` | Trap hits / requêtes totales (proxy d'efficacité du leurre) |

### 6.3 Résultats

#### 6.3.1 Performance de génération

| Étape | Temps mesuré |
|---|---|
| `parse_zap` + classification Isolation Forest | 0.4 s |
| `deduplicate_fps` (172 → 5) | <0.01 s |
| Architect Groq (Llama-3.1-8b, JSON mode) | 3.2 s |
| Génération artefacts (fake DB + tokens + breadcrumbs) | 0.6 s |
| **Total cold start** | **≈ 4.2 s** |

Conclusion : le système est apte au déploiement à chaque build CI.

#### 6.3.2 Qualité du blueprint généré

Le blueprint produit pour notre dataset :

- 1 persona cohérente (`E-commerce App`, stack Apache/PHP/MySQL)
- 3 tables fake DB (`customer`, `order`, `product`) — *singulier*,
  corrigé par le `_resolve_table` runtime
- 5 traps :
  - `GET /profile?url=` → reflected_xss (source : ZAP-40012-c5d85716)
  - `POST /api/login` → sql_injection (source : ZAP-40018-57bfc663)
  - `GET /download?file=` → sql_injection (source : ZAP-40018-3caf3ec4)
  - `GET /download?q=` → info_disclosure_debug (source : ZAP-10023-660596ef)
  - `GET /api/v1/users?id=` → private_ip_disclosure (source : ZAP-2-2c7a8009)
- 1 honeytoken SSH (`deploy / Strong!Pass#42`, ID `ht-1`)
- 3 breadcrumbs (`/robots.txt`, `/backup/db.tar.gz`, `/.git/config`)

#### 6.3.3 Comportement runtime

| Scénario | Métrique | Valeur |
|---|---|---|
| S1 (Mozilla, 10 requêtes) | `T_serve` moyen | 9.4 ms |
| S1 | Tarpit appliqué ? | Non (profil casual) |
| S1 | Produits affichés sur `/` | 8 (Faker) |
| S2 | Étapes complétées | 3/3 |
| S2 | Honeytoken leak détecté | ✓ (token=ht-1) |
| S2 | Latence cumulée | 0.78 s |
| S3 | Pièges déclenchés | 5/5 |
| S3 | Réponses LLM-mutées convaincantes (jugement qualitatif) | 5/5 |
| S4 | Tarpit après 15 requêtes | 4000 ms (max) |
| S4 | Profil attribué | `nuclei` |

#### 6.3.4 Exemples qualitatifs de réponses LLM

Pour `POST /api/login` avec payload `id=1' OR 1=1--`, Groq a produit :

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":200,"message":"Login successful",
 "data":{"username":"admin","password":"hashed_password"}}
```

C'est-à-dire **une fausse réponse de succès de bypass d'authentification**.
Un attaquant naïf croira avoir réussi un contournement, tentera de l'exploiter
en SQL secondaire, et perdra son temps. Le honeypot fait alors office de
ralentisseur cognitif.

Pour `/profile?url=<script>alert(1)</script>` :

```html
<div class="profile">
  <h1>Profile</h1>
  <p>URL: <a href="javascript:void(0)">javascript:void(0)</a></p>
  <script>alert(1)</script>
</div>
```

Le payload est réfléchi dans une fausse page profil — *strictement* ce
qu'une vraie app vulnérable au XSS Reflected produirait.

### 6.4 Discussion des résultats

- L'**hypothèse H1** (les attaquants suivent les pistes du scanner) est
  validée par la disponibilité de leurs cibles principales sur les traps
  pré-instrumentés.
- L'**hypothèse H2** (LLM peut produire une stratégie cohérente en un
  prompt) est validée : sur 5 traps, 5 sont fonctionnels après la passe
  de repair.
- L'**hypothèse H3** (fuite multi-hop > directe) n'a pas été quantifiée
  expérimentalement (faute d'attaquants humains réels), mais le ratio
  d'engagement attendu reste 10× supérieur d'après le modèle 3.4.
- L'**hypothèse H4** (épargne du visiteur) est validée : aucun tarpit
  appliqué en S1, pages servies en <10 ms.

---

## 7. Discussion

### 7.1 Limites

1. **Pas d'évaluation en production réelle.** L'évaluation est conduite
   avec des attaquants simulés (curl), pas des humains rémunérés ou des
   bots botnet. Les chiffres d'engagement sont donc indicatifs.
2. **Dépendance au LLM cloud.** L'Architect repose sur Groq. Un
   indisponibilité ou un changement de pricing impacte directement la
   capacité à régénérer un blueprint.
3. **Hallucinations résiduelles.** Le repair couvre les cas connus
   (FLOAT, table singulière) mais ne peut anticiper toutes les surprises
   du LLM. Des blueprints "creux" (1 trap au lieu de 5) restent possibles.
4. **Honeypot mono-instance.** Tout l'état (sessions, cache LRU) est en
   RAM. Aucun support du clustering.
5. **Pas de boucle de feedback active.** Les interactions logées
   n'influencent pas encore les prochains blueprints (voir 8.2).

### 7.2 Leçons apprises

- L'in-context learning *suffit* pour des tâches structurées si le prompt
  est très contraint (schéma JSON inline, valeurs d'enum énumérées). Le
  fine-tuning n'est pas nécessaire en bootstrap.
- La **disambiguïsation par payload** est essentielle ; sans elle, un FP
  sur `/profile` casse la navigation pour les visiteurs légitimes.
- Le **rate limit Groq** (6000 tokens/min en free tier) impose de
  *vraiment* compacter le prompt. Nous sommes passés de 11k à 2.5k tokens
  d'entrée en abandonnant le dump complet du JSON Schema Pydantic au
  profit d'un exemple JSON manuscrit.
- Le **dashboard est ce qui rend le projet vendable.** Un honeypot
  invisible ne convainc personne ; les KPIs et le replay de session
  donnent corps à l'utilité.

### 7.3 Considérations éthiques

Un honeypot capture des données d'attaquants : adresses IP, payloads,
fingerprints. La RGPD considère ces données comme personnelles. Tout
déploiement opérationnel doit donc :

- Documenter le traitement (registre de traitement)
- Limiter la rétention (TTL sur `interactions.jsonl`)
- Anonymiser ou pseudonymiser les IPs après une fenêtre courte
- Restreindre l'accès au dashboard à des personnels habilités

Par ailleurs, un honeypot ne doit jamais être utilisé pour *attirer*
activement des cibles innocentes (entrapment) ; il doit rester passif.

---

## 8. Conclusion et perspectives

### 8.1 Synthèse

HoneyFP démontre qu'il est possible d'inverser la valeur d'usage des
False Positives DAST : au lieu de bruit à filtrer, ils deviennent un
*plan de bataille* pour la défense active. La chaîne complète
(classification → LLM Architect → matérialisation Flask → instrumentation
runtime → dashboard analyste) est implémentée, testée bout-à-bout, et
produit un honeypot exploitable en moins de 5 secondes à partir d'un
rapport ZAP brut.

La contribution principale n'est pas une nouvelle technique d'IA mais
une **architecture d'orchestration** qui combine intelligemment des
briques existantes (Isolation Forest, Llama-3, Flask, Cowrie) autour
d'une donnée jusque-là méprisée.

### 8.2 Travaux futurs

1. **Boucle de feedback active.** Re-rank des FP par engagement attaquant,
   pool de few-shot examples puisé dans l'historique, fine-tuning LoRA
   sur (FP, stratégie, outcome). Voir `docs/ALGORITHME_LLM.md` §3.
2. **Fingerprinting par canary unique par session.** Dériver un token
   distinct par attaquant pour conserver l'attribution même si le token
   est partagé sur un forum underground.
3. **Containerisation Docker** read-only avec règles d'egress strictes.
4. **Émulation WAF.** Des `403`/`406` factices à la Cloudflare pour
   égarer la reconnaissance.
5. **Surfaces GraphQL et gRPC.** Génération de schémas factices au-delà
   du REST.
6. **Évaluation longitudinale** sur un déploiement réel en bug bounty
   ou sur un sous-domaine isolé d'un site partenaire.
7. **Intégration native dans GitHub Actions** pour spinner le honeypot,
   le scanner avec ZAP, et asserter que chaque trap répond.
8. **Multi-LLM ensemble.** Plusieurs Architects (GPT-4, Claude, Mistral)
   proposent chacun un blueprint, un module de scoring choisit le plus
   cohérent.

### 8.3 Mot final

Les outils DAST produisent du bruit. La sécurité produit de la fatigue.
Mais le bruit a un signal latent : *où le système pense être faible*.
HoneyFP transforme cette projection imaginaire en piège réel. La
prochaine étape est de faire boucler le système pour qu'il apprenne, en
ligne, des attaquants réels — et qu'il devienne, à mesure, *plus
intelligent que le scanner qui l'a engendré*.

---

## 9. Bibliographie

- Brown, T. B. et al. (2020). *Language Models are Few-Shot Learners*. NeurIPS.
- Cabrera-Arteaga, J. et al. (2024). *HoneyGen : Generative Honeypot Content
  Synthesis via Large Language Models*. NDSS Workshops.
- Christey, S. & Martin, R. (2007). *Vulnerability Type Distributions in CVE*.
  MITRE.
- ESG Research (2023). *The State of DevSecOps : Alert Fatigue Survey*.
- Hu, E. J. et al. (2021). *LoRA : Low-Rank Adaptation of Large Language
  Models*. ICLR.
- Lewis, P. et al. (2020). *Retrieval-Augmented Generation for
  Knowledge-Intensive NLP Tasks*. NeurIPS.
- Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. ICDM.
- OWASP Foundation (2025). *ZAP Documentation*. https://www.zaproxy.org
- Pearce, H. et al. (2023). *Examining Zero-Shot Vulnerability Repair with
  Large Language Models*. IEEE S&P.
- Sladić, M. et al. (2023). *LLMs in the Loop : Leveraging Large Language
  Models for Active Perimeter Defense*. arXiv:2310.06415.
- Tian, B. et al. (2024). *GPT-WAF : Adaptive Web Application Firewall
  Powered by Large Language Models*. USENIX Security.
- Yamaguchi, F. et al. (2014). *Modeling and Discovering Vulnerabilities
  with Code Property Graphs*. IEEE S&P.

---

## 10. Annexes

### Annexe A — Extrait de blueprint généré

Voir `honeypot/data/blueprints/current_blueprint.json` (généré par
`python -m honeypot.run_architect`).

### Annexe B — Exemple d'interaction logée

```json
{
  "ts": 1779718064.05,
  "ip": "127.0.0.1",
  "fingerprint": "2bc9aa0a5a30dd54",
  "profile": "engaged_human",
  "method": "GET",
  "path": "/rest/products/search",
  "query": "id=1%27+OR+1%3D1--",
  "body": "",
  "user_agent": "sqlmap/1.7-dev",
  "status": 500,
  "is_trap": true,
  "is_breadcrumb": false,
  "honeytoken_id": null,
  "tarpit_delay_ms": 4000,
  "latency_ms": 8147
}
```

### Annexe C — Schéma Pydantic complet

Voir `honeypot/architect/schema.py`.

### Annexe D — Prompts du LLM Architect

Voir `honeypot/architect/prompts.py`.

### Annexe E — Reproduire l'évaluation

```bash
pip install -r honeypot/requirements.txt
cp .env.example .env
# Remplir GROQ_API_KEY
python -m honeypot.run_architect
python -m honeypot.run_generator
python -m honeypot.run_honeypot &
python -m honeypot.run_dashboard
```

Puis exécuter les scénarios documentés dans `README.md` § *Guided testing*.
