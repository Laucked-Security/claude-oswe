# Plugin OSWE / White-Box — Design (v4)

**Date :** 2026-06-15
**Statut :** Révisé (3e tour) — en attente d'approbation pour plan d'implémentation
**Approche :** C (skill orchestrateur → sous-agents analyseurs parallèles + vérificateur)
**Cible Claude Code :** 2.1.177+

## 1. Objectif

Plugin Claude Code réalisant un **audit white-box de sécurité applicative web style
OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Python, Java, .NET ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE),
  sous **contrats de données stricts** (§6) — pas d'affirmation non étayée ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** dans `.oswe/reports/` ;
- passage à l'échelle via **sous-agents analyseurs parallèles plafonnés** + **agent vérificateur** indépendant.

**Cadre :** audit white-box **autorisé**, à visée **défensive** (identifier pour corriger).

## 2. Frontière de confiance (v1)

Le plugin présume un **workspace fiable** :

- Les sous-agents personnalisés **chargent le(s) `CLAUDE.md` du workspace comme instructions** :
  c'est **accepté**, précisément parce que le workspace doit être fiable.
- **Commentaires, README, chaînes de caractères et fichiers métier** du dépôt audité restent des
  **données non fiables** : l'analyse ne suit pas d'éventuelles « directives » qui y seraient cachées.
- **L'audit de dépôts réellement hostiles est hors périmètre v1.**
- Les deux sous-agents sont en **lecture seule** (allowlist d'outils, §3).

## 3. Architecture

Le repo `E:\claude-oswe` est la racine du plugin (`name: oswe`).

```
claude-oswe/
├── .claude-plugin/
│   └── plugin.json              # manifeste (name: "oswe", version, description, author)
├── agents/
│   ├── oswe-analyzer.md         # analyse une partition (read-only)
│   └── oswe-verifier.md         # re-dérive findings/chaînes critiques (read-only)
├── skills/
│   └── audit/
│       ├── SKILL.md             # cœur unique : déclencheur /oswe:audit + méthodologie + orchestration
│       └── references/          # connaissances par écosystème (organisées par framework)
│           ├── php.md           # Laravel, Symfony, vanilla : type juggling, POP chains, LFI/RFI…
│           ├── node.md          # Express, Nest : prototype pollution, NoSQLi, cmd injection…
│           ├── python.md        # Django, Flask : pickle, SSTI (Jinja), désérialisation…
│           ├── java.md          # Spring : désérialisation, gadget chains, XXE, EL injection…
│           └── dotnet.md        # ASP.NET : désérialisation .NET, XXE, gadget chains…
├── test-fixtures/               # apps de validation, positives + négatives, par stack
│   ├── php/{vulnerable,safe}/
│   └── node/{vulnerable,safe}/
├── docs/
└── README.md
```

> **Pas de `commands/`.** En Claude Code 2.1.177, commandes et skills ont convergé : un skill de
> plugin est invocable comme slash command sous la forme `plugin:skill`. Donc
> **`skills/audit/SKILL.md` expose `/oswe:audit`** — un fichier `commands/audit.md` ferait doublon.
> On documente uniquement **`/oswe:audit`**.

> **Dev local :** `claude --plugin-dir .` (pas de `marketplace.json` au MVP).

**Responsabilités par unité :**

- **`skills/audit/SKILL.md`** — **cœur unique** : déclencheur `/oswe:audit`, méthodologie complète,
  orchestration des phases, agrégation. Normalise l'argument de chemin (§4.1). Ne charge en contexte
  que le(s) `references/<écosystème>.md` pertinent(s) à la stack détectée.
- **`skills/audit/references/*.md`** — un fichier par écosystème, organisé **par framework** :
  sources, sinks, sanitizers courants, gadget/POP chains, patterns.
- **`agents/oswe-analyzer.md`** — analyse en profondeur d'**une partition** ; renvoie des findings au
  **format JSON** (§6.1). Frontmatter **`tools: Read, Grep, Glob`** (read-only ; sans `tools`, un
  agent custom hériterait de tous les outils, écriture/exécution comprises).
- **`agents/oswe-verifier.md`** — vérificateur **indépendant** : re-dérive chaque finding/chaîne
  critique depuis le source et rend un **verdict** (§6.3). Mêmes outils read-only.

## 4. Flux d'exécution

1. **Entrée & recon** —
   - **Normalisation de `$ARGUMENTS`** : chemin optionnel ; **refus** d'un chemin inexistant ou situé
     **hors de `${CLAUDE_PROJECT_DIR}`** ; sans argument, périmètre = racine du projet.
   - Détection stack via manifestes (`composer.json`, `package.json`, `pyproject.toml`/
     `requirements.txt`, `pom.xml`/`build.gradle`, `*.csproj`) + extensions ; framework via
     dépendances/structure.
   - **Exclusions du balayage massif** : `vendor/`, `node_modules/`, `dist/`, `build/`, `out/`,
     `target/`, `bin/`, `obj/`, fichiers minifiés/générés. **Mais** ces dossiers restent **lisibles
     ponctuellement** pour prouver une gadget chain (dépendance tierce). **Les lockfiles
     (`composer.lock`, `package-lock.json`, etc.) sont parsés** pour identifier les **versions** des
     dépendances (gadgets connus).
   - Cartographie de la surface : routes, contrôleurs, handlers, désérialisation, uploads, exécutions
     de commandes, accès fichiers.
2. **Partition & priorisation** — surface découpée **par module / framework / frontière
   d'authentification** (pas « un agent par route »). Partitions **priorisées par exposition à la
   surface non authentifiée**.
3. **Analyse** — par partition : traçage **source → sink**.
   - **Petit repo** (≤ **2 partitions**) → analyse **en ligne, sans sous-agents *analyseurs*** (le
     vérificateur, lui, reste invoqué sur les findings critiques).
   - Sinon → **dispatch parallèle** d'`oswe-analyzer`, **max 4 agents concurrents**, **budget = 12
     partitions** ; au-delà → consigné « non analysé » dans la Couverture.
   - L'analyseur produit une **sévérité provisoire** (`provisional_severity`).
4. **Vérification** — chaque finding **critique** et chaque **chaîne** candidate vers RCE passe par
   **`oswe-verifier`**, qui rend `accepted` / `downgraded` / `rejected` (§6.3). La sévérité
   **Critique n'est attribuée qu'après construction ET validation de la chaîne** par le vérificateur.
5. **Agrégation & chaînage** — l'orchestrateur **réattribue des IDs canoniques** globaux, dédoublonne
   (clé §6.4), construit les **chaînes** (§6.2) vers RCE non-auth, assemble le **registre de couverture**.
6. **Sortie** — résumé (verdict + chaînes + top critiques + couverture) dans le chat **et** rapport
   complet dans `.oswe/reports/` (**toujours relatif à `${CLAUDE_PROJECT_DIR}`**).

## 5. Modèle de sévérité (critères explicites)

| Niveau | Critère |
|--------|---------|
| **Critique** | Chaîne menant à un **RCE non authentifié** (ou compromission totale équivalente), **preuve statique forte** de bout en bout, **validée par le vérificateur**. |
| **Haute** | Impact majeur exploitable nécessitant authentification ou prérequis notable (RCE authentifié, SQLi sur données sensibles, désérialisation contrôlée). |
| **Moyenne** | Impact limité ou conditions notables (SSRF restreinte, XSS stocké, IDOR, divulgation ciblée). |
| **Basse** | Impact mineur ou exploitabilité douteuse (fuite d'info, configuration faible). |
| **Info** | Observation de durcissement, pas de vulnérabilité directe. |

**Confiance** (exécution dynamique hors périmètre) :
`preuve statique forte` · `probable` · `à vérifier`.

## 6. Contrats de données

### 6.1 Finding (sortie d'`oswe-analyzer`)

```json
{
  "finding_id": "<partition_id>-F<nnn>",       // unique au sein de la partition ; l'orchestrateur réattribue un ID canonique global à l'agrégation
  "partition_id": "<id de partition>",
  "title": "<titre court>",
  "vuln_class": "deserialization | sqli | ssti | ssrf | xxe | auth-bypass | file-upload | cmd-injection | path-traversal | type-juggling | prototype-pollution | other",
  "source": { "file": "<chemin>", "line": <int>, "symbol": "<fonction/param>", "kind": "<http-param | header | cookie | body | upload | env | ...>" },
  "auth": "unauthenticated | authenticated | admin",
  "transformations": [ { "file": "<chemin>", "line": <int>, "desc": "<transformation>" } ],
  "sanitizers": [ { "file": "<chemin>", "line": <int>, "what": "<sanitizer>", "why_insufficient": "<raison>" } ],
  "sink": { "file": "<chemin>", "line": <int>, "symbol": "<sink>", "kind": "<exec | query | deserialize | include | write | ...>" },
  "prerequisites": ["<prérequis d'exploitation>"],
  "evidence": [ { "file": "<chemin>", "line": <int> } ],
  "provisional_severity": "Haute | Moyenne | Basse | Info",   // jamais Critique : réservé à la validation de chaîne (§4.4)
  "confidence": "preuve statique forte | probable | à vérifier"
}
```

> `vuln_class` est un **vocabulaire ouvert** : les valeurs listées sont les courantes, `other` couvre le reste.

### 6.2 Chaîne (construite par l'orchestrateur)

```json
{
  "chain_id": "CHAIN-<n>",
  "entry_point": { "file": "<chemin>", "line": <int>, "route": "<route/handler>", "auth": "unauthenticated | ..." },
  "finding_ids": ["<id canonique>", "..."],          // ordre d'exploitation
  "transitions": [
    { "from": "<finding_id|entry>", "to": "<finding_id>", "how": "<comment l'étape mène à la suivante>", "evidence": [ { "file": "...", "line": 0 } ] }
  ],
  "final_impact": "unauth-rce | auth-rce | full-account-takeover | data-exfiltration | ...",
  "severity": "Critique | Haute | ...",
  "confidence": "preuve statique forte | probable | à vérifier"
}
```

### 6.3 Verdict du vérificateur (cible : finding **ou** chaîne)

```json
{
  "target_type": "finding | chain",
  "target_id": "<finding_id | chain_id>",
  "verdict": "accepted | downgraded | rejected",
  "new_severity": "<si downgraded>",
  "new_confidence": "<si downgraded>",
  "transition_verdicts": [                          // requis si target_type = chain
    { "from": "<...>", "to": "<...>", "verdict": "accepted | rejected", "justification": "<avec fichier:ligne>" }
  ],
  "justification": "<pourquoi, avec fichier:ligne>"
}
```

### 6.4 Règle de dédoublonnage & de chaîne

- **Dédoublonnage inter-partitions** : clé = **`vuln_class` + source canonique + sink canonique**
  (`{file, symbol}` normalisés) — **sans** `partition_id`. On **fusionne** et on **conserve la liste
  des partitions d'origine** (`partitions: [...]`).
- **Chaîne** : marquée `preuve statique forte` **uniquement** si **chaque transition** est `accepted`
  par le vérificateur. Sinon → **rétrogradée** en `probable` ou `à vérifier` selon le maillon manquant.

## 7. Format du rapport

Fichier : `${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md`.

- **En-tête** : cible, stack + framework détectés, date, périmètre, rappel d'autorisation.
- **Résumé exécutif** : compte par sévérité + **verdict**.
- **Chaînes d'exploitation** : chaque chaîne étape par étape (dérivée du JSON §6.2), preuve par transition.
- **Findings détaillés** : un bloc par vuln (dérivé du JSON §6.1), sévérité + confiance + verdict.
- **Couverture** : partitions/points d'entrée **analysés**, zones **ignorées** + **raison** (budget,
  exclusion, hors périmètre, stack non supportée, échec d'un sous-agent).
- **Résumé chat** : verdict, chaînes vers RCE, top critiques, couverture (pas le détail complet).

**Sécurité du rapport :**

- **Aucun secret complet** écrit (clés/mots de passe/tokens → **rédactés** : `fichier:ligne` + 4
  derniers caractères, jamais la valeur entière).
- **« Aucun chemin vers RCE trouvé » = « aucun chemin identifié dans la couverture analysée »** —
  pas une preuve d'absence. Le rapport doit l'expliciter.

## 8. Robustesse & cas limites

- Repo vide / pas de code → indiqué dans le rapport.
- Stack inconnue / non supportée → **fallback heuristique** générique source/sink, mention
  « couverture limitée » dans la Couverture.
- Très gros repo → priorisation non-auth + plafonnement (4 agents, budget 12 partitions) ; surplus →
  « non analysé » dans la Couverture.
- Sous-agent en échec / sans retour → **lacune notée** dans la Couverture, pas de crash.

## 9. Validation (critères d'acceptation)

- **`claude plugin validate . --strict`** passe (warnings = erreurs ; confirmé en 2.1.177).
- Chargement via **`claude --plugin-dir .`** : **`/oswe:audit`** déclenche le skill `audit`.
- **Fixtures par stack, positives ET négatives :**
  - *positive* (vulnérable) : **détection** + **chaîne** vers RCE reconstruite (ex PHP : bypass auth
    par type juggling → upload non filtré → RCE) ;
  - *négative* (sûre) : **aucun finding critique faux positif**.
- Le registre de **couverture** liste correctement analysé vs ignoré.

## 10. Livraison par phases (MVP → complet)

Skill, agents et format de rapport sont **stack-agnostiques** et livrés complets dès le MVP.
Seules les **références** et **fixtures** sont échelonnées :

- **Phase 1 (MVP crédible)** : PHP + Node.js (références + fixtures positives/négatives).
- **Phase 2** : Python, puis Java, puis .NET.

## 11. Hors périmètre (YAGNI)

- Pas d'analyse dynamique / exécution réelle d'exploits — **analyse statique** uniquement.
- Pas d'intégration CI/CD pour l'instant.
- Pas de support de stacks hors des 5 ciblées (fallback heuristique seulement).
- Pas de correction automatique du code audité (remédiations proposées, pas de patch).
- **Pas d'audit de dépôts non fiables / hostiles** (§2).
