# Plugin OSWE / White-Box — Design (v5)

**Date :** 2026-06-15
**Statut :** Révisé (4e tour) — en attente d'approbation pour plan d'implémentation
**Approche :** C (skill orchestrateur → sous-agents analyseurs parallèles + vérificateur)
**Cible Claude Code :** 2.1.177+

## 1. Objectif

Plugin Claude Code réalisant un **audit white-box de sécurité applicative web style
OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Python, Java, .NET ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE),
  sous **contrats de données stricts** validés par JSON Schema (§6) ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** dans `.oswe/reports/` ;
- passage à l'échelle via **sous-agents analyseurs parallèles plafonnés** + **agent vérificateur** indépendant.

**Cadre :** audit white-box **autorisé**, à visée **défensive** (identifier pour corriger).

## 2. Frontière de confiance (v1)

- Les sous-agents personnalisés **chargent le(s) `CLAUDE.md` du workspace comme instructions** :
  **accepté**, car le workspace doit être fiable.
- **Commentaires, README, chaînes, fichiers métier** du dépôt audité = **données non fiables** :
  l'analyse ne suit pas d'éventuelles directives cachées.
- **Audit de dépôts hostiles : hors périmètre v1.**
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
│       ├── schemas/             # JSON Schema faisant foi pour les contrats inter-agents
│       │   ├── finding.schema.json
│       │   ├── chain.schema.json
│       │   └── verdict.schema.json
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

> **Pas de `commands/`** : en 2.1.177 le skill de plugin est invocable comme `/oswe:audit`
> (convergence commande/skill). **Dev local :** `claude --plugin-dir .`.

> **`SKILL.md` frontmatter `disable-model-invocation: true`** : l'audit ne se déclenche **que** sur
> `/oswe:audit` explicite. Sans ça, Claude pourrait lancer automatiquement cet audit coûteux et
> écrire un rapport sans commande.

**Responsabilités par unité :**

- **`skills/audit/SKILL.md`** — **cœur unique** : déclencheur `/oswe:audit`, méthodologie,
  orchestration (§4), agrégation, validation des sorties d'agents contre les schémas (§6.5).
  Ne charge que le(s) `references/<écosystème>.md` pertinent(s).
- **`skills/audit/schemas/*.json`** — JSON Schema **faisant foi** ; les exemples de §6 sont illustratifs.
- **`skills/audit/references/*.md`** — un fichier par écosystème, organisé **par framework**.
- **`agents/oswe-analyzer.md`** — analyse **une partition**, renvoie des findings (§6.1).
  Frontmatter **`tools: Read, Grep, Glob`** (read-only).
- **`agents/oswe-verifier.md`** — vérificateur **indépendant** (§6.3). Mêmes outils read-only.

## 4. Flux d'exécution (ordre strict)

1. **Entrée & recon** —
   - **Normalisation de `$ARGUMENTS`** : on résout le **chemin canonique réel** (realpath, suit
     symlinks/junctions) ; **refus** si inexistant ou si le chemin canonique **sort de
     `${CLAUDE_PROJECT_DIR}`** (la comparaison se fait sur chemins **canoniques** pour bloquer toute
     évasion par symlink/junction). Sans argument → périmètre = racine du projet.
   - Détection stack (manifestes + extensions) et framework (dépendances/structure).
   - **Exclusions du balayage massif** : `vendor/`, `node_modules/`, `dist/`, `build/`, `out/`,
     `target/`, `bin/`, `obj/`, minifiés/générés — **mais lisibles ponctuellement** pour prouver une
     gadget chain ; **lockfiles parsés** pour les versions de dépendances.
   - Cartographie de la surface (routes, handlers, désérialisation, uploads, exec, accès fichiers).
2. **Partition & priorisation** — découpage **par module / framework / frontière d'auth** ;
   partitions **priorisées par exposition non authentifiée**.
3. **Analyse** — par partition, traçage **source → sink**. L'analyseur émet des findings (§6.1) avec
   **`provisional_severity` (jamais Critique)**.
   - **Petit repo** (≤ **2 partitions**) → **en ligne, sans sous-agents *analyseurs***.
   - Sinon → **dispatch parallèle** d'`oswe-analyzer`, **max 4 concurrents**, **budget 12 partitions** ;
     surplus → « non analysé » dans la Couverture.
4. **Agrégation & dédoublonnage** — l'orchestrateur **réattribue des IDs canoniques globaux**,
   dédoublonne (clé §6.4) et **fusionne** en conservant le champ `partitions`.
5. **Construction des chaînes candidates** — l'orchestrateur assemble les **chaînes** (§6.2) vers RCE
   non-auth à partir des findings agrégés (les IDs canoniques existent désormais).
6. **Vérification** — `oswe-verifier` reçoit en entrée :
   - **tous les findings impliqués dans une chaîne candidate**,
   - **tous les findings provisoirement `Haute`**,
   - **la (les) chaîne(s) complète(s)**.

   Il rend des verdicts (§6.3). La sévérité **`Critique` est attribuée ici uniquement** si une chaîne
   est **validée** (toutes ses transitions `accepted`). Un finding `rejected` part en **annexe** (§7).
7. **Rapport** — résumé chat **et** rapport complet dans `.oswe/reports/`.

## 5. Modèle de sévérité (critères explicites)

| Niveau | Critère |
|--------|---------|
| **Critique** | Chaîne **RCE non authentifié** (ou compromission totale), **preuve statique forte** bout en bout, **validée par le vérificateur** (attribuée en §4.6, jamais avant). |
| **Haute** | Impact majeur nécessitant authentification ou prérequis notable (RCE authentifié, SQLi sensible, désérialisation contrôlée). |
| **Moyenne** | Impact limité ou conditions notables (SSRF restreinte, XSS stocké, IDOR). |
| **Basse** | Impact mineur ou exploitabilité douteuse (fuite d'info, config faible). |
| **Info** | Durcissement, pas de vulnérabilité directe. |

**Confiance** : `preuve statique forte` · `probable` · `à vérifier`.

## 6. Contrats de données

> Les blocs ci-dessous sont **illustratifs**. Les **JSON Schema de `skills/audit/schemas/` font foi.**

### 6.1 Finding (sortie d'`oswe-analyzer`)

Champs : `finding_id` (`<partition_id>-F<nnn>`, réattribué en canonique à l'agrégation),
`partition_id`, `title`, `vuln_class` (vocabulaire **ouvert** ; `other` pour le reste),
`source` et `sink` = objets `{ file, line, symbol, kind }`, `auth`
(`unauthenticated|authenticated|admin`), `transformations[]`, `sanitizers[]`
(`{ file, line, what, why_insufficient }`), `prerequisites[]`, `evidence[]` (`{ file, line }`),
`provisional_severity` (`Haute|Moyenne|Basse|Info` — **jamais Critique**), `confidence`
(`preuve statique forte|probable|à vérifier`).

**`partitions` (`string[]`)** : peuplé **à la fusion** (§6.4) avec la liste des partitions d'origine.

### 6.2 Chaîne (construite par l'orchestrateur)

Champs : `chain_id` (`CHAIN-<n>`), `entry_point` (`{ file, line, route, auth }`),
`finding_ids[]` (ordre d'exploitation, IDs **canoniques**),
`transitions[]` (`{ from, to, how, evidence[] }`),
`final_impact` (`unauth-rce|auth-rce|account-takeover|data-exfiltration|...`),
`severity`, `confidence`.

### 6.3 Verdict du vérificateur (cible : finding **ou** chaîne)

Champs : `target_type` (`finding|chain`), `target_id`, `verdict`
(`accepted|downgraded|rejected`), `new_severity`/`new_confidence` (si `downgraded`),
`transition_verdicts[]` (**requis si `chain`** : `{ from, to, verdict, justification }`),
`justification` (avec `fichier:ligne`).

**Devenir d'un `rejected`** : retiré du rapport principal, **déplacé en annexe** « Findings écartés »
(avec justification), jamais silencieusement supprimé.

### 6.4 Dédoublonnage & règle de chaîne

- **Clé de dédoublonnage inter-partitions** = `vuln_class` + **source canonique** + **sink canonique**,
  chaque objet normalisé sur **`{ file, symbol, line, kind }`** (inclure **`line` et `kind`** évite de
  fusionner deux flux distincts dans la même fonction). **Sans `partition_id`.** Fusion → on conserve
  `partitions[]` et la liste des `finding_id` sources.
- **Chaîne** marquée `preuve statique forte` **uniquement** si **chaque transition** est `accepted`.
  Sinon → **rétrogradée** en `probable` ou `à vérifier`.

### 6.5 Validation des sorties d'agents

Chaque sortie d'`oswe-analyzer`/`oswe-verifier` est **validée contre son JSON Schema**. En cas de
sortie **non conforme** : **une nouvelle tentative** ; si l'échec persiste, le finding/la partition est
consigné comme **lacune de couverture** (§7) — **jamais inventé ni deviné**.

## 7. Format du rapport

Fichier : `${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md` (**toujours relatif à
la racine projet**).

- **En-tête** : cible, stack + framework, date, périmètre, rappel d'autorisation.
- **Résumé exécutif** : compte par sévérité + **verdict**.
- **Chaînes d'exploitation** : chaque chaîne étape par étape (§6.2), preuve par transition.
- **Findings détaillés** : un bloc par vuln (§6.1), sévérité + confiance + verdict.
- **Couverture** : analysé vs **ignoré + raison** (budget, exclusion, hors périmètre, stack non
  supportée, échec d'agent, **lacune de validation §6.5**).
- **Annexe « Findings écartés »** : les `rejected` du vérificateur, avec justification.
- **Résumé chat** : verdict, chaînes RCE, top critiques, couverture.

**Sécurité du rapport :**

- **Aucun fragment de secret** : un secret découvert est remplacé par **`[REDACTED]`** (jamais de
  « N derniers caractères » — révélerait un secret court) ; seul `fichier:ligne` est indiqué.
- **« Aucun chemin vers RCE » = « aucun chemin identifié dans la couverture analysée »** — pas une
  preuve d'absence ; le rapport doit l'expliciter.

## 8. Robustesse & cas limites

- Repo vide / pas de code → indiqué.
- Stack non supportée → **fallback heuristique** source/sink, « couverture limitée ».
- Très gros repo → priorisation non-auth + plafonnement (4 agents, budget 12) ; surplus « non analysé ».
- Sous-agent en échec / sortie invalide non récupérée → **lacune notée** (§6.5), pas de crash.

## 9. Validation (critères d'acceptation)

- **`claude plugin validate . --strict`** passe.
- **`claude --plugin-dir .`** : `/oswe:audit` déclenche le skill ; il **ne se lance pas
  automatiquement** (`disable-model-invocation: true`).
- **Fixtures par stack, positives ET négatives** :
  - *positive* : **détection** + **chaîne** RCE reconstruite (ex PHP : type juggling → bypass auth →
    upload non filtré → RCE) ;
  - *négative* : **aucun finding critique faux positif**.
- Les sorties d'agents **valident contre les JSON Schema** ; la **couverture** liste analysé vs ignoré.

## 10. Livraison par phases

Skill, agents, schémas et format de rapport sont **stack-agnostiques** et complets dès le MVP.
Seules **références** et **fixtures** sont échelonnées :

- **Phase 1 (MVP)** : PHP + Node.js.
- **Phase 2** : Python, puis Java, puis .NET.

## 11. Hors périmètre (YAGNI)

- Analyse **statique** uniquement (pas d'exécution d'exploits).
- Pas de CI/CD pour l'instant.
- Pas de stacks hors des 5 ciblées (fallback heuristique).
- Pas de patch automatique (remédiations proposées seulement).
- **Pas d'audit de dépôts non fiables / hostiles** (§2).
