# Plugin OSWE / White-Box — Design (v7.1)

**Date :** 2026-06-15
**Statut :** Approuvé — plan d'implémentation détaillé dans `docs/superpowers/plans/`
**Approche :** C (skill orchestrateur → sous-agents analyseurs parallèles + vérificateur)
**Cible Claude Code :** 2.1.177+ · **Node.js ≥ 20** (prérequis dur)

## 1. Objectif

Plugin Claude Code réalisant un **audit white-box de sécurité applicative web style
OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Python, Java, .NET ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE),
  sous **contrats de données validés par un validateur déterministe** (§6) ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** dans `.oswe/reports/` ;
- passage à l'échelle via **analyseurs parallèles plafonnés** + **vérificateur** indépendant **batché**.

**Cadre :** audit white-box **autorisé**, à visée **défensive** (identifier pour corriger).

## 2. Frontière de confiance (v1)

- Les sous-agents personnalisés **chargent le(s) `CLAUDE.md` du workspace comme instructions** :
  **accepté**, car le workspace doit être fiable.
- **Commentaires, README, chaînes, fichiers métier** = **données non fiables** : pas de directive suivie.
- **Audit de dépôts hostiles : hors périmètre v1.**
- Les deux sous-agents sont en **lecture seule** (§3).

## 3. Architecture

Le repo `E:\claude-oswe` est la racine du plugin (`name: oswe`).

```
claude-oswe/
├── .claude-plugin/
│   └── plugin.json
├── agents/
│   ├── oswe-analyzer.md         # analyse une partition (read-only)
│   └── oswe-verifier.md         # re-dérive findings/chaînes critiques (read-only)
├── skills/
│   └── audit/
│       ├── SKILL.md             # cœur : déclencheur /oswe:audit + méthodologie + orchestration
│       ├── schemas/             # JSON Schema faisant foi
│       │   ├── analyzer-response.schema.json   # enveloppe analyseur { partition_id, status, findings[], coverage }
│       │   ├── verifier-response.schema.json    # enveloppe vérificateur { status, verdicts[] }
│       │   ├── finding.schema.json
│       │   ├── final-finding.schema.json        # finding post-orchestration (provenance + sévérité finale requises)
│       │   ├── chain.schema.json
│       │   └── verdict.schema.json
│       ├── scripts/
│       │   ├── validate-output.mjs             # CLI : parse une réponse + valide via validators.mjs
│       │   ├── confine-path.mjs                 # confinement de périmètre déterministe (realpath, anti symlink)
│       │   ├── aggregate-findings.mjs           # dédup/fusion/numérotation OSWE-N indépendante de l'ordre
│       │   ├── apply-verdicts.mjs               # application des verdicts + liaison batch + promotion Critique + journal
│       │   ├── validate-batch.mjs               # CLI du contrat bound-batch (pré-retry §6)
│       │   ├── validators.mjs                  # AJV standalone PRÉCOMPILÉ (autonome, en-tête licence MIT ajv)
│       │   ├── build-validators.mjs            # (dev) régénère validators.mjs depuis schemas/
│       │   ├── package.json                    # (dev) manifeste devDependencies (ajv, esbuild) pour régénérer
│       │   └── test/                            # node:test : validate-output, confine-path, aggregate-findings, apply-verdicts
│       └── references/
│           ├── php.md   ├── node.md   ├── python.md   ├── java.md   └── dotnet.md
├── test-fixtures/
│   ├── php/{vulnerable,safe}/
│   └── node/{vulnerable,safe}/
├── docs/
└── README.md
```

> **Pas de `commands/`** : le skill est invocable `/oswe:audit` (convergence 2.1.177).
> **Dev local :** `claude --plugin-dir .`.
> **`SKILL.md` frontmatter `disable-model-invocation: true`** : audit déclenché **uniquement** sur
> `/oswe:audit` explicite (jamais auto-lancé).

**Responsabilités par unité :**

- **`skills/audit/SKILL.md`** — cœur : déclencheur, méthodologie, orchestration (§4), agrégation,
  **appel du validateur** sur chaque réponse d'agent et sur les chaînes construites (§6.5).
- **`skills/audit/schemas/*.json`** — JSON Schema **faisant foi** (exemples de §6 illustratifs).
- **`skills/audit/scripts/`** — **validateur autonome, zéro dépendance runtime** : `build-validators.mjs`
  (dev only) génère le code **standalone AJV** des schémas puis **inline le seul helper runtime
  référencé** (`ucs2length`) → `validators.mjs` est un fichier ESM sans aucun `import`/`require`, qui
  tourne **sans `node_modules`** (vérifié : la suite de tests passe avec `node_modules` retiré). Committé
  **avec l'en-tête de licence MIT d'ajv**. Pas de bundler (pas d'esbuild). Le **`scripts/package.json`
  (dev)** déclare une seule `devDependency` (`ajv`), nécessaire **uniquement pour régénérer**
  `validators.mjs` — pas à l'exécution. `validate-output.mjs` parse une réponse d'agent/une chaîne et
  appelle ces validateurs → `valid` / liste d'erreurs. **Node.js (≥ 20) est un prérequis dur** : le
  confinement, la validation et l'application des verdicts reposent tous sur des helpers Node sans repli
  cohérent. L'orchestrateur **vérifie `node --version` au démarrage** et **abandonne** si Node est
  absent ou trop ancien (pas d'audit dégradé en mode texte).
- **`agents/oswe-analyzer.md`** — analyse **une partition**, renvoie l'**enveloppe §6.1** en
  **JSON brut uniquement (sans bloc Markdown ni texte hors JSON)**. `tools: Read, Grep, Glob`.
- **`agents/oswe-verifier.md`** — vérificateur indépendant, renvoie l'**enveloppe §6.3** (« JSON brut »),
  read-only.

## 4. Flux d'exécution (ordre strict)

1. **Entrée & recon** — normalisation de `$ARGUMENTS` via **chemin canonique réel** (realpath) ;
   **refus** si inexistant ou hors `${CLAUDE_PROJECT_DIR}` (comparaison canonique → bloque
   symlink/junction). Détection stack/framework. **Exclusions du balayage massif** (`vendor/`,
   `node_modules/`, `dist/`, `build/`, `out/`, `target/`, `bin/`, `obj/`, minifiés/générés) **mais
   lisibles ponctuellement** pour une gadget chain ; **lockfiles parsés** pour les versions.
   Cartographie de la surface.
2. **Partition & priorisation** — par **module / framework / frontière d'auth**, priorisées par
   exposition **non authentifiée**.
3. **Analyse** — par partition, **source → sink**. Findings (§6.1) avec
   **`provisional_severity` (jamais Critique)** et **`verification_status: not-requested`** par défaut.
   - **Petit repo** (≤ **2 partitions**) → **en ligne, sans sous-agents *analyseurs***.
   - Sinon → **dispatch parallèle** d'`oswe-analyzer`, **max 4 concurrents**, **budget 12 partitions**.
   - **Chaque enveloppe analyseur est validée** (§6.5) avant agrégation.
4. **Agrégation & dédoublonnage** — **IDs canoniques globaux**, dédoublonnage (clé §6.4), fusion en
   peuplant `partitions[]`.
5. **Construction des chaînes candidates** — l'orchestrateur assemble les **chaînes** (§6.2) ;
   **chaque chaîne est validée contre `chain.schema.json`** (§6.5).
6. **Vérification (batchée)** — `oswe-verifier` reçoit : **tous les findings d'une chaîne candidate**,
   **tous les findings provisoirement `Haute`**, **la (les) chaîne(s) complète(s)**.
   **Batching** : **≤ 5 findings OU 1 chaîne complète par invocation**, **max 2 vérificateurs
   concurrents**. Chaque invocation renvoie l'**enveloppe `verifier-response`** (§6.4), **validée**
   (§6.5). On met à jour le **`verification_status`** de chaque finding **et chaîne** ciblé
   (`accepted|downgraded|rejected`) ; les cibles non soumises restent `not-requested`. La sévérité
   **`Critique` n'est attribuée ici** qu'à une chaîne **validée** (toutes transitions `accepted`).
   Un `rejected` part en **annexe** (§7).
7. **Rapport** — résumé chat **et** rapport complet dans `.oswe/reports/`.

## 5. Modèle de sévérité

| Niveau | Critère |
|--------|---------|
| **Critique** | Chaîne **RCE non authentifié**, **preuve statique forte** bout en bout, **validée** (§4.6). |
| **Haute** | Impact majeur nécessitant auth ou prérequis notable (RCE authentifié, SQLi sensible, désérialisation contrôlée). |
| **Moyenne** | Impact limité / conditions notables (SSRF restreinte, XSS stocké, IDOR). |
| **Basse** | Impact mineur ou exploitabilité douteuse. |
| **Info** | Durcissement, pas de vuln directe. |

**Confiance** : `preuve statique forte` · `probable` · `à vérifier`.

## 6. Contrats de données

> Blocs **illustratifs** ; les **JSON Schema de `skills/audit/schemas/` font foi**, le **validateur les applique**.

### 6.1 Enveloppe analyseur (`analyzer-response.schema.json`)

`{ partition_id, status: "ok"|"partial"|"error", findings: Finding[], coverage: { analyzed: string[], skipped: [{ path, reason }] } }`

> **Invariant analyseur** : dans cette enveloppe, chaque finding **doit** porter
> `verification_status: "not-requested"` (valeur `const` au niveau de l'enveloppe analyseur) — la
> vérification n'a pas encore eu lieu. Les autres valeurs n'apparaissent qu'après §4.6.

**Finding** (`finding.schema.json`) — champs :
- `finding_id` : **deux formats admis** — partition-scopé `^.+-F\d{3,}$` (sortie analyseur) **ou**
  canonique `^OSWE-\d+$` (après agrégation). Le schéma autorise explicitement les deux.
- `partition_id`, `title`, `vuln_class` (vocabulaire **ouvert**, `other`),
- `source`/`sink` = `{ file, line, symbol, kind }`, `auth` (`unauthenticated|authenticated|admin`),
- `transformations[]`, `sanitizers[] = { file, line, what, why_insufficient }`,
- `prerequisites[]`, `evidence[] = { file, line }`,
- `provisional_severity` (`Haute|Moyenne|Basse|Info` — **jamais Critique**),
- `confidence` (`preuve statique forte|probable|à vérifier`),
- `verification_status` (`not-requested|accepted|downgraded|rejected`),
- **`partitions[]` : FACULTATIF** (absent dans la réponse initiale de l'analyseur ; **peuplé à la
  fusion**, §6.4 — donc sa présence n'est exigée qu'après agrégation).

### 6.2 Chaîne (`chain.schema.json`, construite par l'orchestrateur)

`chain_id` (`CHAIN-<n>`), `entry_point { file, line, route, auth }`, `finding_ids[]` (canoniques,
ordre d'exploitation), `transitions[] { from, to, how, evidence[] }`,
`final_impact` (`unauth-rce|auth-rce|account-takeover|data-exfiltration|...`),
`severity`, `confidence`, **`verification_status` (`not-requested|accepted|downgraded|rejected`)**.

> **Invariant Critique** (encodé en JSON Schema, `if/then`) : `severity: "Critique"` **implique**
> `verification_status: "accepted"` **ET** `confidence: "preuve statique forte"` **ET**
> `final_impact: "unauth-rce"`. Une chaîne ne peut être Critique sans satisfaire les trois.

### 6.3 Enveloppe vérificateur (`verifier-response.schema.json`)

`{ status: "ok"|"partial"|"error", verdicts: Verdict[] }` — une invocation batchée renvoie **plusieurs**
verdicts.

### 6.4 Verdict & dédoublonnage

**Verdict** (`verdict.schema.json`) : `target_type` (`finding|chain`), `target_id`, `verdict`
(`accepted|downgraded|rejected`), `new_severity`/`new_confidence` (si `downgraded`),
`transition_verdicts[]` (**requis si `chain`** : `{ from, to, verdict, justification }`),
`justification` (avec `fichier:ligne`). Un `rejected` → **annexe** (§7), jamais supprimé en silence.

**Dédoublonnage inter-partitions** : clé = `vuln_class` + source canonique + sink canonique,
chaque objet sur **`{ file, symbol, line, kind }`** (inclure **`line` et `kind`** évite de fusionner
deux flux distincts dans la même fonction). **Sans `partition_id`.** Fusion → peuple `partitions[]` et
conserve la liste des `finding_id` sources.

**Règle de chaîne** : `preuve statique forte` **seulement si chaque transition** est `accepted`,
sinon **rétrogradée** (`probable`/`à vérifier`).

### 6.5 Validation des sorties (déterministe)

- Les agents émettent du **JSON brut uniquement** (pas de bloc Markdown, pas de texte hors JSON).
- L'orchestrateur passe **chaque `analyzer-response`, chaque `verifier-response`, et chaque chaîne
  construite** à **`validate-output.mjs`** (validateurs AJV précompilés).
- Les décisions sensibles à l'ordre ou aux invariants sont déléguées à des **helpers Node
  déterministes et testés**, jamais reconstituées en prose : `confine-path.mjs` (confinement),
  `aggregate-findings.mjs` (dédoublonnage/fusion/numérotation `OSWE-N` indépendante de l'ordre),
  `apply-verdicts.mjs` (liaison batch↔réponse, promotion `Critique`, journal `decisions` des rejets).
- **Sortie non conforme** → **une nouvelle tentative** ; échec persistant → **lacune de couverture**
  (§7), **jamais inventée**. (Node ≥ 20 étant un prérequis vérifié au démarrage, il n'y a pas de
  mode dégradé : sans Node l'audit a déjà abandonné.)

## 7. Format du rapport

Fichier : `${CLAUDE_PROJECT_DIR}/.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md` (**relatif racine projet**).

- **En-tête** : cible, stack + framework, date, périmètre, rappel d'autorisation.
- **Résumé exécutif** : compte par sévérité + **verdict**.
- **Chaînes d'exploitation** : étape par étape (§6.2) avec `verification_status`, preuve par transition.
- **Findings détaillés** : un bloc par vuln (§6.1) avec sévérité, confiance, **`verification_status`**.
- **Couverture** : analysé vs **ignoré + raison** (budget, exclusion, hors périmètre, stack non
  supportée, échec d'agent, lacune de validation §6.5, batch verifier neutralisé).
- **Annexe « Findings écartés »** : les `rejected`, avec justification.
- **Résumé chat** : verdict, chaînes RCE, top critiques, couverture.

**Sécurité du rapport :**

- **Aucun fragment de secret** : remplacé par **`[REDACTED]`** ; seul `fichier:ligne` indiqué.
- **« Aucun chemin vers RCE » = « aucun chemin identifié dans la couverture analysée »** (pas une
  preuve d'absence) — explicité dans le rapport.

## 8. Robustesse & cas limites

- Repo vide → indiqué. Stack non supportée → fallback heuristique « couverture limitée ».
- Très gros repo → priorisation non-auth + plafonnement (4 analyseurs / 2 vérificateurs, budget 12).
- Sous-agent en échec / sortie invalide non récupérée → **lacune notée** (§6.5), pas de crash.

## 9. Validation (critères d'acceptation)

- **`claude plugin validate . --strict`** passe.
- **`claude --plugin-dir .`** : `/oswe:audit` déclenche le skill ; **pas d'auto-lancement**
  (`disable-model-invocation: true`).
- **`validate-output.mjs`** : tests unitaires acceptant les enveloppes `analyzer-response` et
  `verifier-response` conformes et rejetant les malformées (fixtures JSON valides/invalides).
- **Fixtures par stack, positives ET négatives** :
  - *positive* : **détection** + **chaîne** RCE reconstruite (ex PHP : type juggling → bypass auth →
    upload non filtré → RCE) ;
  - *négative* : **aucun finding critique faux positif**.
- Chaque finding **et chaîne** du rapport porte un **`verification_status`** ; la **couverture** liste
  analysé vs ignoré.

## 10. Livraison par phases

Skill, agents, schémas, validateur et format de rapport **stack-agnostiques** et complets dès le MVP.
Seules **références** et **fixtures** échelonnées :

- **Phase 1 (MVP)** : PHP + Node.js.
- **Phase 2** : Python, puis Java, puis .NET.

## 11. Hors périmètre (YAGNI)

- Analyse **statique** uniquement. Pas de CI/CD. Pas de stacks hors des 5 (fallback heuristique).
- Pas de patch automatique. **Pas d'audit de dépôts non fiables / hostiles** (§2).
