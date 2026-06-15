# Plugin OSWE / White-Box — Design (v3)

**Date :** 2026-06-15
**Statut :** Révisé (2e tour) — en attente d'approbation pour plan d'implémentation
**Approche :** C (commande fine → skill orchestrateur → sous-agents parallèles + vérificateur)
**Cible Claude Code :** 2.1.177+

## 1. Objectif

Plugin Claude Code réalisant un **audit white-box de sécurité applicative web style
OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Python, Java, .NET ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE),
  sous **contrat de preuve** (§6) — pas d'affirmation non étayée ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** dans `.oswe/reports/` ;
- passage à l'échelle via **sous-agents parallèles plafonnés** + **agent vérificateur** indépendant.

**Cadre :** audit white-box **autorisé**, à visée **défensive** (identifier pour corriger).

## 2. Frontière de confiance (v1)

Le plugin présume un **workspace fiable**. Conséquences techniques honnêtes :

- Les sous-agents personnalisés **chargent le(s) `CLAUDE.md` du workspace comme instructions** :
  on ne peut donc pas les neutraliser en « données ». Ces instructions sont **acceptées**,
  précisément parce que le workspace doit être fiable.
- En revanche, **commentaires, README, chaînes de caractères et fichiers métier** du dépôt audité
  restent des **données non fiables** : l'analyse ne suit pas d'éventuelles « directives » qui y
  seraient cachées.
- **L'audit de dépôts réellement hostiles est hors périmètre v1.**
- Les deux sous-agents sont en **lecture seule** (cf. allowlist d'outils, §3).

## 3. Architecture

Le repo `E:\claude-oswe` est la racine du plugin. (`name: oswe`)

```
claude-oswe/
├── .claude-plugin/
│   └── plugin.json              # manifeste (name: "oswe", version, description, author)
├── commands/
│   └── audit.md                 # → /oswe:audit  (unique commande canonique)
├── agents/
│   ├── oswe-analyzer.md         # analyse une partition (read-only)
│   └── oswe-verifier.md         # re-dérive findings/chaînes critiques (read-only)
├── skills/
│   └── audit/
│       ├── SKILL.md             # méthodologie + orchestration (cœur unique)
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

> **Commande unique :** on ne documente que **`/oswe:audit`**. Le préfixe court (`/audit`) n'est
> pas garanti pour une commande de plugin (dépend des collisions) → on ne s'appuie pas dessus.
> Pas d'alias `white-box` : un seul nom canonique évite toute ambiguïté.

> **Dev local :** `claude --plugin-dir .` (pas de `marketplace.json` au MVP).

**Responsabilités par unité :**

- **`commands/audit.md`** — point d'entrée fin : passe `$ARGUMENTS` (chemin optionnel) et invoque
  le skill `audit`.
- **`skills/audit/SKILL.md`** — **cœur unique** : méthodologie + orchestration. Ne charge en
  contexte que le(s) `references/<écosystème>.md` pertinent(s) à la stack détectée.
- **`skills/audit/references/*.md`** — un fichier par écosystème, organisé **par framework** :
  sources, sinks, sanitizers courants, gadget/POP chains, patterns.
- **`agents/oswe-analyzer.md`** — analyse en profondeur d'**une partition** ; renvoie des findings
  au **format JSON inter-agents** (§6). Frontmatter **`tools: Read, Grep, Glob`** (read-only ;
  sans `tools`, un agent custom hériterait de tous les outils, écriture/exécution comprises).
- **`agents/oswe-verifier.md`** — vérificateur **indépendant** : re-dérive chaque finding/chaîne
  critique depuis le source et rend un **verdict** (§6). Mêmes outils read-only.

## 4. Flux d'exécution

1. **Recon & auto-détection** — stack via manifestes (`composer.json`, `package.json`,
   `pyproject.toml`/`requirements.txt`, `pom.xml`/`build.gradle`, `*.csproj`) + extensions ;
   framework via dépendances/structure. **Exclusions** du périmètre d'analyse : `vendor/`,
   `node_modules/`, `dist/`, `build/`, `out/`, `target/`, `bin/`, `obj/`, fichiers minifiés/générés,
   lockfiles (mentionnés dans la Couverture, pas analysés en profondeur). Cartographie de la
   surface : routes, contrôleurs, handlers, désérialisation, uploads, exécutions de commandes,
   accès fichiers. `/oswe:audit src/api` restreint le périmètre.
2. **Partition & priorisation** — surface découpée **par module / framework / frontière
   d'authentification** (pas « un agent par route » : duplique les middlewares, rate les
   interactions inter-routes). Partitions **priorisées par exposition à la surface non authentifiée**.
3. **Analyse** — par partition : traçage **source → sink**.
   - **Petit repo** (≤ **2 partitions**) → analyse **en ligne**, sans sous-agents.
   - Sinon → **dispatch parallèle** d'`oswe-analyzer`, **max 4 agents concurrents**, **budget = 12
     partitions** analysées en profondeur ; au-delà → consigné « non analysé » dans la Couverture.
4. **Vérification** — chaque finding **critique** et chaque chaîne candidate vers RCE passe par
   **`oswe-verifier`**, qui rend `accepted` / `downgraded` / `rejected` avec justification (§6).
   Une chaîne incomplète est **rétrogradée** en `probable` ou `à vérifier` selon le maillon manquant.
5. **Chaînage & agrégation** — dédoublonnage (clé : `partition_id` + sink + source), construction
   des chaînes vers RCE non-auth à partir des JSON, assemblage du **registre de couverture**.
6. **Sortie** — résumé (verdict + chaînes + top critiques + couverture) dans le chat **et** rapport
   complet dans `.oswe/reports/`.

## 5. Modèle de sévérité (critères explicites)

| Niveau | Critère |
|--------|---------|
| **Critique** | Chaîne menant à un **RCE non authentifié** (ou compromission totale équivalente) avec **preuve statique forte** de bout en bout. |
| **Haute** | Impact majeur exploitable nécessitant authentification ou prérequis notable (RCE authentifié, SQLi sur données sensibles, désérialisation contrôlée). |
| **Moyenne** | Impact limité ou conditions notables (SSRF restreinte, XSS stocké, IDOR, divulgation ciblée). |
| **Basse** | Impact mineur ou exploitabilité douteuse (fuite d'info, configuration faible). |
| **Info** | Observation de durcissement, pas de vulnérabilité directe. |

**Confiance** (l'exécution dynamique étant hors périmètre) :
`preuve statique forte` · `probable` · `à vérifier`.

## 6. Contrats de données

### 6.1 Format JSON inter-agents (sortie d'`oswe-analyzer`)

Chaque finding est un objet **strictement** structuré (pour permettre dédoublonnage et agrégation) :

```json
{
  "finding_id": "OSWE-<n>",
  "partition_id": "<id de partition>",
  "title": "<titre court>",
  "vuln_class": "deserialization | sqli | ssti | ssrf | xxe | auth-bypass | file-upload | cmd-injection | ...",
  "source": "<entrée contrôlable + fichier:ligne>",
  "auth": "unauthenticated | authenticated | admin",
  "transformations": ["<étape + fichier:ligne>", "..."],
  "sanitizers": [{"what": "<sanitizer rencontré>", "why_insufficient": "<raison>"}],
  "sink": "<sink dangereux + fichier:ligne>",
  "prerequisites": ["<prérequis d'exploitation>", "..."],
  "evidence": ["fichier:ligne", "..."],
  "severity": "Critique | Haute | Moyenne | Basse | Info",
  "confidence": "preuve statique forte | probable | à vérifier"
}
```

Les **chaînes** sont structurées comme une liste ordonnée de `finding_id` + description des transitions.

### 6.2 Verdict du vérificateur (sortie d'`oswe-verifier`)

```json
{
  "finding_id": "OSWE-<n>",
  "verdict": "accepted | downgraded | rejected",
  "new_severity": "<si downgraded>",
  "new_confidence": "<si downgraded>",
  "justification": "<pourquoi, avec fichier:ligne>"
}
```

### 6.3 Règle de chaîne

Une chaîne vers RCE n'est annoncée comme exploitable (`preuve statique forte`) que si **chaque
transition** est étayée par les champs ci-dessus **et** acceptée par `oswe-verifier`. Sinon elle est
**rétrogradée** en `probable` ou `à vérifier` (jamais affirmée).

## 7. Format du rapport

Fichier : `.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md`.

- **En-tête** : cible, stack + framework détectés, date, périmètre, rappel d'autorisation.
- **Résumé exécutif** : compte par sévérité + **verdict**.
- **Chaînes d'exploitation** : chaque chaîne étape par étape, avec le contrat de preuve par maillon.
- **Findings détaillés** : un bloc par vuln (dérivé du JSON §6.1), sévérité + confiance + verdict.
- **Couverture** : partitions/points d'entrée **analysés**, et zones **ignorées** + **raison**
  (budget, exclusion, hors périmètre, stack non supportée, échec d'un sous-agent).
- **Résumé chat** : verdict, chaînes vers RCE, top critiques, couverture (pas le détail complet).

**Sécurité du rapport :**

- **Aucun secret complet** n'est écrit (clés/mots de passe/tokens découverts → **rédactés**,
  p. ex. `fichier:ligne` + 4 derniers caractères, jamais la valeur entière).
- **« Aucun chemin vers RCE trouvé » signifie uniquement « aucun chemin identifié dans la couverture
  analysée »** — ce n'est pas une preuve d'absence de vulnérabilité. La formulation du rapport doit
  l'expliciter.

## 8. Robustesse & cas limites

- Repo vide / pas de code → indiqué dans le rapport.
- Stack inconnue / non supportée → **fallback heuristique** générique source/sink, mention
  « couverture limitée » dans la Couverture.
- Très gros repo → priorisation non-auth + plafonnement (4 agents, budget 12 partitions) ;
  surplus → « non analysé » dans la Couverture.
- Sous-agent en échec / sans retour → **lacune notée** dans la Couverture, pas de crash.

## 9. Validation (critères d'acceptation)

- **`claude plugin validate . --strict`** passe (warnings traités comme erreurs ; confirmé supporté
  en 2.1.177).
- Chargement via **`claude --plugin-dir .`** : `/oswe:audit` apparaît, le skill `audit` s'invoque.
- **Fixtures par stack, positives ET négatives :**
  - *positive* (vulnérable) : le plugin **détecte** la/les vuln(s) et **reconstruit la chaîne** vers
    RCE (ex PHP : bypass auth par type juggling → upload non filtré → RCE) ;
  - *négative* (sûre) : **aucun finding critique faux positif** sur la version corrigée.
- Le registre de **couverture** liste correctement analysé vs ignoré.

## 10. Livraison par phases (MVP → complet)

Commande, skill, agents et format de rapport sont **stack-agnostiques** et livrés complets dès le MVP.
Seules les **références** et **fixtures** sont échelonnées :

- **Phase 1 (MVP crédible)** : PHP + Node.js (références + fixtures positives/négatives).
- **Phase 2** : Python, puis Java, puis .NET.

## 11. Hors périmètre (YAGNI)

- Pas d'analyse dynamique / exécution réelle d'exploits — **analyse statique** uniquement.
- Pas d'intégration CI/CD pour l'instant.
- Pas de support de stacks hors des 5 ciblées (fallback heuristique seulement).
- Pas de correction automatique du code audité (remédiations proposées, pas de patch).
- **Pas d'audit de dépôts non fiables / hostiles** (cf. §2).
