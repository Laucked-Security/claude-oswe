# Plugin OSWE / White-Box — Design

**Date :** 2026-06-15
**Statut :** Approuvé (brainstorming) — prêt pour plan d'implémentation

## 1. Objectif

Plugin Claude Code déclenché par `/oswe` (alias `/white-box`) réalisant un **audit
white-box de sécurité applicative web style OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Java/.NET, Python ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE) ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** écrit sur disque ;
- passage à l'échelle via **dispatch de sous-agents parallèles** (approche C).

Cadre : audit white-box **autorisé**, à visée **défensive** (identifier et corriger).

## 2. Architecture

Le repo `E:\claude-oswe` est la racine du plugin.

```
claude-oswe/
├── .claude-plugin/
│   └── plugin.json              # manifeste (nom, version, description, author)
├── commands/
│   ├── oswe.md                  # /oswe  [chemin optionnel]
│   └── white-box.md             # /white-box → alias, même comportement
├── agents/
│   └── oswe-auditor.md          # sous-agent spécialisé (contexte isolé, focus sécu)
├── skills/
│   └── oswe-audit/
│       ├── SKILL.md             # méthodologie + orchestration
│       └── references/
│           ├── php.md           # type juggling, POP chains, LFI/RFI…
│           ├── node.md          # prototype pollution, NoSQLi, cmd injection…
│           ├── java-dotnet.md   # désérialisation, gadget chains, XXE, EL injection…
│           └── python.md        # pickle, SSTI (Jinja/Flask), désérialisation…
├── test-fixtures/               # mini-app volontairement vulnérable (validation E2E)
└── README.md
```

**Responsabilités par unité :**

- **`commands/oswe.md` & `commands/white-box.md`** — points d'entrée fins. Ne contiennent
  que le déclencheur, l'argument de chemin optionnel (`$ARGUMENTS`) et l'invocation du
  skill `oswe-audit`. `white-box.md` est un alias strict de `oswe.md`.
- **`skills/oswe-audit/SKILL.md`** — porte la méthodologie complète et orchestre les phases.
  Ne charge en contexte que le(s) fichier(s) `references/<langage>.md` pertinents à la
  stack détectée.
- **`skills/oswe-audit/references/*.md`** — bases de connaissances par langage : sources
  (entrées contrôlables), sinks dangereux, gadget/POP chains, patterns de vuln spécifiques.
- **`agents/oswe-auditor.md`** — sous-agent au system prompt orienté sécurité, dispatché en
  parallèle (un par point d'entrée) pour analyser en profondeur et renvoyer des findings
  structurés. Outils en lecture/recherche uniquement (pas d'écriture/exécution).

## 3. Flux d'exécution

1. **Recon & auto-détection** — identifie la stack (fichiers manifestes : `composer.json`,
   `package.json`, `pom.xml`/`*.csproj`, `requirements.txt`/`pyproject.toml` ; extensions de
   fichiers) et cartographie la surface d'attaque : routes, contrôleurs, handlers de
   requêtes, points de désérialisation, uploads, exécutions de commandes, accès fichiers.
   Un chemin passé en argument (`/oswe src/api`) restreint le périmètre.
2. **Décomposition** — produit la liste des points d'entrée, **priorisés par exposition à la
   surface non authentifiée** (reachability depuis un attaquant anonyme).
3. **Analyse** — pour chaque point d'entrée : traçage **source → sink** (données contrôlées
   par l'attaquant jusqu'au sink dangereux), identification des vulns, évaluation de
   l'exploitabilité.
   - Repo conséquent / plusieurs points d'entrée → **dispatch parallèle** de sous-agents
     `oswe-auditor`, **par batch plafonné** (limite de concurrence pour maîtriser le coût) ;
   - petit repo (seuil ~1 point d'entrée ou peu de fichiers) → analyse **en ligne**, sans
     sous-agents.
4. **Chaînage** — agrégation des findings, dédoublonnage, puis construction de **chaînes
   d'exploitation** combinant plusieurs vulns vers un **RCE non authentifié**.
5. **Sortie** — résumé (verdict + chaînes + top findings critiques) dans le chat **et**
   rapport complet écrit sur disque.

## 4. Format du rapport & modèle de sévérité

Fichier : `oswe-report-YYYY-MM-DD-HHMM.md` (racine du repo, ou dossier ciblé).

- **En-tête** : cible, stack détectée, date, périmètre audité, rappel d'autorisation.
- **Résumé exécutif** : compte des findings par sévérité + **verdict** (un chemin vers RCE
  non-auth a-t-il été trouvé ?).
- **Chaînes d'exploitation** (section phare) : chaque chaîne décrite étape par étape,
  bout-à-bout (ex : *type juggling sur le login → bypass auth → upload non filtré → RCE*).
- **Findings détaillés**, un bloc par vuln :
  - ID, titre, **classe** (SQLi, désérialisation, SSTI, SSRF, XXE…),
  - **sévérité** : Critique / Haute / Moyenne / Basse / Info,
  - **confiance** : confirmé / probable / à vérifier,
  - `fichier:ligne`, **flux de données taintées** (source → sink),
  - **exploitation** (étapes / esquisse de PoC), **remédiation**.
- **Résumé chat** : verdict, chaînes vers RCE, top des findings critiques (pas le détail complet).

## 5. Robustesse & cas limites

- Repo vide / pas de code → le rapport l'indique explicitement.
- Stack inconnue / non supportée → **fallback heuristique** générique source/sink, avec
  mention « couverture limitée ».
- Très gros repo → **priorisation** par accessibilité depuis la surface non-auth +
  **plafonnement** du nombre de sous-agents concurrents.
- Sous-agent qui échoue ou ne renvoie rien → la **lacune est notée** dans le rapport, pas de crash.

## 6. Éthique

La méthodologie pose en préambule que l'audit est white-box **autorisé** (code possédé ou
dont le test est permis), à visée **défensive** : l'objectif final est d'identifier les vulns
**pour les corriger**.

## 7. Validation (test de bout-en-bout)

Dossier `test-fixtures/` : mini-app volontairement vulnérable (ex : bypass d'authentification
par type juggling PHP menant à un upload non filtré → RCE). On lance `/oswe test-fixtures/`
et on vérifie que le plugin :

1. **se charge** (commandes visibles, skill invoqué) ;
2. **détecte** la/les vuln(s) plantée(s) ;
3. **reconstruit la chaîne** vers RCE dans le rapport.

## 8. Hors périmètre (YAGNI)

- Pas d'analyse dynamique / exécution réelle d'exploits — analyse statique du source uniquement.
- Pas d'intégration CI/CD pour l'instant.
- Pas de support de stacks hors des 4 ciblées (fallback heuristique seulement).
