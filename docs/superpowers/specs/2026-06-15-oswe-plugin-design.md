# Plugin OSWE / White-Box — Design (v2)

**Date :** 2026-06-15
**Statut :** Révisé après revue — en attente d'approbation pour plan d'implémentation
**Approche :** C (commande fine → skill orchestrateur → sous-agents parallèles + vérificateur)

## 1. Objectif

Plugin Claude Code réalisant un **audit white-box de sécurité applicative web style
OSWE / OffSec en profondeur** :

- multi-stack : PHP, Node.js/JS/TS, Python, Java, .NET ;
- **auto-détection** de la stack et de la surface d'attaque (points d'entrée) ;
- recherche de vulnérabilités web **et chaînage vers un RCE non authentifié** (signature OSWE),
  sous **contrat de preuve** (cf. §6) — pas d'affirmation non étayée ;
- sortie double : **résumé dans le chat** + **rapport markdown daté** écrit dans `.oswe/reports/` ;
- passage à l'échelle via **dispatch de sous-agents parallèles** plafonnés + **agent vérificateur** indépendant.

**Cadre :** audit white-box **autorisé**, à visée **défensive** (identifier pour corriger).

## 2. Frontière de confiance (v1)

- L'outil ne s'utilise que sur des **workspaces déjà approuvés et fiables**. Un dépôt hostile
  pourrait contenir des instructions (dans `CLAUDE.md`, commentaires, chaînes, READMEs) visant à
  détourner l'audit.
- **Règle anti-injection** imposée au skill et à tous les sous-agents : tout contenu du dépôt
  audité est traité comme **donnée à analyser**, jamais comme instruction à exécuter. Les agents
  ne suivent pas les directives trouvées dans le code/la doc audités.
- Les sous-agents d'analyse sont en **lecture/recherche seule** (pas d'écriture, pas d'exécution).

## 3. Architecture

Le repo `E:\claude-oswe` est la racine du plugin. (`name: oswe`)

```
claude-oswe/
├── .claude-plugin/
│   ├── plugin.json              # manifeste (name: "oswe", version, description, author)
│   └── marketplace.json         # marketplace de dev pour test local
├── commands/
│   ├── audit.md                 # → /oswe:audit  (canonique ; /audit en court)
│   └── white-box.md             # → /oswe:white-box  (alias strict d'audit)
├── agents/
│   ├── oswe-analyzer.md         # sous-agent d'analyse (read-only, focus sécu)
│   └── oswe-verifier.md         # sous-agent indépendant : re-dérive les findings/chaînes critiques
├── skills/
│   └── audit/
│       ├── SKILL.md             # méthodologie + orchestration (cœur unique)
│       └── references/          # connaissances par écosystème (organisées par framework à l'intérieur)
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

**Responsabilités par unité :**

- **`commands/audit.md`** — point d'entrée fin. Passe `$ARGUMENTS` (chemin optionnel) et invoque
  le skill `audit`. **`commands/white-box.md`** est un alias strict (même corps).
- **`skills/audit/SKILL.md`** — **cœur unique** : méthodologie complète + orchestration des phases.
  Ne charge en contexte que le(s) `references/<écosystème>.md` pertinent(s) à la stack détectée.
- **`skills/audit/references/*.md`** — un fichier par écosystème, organisé **par framework** :
  sources (entrées contrôlables), sinks dangereux, sanitizers courants, gadget/POP chains, patterns.
- **`agents/oswe-analyzer.md`** — sous-agent d'analyse en profondeur d'une partition de la surface
  d'attaque ; renvoie des findings au **format de preuve** (§6). Read-only.
- **`agents/oswe-verifier.md`** — sous-agent **indépendant** qui re-vérifie chaque finding critique
  et chaque chaîne RCE en re-dérivant les maillons à partir du source, pour réduire les hallucinations.

## 4. Flux d'exécution

1. **Recon & auto-détection** — stack via manifestes (`composer.json`, `package.json`,
   `pyproject.toml`/`requirements.txt`, `pom.xml`/`build.gradle`, `*.csproj`) + extensions ;
   framework via dépendances/structure. Cartographie de la surface : routes, contrôleurs, handlers,
   désérialisation, uploads, exécutions de commandes, accès fichiers. `/oswe:audit src/api` restreint
   le périmètre.
2. **Partition & priorisation** — la surface est découpée **par module / framework / frontière
   d'authentification** (pas « un agent par route » : ça duplique les middlewares et rate les
   interactions inter-routes). Partitions **priorisées par exposition à la surface non authentifiée**.
3. **Analyse** — par partition : traçage **source → sink** (donnée attaquant → sink dangereux).
   - Repo conséquent → **dispatch parallèle** d'`oswe-analyzer`, **max 4 concurrents**, sous un
     **budget de surfaces** (plafond de partitions analysées en profondeur) ; le reste est consigné
     comme « non analysé » dans le registre de couverture.
   - Petit repo → analyse **en ligne**.
4. **Vérification** — chaque finding critique et chaque chaîne candidate vers RCE passe par
   **`oswe-verifier`** : une chaîne n'est marquée **« preuve statique forte »** que si **chaque
   transition** est étayée (cf. §6). Sinon → « probable » ou « à vérifier ».
5. **Chaînage & agrégation** — dédoublonnage, construction des chaînes d'exploitation vers RCE
   non-auth, assemblage du **registre de couverture** (analysé / ignoré + raison).
6. **Sortie** — résumé (verdict + chaînes + top critiques + couverture) dans le chat **et** rapport
   complet dans `.oswe/reports/`.

## 5. Modèle de sévérité (critères explicites)

| Niveau | Critère |
|--------|---------|
| **Critique** | Chaîne menant à un **RCE non authentifié** (ou compromission totale équivalente) avec **preuve statique forte** de bout en bout. |
| **Haute** | Vuln à impact majeur exploitable mais nécessitant authentification ou prérequis notable (ex : RCE authentifié, SQLi sur données sensibles, désérialisation contrôlée). |
| **Moyenne** | Impact limité ou conditions notables (SSRF restreinte, XSS stocké, IDOR, divulgation ciblée). |
| **Basse** | Faiblesse à impact mineur ou exploitabilité douteuse (fuite d'info, configuration faible). |
| **Info** | Observation de durcissement, pas de vulnérabilité directe. |

**Confiance** (remplace « confirmé », l'exécution dynamique étant hors périmètre) :
`preuve statique forte` · `probable` · `à vérifier`.

## 6. Contrat de preuve (par finding)

Tout finding **doit** renseigner :

- **Entrée (source)** + **état d'authentification** requis pour l'atteindre ;
- **Transformations** subies par la donnée ;
- **Validations / sanitizers** rencontrés, et **pourquoi insuffisants** ;
- **Sink** + **classe** de vulnérabilité ;
- **Prérequis** d'exploitation ;
- **Références `fichier:ligne`** pour chaque maillon.

**Règle de chaîne :** une chaîne vers RCE n'est annoncée comme exploitable (`preuve statique forte`)
que si **chaque transition** est supportée par les éléments ci-dessus, après passage par `oswe-verifier`.
À défaut, elle est présentée comme hypothétique (`à vérifier`).

## 7. Format du rapport

Fichier : `.oswe/reports/oswe-report-YYYY-MM-DD-HHMM.md`.

- **En-tête** : cible, stack + framework détectés, date, périmètre, rappel d'autorisation.
- **Résumé exécutif** : compte par sévérité + **verdict** (chemin RCE non-auth trouvé ? niveau de preuve).
- **Chaînes d'exploitation** (section phare) : chaque chaîne décrite étape par étape, avec le contrat
  de preuve par maillon (ex : *type juggling login → bypass auth → upload non filtré → RCE*).
- **Findings détaillés** : un bloc par vuln, au **format de preuve** (§6), avec sévérité + confiance.
- **Couverture** : partitions/points d'entrée **analysés**, et zones **ignorées** avec la **raison**
  (budget, hors périmètre, stack non supportée, échec d'un sous-agent).
- **Résumé chat** : verdict, chaînes vers RCE, top critiques, couverture (pas le détail complet).

## 8. Robustesse & cas limites

- Repo vide / pas de code → le rapport l'indique.
- Stack inconnue / non supportée → **fallback heuristique** générique source/sink, mention
  « couverture limitée », consignée dans la section Couverture.
- Très gros repo → priorisation non-auth + plafonnement (max 4 agents, budget de surfaces) ;
  le surplus apparaît dans la couverture comme « non analysé ».
- Sous-agent en échec / sans retour → **lacune notée** dans la couverture, pas de crash.

## 9. Validation (critères d'acceptation)

- `claude plugin validate .` passe (syntaxe des manifestes). *(`--strict` ajouté si confirmé supporté
  à l'implémentation.)*
- Le plugin se charge : `/oswe:audit` et `/oswe:white-box` apparaissent, le skill `audit` s'invoque.
- **Fixtures par stack, positives ET négatives :**
  - *positive* (vulnérable) : le plugin **détecte** la/les vuln(s) plantée(s) et **reconstruit la
    chaîne** vers RCE dans le rapport (ex PHP : bypass auth par type juggling → upload non filtré → RCE) ;
  - *négative* (sûre) : le plugin **ne produit pas** de finding critique faux positif (la version
    corrigée ne déclenche pas la chaîne).
- Le registre de couverture liste correctement analysé vs ignoré.

## 10. Livraison par phases (MVP → complet)

Commande, skill, agents et format de rapport sont **stack-agnostiques** et livrés complets dès le MVP.
Seules les **références** et **fixtures** sont échelonnées :

- **Phase 1 (MVP crédible)** : PHP + Node.js (références + fixtures positives/négatives).
- **Phase 2** : Python, puis Java, puis .NET.

## 11. Hors périmètre (YAGNI)

- Pas d'analyse dynamique / exécution réelle d'exploits — **analyse statique** du source uniquement.
- Pas d'intégration CI/CD pour l'instant.
- Pas de support de stacks hors des 5 ciblées (fallback heuristique seulement).
- Pas de correction automatique du code audité (le rapport propose des remédiations, il ne patche pas).
