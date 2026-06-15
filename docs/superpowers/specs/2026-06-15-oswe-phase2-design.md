# Plugin OSWE — Phase 2 (Python / Java / .NET) — Design

**Date :** 2026-06-15
**Statut :** Approuvé (brainstorming) — prêt pour plan d'implémentation
**Base :** MVP mergé sur `master` (PHP + Node). Phase 2 sur `feat/oswe-phase2`.

## 1. Objectif

Étendre la couverture d'audit du plugin `oswe` à **Python, Java et .NET**, en suivant le pattern
établi par le MVP. **Quasi-additif** : pas de changement des **schémas, helpers Node ni contrats**
(déjà stack-agnostiques) ; **une clarification minimale du SKILL** (multi-stack, §2.1) ; et la **mise à
jour des docs/manifest user-facing** qui annoncent encore PHP/Node comme seul périmètre.

**Vérifié dans le MVP mergé :**
- `skills/audit/SKILL.md` §1 charge les références **génériquement** : « Load … `references/<ecosystem>.md`
  for the detected stack » (aucun `php`/`node` en dur).
- La détection de stack liste déjà `pyproject.toml`/`requirements.txt`, `pom.xml`/`build.gradle`,
  `*.csproj`. Python/Java/.NET sont donc **déjà détectés** ; il manque les références, les fixtures, la
  règle multi-stack, et les mises à jour de docs.

## 2. Périmètre

**Ajouts :**

```
skills/audit/references/{python,java,dotnet}.md        # NOUVEAU (3 références)
test-fixtures/{python,java,dotnet}/{vulnerable,safe}/  # NOUVEAU (6 fixtures + 3 EXPECTED.md)
```

**Modifications (nécessaires pour que le plugin soit cohérent après Phase 2) :**
- `skills/audit/SKILL.md` — **une** clarification : règle multi-stack (§2.1 ci-dessous).
- `.claude-plugin/plugin.json` — la `description` dit encore « (PHP, Node.js in MVP) » → ajouter
  Python/Java/.NET.
- `README.md` — la section *Scope* dit « Python, Java, .NET are planned (Phase 2) » → les passer en
  **supportés**.
- `docs/superpowers/plans/2026-06-15-oswe-plugin-mvp.md` / spec MVP — la mention « Phase 2 (separate
  plan) » est résolue par ce travail ; mettre une note de renvoi vers ce spec (cosmétique, non bloquant).

**Hors périmètre :** aucune modif de `schemas/`, `scripts/` ; pas de fixture de désérialisation à vraie
gadget-chain (libs dans des dossiers exclus du scan) — la référence documente ce savoir, la fixture
utilise une variante auto-suffisante.

### 2.1 Règle multi-stack (clarification SKILL)

Aujourd'hui `SKILL.md` §1 dit « Load only the relevant `references/<ecosystem>.md` » (singulier). Un
vrai dépôt peut être **polyglotte** (ex. backend Java + frontend Node). La règle devient :

> Detect **all** stacks present (a repo may be polyglot). **Load every relevant
> `references/<ecosystem>.md`** for the detected stacks. The partition phase (§2) already separates the
> surface by module / framework — **partition by stack too**, so each partition is analyzed against its
> own stack's reference.

C'est la **seule** modification de comportement du SKILL ; elle est cohérente avec le découpage par
module/framework déjà en place.

## 3. Références (docs de connaissances)

Même structure que `php.md` / `node.md` : **Sources** (entrées contrôlables) ; **Sinks dangereux par
classe** ; **frontières d'authentification** du framework ; **sanitizers et pourquoi ils échouent**.
Couverture signature **complète** par stack (même si la fixture n'utilise qu'une variante).

- **`python.md`** — Sources : Flask (`request.args/form/json/cookies/headers`, `request.values`),
  Django (`request.GET/POST/body`, `request.META`). Sinks : **SSTI** (`render_template_string`,
  `Template().render`, Jinja2 sans autoescape) ; **désérialisation** (`pickle.loads`,
  `yaml.load` non-safe, `marshal`) ; **command injection** (`os.system`, `subprocess` `shell=True`,
  `os.popen`) ; **code eval** (`eval`, `exec`, `compile`) ; **SQLi** (concat dans `cursor.execute`,
  `.raw()`, f-strings) ; **SSRF** (`requests`/`urllib` sur URL attaquant) ; **path traversal** (`open`,
  `send_file` avec chemin attaquant). Frontières : décorateurs `@login_required`, vérifs `session`,
  Flask `SECRET_KEY` faible/hardcodé → cookie de session forgeable. Sanitizers : `markupsafe.escape`
  (XSS, pas SSTI/RCE), `shlex.quote` (et son absence), allow-list vs `os.path.basename`.

- **`java.md`** — Sources : Spring (`@RequestParam`, `@RequestBody`, `@PathVariable`,
  `@RequestHeader`, `@CookieValue`, `HttpServletRequest`). Sinks : **désérialisation Java**
  (`ObjectInputStream.readObject` sur données attaquant, gadget chains connues — documenté, lire
  `vendor/` à la demande pour prouver) ; **injection SpEL/EL** (`SpelExpressionParser.parseExpression`,
  `@Value` dynamique) ; **command injection** (`Runtime.exec`, `ProcessBuilder` construit par concat) ;
  **SQLi** (concat JDBC, `@Query` natif concaténé) ; **XXE** (`DocumentBuilderFactory`/`SAXParser` sans
  `disallow-doctype-decl`) ; **SSRF** (`RestTemplate`/`HttpClient` sur hôte attaquant) ; **path
  traversal**. Frontières : `@PreAuthorize`/`@Secured`, config `SecurityFilterChain`, en-têtes de proxy
  de confiance mal validés. Sanitizers : encodage HTML (pas SpEL/exec), requêtes paramétrées.

- **`dotnet.md`** — Sources : ASP.NET (`Request.Query/Form/Body`, `Request.Cookies`, `Request.Headers`,
  binding de modèle, `[FromBody]`). Sinks : **désérialisation** (`BinaryFormatter.Deserialize`,
  Json.NET `TypeNameHandling.All/Auto`, `JavaScriptSerializer` avec resolver, gadgets) ; **command
  injection** (`Process.Start` avec `cmd /c`/`bash -c` concaténé) ; **SQLi** (concat dans
  `SqlCommand`, EF `FromSqlRaw`) ; **XXE** (`XmlDocument`/`XmlReader` avec `DtdProcessing.Parse`) ;
  **SSRF** (`HttpClient`/`WebRequest`) ; **path traversal**. Frontières : `[Authorize]`,
  middleware d'auth, cookies/claims non signés ou contrôlés client. Sanitizers : encodage de sortie,
  requêtes paramétrées, `XmlResolver=null`.

## 4. Fixtures vulnérables (chaîne 2 étapes unauth → RCE = Critique)

Chaque app est **auto-suffisante, mono-fichier** (pas de lib gadget externe), et expose une chaîne
**non authentifiée → bypass → RCE**, comme PHP (magic-hash → upload) et Node (NoSQLi → cmd-injection).

> **Toutes les fixtures sont *static-only*** : le plugin ne les exécute ni ne les compile (analyse
> statique du source uniquement). Elles n'ont **pas** besoin d'être **exécutables ni déployables** (ni
> serveur qui démarre, ni config de build complète) ; mais le source doit être **syntaxiquement valide**
> — vérifié quand l'outil local existe (ex. `python -m py_compile` si Python est dispo ; Java/.NET par
> inspection, faute de toolchain ici). La vuln est dans le *pattern* de code, indépendante de l'OS.

- **`python/vulnerable/`** (Flask, `app.py` + `requirements.txt`) :
  - **Étape 1 — bypass (broken access control / mass assignment)** : `POST /login` lit le JSON du
    corps et fait confiance à un champ client `is_admin` qu'il copie dans la session
    (`session['admin'] = body.get('is_admin')`). Un attaquant non authentifié envoie
    `{"user":"x","is_admin":true}` → session admin.
  - **Étape 2 — RCE (SSTI Jinja2)** : `GET/POST /render`, gardé par `session['admin']`, fait
    `render_template_string(request.values['tpl'])`. Payload `{{ ''.__class__.__mro__[1].__subclasses__()… }}`
    → exécution. Chaîne : unauth → `is_admin:true` → SSTI → **RCE**.

- **`java/vulnerable/`** (Spring Boot, un `@RestController` + `pom.xml`) :
  - **Étape 1 — bypass (en-tête de confiance)** : l'autorisation lit l'en-tête `X-User-Role` sans le
    valider (`if ("admin".equals(request.getHeader("X-User-Role")))`). Un attaquant fixe
    `X-User-Role: admin`.
  - **Étape 2 — RCE (injection SpEL)** : route admin évalue
    `new SpelExpressionParser().parseExpression(req.getParameter("q")).getValue()`. Payload
    `T(java.lang.Runtime).getRuntime().exec(...)` → RCE. Chaîne : unauth → header forgé → SpEL → **RCE**.

- **`dotnet/vulnerable/`** (ASP.NET minimal API ou controller, `Program.cs`/`*.cs` + `*.csproj`) :
  - **Étape 1 — bypass (cookie forgeable)** : l'autorisation ne vérifie que
    `Request.Cookies["admin"] == "1"` (valeur contrôlée par le client, non signée). L'attaquant pose
    le cookie `admin=1`.
  - **Étape 2 — RCE (command injection)** : route admin construit une commande shell par concaténation
    et l'exécute via `Process.Start` (`"/bin/sh","-c", "ping -c 1 " + host"` — invocation **Unix-style**,
    pas `cmd.exe`/Windows-only) ; l'entrée `Request.Query["host"]` n'est ni échappée ni validée. Payload
    `host=127.0.0.1; whoami` → RCE. Chaîne : unauth → cookie forgé → command injection → **RCE**. (Les
    fixtures n'étant jamais exécutées, l'OS hôte est indifférent : la vuln est la concaténation non
    assainie dans une invocation shell, repérée **statiquement** ; fixture static-only.)

## 5. Fixtures safe (contrepartie durcie)

Pour chaque stack, la version qui **mitige correctement les deux maillons** (l'auditeur ne doit produire
**aucun Critique faux-positif**). Les contre-mesures sont des **vérifications explicites en code**,
**non ambiguës à la lecture statique** — on n'emploie **pas** d'annotations (`@PreAuthorize`,
`[Authorize]`) dont l'effet dépend d'une config de sécurité externe absente d'une fixture mono-fichier
(ce serait trompeur). **Aucun secret hardcodé** : en white-box l'auditeur lit le source, donc tout
secret/credential littéral serait lui-même un bypass — les secrets viennent de **l'environnement
uniquement** et l'app **refuse (deny)** s'ils ne sont pas configurés. Toutes static-only.

- **Python safe** : le rôle n'est **jamais** pris du corps client — l'app valide `username/password`
  contre des identifiants lus dans **l'environnement** (`os.environ`, **pas** de valeur littérale ; deny
  si absents) avant de poser la session ; `/render` rend un **template fixe** (l'entrée n'est qu'une
  *donnée* passée au contexte, jamais le template) — pas de `render_template_string` sur l'entrée.
- **Java safe** : l'autorisation **ne lit pas** `X-User-Role` ; **check explicite en code** comparant un
  token d'en-tête à un secret lu dans **l'environnement** (`System.getenv`, deny si absent — **pas** de
  fallback littéral). Le sink SpEL **n'existe pas** : la valeur est traitée comme **donnée littérale**,
  jamais `parseExpression(input)`.
- **.NET safe** : l'autorisation **ne lit pas** un cookie brut ; **check explicite en code** comparant un
  token d'en-tête à un secret lu dans **l'environnement** (`Environment.GetEnvironmentVariable`, deny si
  absent). L'exécution passe par `Process.Start` avec une **liste d'arguments** (`ProcessStartInfo`,
  `UseShellExecute=false`, **sans shell**) + **allow-list** sur `host` (`^[a-z0-9.-]+$`).

## 6. EXPECTED.md (par fixture vulnérable)

Comme le MVP : décrit la chaîne **Critique** attendue, les 2 findings (classe, `fichier:ligne` du
source et du sink) et le parcours unauth → bypass → RCE. Sert de référence au comparatif d'acceptance.

## 7. Manifestes & détection

Chaque fixture porte le manifeste qui déclenche la détection de stack et un marqueur **« DO NOT
DEPLOY »** (traité comme donnée, pas instruction) :
- Python : `requirements.txt` (Flask) — `pyproject.toml` optionnel.
- Java : `pom.xml` (Spring Boot).
- .NET : un `*.csproj` (ASP.NET).

## 8. Validation & acceptance

Mêmes gates que le MVP :
0. **Régression MVP** : `( cd skills/audit/scripts && npm test )` (= `node --test`) reste **88/88**.
   Phase 2 ne touche pas `scripts/`, mais on relance la suite avant merge pour ne pas intégrer un MVP
   cassé par accident.
1. **`claude plugin validate . --strict`** reste vert : la seule édition du SKILL est dans le **corps**
   (règle multi-stack §2.1), **pas le frontmatter** ; le reste n'ajoute que du markdown/source.
2. **Conformité de contenu** des références : marqueurs de classes de vulns présents (grep par stack —
   ex. python : `SSTI`, `pickle`, `subprocess` ; java : `readObject`, `SpelExpressionParser`, `XXE` ;
   dotnet : `BinaryFormatter`/`TypeNameHandling`, `Process.Start`, `XmlResolver`).
3. **Vulns plantées** présentes dans les fixtures vulnérables (grep) et **absentes/mitigées** dans les
   safe (grep des contre-mesures).
4. **Syntaxe** : Python `python -m py_compile` si Python dispo ; sinon, et pour Java/.NET (pas de
   JDK/.NET SDK dans le sandbox), vérification **par inspection** + marqueurs — exactement comme les
   fixtures PHP du MVP (non lintées, faute de PHP).
5. **Acceptance E2E — gate de merge OBLIGATOIRE (pas optionnel).** Phase 2 **n'est pas mergeable** tant
   que les **6 rapports** n'ont pas été produits et comparés : `/oswe:audit` sur chacune des 3
   `vulnerable/` → chaîne **Critique** conforme à son `EXPECTED.md` ; sur chacune des 3 `safe/` →
   **aucun Critique** (zéro faux-positif). L'exécution se fait dans la session interactive de
   l'utilisateur (les `claude -p` imbriqués que l'agent lance sont facturés sur le solde API séparé,
   épuisé — cf. expérience MVP) ; **l'agent fait le comparatif rapport↔EXPECTED pour chacun**. Les 6
   comparatifs verts sont la condition de merge, au même titre que les gates 1–4.

## 9. Hors périmètre (rappel)

- Aucune modif de `schemas/` ni `scripts/` (déjà stack-agnostiques). La **seule** édition de `SKILL.md`
  est la règle multi-stack (§2.1) — pas de changement des contrats ni de la mécanique de vérification.
- Pas de fixture reposant sur une vraie gadget-chain de désérialisation (libs externes exclues du scan).
- Pas d'exécution/compilation des fixtures par le plugin (analyse statique uniquement ; fixtures static-only).
