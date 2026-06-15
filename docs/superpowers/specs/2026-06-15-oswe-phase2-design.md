# Plugin OSWE — Phase 2 (Python / Java / .NET) — Design

**Date :** 2026-06-15
**Statut :** Approuvé (brainstorming) — prêt pour plan d'implémentation
**Base :** MVP mergé sur `master` (PHP + Node). Phase 2 sur `feat/oswe-phase2`.

## 1. Objectif

Étendre la couverture d'audit du plugin `oswe` à **Python, Java et .NET**, en suivant le pattern
établi par le MVP. **Purement additif** : aucune modification du SKILL, des schémas, des helpers Node
ni des contrats — ils sont déjà stack-agnostiques.

**Vérifié dans le MVP mergé :**
- `skills/audit/SKILL.md` §1 charge les références **génériquement** : « Load only the relevant
  `references/<ecosystem>.md` for the detected stack » (aucun `php`/`node` en dur).
- La détection de stack liste déjà `pyproject.toml`/`requirements.txt`, `pom.xml`/`build.gradle`,
  `*.csproj`. Python/Java/.NET sont donc **déjà détectés** ; il manque seulement les références et les
  fixtures.

Donc Phase 2 = ajouter des **fichiers**, rien d'autre. Le plugin charge la nouvelle référence dès qu'il
détecte le stack.

## 2. Périmètre

Ajouts uniquement :

```
skills/audit/references/
├── python.md            # NOUVEAU
├── java.md              # NOUVEAU
└── dotnet.md            # NOUVEAU

test-fixtures/
├── python/{vulnerable,safe}/   # NOUVEAU (Flask)
├── java/{vulnerable,safe}/     # NOUVEAU (Spring)
└── dotnet/{vulnerable,safe}/   # NOUVEAU (ASP.NET)
```

Chaque dossier `vulnerable/` contient un `EXPECTED.md` décrivant la chaîne Critique attendue.

**Hors périmètre :** aucune modif de `SKILL.md`, `schemas/`, `scripts/` ; pas de fixture de
désérialisation à vraie gadget-chain (dépendrait de libs dans des dossiers exclus du scan) — la
référence documente ce savoir, la fixture utilise une variante auto-suffisante.

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
  - **Étape 2 — RCE (command injection)** : route admin fait
    `Process.Start("cmd.exe", "/c ping " + Request.Query["host"])`. Payload `host=127.0.0.1 & whoami`
    → RCE. Chaîne : unauth → cookie forgé → command injection → **RCE**.

## 5. Fixtures safe (contrepartie durcie)

Pour chaque stack, la version qui **mitige correctement les deux maillons** (l'auditeur ne doit produire
**aucun Critique faux-positif**) :

- **Python safe** : autorisation côté serveur (le rôle n'est jamais pris du corps client ; auth par
  identifiants validés) ; `/render` rendu via un **template fixe** avec autoescape (jamais
  `render_template_string` sur l'entrée).
- **Java safe** : autorisation via `@PreAuthorize`/contexte de sécurité réel (pas l'en-tête client) ;
  pas de SpEL construit depuis l'entrée (valeur traitée comme donnée littérale, ou allow-list stricte).
- **.NET safe** : autorisation via `[Authorize]` / cookie d'auth **signé** (pas une valeur client
  brute) ; exécution via `Process.Start` avec **liste d'arguments** (sans shell) + allow-list sur
  `host` (`^[a-z0-9.-]+$`).

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
1. **`claude plugin validate . --strict`** reste vert (on n'ajoute que du markdown/source ; pas de
   frontmatter de skill/agent modifié).
2. **Conformité de contenu** des références : marqueurs de classes de vulns présents (grep par stack —
   ex. python : `SSTI`, `pickle`, `subprocess` ; java : `readObject`, `SpelExpressionParser`, `XXE` ;
   dotnet : `BinaryFormatter`/`TypeNameHandling`, `Process.Start`, `XmlResolver`).
3. **Vulns plantées** présentes dans les fixtures vulnérables (grep) et **absentes/mitigées** dans les
   safe (grep des contre-mesures).
4. **Syntaxe** : Python `python -m py_compile` si Python dispo ; sinon, et pour Java/.NET (pas de
   JDK/.NET SDK dans le sandbox), vérification **par inspection** + marqueurs — exactement comme les
   fixtures PHP du MVP (non lintées, faute de PHP).
5. **Acceptance E2E** (lancée par l'utilisateur dans sa session) : `/oswe:audit` sur chaque
   `vulnerable/` → chaîne **Critique** conforme à `EXPECTED.md` ; sur chaque `safe/` → **aucun
   Critique**. Comparatif des rapports comme pour PHP/Node.

## 9. Hors périmètre (rappel)

- Aucune modif de `SKILL.md`, `schemas/`, `scripts/` (vérifié inutile — déjà stack-agnostiques).
- Pas de fixture reposant sur une vraie gadget-chain de désérialisation (libs externes exclues du scan).
- Pas d'exécution/compilation des fixtures par le plugin (analyse statique uniquement).
