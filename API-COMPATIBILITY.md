# API Compatibility Report - Client/Server

## ❌ Incohérences détectées

### 1. Recommendation.title (CRITIQUE)

**Problème:** Le client attend un champ `title` que le serveur ne fournit pas.

**Client** (`bqaudit/src/bqaudit/api/models.py:143`):
```python
class Recommendation(BaseModel):
    type: str
    priority: str
    title: str  # ← REQUIS
    description: str
    savings_eur: float
    implementation_steps: List[str]
```

**Server** (`bqaudit-server/src/api/models/recommendation.py:49`):
```python
class Recommendation(BaseModel):
    type: RecommendationType
    priority: Priority
    # MANQUE: title
    description: str
    savings_eur: float
    implementation_steps: list[str]
```

**Impact:** Client crashera à la désérialisation avec erreur Pydantic validation.

**Solution:**
- Option A: Rendre `title` optionnel côté client
- Option B: Ajouter `title` côté serveur (généré depuis début de description)

---

### 2. AuditResponse.new_ephemeral_token (RÉSOLU)

**Problème:** Le serveur ne retourne pas le nouveau token.

**Client** (`bqaudit/src/bqaudit/api/models.py:172`):
```python
class AuditResponse(BaseModel):
    recommendations: List[Recommendation]
    summary: AuditSummary
    audit_id: str
    new_ephemeral_token: Optional[str] = Field(default=None)  # ← OPTIONNEL
```

**Server** (`bqaudit-server/src/api/models/audit_response.py:45`):
```python
class AuditResponse(BaseModel):
    recommendations: list[Recommendation]
    summary: AuditSummary
    audit_id: str
    # MANQUE: new_ephemeral_token
```

**Statut:** ⚠️ Temporairement résolu - Client utilise mock renewal quand field absent
**TODO:** Serveur doit populer ce champ (voir `bqaudit-server/TODO.md`)

---

### 3. Types stricts vs loose (OK)

**Client:** Utilise `str` pour flexibilité
```python
type: str
priority: str
```

**Server:** Utilise types stricts pour validation
```python
type: RecommendationType  # Literal["storage", "partitioning", ...]
priority: Priority  # Enum(HIGH, MEDIUM, LOW)
```

**Impact:** ✅ Pas de problème - les strings sont compatibles avec les Enum/Literal côté client

---

## 🚨 Action requise immédiate

### Client ne peut pas désérialiser les recommendations du serveur

Le client va crasher avec:
```
ValidationError: 1 validation error for Recommendation
title
  Field required
```

**Test rapide:**
```bash
curl -X POST https://bqaudit-server-evyc2k5v5a-ew.a.run.app/v1/audit \
  -H "Content-Type: application/json" \
  -H "X-Ephemeral-Token: test-valid-token-x" \
  -d '{"project_id":"'$(python3 -c "print('a'*64)")'", "metadata": {"tables": [{"size_bytes": 10000000000, "time_partitioning_type": null}], "queries": []}}'
```

Si la réponse contient des recommendations sans `title`, le client crashera.

---

## Recommandations

1. **Urgent:** Rendre `title` optionnel côté client OU l'ajouter côté serveur
2. **Normal:** Implémenter `new_ephemeral_token` côté serveur (déjà dans TODO)
3. **Nice-to-have:** Aligner les types (str vs Enum) pour cohérence
