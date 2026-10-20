# Análise Estatística - Teste de McNemar

**Data da Análise**: 2026-10-19 23:04:58

## Metodologia

- **Teste**: McNemar (bicaudal)
- **Nível de significância**: α = 0.05
- **Correção**: Holm-Bonferroni para comparações múltiplas
- **Tamanho de efeito**: Phi coefficient (φ)
  - Pequeno: |φ| < 0.1
  - Médio: 0.1 ≤ |φ| < 0.3
  - Grande: |φ| ≥ 0.3

### Estatística de McNemar

```
χ² = (b - c)² / (b + c)
```

Onde:
- **b**: número de casos classificados corretamente apenas pela configuração 1
- **c**: número de casos classificados corretamente apenas pela configuração 2

### Phi Coefficient (tamanho de efeito)

```
φ = (b - c) / sqrt((b + c) × N)
```

## Configurações de Contexto

- **CO (Code Only)**: Apenas o código da função vulnerável
- **CC (Code + Callees)**: Código da função mais funções chamadas por ela
- **CK (Code + Callers)**: Código da função mais funções que a chamam

## Resultados Detalhados por Modelo

### Gemini 3.0 Flash

#### CO vs CC

**Tamanho amostral**: n = 157

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 1.0000 | 0.9554 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 1.0000 | 0.9554 |
| F1-Score | 1.0000 | 0.9772 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 150 | b = 7 |
| **Config1 Incorreto** | c = 0 | d = 0 |

**Teste de McNemar**:

- χ² = 5.1429
- p-value = 0.0233
- φ = 0.2112 (medium effect size)
- **Significância**: Não significativo (α_corrigido = 0.0056)
- **Melhor configuração**: code (Config 1)

---

#### CO vs CK

**Tamanho amostral**: n = 140

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.9929 | 0.9643 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.9929 | 0.9643 |
| F1-Score | 0.9964 | 0.9818 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 134 | b = 5 |
| **Config1 Incorreto** | c = 1 | d = 0 |

**Teste de McNemar**:

- χ² = 1.5000
- p-value = 0.2207
- φ = 0.1380 (medium effect size)
- **Significância**: Não significativo (α_corrigido = 0.0083)
- **Melhor configuração**: code (Config 1)

---

#### CC vs CK

**Tamanho amostral**: n = 68

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.9559 | 0.9265 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.9559 | 0.9265 |
| F1-Score | 0.9774 | 0.9618 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 63 | b = 2 |
| **Config1 Incorreto** | c = 0 | d = 3 |

**Teste de McNemar**:

- χ² = 0.5000
- p-value = 0.4795
- φ = 0.1715 (medium effect size)
- **Significância**: Não significativo (α_corrigido = 0.0125)
- **Melhor configuração**: code_callees (Config 1)

---

### GPT-4.1 Mini

#### CO vs CC

**Tamanho amostral**: n = 237

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.7384 | 0.5401 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.7384 | 0.5401 |
| F1-Score | 0.8495 | 0.7014 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 123 | b = 52 |
| **Config1 Incorreto** | c = 5 | d = 57 |

**Teste de McNemar**:

- χ² = 37.1228
- p-value = 0.0000
- φ = 0.4044 (large effect size)
- **Significância**: ✓ SIGNIFICATIVO (com correção Holm-Bonferroni, α = 0.0042)
- **Melhor configuração**: code (Config 1)

---

#### CO vs CK

**Tamanho amostral**: n = 221

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.7059 | 0.6923 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.7059 | 0.6923 |
| F1-Score | 0.8276 | 0.8182 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 135 | b = 21 |
| **Config1 Incorreto** | c = 18 | d = 47 |

**Teste de McNemar**:

- χ² = 0.1026
- p-value = 0.7488
- φ = 0.0323 (small effect size)
- **Significância**: Não significativo (α_corrigido = 0.0167)
- **Melhor configuração**: code (Config 1)

---

#### CC vs CK

**Tamanho amostral**: n = 129

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.4651 | 0.6822 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.4651 | 0.6822 |
| F1-Score | 0.6349 | 0.8111 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 58 | b = 2 |
| **Config1 Incorreto** | c = 30 | d = 39 |

**Teste de McNemar**:

- χ² = 22.7812
- p-value = 0.0000
- φ = -0.4358 (large effect size)
- **Significância**: ✓ SIGNIFICATIVO (com correção Holm-Bonferroni, α = 0.0045)
- **Melhor configuração**: code_callers (Config 2)

---

### GPT-5 Mini

#### CO vs CC

**Tamanho amostral**: n = 222

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.8964 | 0.8423 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.8964 | 0.8423 |
| F1-Score | 0.9454 | 0.9144 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 180 | b = 19 |
| **Config1 Incorreto** | c = 7 | d = 16 |

**Teste de McNemar**:

- χ² = 4.6538
- p-value = 0.0310
- φ = 0.1579 (medium effect size)
- **Significância**: Não significativo (α_corrigido = 0.0063)
- **Melhor configuração**: code (Config 1)

---

#### CO vs CK

**Tamanho amostral**: n = 213

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.8779 | 0.7700 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.8779 | 0.7700 |
| F1-Score | 0.9350 | 0.8700 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 157 | b = 30 |
| **Config1 Incorreto** | c = 7 | d = 19 |

**Teste de McNemar**:

- χ² = 13.0811
- p-value = 0.0003
- φ = 0.2591 (medium effect size)
- **Significância**: ✓ SIGNIFICATIVO (com correção Holm-Bonferroni, α = 0.0050)
- **Melhor configuração**: code (Config 1)

---

#### CC vs CK

**Tamanho amostral**: n = 122

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.8361 | 0.7787 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.8361 | 0.7787 |
| F1-Score | 0.9107 | 0.8756 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 89 | b = 13 |
| **Config1 Incorreto** | c = 6 | d = 14 |

**Teste de McNemar**:

- χ² = 1.8947
- p-value = 0.1687
- φ = 0.1454 (medium effect size)
- **Significância**: Não significativo (α_corrigido = 0.0071)
- **Melhor configuração**: code_callees (Config 1)

---

### Claude Haiku 4.5

#### CO vs CC

**Tamanho amostral**: n = 237

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.9916 | 0.9789 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.9916 | 0.9789 |
| F1-Score | 0.9958 | 0.9893 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 230 | b = 5 |
| **Config1 Incorreto** | c = 2 | d = 0 |

**Teste de McNemar**:

- χ² = 0.5714
- p-value = 0.4497
- φ = 0.0737 (small effect size)
- **Significância**: Não significativo (α_corrigido = 0.0100)
- **Melhor configuração**: code (Config 1)

---

#### CO vs CK

**Tamanho amostral**: n = 221

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.9683 | 0.9774 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.9683 | 0.9774 |
| F1-Score | 0.9839 | 0.9886 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 209 | b = 5 |
| **Config1 Incorreto** | c = 7 | d = 0 |

**Teste de McNemar**:

- χ² = 0.0833
- p-value = 0.7728
- φ = -0.0388 (small effect size)
- **Significância**: Não significativo (α_corrigido = 0.0250)
- **Melhor configuração**: code_callers (Config 2)

---

#### CC vs CK

**Tamanho amostral**: n = 129

| Métrica | Config 1 | Config 2 |
|---------|----------|----------|
| Acurácia | 0.9690 | 0.9767 |
| Precisão | 1.0000 | 1.0000 |
| Recall | 0.9690 | 0.9767 |
| F1-Score | 0.9843 | 0.9882 |

**Tabela de Contingência 2×2**:

|  | Config2 Correto | Config2 Incorreto |
|---|---|---|
| **Config1 Correto** | a = 123 | b = 2 |
| **Config1 Incorreto** | c = 3 | d = 1 |

**Teste de McNemar**:

- χ² = 0.0000
- p-value = 1.0000
- φ = -0.0394 (small effect size)
- **Significância**: Não significativo (α_corrigido = 0.0500)
- **Melhor configuração**: code_callers (Config 2)

---

## Tabela Resumo

| Modelo | Comparação | n | χ² | p-value | φ | Efeito | Sig. | Melhor |
|--------|------------|---|-----|---------|---|--------|------|--------|
| Gemini 3.0 Flash | CO vs CC | 157 | 5.143 | 0.0233 | 0.211 | medium |  | code |
| Gemini 3.0 Flash | CO vs CK | 140 | 1.500 | 0.2207 | 0.138 | medium |  | code |
| Gemini 3.0 Flash | CC vs CK | 68 | 0.500 | 0.4795 | 0.171 | medium |  | code_callees |
| GPT-4.1 Mini | CO vs CC | 237 | 37.123 | 0.0000 | 0.404 | large | ✓ | code |
| GPT-4.1 Mini | CO vs CK | 221 | 0.103 | 0.7488 | 0.032 | small |  | code |
| GPT-4.1 Mini | CC vs CK | 129 | 22.781 | 0.0000 | -0.436 | large | ✓ | code_callers |
| GPT-5 Mini | CO vs CC | 222 | 4.654 | 0.0310 | 0.158 | medium |  | code |
| GPT-5 Mini | CO vs CK | 213 | 13.081 | 0.0003 | 0.259 | medium | ✓ | code |
| GPT-5 Mini | CC vs CK | 122 | 1.895 | 0.1687 | 0.145 | medium |  | code_callees |
| Claude Haiku 4.5 | CO vs CC | 237 | 0.571 | 0.4497 | 0.074 | small |  | code |
| Claude Haiku 4.5 | CO vs CK | 221 | 0.083 | 0.7728 | -0.039 | small |  | code_callers |
| Claude Haiku 4.5 | CC vs CK | 129 | 0.000 | 1.0000 | -0.039 | small |  | code_callers |

## Principais Achados

**3 diferença(s) significativa(s) encontrada(s)** (após correção de Holm-Bonferroni):

- **GPT-4.1 Mini** - CO vs CC: code é superior a code_callees (χ² = 37.123, p = 0.0000, φ = 0.404)
- **GPT-4.1 Mini** - CC vs CK: code_callees é inferior a code_callers (χ² = 22.781, p = 0.0000, φ = -0.436)
- **GPT-5 Mini** - CO vs CK: code é superior a code_callers (χ² = 13.081, p = 0.0003, φ = 0.259)
