# Guia de Auditoria Solana em Portugues Brasileiro

Audite programas Solana como um profissional de seguranca. Este guia explica tudo em portugues.

---

## 1. O que faz

O **Solana Auditor Skill** transforma o Claude Code em um auditor de seguranca completo para programas Solana. Ele cobre:

| Fase | O que faz |
|------|-----------|
| **Fase 0** | Safety Guard — checagens pre-voo |
| **Fase 1** | Reconhecimento — superficie de ataque |
| **Fase 2** | Analise Estatica (SAST) — 45 regras de seguranca |
| **Fase 3** | Verificacao Formal — provas QED 2A |
| **Fase 4** | Triagem de Findings — classificacao CVSS |
| **Fase 5** | Geracao de Relatorio — markdown + JSON |
| **Fase 6** | Remediation — orientacao de correcao |

### Regras de seguranca

- **45 regras Solana** cobrindo Anchor, Token-2022, CPI, overflow, access control
- **5 regras de seguranca do agente** (consent gate, scope boundary, audit trail)
- **50 regras no total**

### Comandos disponiveis

```
/audit <repo>         # Auditoria completa (7 fases)
/audit-quick <repo>   # Varredura rapida SAST (~5 min)
/audit-resume <repo>  # Retomar auditoria interrompida
/audit-report         # Gerar relatorio final
/audit-poc <finding>  # Gerar PoC de exploit (precisa consentimento)
/audit-findings       # Listar/gerenciar findings
/audit-fix            # Gerar sugestoes de correcao inline
/audit-pr             # Revisar PRs abertos
/audit-history        # Gerenciar historico de auditorias
```

---

## 2. Como instalar

### Instalacao automatica (recomendada)

```bash
cd solana-auditor-skill
./install.sh -y
```

O instalador copia:
- **Arquivos do skill** -> `~/.claude/skills/solana-auditor-skill/`
- **Comandos slash (9)** -> `~/.claude/commands/`
- **Regras de path-scope** -> `~/.claude/rules/`
- **Configs de agentes** -> `~/.claude/skills/solana-auditor-skill/agents/`
- **CLAUDE.md** -> `~/.claude/skills/solana-auditor-skill/`

### Instalacao manual

```bash
mkdir -p ~/.claude/skills/solana-auditor-skill
cp -r skill/ ~/.claude/skills/solana-auditor-skill/
cp CLAUDE.md ~/.claude/skills/solana-auditor-skill/
mkdir -p ~/.claude/commands ~/.claude/rules
cp commands/*.md ~/.claude/commands/
cp rules/*.rules ~/.claude/rules/
```

---

## 3. Como usar

### Varredura rapida (primeiro contato)

Quando voce recebe um novo repo ou PR pela primeira vez:

```
/audit-quick https://github.com/usuario/programa-solana
```

Isso executa:
- Phase 0 Safety Guard
- Varredura SAST heuristica (~5 minutos)
- Output: `findings.json` com findings de HIGH/CRITICAL

### Auditoria completa (producao)

Para uma auditoria de producao real:

```
/audit https://github.com/usuario/programa-solana
```

Isso executa todas as 7 fases, incluindo:
- Verificacao formal QED 2A
- Classificacao CVSS completa
- Geracao de relatorio

### Gerar relatorio final

Apos a auditoria, gere o relatorio:

```
/audit-report
```

Output:
- `AUDIT_REPORT.md` (markdown formatado)
- `findings.json` (dados estruturados)

### Corrigir vulnerabilidades

Apos identificar findings, gere sugestoes de correcao:

```
/audit-fix
```

---

## 4. Exemplo completo (audit step-by-step)

### Passo 1: Clone o repo a ser auditado

```bash
git clone https://github.com/usuario/programa-solana
cd programa-solana
```

### Passo 2: Inicie a auditoria rapida

```
/audit-quick .
```

O auditor vai:
1. Executar Phase 0 Safety Guard
2. Escanear todos os arquivos `.rs` em `programs/`
3. Aplicar as 45 regras de seguranca
4. Gerar `findings.json`

### Passo 3: Revise os findings

```bash
cat findings.json | python3 -m json.tool
```

### Passo 4: Se encontrar issues, faca auditoria completa

```
/audit .
```

### Passo 5: Gere o relatorio

```
/audit-report
```

### Passo 6: Abra o dashboard HTML

```bash
python3 scripts/dashboard.py findings.json /tmp/audit_dashboard.html
open /tmp/audit_dashboard.html
```

---

## 5. Entendendo os resultados (findings.json explained)

O arquivo `findings.json` e a saida principal da auditoria. Cada finding segue esta estrutura:

```json
{
  "id": "CRIT-01",
  "title": "Acao admin sem assinatura via invoke",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cwe": "CWE-306",
  "rule": "Rule 8 — Signer Verification",
  "file": "programs/vault/src/lib.rs",
  "line": 42,
  "description": "A instrucao `admin_withdraw` chama `invoke` sem verificar `ctx.accounts.admin.is_signer`.",
  "impact": "Dreno completo do cofre do programa se a chave admin for comprometida.",
  "remediation": "Adicionar `require!(ctx.accounts.admin.is_signer)`",
  "poc_status": "pending"
}
```

### Campos explicados

| Campo | Significado |
|-------|-------------|
| `id` | Identificador unico (ex: CRIT-01, HIGH-02) |
| `title` | Titulo curto do finding |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `cvss` | Pontuacao CVSS 3.1 (0-10) |
| `cvss_vector` | Vetor CVSS completo (verificavel matematicamente) |
| `cwe` | CWE (Common Weakness Enumeration) |
| `rule` | Qual regra do audit.rules detectou |
| `file` | Arquivo onde o finding foi encontrado |
| `line` | Linha especifica |
| `description` | Explicacao detalhada |
| `impact` | Impacto se exploitado |
| `remediation` | Como corrigir |
| `poc_status` | Status do PoC (pending, generated, verified) |

### Escala de severidade

| Nivel | Significado |
|-------|-------------|
| **CRITICAL** | Perda total de fundos ou bypass de autoridade |
| **HIGH** | Perda significativa ou falha logica major |
| **MEDIUM** | Perda indireta ou violacao moderada |
| **LOW** | Issue menor, sem caminho de perda direto |
| **INFO** | Documentacao ou qualidade de codigo |

---

## 6. Corrigindo vulnerabilidades (fix workflow)

### Fluxo de remediao

```
1. Revise os findings (sorted by severity)
       |
       v
2. Para cada CRITICAL/HIGH, gere fix suggestions
       |
       v
3. Aplique as correcoes sugeridas
       |
       v
4. Re-escaneie com /audit-quick
       |
       v
5. Verifique que findings foram resolvidos
       |
       v
6. Gere relatorio final com /audit-report
```

### Gerar sugestoes de correcao

```
/audit-fix
```

O auditor vai:
1. Para cada finding CRITICAL/HIGH
2. Analisar o codigo vulneravel
3. Propor correcao especifica
4. Incluir codigo seguro como exemplo

### Exemplo de remediao

**Finding:** `admin_withdraw` sem verificacao de signer

**Codigo vulneravel:**
```rust
pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // VULNERAVEL: Nao verifica se admin e signer
    let dest = &mut ctx.accounts.destination;
    **dest.lamports.borrow_mut() += amount;
    Ok(())
}
```

**Correcao sugerida:**
```rust
pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
    // CORRIGIDO: Verifica assinatura do admin
    require!(ctx.accounts.admin.is_signer, ErrorCode::Unauthorized);
    let dest = &mut ctx.accounts.destination;
    **dest.lamports.borrow_mut() += amount;
    Ok(())
}
```

### Validacao

Apos aplicar correcoes, re-escaneie:

```
/audit-quick .
```

Verifique que o finding nao aparece mais.

---

## 7. Dashboard HTML (como abrir e ler)

### Gerar o dashboard

```bash
python3 scripts/dashboard.py findings.json /tmp/audit_dashboard.html
```

### Abrir no navegador

```bash
open /tmp/audit_dashboard.html
# ou
xdg-open /tmp/audit_dashboard.html  # Linux
```

### O que o dashboard mostra

O dashboard HTML interativo inclui:

| Secao | O que mostra |
|-------|-------------|
| **Resumo** | Total de findings por severidade |
| **Grafico de barras** | Distribuicao CRITICAL/HIGH/MEDIUM/LOW/INFO |
| **Mapa CWE** | Mapeamento para Common Weakness Enumeration |
| **Score medio CVSS** | Media ponderada de severidade |
| **Lista de findings** | Todos os findings com links para o codigo |

### Lendo o dashboard

1. **Verifique o total de CRITICALs primeiro** — esses precisam ser corrigidos antes de qualquer outra coisa
2. **Confira o score medio CVSS** — acima de 8.0 indica risco alto
3. **Olhe o mapa CWE** — identifica categorias de vulnerabilidades mais frequentes
4. **Use a lista de findings** — clique para ver detalhes de cada issue

### Exemplo de leitura

```
Dashboard Summary:
- CRITICAL: 2
- HIGH: 5
- MEDIUM: 12
- LOW: 8
- INFO: 3
- Average CVSS: 7.2
- Top CWE: CWE-306 (Missing Authentication)
```

**Interpretacao:** 2 finding CRITICAL e score medio 7.2 indicam programa de alto risco. Foco nos CWE-306 primeiro.

---

## Referencias

- Documentacao completa: [README.md](../../README.md)
- Verificacao de integridade: [VERIFICATION.md](../../VERIFICATION.md)
- Especificacao tecnica: [SPEC.md](../../spec.md)
- Glossario de seguranca (EN + PT-BR): [skill/00-terminology.md](../../skill/00-terminology.md)

---

## Suporte

Para duvidas ou problemas:
1. Verifique se a instalacao foi bem-sucedida: `ls ~/.claude/skills/solana-auditor-skill/`
2. Teste a integridade: `bash tests/test-skill-integrity.sh`
3. Execute o demo: `bash demo.sh`

---

**Autor:** Superteam Brasil, 2026
**Licenca:** MIT