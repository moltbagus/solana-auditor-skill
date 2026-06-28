# Audit-on-Push GitHub Actions Template

Execute auditoria de seguranca automatica em cada push e PR.

## Como adicionar a qualquer repositorio Anchor

1. Copie `.github/workflows/audit-on-push.yml` para seu repositorio
2. Adicione `ANTHROPIC_API_KEY` nos secrets do repositorio (Settings > Secrets > Actions)
3. Deduze — a auditoria executa automaticamente

## O que faz

- Executa `/audit-quick` em cada push e PR
- Verifica se existem descobertas CRITICAL
- Bloqueia o merge se encontrar vulnerabilidades CRITICAL
- Faz upload dos resultados para GitHub Security tab (SARIF)
- Disponibiliza relatorio como artifact

## Configuracao

### Variaveis de ambiente
| Variavel | Necessaria | Descricao |
|----------|------------|-----------|
| ANTHROPIC_API_KEY | Sim | Chave da API Anthropic |

### Parametros ajustaveis
- `branches`: Quais branches disparam a auditoria
- `python-version`: Versao do Python (default: 3.9)
- `audit-quick`: Troque para `/audit` para auditoria completa

## Exemplo de saida

```
[1/3] Reconhecimento... OK
[2/3] Analise estatica... OK (50 regras aplicadas)
[3/3] Triagem... OK

Resumo:
  CRITICAL: 0
  HIGH: 1
  MEDIUM: 3

AUDIT PASSED — Nenhuma descoberta CRITICAL
```

## Limites

- Necessita `ANTHROPIC_API_KEY` (custo de API)
- Para auditoria completa (Phase 3 formal verification), use `/audit` ao inves de `/audit-quick`
- PoC exploits nao sao gerados automaticamente (consentimento necessario)