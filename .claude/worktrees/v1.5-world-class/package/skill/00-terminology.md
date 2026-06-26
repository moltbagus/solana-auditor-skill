# Solana Auditor Terminology

## Anchor
Anchor is a framework for writing Solana programs in Rust. Key concepts:

| Term | Definition | PT-BR (Português) |
|------|------------|-------------------|
| `#[program]` | Marks the module containing instruction handlers | Marca o módulo que contém os handlers de instrução |
| `#[derive(Accounts)]` | Derives `Account` deserialization with constraints | Deriva a desserialização de `Account` com restrições |
| `#[account(...)]` | Macro for account metadata and constraints | Macro para metadados e restrições de conta |
| `Context<T>` | Type containing accounts and program data for an instruction | Tipo que contém contas e dados do programa para uma instrução |
| PDA | Program Derived Address — deterministic address not backed by a private key | Endereço Derivado de Programa — endereço determinístico sem chave privada |
| CPI | Cross-Program Invocation — calling one program from another | Invocação entre Programas — chamar um programa de outro |
| IDL | Interface Definition Language — JSON schema for a program's instructions | Linguagem de Definição de Interface — esquema JSON das instruções |

## Key Constraints / Restrições Principais
| Constraint | What it does | PT-BR |
|------------|-------------|-------|
| `init` | Creates a new account; requires `payer` and `space` | Cria nova conta; requer `payer` e `space` |
| `mut` | Marks account as mutable; Anchor enforces write capability | Marca conta como mutável |
| `signer` | Verifies the account signed the transaction | Verifica se a conta assinou a transação |
| `owner` | Verifies the account is owned by the specified program | Verifica se a conta pertence ao programa especificado |
| `has_one` | Verifies a specific field matches a provided pubkey | Verifica se um campo corresponde a uma pubkey fornecida |
| `bump` | Extracts canonical bump seed for PDA derivation | Extrai o bump canônico para derivação de PDA |
| `seeds` | Defines the seed for PDA derivation | Define a semente para derivação de PDA |
| `executable` | Verifies the account is a program | Verifica se a conta é um programa executável |

## Solana Runtime Terms / Termos de Runtime Solana
| Term | Definition | PT-BR |
|------|-------------|-------|
| sealevel | Solana's parallel transaction execution runtime | Runtime de execução paralela de transações da Solana |
| `invoke` | Low-level CPI — calls another program | CPI de baixo nível — chama outro programa |
| `invoke_signed` | CPI with PDA signing using seeds | CPI com assinatura PDA usando sementes |
| `rent` | Solana's storage rent mechanism (8 bytes per lamport per epoch) | Mecanismo de aluguel de armazenamento Solana |
| `rent_exempt` | Accounts must have enough lamports to be rent-exempt | Contas devem ter lamports suficientes para isenção de aluguel |
| `AccountInfo` | Raw account type in Solana programs | Tipo bruto de conta em programas Solana |
| `RefCell` | Interior mutability wrapper for account data | Wrapper de mutabilidade interior para dados da conta |

## Security Terms / Termos de Segurança
| Term | Definition | PT-BR |
|------|-------------|-------|
| CWE | Common Weakness Enumeration — vulnerability classification | Enumeração Comum de Vulnerabilidades |
| CVSS | Common Vulnerability Scoring System — severity scoring | Sistema Comum de Pontuação de Vulnerabilidades |
| SAST | Static Application Security Testing | Teste Estático de Segurança de Aplicações |
| DAST | Dynamic Application Security Testing | Teste Dinâmico de Segurança de Aplicações |
| PoC | Proof of Concept — exploit demonstration | Prova de Conceito — demonstração de exploração |
| Invariant | A condition that must always hold true | Invariante — condição que deve ser sempre verdadeira |
| FV | Formal Verification — mathematical proof of invariants | Verificação Formal — prova matemática de invariantes |

## Token Extensions (2022) / Extensões de Token
| Extension | Risk | PT-BR |
|-----------|------|-------|
| `metadata_pointer` | Can point to fake metadata; verify mint authority | Pode apontar para metadados falsos; verifique autoridade de mint |
| `mint_close_authority` | Mint can be closed; lock funds unexpectedly | Mint pode ser fechado; bloqueia fundos inesperadamente |
| `transfer_fee` | Fee extracted from transfers; verify accounting | Taxa extraída de transferências; verifique contabilidade |
| `confidential_transfer` | Encrypted amounts; verify fee extraction on settle | Valores criptografados; verifique taxa no settle |
| `interest_bearing` | Rate can be updated; check update authority | Taxa pode ser atualizada; verifique autoridade |

## Severity Ratings / Classificação de Gravidade
| Rating | Meaning | PT-BR |
|--------|---------|-------|
| CRITICAL | Total fund loss or complete authority bypass | Perda total de fundos ou bypass completo de autoridade |
| HIGH | Significant loss or major logic flaw | Perda significativa ou falha lógica grave |
| MEDIUM | Indirect loss or moderate best-practice violation | Perda indireta ou violação moderada de boas práticas |
| LOW | Minor issue, no direct loss path | Problema menor, sem caminho direto de perda |
| INFO | Documentation or code quality note | Nota de documentação ou qualidade de código |

## Brazilian Portuguese Security Phrases / Frases de Segurança em PT-BR

| English | Português |
|---------|-----------|
| This program has a critical vulnerability. | Este programa tem uma vulnerabilidade crítica. |
| The signer check is missing. | A verificação de signatário está faltando. |
| Integer overflow detected. | Estouro de inteiro detectado. |
| Missing authority check. | Verificação de autoridade ausente. |
| PDA derivation is not canonical. | A derivação de PDA não é canônica. |
| Cross-Program Invocation (CPI) is unsafe. | A Invocação entre Programas (CPI) não é segura. |
| Token account owner not verified. | Proprietário da conta de token não verificado. |
| Rent exemption not guaranteed. | Isenção de aluguel não garantida. |
| Reinitialization attack possible. | Ataque de reinicialização possível. |
| Upgrade authority is a single key. | A autoridade de upgrade é uma chave única. |
| Close target is user-supplied. | O alvo de fechamento é fornecido pelo usuário. |
| Account discriminator check missing. | Verificação de discriminador de conta ausente. |

## How to Use This Glossary / Como Usar Este Glossário

Search for a term in either language. The glossary is bilingual: each row
contains the English term, its definition, and the Portuguese translation.

Procure um termo em qualquer idioma. O glossário é bilíngue: cada linha
contém o termo em inglês, sua definição e a tradução em português.
