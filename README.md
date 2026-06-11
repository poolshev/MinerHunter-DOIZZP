# MinerHunter-DOIZZP

Ferramenta de diagnostico seguro para Windows focada em identificar possiveis malwares de mineracao, processos evasivos, itens suspeitos de inicializacao, tarefas agendadas, servicos e conexoes ativas.

> Importante: esta ferramenta nao substitui antivirus. Ela ajuda a localizar sinais suspeitos sem apagar arquivos automaticamente.

## Objetivo

Identificar casos em que o PC fica com CPU/GPU alta parado e o consumo cai ao abrir o Gerenciador de Tarefas, comportamento comum em mineradores maliciosos evasivos.

## O que o MinerHunter faz

- Lista processos com CPU, RAM, caminho do executavel, empresa e assinatura digital.
- Gera relatorio `.txt` e tabelas `.csv`.
- Procura processos sem assinatura ou rodando em locais suspeitos.
- Lista itens de inicializacao do Windows.
- Lista servicos.
- Lista tarefas agendadas fora da pasta Microsoft.
- Lista conexoes TCP ativas com PID.
- Permite mover arquivo suspeito para quarentena manual.

## O que ele nao faz

- Nao apaga arquivos automaticamente.
- Nao remove chaves de registro automaticamente.
- Nao altera arquivos do Windows.
- Nao desativa drivers, anticheats, Steam, Discord ou programas legitimos sozinho.

## Caminho recomendado

Extraia a pasta diretamente no disco C:, ficando assim:

```txt
C:\MinerHunter-DOIZZP\
├── MinerHunter.ps1
├── Run-MinerHunter.bat
├── Install-To-C.bat
├── Reports\
├── Quarantine\
├── tools\
└── docs\
```

## Como instalar

### Opcao 1 - Manual

1. Extraia o ZIP.
2. Copie a pasta `MinerHunter-DOIZZP` para o disco `C:`.
3. O caminho final deve ser:

```txt
C:\MinerHunter-DOIZZP
```

### Opcao 2 - Instalador

1. Extraia o ZIP em qualquer lugar.
2. Clique com o botao direito em `Install-To-C.bat`.
3. Escolha `Executar como administrador`.
4. Ele copiara os arquivos para `C:\MinerHunter-DOIZZP`.

## Como executar

1. Abra:

```txt
C:\MinerHunter-DOIZZP
```

2. Clique com o botao direito em:

```txt
Run-MinerHunter.bat
```

3. Escolha:

```txt
Executar como administrador
```

4. Selecione a opcao `1 - Diagnostico completo`.

## Onde ficam os relatorios

```txt
C:\MinerHunter-DOIZZP\Reports
```

Arquivos gerados:

```txt
MinerHunter_Report_DATA.txt
Processes_DATA.csv
Suspects_DATA.csv
Startup_DATA.csv
Services_DATA.csv
ScheduledTasks_DATA.txt
Network_DATA.csv
```

## Como analisar suspeitos

Priorize itens no arquivo:

```txt
Suspects_DATA.csv
```

Sinais de alerta:

- Arquivo sem assinatura digital.
- Nome aleatorio, exemplo: `xj29sk.exe`.
- Processo em `AppData`, `Temp`, `ProgramData` ou `Users\Public`.
- Nomes como `xmrig`, `miner`, `xmr`, `monero`, `cryptonight`, `nicehash`.
- Processo com CPU alta sem programa aberto.
- Tarefa agendada desconhecida chamando um `.exe` suspeito.
- Servico desconhecido iniciando automaticamente.

## Quarentena segura

Use a opcao `2 - Mover arquivo suspeito para quarentena` apenas depois de confirmar o caminho.

A quarentena fica em:

```txt
C:\MinerHunter-DOIZZP\Quarantine
```

A ferramenta move o arquivo, em vez de apagar. Isso reduz o risco de quebrar o Windows ou algum programa legitimo.

## Recomendacao de verificacao adicional

Depois do relatorio:

1. Baixe Autoruns da Microsoft Sysinternals.
2. Abra como administrador.
3. Desabilite itens suspeitos de inicializacao, sem excluir de primeira.
4. Rode Microsoft Defender Offline se a suspeita for forte.
5. Reinicie e rode o MinerHunter novamente.

## Aviso

Nunca coloque em quarentena arquivos de:

```txt
C:\Windows\System32
C:\Windows\SysWOW64
C:\Program Files\AMD
C:\Program Files\NVIDIA Corporation
C:\Program Files\Steam
C:\Program Files\Rockstar Games
C:\Program Files\FiveM
```

sem ter certeza absoluta.

## Licenca sugerida

MIT License.
