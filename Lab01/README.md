# Lab 01: Análise de Eventos de Autenticação no Windows (Event ID 4625)

## Objetivo
Validar a telemetria de auditoria nativa do Windows após tentativas de Logon mal-sucedidas, identificando o Event ID no Event Viewer e aplicando filtros
de intervalo de tempo para isolar eventos específicos.

## Contexto
Gerei este evento de forma controlada para aprender como um 4625 aparece no log e como filtrá-lo por horário. É a base para depois detectar Brute Force e Password Spraying.

## Ferramentas Utilizadas
- Windows 10 em VM (VirtualBox - Ambiente em modo NAT);
- Visualizador de Eventos (eventvwr.msc);
- PowerShell.

## Procedimentos
1. Iniciar o Windows e ir para tela de sessão do usuário. 
2. Execução de múltiplas falhas de Logon intencionais com PIN incorreto às **13:32** do dia **04/11/2026**.
3. Verificação de tentativas de autenticação no Visualizador de Eventos, utilizando filtragem do **Event ID 4625**.
4. Utilizar linha de comando no PowerShell para filtragem de horário para isolar as tentativas do teste e desconsiderar eventos acidentais posteriores.
5. Analisar e Capturar o resultado da linha de comando, mostrando várias tentativas seguidas mal-sucedidas de Logon.
  

## Análise de Logs
- **Event ID Capturado:** 4625 (Falha de Logon.)
- **Requerente:** DESKTOP-JVKPULU$ (Conta da própria máquina que registrou a falha.)
- **Logon Type:** 2 (Alguém que digitou na própria máquina.)
- **Conta-Alvo:** - (Vazio nesse evento.)
- **Status:** 0xC000006D (Indica uma falha de logon.)
- **SubStatus:** 0xC0000380 (Indica que um PIN incorreto foi inserido ao tentar fazer login ou autenticação no sistema.)
- **Processo Responsável:** svchost.exe
- **IP de Origem:** 127.0.0.1 (Loopback.)

### Evidência 
**Comando utilizado no PowerShell:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=[datetime]'2026-11-04 13:30:00'; EndTime=[datetime]'2026-11-04 13:40:00'} -MaxEvents 5 | Format-List TimeCreated, Message
```

<img width="769" height="561" alt="Event 4625, às 13:32:30, Logon Tipo 2, Origem 127.0.0.1" src="https://github.com/user-attachments/assets/4712b642-f774-4991-b7f5-f7f233688d17" />
<img width="780" height="562" alt="Event 4625, às 13:32:28, Logon Tipo 2, Origem 127.0.0.1" src="https://github.com/user-attachments/assets/0b3f12aa-8e9b-4753-bc73-a268b2a7a639" />
<img width="778" height="565" alt="Event 4625, às 13:32:27, Logon Tipo 2, Origem 127.0.0.1" src="https://github.com/user-attachments/assets/71eb5033-9aa7-40ab-82b4-5ef4ecdd450c" />
<img width="782" height="563" alt="Event 4625, às 13:32:25, Logon Tipo 2, Origem 127.0.0.1" src="https://github.com/user-attachments/assets/55a88cbb-870c-4633-9cb1-b68adee41e41" />




## MITRE ATT&CK
| Técnica | ID | Relação com este lab |
|---|---|---|
| Brute Force | T1110 | Muitas falhas contra uma conta. O 4625 é a base para detectar. |
| Password Spraying | T1110.003 | Poucas senhas testadas em várias contas. |
| Valid Accounts | T1078 | Logon bem-sucedido (4624) depois das falhas, indicando acesso com conta válida. |

>**Nota:** Nenhuma dessas técnicas ocorreu neste lab. A tabela mostra o que o 4625 ajuda a detectar.

## Conclusão

**O que aconteceu?:** 4 Falhas (Event ID 4625) intencionais de PIN às 13:32, todas Logon Tipo 2, com origem do IP 127.0.0.1 (Loopback).

**Classificação:** Benign True Positive/Baixo Risco, sem necessidade de escalar. O volume de alertas e o IP de origem diminui drasticamente o nível do Risco.

**Seria um incidente, se houvesse:**
1. Dezenas de eventos 4625 gerado em um curto período de tempo na mesma conta, caracterizando-se ser um Brute Force (T1110).
2. Eventos 4625 em várias contas diferentes, sendo um provável Password Spraying (T1110.003).
3. Um evento 4624 (Logon bem-sucedido) logo após diversas falhas, com processos de reconhecimento ou persistência em seguida.
4. IP de origem for externo.

## O que eu faria

- **Neste lab:** Classificar como benign true positive, registrar e não escalar.
- **Se fossem dezenas de 4625 em um curto período:** Identificar as contas, o IP de origem, procurar um 4624 logo depois, checar processos criados após o Login (4688 ou Sysmon 1) e escalar. Como contenção, bloquear o IP ou a conta temporariamente e exigir troca de senha.

## O que aprendi

- Aprendi a reconhecer o evento 4625 e ler os campos que importam: tipo de logon, Status e SubStatus, e IP de origem.
- Aprendi a filtrar por horário com `Get-WinEvent` para isolar só os eventos do teste.
- Um 4625 isolado normalmente é inofensivo. Um alerta real dependeria do volume, contas-alvo, origem e o que acontece depois do Login.





