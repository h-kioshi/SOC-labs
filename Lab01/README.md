# Lab 01: Análise de Eventos de Autenticação no Windows (Event ID 4625)

## Objetivo
Validar a telemetria de auditoria nativa do Windows após tentativas de Logon mal-sucedidas, identificando o Event ID no Event Viewer e aplicando filtros
de intervalo de tempo para isolar eventos específicos.

## Ferramentas Utilizadas
- Windows 10 em VM (VirtualBox - Ambiente em modo NAT);
- Visualizador de Eventos (eventvwr.msc);
- PowerShell.

## Procedimentos
1. Iniciar o Windows e ir para tela de sessão do usuário. 
2. Execução de múltiplas falhas de Logon intencionais com PIN incorretos às **13:32** do dia **04/11/2026**.
3. Verificação de tentativas de autenticação no Visualizador de Eventos, utilizando filtragem do **Event ID 4625**.
4. Utilizar linha de comando no PowerShell para filtragem de horário para isolar as tentativas suspeitas e desconsiderar eventos acidentais posteriores.
5. Analisar e Capturar o resultado da linha de comando, mostrando várias tentativas seguidas mal-sucedidas de Logon.
  

## Evidências e Análise de Logs
- **Event ID Capturado:** 4625 (Falha de Logon)
- **Logon Type:** 2
- **Status:** 0xC000006D (Indica uma falha de logon.)
- **SubStatus:** 0xC0000380 (Indica que um PIN incorreto foi inserido ao tentar fazer login ou autenticação no sistema.)
- **Processo Responsável:** svchost.exe

### Evidência 
<img width="769" height="561" alt="{97C51569-C9F2-4B40-8FCF-ED876C2D0313}" src="https://github.com/user-attachments/assets/4712b642-f774-4991-b7f5-f7f233688d17" />
<img width="780" height="562" alt="{97CEFADA-2692-40E8-BC71-825CCAC38C74}" src="https://github.com/user-attachments/assets/0b3f12aa-8e9b-4753-bc73-a268b2a7a639" />
<img width="778" height="565" alt="{3BD1D35B-997B-4928-9CD2-5EF7249226A6}" src="https://github.com/user-attachments/assets/71eb5033-9aa7-40ab-82b4-5ef4ecdd450c" />
<img width="782" height="563" alt="{3140886D-31CA-4878-A48B-47BEA6799804}" src="https://github.com/user-attachments/assets/55a88cbb-870c-4633-9cb1-b68adee41e41" />



### Nota Metodológica
Embora simular a falha de senha seja um procedimento simples, a análise do **Event ID 4625** é importante pelos seguintes motivos:

1. **Criação de Alertas Precisos:** Entender como o log funciona na prática é o primeiro passo para configurar alertas no SIEM sem gerar
alarmes falsos o tempo todo. Se o analista não souber como um falso positivo legítimo se parece na origem, não conseguirá calibrar alertas para evitar
o cansaço de alertas (alert fatigue).

2. **Mapeamento de Baseline:** A presença do `Logon Type 2` e do IP de loopback (`127.0.0.1`) estabelece a linha de base (*baseline*) de um erro de
digitação humano comum. Isso permite diferenciar rapidamente o uso cotidiano do sistema de um comportamento anômalo.

3. **Prática de Resposta a Incidentes:** A utilização de rotinas no PowerShell para aplicar filtros de janela de tempo
(`StartTime`/`EndTime`) simula o processo real de triagem de incidentes, em que o analista precisa isolar eventos específicos
dentro de volumes massivos de logs corporativos.


## Conclusão
É de suma importância analisar, também, o contexto dos eventos. Não basta chegar numa conclusão com base num caso isolado. Usando esse
lab como exemplo, seria necessário identificar quantidade de tentativas pelo tempo, se o usuário logou com sucesso, quais foram suas ações após isso 
e entre outros fatores. Se basear em apenas algumas tentativas mal-sucedidas de logon, sendo que não necessariamente que o PC estaria comprometido e escalar o caso, 
pode ser bastante prejudicial para a equipe. Por isso, no caso desse lab, seria classificado como um False Positive/Low Risk. O caso teria uma classificação maior, 
se houvesse dezenas ou centenas de tentativas num curto intervalo, podendo-se caracterizar como um Brute Force. Dezenas de Eventos 4625 em usuários diferentes 
em um curto período, caracterizando-se como um Password Spraying. Ou se houve um logon bem-sucedido seguido pela execução de processos de reconhecimento e
persistência, pode indicar o inicio da fase de exploração do agente de ameaça. 

