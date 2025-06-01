# Lantopolog Clone - Versão Inicial

Este é o código inicial para o software de mapeamento de rede, desenvolvido com base no planejamento aprovado.

**Status Atual:**

*   Estrutura básica do projeto criada (core, gui, utils).
*   Dependências principais listadas em `requirements.txt`.
*   Módulo inicial `core/snmp_scanner.py` implementado:
    *   Utiliza `pysnmp` e `asyncio`.
    *   Função `test_snmp_connectivity` para verificar acesso SNMP v1/v2c/v3 a um IP.
    *   Função `scan_network` para iniciar a varredura (atualmente simplificada para IPs individuais).
    *   Função `get_device_details` para coletar informações básicas (sysDescr, sysName, sysObjectID) - coleta de tabelas (IF, MAC, LLDP/CDP) ainda é um placeholder.
*   Interface gráfica (`gui/main_window.py`) criada com PyQt6:
    *   Layout principal com painéis esquerdo (Descoberta, Dispositivos, Alertas), central (Mapa - placeholder) e inferior (Detalhes, Log).
    *   Funcionalidade básica na aba "Descoberta" para iniciar uma varredura SNMP (atualmente só v2c com community string e IP único).
    *   Utiliza QThread para rodar o scanner SNMP assíncrono sem bloquear a UI.
    *   Exibe dispositivos descobertos na lista e seus detalhes básicos ao selecionar.
    *   Exibe logs de progresso.
*   Ponto de entrada `main.py` configurado para iniciar a aplicação.

**Próximos Passos (Conforme Planejamento):**

*   Implementar a lógica completa de parsing de ranges de IP na UI e no scanner.
*   Adicionar suporte completo para configuração e uso de SNMPv3 na UI e no scanner.
*   Implementar a coleta de tabelas SNMP (`_get_snmp_table`) para interfaces, MACs, LLDP/CDP, VLANs.
*   Desenvolver o módulo de processamento para construir a topologia (grafo NetworkX) a partir dos dados coletados.
*   Implementar a visualização do grafo na área do mapa (usando QGraphicsView ou similar).
*   Adicionar funcionalidades de edição de mapa, monitoramento, alertas, etc.

**Como Configurar e Executar (Ambiente Linux/Sandbox):**

1.  **Criar Ambiente Virtual (Recomendado):**
    ```bash
    python3.11 -m venv venv
    source venv/bin/activate
    ```
2.  **Instalar Dependências:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Executar a Aplicação:**
    ```bash
    python3.11 main.py
    ```

**Observações:**

*   A funcionalidade de scan atual é muito básica e serve como prova de conceito da integração SNMP/Asyncio/PyQt.
*   A visualização do mapa ainda não está implementada.
*   O código precisa de mais tratamento de erros e validação de entradas.

