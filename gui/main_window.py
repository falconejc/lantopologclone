# /home/ubuntu/lantopolog_clone/gui/main_window.py

import sys
import asyncio
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QMenuBar, QToolBar, QStatusBar, QTextEdit, QListWidget,
    QPushButton, QLabel, QLineEdit, QFormLayout, QSplitter, QGroupBox
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Importar o scanner (ajustar caminho se necessário)
from core.snmp_scanner import SnmpScanner

# Classe para rodar o asyncio em uma thread separada
class ScannerThread(QThread):
    result_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def __init__(self, scanner, config):
        super().__init__()
        self.scanner = scanner
        self.config = config

    def run(self):
        try:
            # --- Integração Asyncio com QThread --- 
            # Cria um novo loop de eventos para esta thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.log_signal.emit("Iniciando varredura SNMP...")
            # Executa a função assíncrona principal do scanner
            discovered_devices = loop.run_until_complete(self.scanner.scan_network(self.config))
            self.log_signal.emit(f"Varredura concluída. {len(discovered_devices)} dispositivo(s) descoberto(s).")
            
            # Coleta detalhes (pode ser pesado, talvez fazer em outra etapa/thread)
            detailed_devices = []
            if discovered_devices:
                 self.log_signal.emit("Coletando detalhes dos dispositivos...")
                 tasks = [self.scanner.get_device_details(dev) for dev in discovered_devices]
                 detailed_devices = loop.run_until_complete(asyncio.gather(*tasks))
                 self.log_signal.emit("Coleta de detalhes concluída.")
            
            self.result_signal.emit(detailed_devices)
            loop.close()
            # --- Fim da Integração --- 
        except Exception as e:
            self.log_signal.emit(f"Erro na thread do scanner: {e}")
            self.result_signal.emit([]) # Emite lista vazia em caso de erro

class MainWindow(QMainWindow):
    """Janela Principal da Aplicação."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lantopolog Clone (Planejamento)")
        self.setGeometry(100, 100, 1200, 800)

        self.scanner = SnmpScanner() # Instancia o scanner
        self.scanner_thread = None

        self._create_actions()
        self._create_menu_bar()
        self._create_tool_bar()
        self._create_status_bar()
        self._create_central_widget()

    def _create_actions(self):
        self.quit_action = QAction("&Sair", self)
        self.quit_action.triggered.connect(self.close)
        # Adicionar mais ações (Novo Scan, Abrir, Salvar...)

    def _create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&Arquivo")
        file_menu.addAction(self.quit_action)
        # Adicionar outros menus (Editar, Visualizar, Ferramentas, Ajuda)

    def _create_tool_bar(self):
        tool_bar = QToolBar("Barra de Ferramentas Principal")
        self.addToolBar(tool_bar)
        # Adicionar botões à toolbar (Novo Scan, Abrir, Salvar...)

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Pronto")

    def _create_central_widget(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        # Splitter para dividir painel esquerdo e central
        splitter_main = QSplitter(Qt.Orientation.Horizontal)

        # --- Painel Esquerdo --- 
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_tabs = QTabWidget()
        left_layout.addWidget(left_tabs)

        # Aba Descoberta
        discovery_tab = QWidget()
        discovery_layout = QFormLayout(discovery_tab)
        self.ip_range_input = QLineEdit("192.168.1.0/24") # Exemplo
        self.community_input = QLineEdit("public") # Exemplo
        self.scan_button = QPushButton("Iniciar Varredura")
        discovery_layout.addRow("Range IP/Subnet:", self.ip_range_input)
        discovery_layout.addRow("Community (v1/v2c):", self.community_input)
        # TODO: Adicionar campos para SNMPv3
        discovery_layout.addRow(self.scan_button)
        self.scan_button.clicked.connect(self.start_scan)

        # Aba Dispositivos
        devices_tab = QWidget()
        devices_layout = QVBoxLayout(devices_tab)
        self.device_list_widget = QListWidget()
        devices_layout.addWidget(QLabel("Dispositivos Descobertos:"))
        devices_layout.addWidget(self.device_list_widget)

        # Aba Alertas
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(alerts_tab)
        self.alerts_list_widget = QListWidget()
        alerts_layout.addWidget(QLabel("Alertas:"))
        alerts_layout.addWidget(self.alerts_list_widget)

        left_tabs.addTab(discovery_tab, "Descoberta")
        left_tabs.addTab(devices_tab, "Dispositivos")
        left_tabs.addTab(alerts_tab, "Alertas")

        # --- Painel Central (Mapa) --- 
        map_panel = QGroupBox("Mapa da Rede") # Usando QGroupBox como placeholder
        map_layout = QVBoxLayout(map_panel)
        # TODO: Adicionar o widget real de visualização do mapa (ex: QGraphicsView)
        map_layout.addWidget(QLabel("[Área para visualização gráfica do mapa]"))

        # --- Adiciona painéis ao splitter principal --- 
        splitter_main.addWidget(left_panel)
        splitter_main.addWidget(map_panel)
        splitter_main.setSizes([300, 900]) # Tamanhos iniciais

        # --- Painel Inferior (Detalhes/Log) --- 
        bottom_panel = QWidget()
        bottom_layout = QVBoxLayout(bottom_panel)
        bottom_tabs = QTabWidget()
        bottom_layout.addWidget(bottom_tabs)
        bottom_panel.setMaximumHeight(200) # Limita altura do painel inferior

        # Aba Detalhes
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        self.details_text_edit = QTextEdit()
        self.details_text_edit.setReadOnly(True)
        details_layout.addWidget(self.details_text_edit)
        # TODO: Popular com detalhes do item selecionado

        # Aba Log
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        log_layout.addWidget(self.log_text_edit)

        bottom_tabs.addTab(details_tab, "Detalhes")
        bottom_tabs.addTab(log_tab, "Log")

        # --- Splitter Vertical para Mapa e Painel Inferior --- 
        splitter_vertical = QSplitter(Qt.Orientation.Vertical)
        splitter_vertical.addWidget(splitter_main) # Adiciona o splitter horizontal (esquerda/mapa)
        splitter_vertical.addWidget(bottom_panel)
        splitter_vertical.setSizes([600, 200]) # Tamanhos iniciais

        main_layout.addWidget(splitter_vertical)

        # Conectar sinais da lista de dispositivos
        self.device_list_widget.currentItemChanged.connect(self.display_device_details)

    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.log_message("Varredura já em andamento.")
            return

        # TODO: Ler configurações de todos os ranges/credenciais da UI
        # Exemplo simples com um único target e community
        ip_target = self.ip_range_input.text().strip() # Simplificado - assumindo um IP/host por enquanto
        community = self.community_input.text().strip()
        
        # Validar entradas minimamente
        if not ip_target or not community:
             self.log_message("Erro: Preencha o IP/Host e a Community String.")
             return

        # Configuração para o scanner (precisa expandir para ranges e v3)
        scan_config = [
            # TODO: Implementar lógica real para parsear ranges (ex: 192.168.1.0/24)
            # Por agora, trata a entrada como um único host
            {
                'target': ip_target, 
                'version': 'v2c', # Assumindo v2c por enquanto
                'community': community
            }
            # Adicionar mais dicts para outros ranges/creds
        ]

        self.log_message(f"Iniciando varredura para: {ip_target} com community: {community}")
        self.scan_button.setEnabled(False)
        self.status_bar.showMessage("Varredura em andamento...")
        self.device_list_widget.clear()
        self.details_text_edit.clear()

        # Inicia a thread do scanner
        self.scanner_thread = ScannerThread(self.scanner, scan_config)
        self.scanner_thread.result_signal.connect(self.scan_finished)
        self.scanner_thread.log_signal.connect(self.log_message)
        self.scanner_thread.finished.connect(lambda: self.scan_button.setEnabled(True))
        self.scanner_thread.finished.connect(lambda: self.status_bar.showMessage("Varredura concluída."))
        self.scanner_thread.start()

    def scan_finished(self, detailed_devices):
        self.log_message(f"Recebidos {len(detailed_devices)} dispositivos detalhados.")
        self.device_list_widget.clear()
        self.discovered_data = {} # Armazena dados para exibição de detalhes
        if not detailed_devices:
             self.log_message("Nenhum dispositivo SNMP encontrado ou erro na coleta.")
             return
             
        for device in detailed_devices:
            ip = device.get("ip", "IP Desconhecido")
            name = device.get("sysName", "")
            descr = device.get("sysDescr", "Descrição Desconhecida")
            display_text = f"{ip} ({name})" if name else ip
            self.device_list_widget.addItem(display_text)
            # Guarda os dados completos associados ao texto exibido
            self.discovered_data[display_text] = device 

    def display_device_details(self, current_item, previous_item):
        if current_item:
            item_text = current_item.text()
            device_data = self.discovered_data.get(item_text)
            if device_data:
                details = "\n".join(f"{key}: {value}" for key, value in device_data.items())
                self.details_text_edit.setText(details)
            else:
                self.details_text_edit.setText(f"Detalhes não encontrados para {item_text}")
        else:
            self.details_text_edit.clear()

    def log_message(self, message):
        self.log_text_edit.append(message)

    def closeEvent(self, event):
        # Garante que a engine SNMP seja fechada corretamente
        # (Pode precisar de mais lógica se a thread ainda estiver rodando)
        # self.scanner.snmp_engine.transportDispatcher.closeDispatcher()
        print("Fechando aplicação...")
        event.accept()

# Para testar a janela isoladamente (opcional)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec())

