import tkinter as tk
from tkinter import ttk, Scrollbar
from scapy.all import sniff
import threading
import time


class NetworkAnalyzerApp:
    def init(self, root):
        self.root = root
        self.root.title("Análise de Tráfego de Dados - Scapy")
        self.root.geometry("900x600")

# Criar interface principal
        self.create_widgets()

        # Iniciar captura de pacotes
        self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        self.sniff_thread.start()

    def create_widgets(self):
        # Criando frames principais
        self.summary_frame = tk.Frame(self.root, padx=10, pady=5, relief=tk.GROOVE, bd=2)
        self.summary_frame.pack(side=tk.TOP, fill=tk.X)

        self.table_frame = tk.Frame(self.root, padx=10, pady=5, relief=tk.GROOVE, bd=2)
        self.table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Criar painel de resumo
        self.create_summary_panel()

        # Criar painel da tabela com dados em tempo real
        self.create_table_panel()

    def create_summary_panel(self):
        """Painel para mostrar informações gerais de tráfego de rede."""
        tk.Label(self.summary_frame, text="Resumo de Tráfego de Rede", font=("Arial", 12, "bold")).pack()

        self.packet_count_var = tk.StringVar(value="0")
        tk.Label(self.summary_frame, text="Pacotes Capturados:").pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(self.summary_frame, textvariable=self.packet_count_var, font=("Arial", 12, "bold")).pack(
            side=tk.LEFT
        )

    def create_table_panel(self):
        """Criação da tabela dinâmica com os pacotes capturados."""
        columns = ("Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol")

        self.tree = ttk.Treeview(
            self.table_frame, columns=columns, show="headings", selectmode="browse", height=20
        )
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.W, stretch=True)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Adicionar Scrollbar
        scrollbar = Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=scrollbar.set)

    def process_packet(self, packet):
        """Processar pacotes para análise de dados."""
        try:
            # Capturar dados essenciais do pacote
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                protocol = packet["IP"].proto

                # Identificar porta para pacotes TCP/UDP
                if packet.haslayer("TCP"):
                    src_port = packet["TCP"].sport
                    dst_port = packet["TCP"].dport
                    protocol_name = "TCP"
                elif packet.haslayer("UDP"):
                    src_port = packet["UDP"].sport
                    dst_port = packet["UDP"].dport
                    protocol_name = "UDP"
                else:
                    src_port = dst_port = 0
                    protocol_name = "IP"

                # Atualizar o painel visual com os dados do pacote
                self.tree.insert(
                    "",
                    tk.END,
                    values=(time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, src_port, dst_port, protocol_name),
                )
# Atualizar contagem de pacotes no painel de resumo
                current_count = int(self.packet_count_var.get()) + 1
                self.packet_count_var.set(str(current_count))
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

    def start_sniffing(self):
        """Método para capturar pacotes em tempo real usando scapy."""
        sniff(prn=self.process_packet, store=False, timeout=0, filter="ip")


# Configuração da Interface Gráfica Principal
root = tk.Tk()
app = NetworkAnalyzerApp(root)
root.mainloop()