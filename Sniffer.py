from scapy.all import sniff, PcapReader, wrpcap


class Sniffer:
    def __init__(self):
        self.captured_packets = []

    def start_sniff(self, interface="any", filter=""):
        """
        Función que inicia el sniffing, recoge los paquetes los imprime por pantalla y los guarda

            args:
                interface (str): Interfaz de red a escuchar
                filter (str): Filtro de captura
        """
        try:
            print("[+] Iniciando captura de paquetes")
            self.captured_packets = sniff(
                iface=interface,
                filter=filter,
                prn=lambda x: x.summary(), #Definimos la función lambda que en x recibe el paquete interpretado y lo imprime
                store=True #Guarda los paquetes capturados
                )

        except KeyboardInterrupt:
            print(f"Captura detenida total paquetes capturados {len(self.captured_packets)}")


    def read_pcap(self, pcap):
        """
        Lee un archivo .pacap y lo guarda en la variable self.captured_packets

            args:
                pcap (str): Ruta del archivo .pcap
        """
        try:
            self.captured_packets = PcapReader(pcap)
            print(f"Leido correctamente archivo {pcap}")
        except Exception as e:
            print("Error {e} al leer el paquete")

    def filter_by_protocol(self, protocol):
        """
        Función que usa el metodo .hashlayer para filtrar los paquetes por protocolo

            args:
                protocol (str): Protocolo a filtrar
        """
        filtered_packets = [pkt for pkt in self.captured_packets if pkt.haslayer(protocol)]
        return filtered_packets


    def filter_by_text(self, text):
        """
        Filtra por los paquetes que tienen el texto que le pasemos.

        args:
            text (str): Texto a buscar
        """
        filtered_packets = [] #inicializo lista vacia para almacenar el filtrado.

        for pkt in self.captured_packets: #Para el paquete en el los paquetes capturados
            found = False # Variable para saber si se ha encontrado el texto
            layer = pkt #tenemos la primera capa

            while layer: #Mientras tengamos capas.
                for field in layer.fields_desc: # Para cada campo de la capa 
                    field_name = field.name #Guardo el nombre de esta
                    field_value = layer.getfieldval(field_name) #Guardo el valor del campo (getfieldval devuelve el valor de un campo que le pasemos en este caso en field_name)
                    if text in field_name or text in str(field_value): #Si el texto está en el nombre del campo o en el valor del campo
                        filtered_packets.append(pkt) #Agrego el paquete a la lista de paquetes filtrados
                        found = True #Marco el texto como encontrado
                    if found: #Si el texto ya se ha encontrado
                        break
                    layer = layer.payload #Paso a la siguiente capa
        return filtered_packets


    def print_pkt_dtail(self, paquetes=None):
        """Imprime los paquetes capturados por pantalla"""
        if not paquetes:
            paquetes = self.captured_packets
        for pkt in paquetes:
            pkt.show()
            print("--- --- ---" * 20)


    def export_to_pcap(self, paquetes, ruta="captura.pcap"):
        """Exporta los paquetes a un archivo pcap"""
        wrpcap(ruta, paquetes)
        print(f"[+]Paquetes exportados a {ruta}")


