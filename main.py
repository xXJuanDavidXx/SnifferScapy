from Sniffer import Sniffer
import traceback
import argparse
import sys


def main(sniff, interface, filter, read_pcap, fp, ft, exp, r):
    """
    Main del programa, se encarga de definir la logica de ejecucion del programa
    recibe varios argumentos, en funcion de los argumentos pasados la ejecucion que va a tener
    """
    sniffer = Sniffer()
    try:
        if sniff and read_pcap:
                print("[+] No se puede leer y hacer sniffing al mismo tiempo")
                sys.exit(1)

        elif sniff: # EN CASO DE CAPTURAR PAQUETES
            print("[+] Iniciando la captura de paquetes ctrl + c para detener...")
            paquetes = sniffer.start_sniff(interface, filter)
            
            if fp and ft:
                print("Solo se puede filtrar por texto o por protocolo") # Tengo que probar si funcionan en conjunto.
                sys.exit(1)

            elif fp:
                fpaquetes = sniffer.filter_by_protocol(fp)
                sniffer.print_pkt_dtail(fpaquetes)

                if exp and r:
                    print(f"Importando en {r}")
                    sniffer.export_to_pcap(fpaquetes, r)
                elif exp:
                    print("Importando en capture.pcap")
                    sniffer.export_to_pcap(fpaquetes)

            elif ft:
                fpaquetes = sniffer.filter_by_text(ft)
                
                sniffer.print_pkt_dtail(fpaquetes)
                if exp and r:
                    print(f"Importando en {r}")
                    sniffer.export_to_pcap(fpaquetes, r)
                elif exp:
                    print("Importando en capture.pcap")
                    sniffer.export_to_pcap(fpaquetes)
                
            else:
                sniffer.print_pkt_dtail(paquetes)
                if exp and r:
                    print(f"[+]Importando en {r}")
                    sniffer.export_to_pcap(paquetes, r)
                elif exp:
                    print("[+]Importando en capture.pcap")
                    sniffer.export_to_pcap(paquetes)
                
                
            sys.exit()            


#EN CASO DE LEER UN ARCHIVO .pcap################
        elif read_pcap:  
            print("[+] Leyendo archivo pcap...")
            paquetes = sniffer.read_pcap(read_pcap)

            if fp and ft:
                print("Solo se puede filtrar por texto o por protocolo") # Tengo que probar si funcionan en conjunto.
                sys.exit(1)

            elif fp:
                fpaquetes = sniffer.filter_by_protocol(fp)
                sniffer.print_pkt_dtail(fpaquetes)

            elif ft:
                 #Debemos Corregir el error.(Bucle infinito.)
                 fpaquetes = sniffer.filter_by_text(ft)
                 sniffer.print_pkt_dtail(fpaquetes)
            else:
                sniffer.print_pkt_dtail(paquetes)
            sys.exit()


    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
        print(f"Tipo de error: {type(e).__name__}")  # Muestra el tipo de error
        print(f"Argumentos del error: {e.args}") 



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Sniffer de red con scapy')
    parser.add_argument("--sniff", action="store_true", help="Capturar paquetes.")
    parser.add_argument("-f", "--filter", type=str, help="Filtro para capturar paquetes.")
    parser.add_argument('-i', '--interface', type=str, help='Interface de red a escanear',)
    parser.add_argument('-ft', '--filterText', type=str, help='Texto a buscar en la captura')
    parser.add_argument('-fp', '--filterProtocol', type=str, help="Protocolo a filtrar.")
    parser.add_argument('--ReadPcap', type=str, help="La ruta del archivo pcap a leer.")
    parser.add_argument('--ExportPcap', action="store_true", help="Exporta un archivo pcap")
    parser.add_argument('-r', '--ruta', type=str, help="La ruta del archivo a exportar")

    args = parser.parse_args()

    main(args.sniff, 
         args.interface, 
         args.filter, 
         args.ReadPcap, 
         args.filterProtocol, 
         args.filterText,
         args.ExportPcap,
         args.ruta
         ) 
