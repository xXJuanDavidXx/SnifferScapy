from Sniffer import Sniffer
import argparse
import sys


def main(sniff, interface, filter,):
    """
    Main del programa, se encarga de definir la logica de ejecucion del programa
    recibe varios argumentos, en funcion de los argumentos pasados la ejecucion que va a tener
    """
    sniffer = Sniffer()
    try:
        if sniff:
            #SUGERENCIA: Implementar validacion en caso de que ademas de sniff se pase un argumento como readpcap porque habira conficto
            print("[+] Iniciando la captura de paquetes ctrl + c para detener...")
            paquetes = sniffer.start_sniff(interface, filter)
            sniffer.print_pkt_dtail(paquetes)
            sys.exit()            


    except Exception as e:
        print(f"Error: {e}")




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

    main(args.sniff, args.interface, args.filter) 
