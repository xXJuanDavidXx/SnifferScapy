# SnifferScapy

Este es un sniffer de red simple que utiliza Scapy para capturar, analizar y guardar paquetes de red.

## Uso

### Requisitos

Asegúrate de tener las dependencias instaladas:

```bash
pip install -r requirements.txt
```

### Captura de paquetes

Para iniciar la captura de paquetes en una interfaz de red específica:

```bash
sudo python3 main.py --sniff -i <nombre_de_la_interfaz>
```

> **Nota:** Se requieren privilegios de superusuario (`sudo`) para la captura de paquetes.

### Filtrado durante la captura

Puedes aplicar filtros durante la captura:

- **Filtrar por protocolo (ej. TCP, UDP, ICMP):**
  ```bash
  sudo python3 main.py --sniff -i <interfaz> -fp TCP
  ```

- **Filtrar por texto contenido en el paquete:**
  ```bash
  sudo python3 main.py --sniff -i <interfaz> -ft "GET"
  ```

- **Usar un filtro de BPF (Berkeley Packet Filter):**
  ```bash
  sudo python3 main.py --sniff -i <interfaz> -f "port 80"
  ```

### Exportar la captura a un archivo `.pcap`

Añade el flag `--ExportPcap` para guardar los paquetes capturados.

- **Guardar en `capture.pcap` (nombre por defecto):**
  ```bash
  sudo python3 main.py --sniff -i <interfaz> --ExportPcap
  ```

- **Guardar en un archivo con nombre personalizado:**
  ```bash
  sudo python3 main.py --sniff -i <interfaz> --ExportPcap -r mi_captura.pcap
  ```

### Leer desde un archivo `.pcap`

Para analizar un archivo de captura existente:

```bash
python3 main.py --ReadPcap <ruta_del_archivo.pcap>
```

También puedes filtrar los paquetes al leer un archivo:

```bash
python3 main.py --ReadPcap <archivo.pcap> -fp UDP
```

## Argumentos

| Argumento | Alias | Descripción | Ejemplo |
|---|---|---|---|
| `--sniff` | | Inicia la captura de paquetes. | `--sniff` |
| `--interface` | `-i` | Interfaz de red para la captura. | `-i eth0` |
| `--filter` | `-f` | Filtro BPF para la captura. | `-f "tcp port 443"` |
| `--filterProtocol` | `-fp` | Filtra los paquetes por protocolo. | `-fp ICMP` |
| `--filterText` | `-ft` | Filtra los paquetes por un texto específico. | `-ft "User-Agent"` |
| `--ReadPcap` | | Lee y analiza un archivo `.pcap`. | `--ReadPcap captura.pcap` |
| `--ExportPcap` | | Exporta la captura a un archivo `.pcap`. | `--ExportPcap` |
| `--ruta` | `-r` | Ruta y nombre del archivo a exportar. | `-r /tmp/mi_captura.pcap` |
