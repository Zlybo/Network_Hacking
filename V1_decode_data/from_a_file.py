from scapy.all import *


class PcapGameAnalyzer:
    def __init__(self, source_port=xxxxx, dest_port=xxxx):
        self.source_port = source_port
        self.dest_port = dest_port
        self.packet_count = 0
        self.udp_count = 0
        self.game_packet_count = 0
        print(f"Analizando paquetes UDP entre puertos {source_port} y {dest_port}")

    def decode_packet(self, payload):
        try:
            hex_data = payload.hex()
            print(f"Datos Raw: {hex_data[:60]}...")  # Mostramos más datos para debug

            # Verificamos si tiene el patrón típico del juego (04 al inicio)
            if hex_data.startswith('04'):
                if len(hex_data) < 200:  # Paquete pequeño
                    try:
                        # Intentamos decodificar desde el byte 16
                        x = int(hex_data[16:24], 16) if len(hex_data) >= 24 else 0
                        y = int(hex_data[24:32], 16) if len(hex_data) >= 32 else 0
                        rotation = int(hex_data[32:40], 16) if len(hex_data) >= 40 else 0

                        return {
                            "type": "player",
                            "x": x / 1000.0,
                            "y": y / 1000.0,
                            "rotation": (rotation / 65536.0) * 360
                        }
                    except ValueError as e:
                        return {"error": f"Error convirtiendo valores: {e}"}
                else:
                    # Para paquetes grandes, intentamos extraer múltiples coordenadas
                    entities = []
                    pos = 16
                    try:
                        while pos < len(hex_data) - 32:
                            entity_x = int(hex_data[pos:pos + 8], 16)
                            entity_y = int(hex_data[pos + 8:pos + 16], 16)
                            entities.append({
                                "x": entity_x / 1000.0,
                                "y": entity_y / 1000.0
                            })
                            pos += 32
                    except ValueError:
                        pass

                    return {
                        "type": "world",
                        "entities": entities
                    }
            return {"error": "No es un paquete del juego (no comienza con 04)"}

        except Exception as e:
            return {"error": f"Error general decodificando: {str(e)}"}

    def analyze_pcap(self, pcap_file):
        try:
            print(f"Leyendo archivo: {pcap_file}")
            packets = rdpcap(pcap_file)
            print(f"Total de paquetes en el archivo: {len(packets)}")

            for pkt in packets:
                self.packet_count += 1
                try:
                    if UDP in pkt:
                        self.udp_count += 1
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport

                        # Verifica si es un paquete entre los puertos del juego
                        if ((sport == self.source_port and dport == self.dest_port) or
                                (sport == self.dest_port and dport == self.source_port)):

                            print(f"\nPaquete del juego #{self.game_packet_count + 1}")
                            print(f"Puertos: {sport} -> {dport}")

                            if Raw in pkt:
                                payload = pkt[Raw].load
                                result = self.decode_packet(payload)

                                if "error" not in result:
                                    self.game_packet_count += 1
                                    if result["type"] == "player":
                                        print(f"Posición del jugador:")
                                        print(f"X: {result['x']:.2f}")
                                        print(f"Y: {result['y']:.2f}")
                                        print(f"Rotación: {result['rotation']:.2f}°")
                                    else:
                                        print(f"Entidades en el mundo: {len(result['entities'])}")
                                        for i, entity in enumerate(result['entities'][:3]):
                                            print(f"Entidad {i}: X={entity['x']:.2f}, Y={entity['y']:.2f}")
                                else:
                                    print(f"Error: {result['error']}")

                except Exception as e:
                    print(f"Error en paquete individual: {e}")
                    continue

            # Resumen final
            print("\n=== Resumen de análisis ===")
            print(f"Total de paquetes procesados: {self.packet_count}")
            print(f"Paquetes UDP encontrados: {self.udp_count}")
            print(f"Paquetes del juego decodificados: {self.game_packet_count}")

        except Exception as e:
            print(f"Error leyendo pcap: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python script.py archivo.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analyzer = PcapGameAnalyzer(65002, 7795)  # Usando los puertos correctos
    analyzer.analyze_pcap(pcap_file)