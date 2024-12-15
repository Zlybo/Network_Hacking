from scapy.all import *
import signal
import sys


class GamePacketAnalyzer:
    def __init__(self, source_port=xxxxx, dest_port=xxxx):
        self.source_port = source_port
        self.dest_port = dest_port
        self.running = True
        print(f"Iniciando captura para puertos {source_port} <-> {dest_port}")

    def decode_packet(self, payload):
        try:
            hex_data = payload.hex()

            if hex_data.startswith('04'):  # Verificamos que sea un paquete del juego
                if len(hex_data) < 200:  # Paquete pequeño (posición del jugador)
                    x = int(hex_data[16:24], 16)
                    y = int(hex_data[24:32], 16)
                    rotation = int(hex_data[32:40], 16)

                    return {
                        "type": "player",
                        "x": x / 1000.0,
                        "y": y / 1000.0,
                        "rotation": (rotation / 65536.0) * 360
                    }
                else:  # Paquete grande (estado del mundo)
                    entities = []
                    pos = 16
                    while pos < len(hex_data) - 32:
                        try:
                            entity_x = int(hex_data[pos:pos + 8], 16)
                            entity_y = int(hex_data[pos + 8:pos + 16], 16)
                            entities.append({
                                "x": entity_x / 1000.0,
                                "y": entity_y / 1000.0
                            })
                            pos += 32
                        except ValueError:
                            break

                    return {
                        "type": "world",
                        "entities": entities
                    }
            return None
        except Exception as e:
            print(f"Error decodificando: {e}")
            return None

    def packet_callback(self, pkt):
        try:
            if UDP in pkt and Raw in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

                # Verifica si el paquete es entre los puertos que nos interesan
                if ((sport == self.source_port and dport == self.dest_port) or
                        (sport == self.dest_port and dport == self.source_port)):

                    # Obtiene y decodifica el payload
                    payload = pkt[Raw].load
                    result = self.decode_packet(payload)

                    if result:
                        if result["type"] == "player":
                            print("\033[H\033[J")  # Limpia la pantalla
                            print(f"Posición del jugador:")
                            print(f"X: {result['x']:.2f}")
                            print(f"Y: {result['y']:.2f}")
                            print(f"Rotación: {result['rotation']:.2f}°")
                        else:
                            print(f"\nEntidades en el mundo: {len(result['entities'])}")
                            for i, entity in enumerate(result['entities'][:3]):
                                print(f"Entidad {i}: X={entity['x']:.2f}, Y={entity['y']:.2f}")
        except Exception as e:
            print(f"Error procesando paquete: {e}")

    def signal_handler(self, signum, frame):
        print("\nDeteniendo captura...")
        self.running = False

    def start_capture(self):
        try:
            # Registra el manejador de señales para Ctrl+C
            signal.signal(signal.SIGINT, self.signal_handler)

            # Configura el filtro para capturar solo paquetes UDP en los puertos específicos
            filter_str = f"udp and (port {self.source_port} or port {self.dest_port})"

            print("Iniciando captura... (Presiona Ctrl+C para detener)")
            print("Esperando paquetes del juego...")

            # Inicia la captura
            sniff(filter=filter_str,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda x: not self.running)

        except Exception as e:
            print(f"Error en captura: {e}")
        finally:
            print("Captura finalizada")


if __name__ == "__main__":
    try:
        # Crea e inicia el analizador
        analyzer = GamePacketAnalyzer()
        analyzer.start_capture()
    except Exception as e:
        print(f"Error general: {e}")
        sys.exit(1)