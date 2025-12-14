import logging
from collections import Counter
import sys

try:
    from scapy.all import PcapReader, IP, TCP, UDP, ARP, ICMP, Ether
except ImportError:
    print("Scapy non è installato. Per favore installalo con: pip install scapy")
    exit(1)

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

PCAP_FILE = "Srb_JOFA_FCA_10s_PLC.pcap"

def analyze_pcap(filename):
    logging.info(f"Inizio analisi del file: {filename}...")
    
    total_packets = 0
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    
    # Statistiche Lunghezza Pacchetti
    pkt_lens = []
    
    try:
        # Usa PcapReader per leggere il file pacchetto per pacchetto (streaming)
        with PcapReader(filename) as pcap_reader:
            for pkt in pcap_reader:
                total_packets += 1
                
                # Feedback visuale ogni 1000 pacchetti
                if total_packets % 1000 == 0:
                    print(f"\rProcessati {total_packets} pacchetti...", end="", flush=True)

                # Statistiche lunghezza
                pkt_len = len(pkt)
                pkt_lens.append(pkt_len)

                # Conteggio protocolli livello trasporto/rete
                if pkt.haslayer(TCP):
                    protocols['TCP'] += 1
                elif pkt.haslayer(UDP):
                    protocols['UDP'] += 1
                elif pkt.haslayer(ICMP):
                    protocols['ICMP'] += 1
                elif pkt.haslayer(ARP):
                    protocols['ARP'] += 1
                else:
                    protocols['Other'] += 1
                    
                # Analisi IP
                if pkt.haslayer(IP):
                    src_ips[pkt[IP].src] += 1
                    dst_ips[pkt[IP].dst] += 1
                    
    except FileNotFoundError:
        logging.error(f"\nErrore: Il file '{filename}' non è stato trovato.")
        return
    except KeyboardInterrupt:
        logging.info("\nAnalisi interrotta dall'utente.")
    except Exception as e:
        logging.error(f"\nErrore durante l'analisi: {e}")
        return

    print(f"\n\nAnalisi completata. Totale pacchetti: {total_packets}")

    if total_packets > 0:
        # Calcolo statistiche lunghezza
        min_len = min(pkt_lens)
        max_len = max(pkt_lens)
        avg_len = sum(pkt_lens) / len(pkt_lens)

        print(f"\n--- Statistiche Lunghezza Pacchetti ---")
        print(f"Conteggio: {total_packets}")
        print(f"Media: {avg_len:.2f} bytes")
        print(f"Min: {min_len} bytes")
        print(f"Max: {max_len} bytes")

        print("\n--- Distribuzione Protocolli ---")
        for proto, count in protocols.most_common():
            print(f"{proto}: {count} ({count/total_packets*100:.1f}%)")

        print("\n--- Top Indirizzi IP Sorgente ---")
        for ip, count in src_ips.most_common(5):
            print(f"{ip}: {count}")

        print("\n--- Top Indirizzi IP Destinazione ---")
        for ip, count in dst_ips.most_common(5):
            print(f"{ip}: {count}")
    else:
        print("Nessun pacchetto trovato o file vuoto.")

if __name__ == "__main__":
    analyze_pcap(PCAP_FILE)
