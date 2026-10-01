from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

VALID_SIP_METHODS = ("INVITE", "REGISTER", "BYE", "ACK", "OPTIONS", "SUBSCRIBE", "CANCEL", "SIP/2.0")

def analyze_pcap(file_path, filter_ip=None):
    packet_summaries = []
    dns_queries = set()
    sip_messages = []

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        return {"error": str(e), "packets": [], "dns": [], "sip": []}

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            
            if filter_ip and filter_ip not in ip_src and filter_ip not in ip_dst:
                continue

            proto_name = "OTHER"
            sport, dport = "-", "-"
            
            if pkt.haslayer(TCP):
                proto_name = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Extracción segura de payload
            payload_str = ""
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                try:
                    raw_payload = bytes(pkt[TCP].payload) if pkt.haslayer(TCP) else bytes(pkt[UDP].payload)
                    payload_str = raw_payload.decode('utf-8', errors='ignore')
                except:
                    pass

            is_sip = False
            # Verificamos puertos SIP estándar o si el texto contiene patrones reales de SIP
            if sport in (5060, 5061) or dport in (5060, 5061) or "SIP/2.0" in payload_str:
                # Buscar la línea exacta que contenga el método SIP para evitar basura binaria de túneles IPsec
                lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
                sip_line = None
                
                for line in lines:
                    if line.strip().startswith(VALID_SIP_METHODS):
                        sip_line = line.strip()
                        break
                
                # Si no encontramos la línea limpia exacta pero venía por puerto SIP, cogemos la primera línea si es legible
                if not sip_line and lines and sport in (5060, 5061):
                    clean_line = lines[0].strip()
                    if all(32 <= ord(c) < 127 for c in clean_line[:10]):  # Comprobar que es texto imprimible
                        sip_line = clean_line

                if sip_line:
                    is_sip = True
                    sip_messages.append({
                        "src": ip_src,
                        "dst": ip_dst,
                        "info": sip_line[:120],
                        "port": f"{sport} -> {dport}"
                    })

            packet_summaries.append({
                "src": ip_src,
                "dst": ip_dst,
                "protocol": proto_name,
                "sport": sport,
                "dport": dport,
                "length": len(pkt),
                "is_sip": is_sip
            })

        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                dns_queries.add(qname)
            except:
                pass

    return {
        "total_packets": len(packets),
        "filtered_packets": len(packet_summaries),
        "packets": packet_summaries[:200],
        "dns": list(dns_queries),
        "sip": sip_messages
    }