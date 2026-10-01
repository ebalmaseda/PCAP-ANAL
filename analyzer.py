from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
import re

VALID_SIP_METHODS = ("INVITE", "REGISTER", "BYE", "ACK", "OPTIONS", "SUBSCRIBE", "CANCEL", "SIP/2.0")

def extract_sip_number(header_line):
    if not header_line:
        return "Desconocido"
    match = re.search(r'sip:([^@;>]+)', header_line)
    if match:
        return match.group(1)
    return "Desconocido"

def analyze_pcap(file_path, filter_ip=None):
    dns_queries = set()
    sip_messages = []
    call_flows = {}
    tcp_connections = []
    devices = {}
    rtp_stats_map = {} # Para agrupar flujos de audio por IP/Puerto
    
    stats = {
        "total_packets": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "other_count": 0,
        "sip_errors": 0,
        "critical_errors": 0,
        "tcp_resets": 0,
        "rtp_packets": 0
    }

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        return {"error": str(e), "dns": [], "sip": [], "tcp": [], "rtp": [], "devices": {}, "stats": {}, "flows": {}, "verdict": {"level": "danger", "title": "Error", "desc": str(e), "recommendations": []}}

    stats["total_packets"] = len(packets)

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            
            if filter_ip and filter_ip not in ip_src and filter_ip not in ip_dst:
                continue

            sport, dport = "-", "-"
            
            if pkt.haslayer(TCP):
                stats["tcp_count"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                flag_str = str(flags)
                is_rst = 'R' in flag_str or flags & 0x04
                is_fin = 'F' in flag_str or flags & 0x01
                
                if is_rst:
                    stats["tcp_resets"] += 1

                tcp_status = "TCP Normal"
                status_level = "success"
                explanation = "Tráfico TCP fluido."
                if is_rst:
                    tcp_status = "RST (Corte de red)"
                    status_level = "danger"
                    explanation = "Corte abrupto de sesión (posible bloqueo de Firewall)."
                elif is_fin:
                    tcp_status = "FIN (Cierre)"
                    explanation = "Cierre ordenado."

                tcp_connections.append({
                    "src": ip_src, "dst": ip_dst, "port": f"{sport} ➔ {dport}",
                    "status_desc": tcp_status, "explanation": explanation, "level": status_level
                })

            elif pkt.haslayer(UDP):
                stats["udp_count"] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                
                # Excluir puertos conocidos como SIP (5060/5061) y DNS (53)
                if sport not in (5060, 5061, 53) and dport not in (5060, 5061, 53):
                    payload_len = len(pkt[UDP].payload)
                    # El RTP suele usar puertos efímeros altos (ej. > 1024 o > 5000)
                    if payload_len > 10: 
                        stats["rtp_packets"] += 1
                        flow_key = f"{ip_src}:{sport} ➔ {ip_dst}:{dport}"
                        if flow_key not in rtp_stats_map:
                            rtp_stats_map[flow_key] = {"stream": flow_key, "packets": 0, "bytes": 0}
                        rtp_stats_map[flow_key]["packets"] += 1
                        rtp_stats_map[flow_key]["bytes"] += len(pkt)
                        flow_key = f"{ip_src}:{sport} ➔ {ip_dst}:{dport}"
                        if flow_key not in rtp_stats_map:
                            rtp_stats_map[flow_key] = {"stream": flow_key, "packets": 0, "bytes": 0}
                        rtp_stats_map[flow_key]["packets"] += 1
                        rtp_stats_map[flow_key]["bytes"] += len(pkt)

            elif pkt.haslayer(ICMP):
                stats["icmp_count"] += 1
            else:
                stats["other_count"] += 1

            # Procesamiento SIP
            payload_str = ""
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                try:
                    raw_payload = bytes(pkt[TCP].payload) if pkt.haslayer(TCP) else bytes(pkt[UDP].payload)
                    payload_str = raw_payload.decode('utf-8', errors='ignore')
                except:
                    pass

            if sport in (5060, 5061) or dport in (5060, 5061) or "SIP/2.0" in payload_str:
                lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
                sip_line = None
                call_id = "Desconocido"
                from_num = "N/A"
                to_num = "N/A"
                
                for line in lines:
                    if line.strip().startswith(VALID_SIP_METHODS):
                        sip_line = line.strip()
                    if line.lower().startswith("call-id:"):
                        call_id = line.split(":", 1)[1].strip()
                    if line.lower().startswith("from:"):
                        from_num = extract_sip_number(line)
                    if line.lower().startswith("to:"):
                        to_num = extract_sip_number(line)

                if not sip_line and lines and sport in (5060, 5061):
                    clean_line = lines[0].strip()
                    if all(32 <= ord(c) < 127 for c in clean_line[:10]):
                        sip_line = clean_line

                if sip_line:
                    is_error = False
                    is_critical = False
                    status_code = 0
                    if "SIP/2.0 " in sip_line:
                        parts = sip_line.split(" ")
                        if len(parts) > 1 and parts[1].isdigit():
                            status_code = int(parts[1])
                            if status_code >= 400 and status_code not in (401, 407):
                                is_error = True
                                stats["sip_errors"] += 1
                                if status_code in (404, 486, 503, 408, 603):
                                    is_critical = True
                                    stats["critical_errors"] += 1

                    if ip_src not in devices and from_num != "N/A":
                        devices[ip_src] = {"ip": ip_src, "extension": from_num, "status": "Endpoint / Terminal"}
                    if ip_dst not in devices and to_num != "N/A" and to_num != "Desconocido":
                        devices[ip_dst] = {"ip": ip_dst, "extension": to_num, "status": "Servidor / Destino"}

                    msg_data = {
                        "src_ip": ip_src, "dst_ip": ip_dst, "from_num": from_num, "to_num": to_num,
                        "info": sip_line[:100], "is_error": is_error, "is_critical": is_critical
                    }
                    sip_messages.append(msg_data)
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    call_flows[call_id].append(msg_data)

        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                dns_queries.add(qname)
            except:
                pass

    # Veredicto y recomendaciones
    recommendations = []
    if stats["tcp_resets"] > 0:
        verdict = {"level": "danger", "title": "🚨 Causa Raíz: Corte de Red (TCP RST)", "desc": "Cortes violentos detectados en la red."}
        recommendations = ["Verifique reglas de Firewall y estado del puerto en el switch Cisco Meraki."]
    elif stats["critical_errors"] > 0:
        verdict = {"level": "danger", "title": "🚨 Causa Raíz: Llamada Rechazada", "desc": "Errores críticos en la centralita (ej. 486 Ocupado)."}
        recommendations = ["Compruebe el estado del usuario de destino o el plan de marcación."]
    else:
        verdict = {"level": "success", "title": "✅ Tráfico Saludable", "desc": "Operativa normal de red y voz."}
        recommendations = ["Infraestructura en estado óptimo."]

    return {
        "total_packets": stats["total_packets"],
        "dns": list(dns_queries),
        "sip": sip_messages,
        "tcp": tcp_connections[:150],
        "rtp": list(rtp_stats_map.values()),
        "devices": list(devices.values()),
        "stats": stats,
        "flows": call_flows,
        "verdict": verdict,
        "recommendations": recommendations
    }