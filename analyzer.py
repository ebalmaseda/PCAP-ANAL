from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import re
import base64

VALID_SIP_METHODS = ("INVITE", "REGISTER", "BYE", "ACK", "OPTIONS", "SUBSCRIBE", "CANCEL", "SIP/2.0")

def extract_sip_number(header_line):
    if not header_line:
        return "Desconocido"
    match = re.search(r'sip:([^@;>]+)', header_line)
    if match:
        return match.group(1)
    return "Desconocido"

def get_tcp_flags_desc(flags):
    flag_list = []
    if 'S' in str(flags) or flags & 0x02: flag_list.append("SYN")
    if 'A' in str(flags) or flags & 0x10: flag_list.append("ACK")
    if 'F' in str(flags) or flags & 0x01: flag_list.append("FIN")
    if 'R' in str(flags) or flags & 0x04: flag_list.append("RST")
    if 'P' in str(flags) or flags & 0x08: flag_list.append("PSH")
    return "+".join(flag_list) if flag_list else str(flags)

def analyze_stream_health(packets):
    """Analiza los paquetes de un stream y devuelve un diagnóstico experto."""
    syn_count = 0
    syn_ack_count = 0
    retrans_count = 0
    has_rst = False
    has_fin = False
    has_data = False

    for pkt in packets:
        flags = pkt["flags"]
        if "SYN" in flags and "ACK" not in flags:
            syn_count += 1
        elif "SYN" in flags and "ACK" in flags:
            syn_ack_count += 1
        if "RST" in flags:
            has_rst = True
        if "FIN" in flags:
            has_fin = True
        if "Len: 0" not in pkt["explanation"] and "Payload vacío" not in pkt["explanation"]:
            has_data = True
        if "Retransmission" in pkt["explanation"] or (syn_count > 1 and "SYN" in flags):
            retrans_count += 1

    # Heurísticas de diagnóstico
    if has_rst:
        return "danger", "🔴 Cortado por Firewall / RST (Conexión reseteada violentamente)"
    elif syn_count > 0 and syn_ack_count == 0:
        return "danger", "⚠️ Destino Inaccesible / Filtrado (SYN sin respuesta - Posible bloqueo de Fortinet)"
    elif syn_count > 0 and syn_ack_count > 0 and retrans_count > 2:
        return "warning", "🟠 Problemas de Red / Retransmisiones masivas en el Handshake"
    elif has_fin or has_data:
        return "success", "🟢 Sesión Fluida / Completada con éxito"
    else:
        return "info", "🔵 Tráfico TCP Estándar"

def clean_payload_text(payload_bytes, dport, sport):
    if not payload_bytes:
        return "Segmento sin carga útil (Payload vacío / Control TCP puro)."
    
    if dport == 53 or sport == 53:
        return f"[Protocolo DNS - Consulta/Respuesta]\nTamaño del payload: {len(payload_bytes)} bytes."
    elif dport == 443 or sport == 443:
        return f"[Tráfico TLS / HTTPS - Puerto 443]\n🔒 Sesión cifrada extremo a extremo.\nLongitud del segmento: {len(payload_bytes)} bytes."

    try:
        text = payload_bytes.decode('utf-8', errors='strict')
        printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t") / len(text)
        if printable_ratio < 0.7:
            raise ValueError("Tráfico binario")
        return text.strip()
    except:
        hex_preview = " ".join(f"{b:02X}" for b in payload_bytes[:32])
        if len(payload_bytes) > 32:
            hex_preview += " ..."
        return (
            f"📦 [Datos Binarios de Capa de Aplicación]\n"
            f"--------------------------------------------------\n"
            f"• Puertos: {sport} ➔ {dport}\n"
            f"• Tamaño payload: {len(payload_bytes)} bytes.\n"
            f"• Vista Hexadecimal:\n{hex_preview}"
        )

def analyze_pcap(file_path, filter_ip=None):
    sip_messages = []
    call_flows = {}
    tcp_streams = {}
    raw_errors = []
    devices = {}
    
    stats = {
        "total_packets": 0, "tcp_count": 0, "udp_count": 0, 
        "sip_errors": 0, "critical_errors": 0, "tcp_resets": 0
    }

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        return {
            "error": str(e), "sip": [], "tcp_streams": {}, "errors": [], 
            "devices": [], "stats": {}, "flows": {}, 
            "verdict": {"level": "danger", "title": "Error de Lectura", "desc": str(e)}
        }

    stats["total_packets"] = len(packets)

    for idx, pkt in enumerate(packets):
        pkt_num = idx + 1
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            
            if filter_ip and filter_ip not in ip_src and filter_ip not in ip_dst:
                continue

            sport, dport = "-", "-"
            payload_bytes = b""
            
            if pkt.haslayer(TCP):
                stats["tcp_count"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                flags_str = get_tcp_flags_desc(flags)
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                window = pkt[TCP].window
                
                is_rst = 'R' in flags_str
                is_fin = 'F' in flags_str
                
                if pkt[TCP].payload:
                    payload_bytes = bytes(pkt[TCP].payload)

                endpoint1 = (ip_src, sport)
                endpoint2 = (ip_dst, dport)
                stream_key = tuple(sorted([endpoint1, endpoint2], key=lambda x: (x[0], x[1])))
                stream_id = f"{stream_key[0][0]}:{stream_key[0][1]} ↔ {stream_key[1][0]}:{stream_key[1][1]}"

                if is_rst:
                    stats["tcp_resets"] += 1
                    raw_errors.append({
                        "pkt_index": pkt_num,
                        "type": "Seguridad / Firewall",
                        "summary": f"Corte de sesión (TCP RST) en stream {stream_id}",
                        "desc": f"El dispositivo de red ha reseteado la conexión violentamente entre {ip_src} y {ip_dst}."
                    })

                formatted_payload = clean_payload_text(payload_bytes, dport, sport)
                
                wireshark_inspect = (
                    f"Frame {pkt_num}: {len(pkt)} bytes on wire\n"
                    f"Stream ID: {stream_id}\n"
                    f"--------------------------------------------------\n"
                    f"INTERNET PROTOCOL VERSION 4 (IPv4)\n"
                    f"  • Source Address:      {ip_src}\n"
                    f"  • Destination Address: {ip_dst}\n"
                    f"  • Time to Live (TTL):  {pkt[IP].ttl}\n\n"
                    f"TRANSMISSION CONTROL PROTOCOL (TCP)\n"
                    f"  • Source Port:         {sport}\n"
                    f"  • Destination Port:    {dport}\n"
                    f"  • Sequence Number:     {seq}\n"
                    f"  • Acknowledgment Num:  {ack}\n"
                    f"  • Flags:               0x{int(flags):03x} [{flags_str}]\n"
                    f"  • Window Size:         {window}\n"
                    f"  • Segment Length:      {len(payload_bytes)} bytes\n"
                    f"--------------------------------------------------\n"
                    f"CARGA ÚTIL / PAYLOAD:\n{formatted_payload}"
                )

                b64_payload = base64.b64encode(wireshark_inspect.encode('utf-8', errors='ignore')).decode('utf-8')
                
                packet_item = {
                    "pkt_index": pkt_num,
                    "src": ip_src, 
                    "dst": ip_dst,
                    "port": f"{sport} ➔ {dport}",
                    "flags": flags_str,
                    "seq_ack": f"Seq: {seq} | Ack: {ack}",
                    "status_desc": f"TCP {flags_str}",
                    "explanation": f"Win: {window} | Len: {len(payload_bytes)} bytes",
                    "full_payload": b64_payload,
                    "is_rst": is_rst,
                    "is_fin": is_fin
                }

                if stream_id not in tcp_streams:
                    tcp_streams[stream_id] = {
                        "stream_id": stream_id,
                        "ip_a": stream_key[0][0],
                        "ip_b": stream_key[1][0],
                        "packets": []
                    }
                tcp_streams[stream_id]["packets"].append(packet_item)

            elif pkt.haslayer(UDP):
                stats["udp_count"] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if pkt[UDP].payload:
                    payload_bytes = bytes(pkt[UDP].payload)

            payload_str = payload_bytes.decode('utf-8', errors='ignore') if payload_bytes else ""

            if sport in (5060, 5061) or dport in (5060, 5061) or "SIP/2.0" in payload_str:
                lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
                sip_line = None
                call_id = "Desconocido"
                from_num, to_num = "N/A", "N/A"
                
                for line in lines:
                    if line.strip().startswith(VALID_SIP_METHODS):
                        sip_line = line.strip()
                    if line.lower().startswith("call-id:"):
                        call_id = line.split(":", 1)[1].strip()
                    if line.lower().startswith("from:"):
                        from_num = extract_sip_number(line)
                    if line.lower().startswith("to:"):
                        to_num = extract_sip_number(line)

                if sip_line:
                    is_critical = False
                    status_code = 0
                    if "SIP/2.0 " in sip_line:
                        parts = sip_line.split(" ")
                        if len(parts) > 1 and parts[1].isdigit():
                            status_code = int(parts[1])
                            if status_code >= 400 and status_code not in (401, 407):
                                stats["sip_errors"] += 1
                                if status_code in (404, 486, 503, 408, 603):
                                    is_critical = True
                                    stats["critical_errors"] += 1
                                    raw_errors.append({
                                        "pkt_index": pkt_num,
                                        "type": "Proveedor / Centralita",
                                        "summary": f"Llamada rechazada (Código SIP {status_code})",
                                        "desc": f"Motivo: {sip_line}"
                                    })

                    if ip_src not in devices and from_num != "N/A":
                        devices[ip_src] = {"ip": ip_src, "extension": from_num, "role": "Terminal / IP Phone"}

                    b64_sip_payload = base64.b64encode(payload_str.encode('utf-8', errors='ignore')).decode('utf-8')
                    msg_data = {
                        "pkt_index": pkt_num,
                        "src_ip": ip_src, "dst_ip": ip_dst,
                        "from_num": from_num, "to_num": to_num,
                        "info": sip_line[:100], "full_payload": b64_sip_payload,
                        "is_critical": is_critical
                    }
                    sip_messages.append(msg_data)
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    call_flows[call_id].append(msg_data)

    # Post-procesado: Calcular salud de cada stream mediante IA heurística
    for s_id, s_data in tcp_streams.items():
        level, diagnosis = analyze_stream_health(s_data["packets"])
        s_data["health_level"] = level
        s_data["diagnosis"] = diagnosis

    grouped_errors = {}
    for err in raw_errors:
        key = (err["type"], err["summary"])
        if key not in grouped_errors:
            grouped_errors[key] = {
                "type": err["type"], "summary": err["summary"],
                "desc": err["desc"], "first_pkt": err["pkt_index"], "count": 1
            }
        else:
            grouped_errors[key]["count"] += 1

    clean_errors = list(grouped_errors.values())

    if stats["tcp_resets"] > 0 or stats["critical_errors"] > 0:
        verdict = {
            "level": "danger", 
            "title": "🚨 Incidencia Detectada en la Infraestructura", 
            "desc": "Se han localizado cortes de red o rechazos de llamadas. Revisa el resumen de alertas inferior."
        }
    else:
        verdict = {
            "level": "success", 
            "title": "✅ Tráfico de Oficina Saludable", 
            "desc": "No se aprecian anomalías críticas de red ni en la centralita."
        }

    return {
        "total_packets": stats["total_packets"],
        "sip": sip_messages, 
        "tcp_streams": tcp_streams,
        "errors": clean_errors, 
        "devices": list(devices.values()),
        "stats": stats, 
        "flows": call_flows, 
        "verdict": verdict
    }