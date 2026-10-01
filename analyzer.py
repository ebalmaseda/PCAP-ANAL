from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import re

VALID_SIP_METHODS = ("INVITE", "REGISTER", "BYE", "ACK", "OPTIONS", "SUBSCRIBE", "CANCEL", "SIP/2.0")

def extract_sip_number(header_line):
    if not header_line:
        return "Desconocido"
    match = re.search(r'sip:([^@;>]+)', header_line)
    if match:
        return match.group(1)
    return "Desconocido"

def clean_payload_text(payload_bytes, dport, sport):
    """Limpia y da formato legible al payload según el tipo de tráfico"""
    if not payload_bytes:
        return "Paquete sin carga útil (Payload vacío)."
    
    # Identificar puertos comunes
    if dport == 53 or sport == 53:
        return f"[Protocolo DNS - Consulta/Respuesta de Nombres]\nDatos binarios / consulta analizada en puerto 53.\nTamaño del payload: {len(payload_bytes)} bytes."
    elif dport == 443 or sport == 443:
        return f"[Tráfico Segurizado TLS / HTTPS - Puerto 443]\n🔒 Los datos de esta sesión están cifrados extremo a extremo por seguridad.\nLongitud del segmento: {len(payload_bytes)} bytes."
    
    # Intentar decodificar como texto plano legible limpiando caracteres extraños
    try:
        text = payload_bytes.decode('utf-8', errors='ignore')
        # Filtrar caracteres de control no imprimibles si hay mucho ruido binario
        clean_text = "".join(ch if ord(ch) >= 32 or ch in "\n\r\t" else "." for ch in text)
        return clean_text.strip()
    except:
        return f"[Datos binarios no legibles]\nTamaño: {len(payload_bytes)} bytes."

def analyze_pcap(file_path, filter_ip=None):
    sip_messages = []
    call_flows = {}
    tcp_connections = []
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
            "error": str(e), "sip": [], "tcp": [], "errors": [], 
            "devices": [], "stats": {}, "flows": {}, 
            "verdict": {"level": "danger", "title": "Error de Lectura", "desc": str(e)}
        }

    stats["total_packets"] = len(packets)

    for idx, pkt in enumerate(packets):
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
                is_rst = 'R' in str(flags) or flags & 0x04
                is_fin = 'F' in str(flags) or flags & 0x01
                
                if pkt[TCP].payload:
                    payload_bytes = bytes(pkt[TCP].payload)

                if is_rst:
                    stats["tcp_resets"] += 1
                    raw_errors.append({
                        "pkt_index": idx + 1,
                        "type": "Seguridad / Firewall",
                        "summary": f"Corte de sesión (TCP RST) entre {ip_src} y {ip_dst}",
                        "desc": "El Fortinet o dispositivo de red ha reseteado la conexión violentamente."
                    })

                if len(tcp_connections) < 1000:
                    formatted_payload = clean_payload_text(payload_bytes, dport, sport)
                    tcp_connections.append({
                        "pkt_index": idx + 1,
                        "src": ip_src, "dst": ip_dst,
                        "port": f"{sport} ➔ {dport}",
                        "status_desc": "RST (Corte)" if is_rst else ("FIN (Cierre)" if is_fin else "TCP Normal"),
                        "explanation": "Corte abrupto de sesión." if is_rst else "Tráfico TCP fluido.",
                        "full_payload": formatted_payload,
                        "level": "danger" if is_rst else "success"
                    })

            elif pkt.haslayer(UDP):
                stats["udp_count"] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if pkt[UDP].payload:
                    payload_bytes = bytes(pkt[UDP].payload)

            # Procesamiento de SIP
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
                                        "pkt_index": idx + 1,
                                        "type": "Proveedor / Centralita",
                                        "summary": f"Llamada rechazada (Código SIP {status_code})",
                                        "desc": f"Motivo: {sip_line}"
                                    })

                    if ip_src not in devices and from_num != "N/A":
                        devices[ip_src] = {"ip": ip_src, "extension": from_num, "role": "Terminal / IP Phone"}

                    msg_data = {
                        "pkt_index": idx + 1,
                        "src_ip": ip_src, "dst_ip": ip_dst,
                        "from_num": from_num, "to_num": to_num,
                        "info": sip_line[:100], "full_payload": payload_str,
                        "is_critical": is_critical
                    }
                    sip_messages.append(msg_data)
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    call_flows[call_id].append(msg_data)

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
        "sip": sip_messages, "tcp": tcp_connections,
        "errors": clean_errors, "devices": list(devices.values()),
        "stats": stats, "flows": call_flows, "verdict": verdict
    }