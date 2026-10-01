from scapy.utils import rdpcap
from datetime import datetime
from collections import defaultdict
from scapy.layers.inet import IP



# ==========================================
# SERVICIOS CONOCIDOS
# ==========================================

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    5060: "SIP",
    5061: "SIP-TLS",
    3389: "RDP"
}


def get_service(src_port, dst_port):

    if src_port in COMMON_PORTS:
        return COMMON_PORTS[src_port]

    if dst_port in COMMON_PORTS:
        return COMMON_PORTS[dst_port]

    return "OTHER"

# ==========================================
# CONVERSOR DE UNIDADES
# ==========================================    

def format_bytes(num_bytes):

    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"

    if num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"

    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.2f} KB"

    return f"{num_bytes} B"
 
# ==========================================
# EXTRACTOR DNS
# ==========================================    

import re

def extract_domains_from_dns_payload(payload):

    domains = []

    try:

        i = 12  # DNS header

        labels = []

        while i < len(payload):

            length = payload[i]

            if length == 0:

                if labels:

                    domain = ".".join(labels)

                    if (
                        "." in domain
                        and
                        "in-addr.arpa" not in domain
                    ):
                        domains.append(
                            domain.lower()
                        )

                labels = []
                i += 1
                continue

            # compresión DNS
            if length >= 192:
                break

            if (
                length < 1
                or
                length > 63
            ):
                break

            i += 1

            if i + length > len(payload):
                break

            label = payload[
                i:i + length
            ].decode(
                "ascii",
                errors="ignore"
            )

            labels.append(label)

            i += length

    except Exception:
        pass

    return domains


# ==========================================
# ANALIZADOR PRINCIPAL
# ==========================================

def analyze_pcap(filepath):

    packets = rdpcap(filepath)

    total_packets = len(packets)
    total_bytes = 0

    packet_sizes = []
    timestamps = []

    protocols = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "OTHER": 0
    }

    hosts = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )

    flows = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )
    
    conversations = defaultdict(
        lambda: {
            "packets_ab": 0,
            "packets_ba": 0,
            "bytes_ab": 0,
            "bytes_ba": 0
        }
    )

    services = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )

    ports = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )

    dns_servers = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )
    
    dns_clients = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )

    dns_conversations = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0
        }
    )

    dns_queries = []
    dns_domains = defaultdict(int)

    sip_messages = []
    sip_errors = []

    rtp_streams = []

    tls_sessions = []

    timeline = defaultdict(int)

    # ==========================================
    # RECORRIDO DE PAQUETES
    # ==========================================

    for pkt in packets:

        size = len(pkt)

        total_bytes += size

        packet_sizes.append(size)

        try:

            ts = float(pkt.time)

            timestamps.append(ts)

            timeline[int(ts)] += 1

        except Exception:
            pass

        try:

            raw = bytes(pkt)

            if len(raw) < 38:
                continue

            protocol_num = raw[23]

            if protocol_num == 6:

                proto_name = "TCP"
                protocols["TCP"] += 1

            elif protocol_num == 17:

                proto_name = "UDP"
                protocols["UDP"] += 1

            elif protocol_num == 1:

                proto_name = "ICMP"
                protocols["ICMP"] += 1

            else:

                proto_name = "OTHER"
                protocols["OTHER"] += 1

            from scapy.layers.inet import IP

            src_port = 0
            dst_port = 0

            if proto_name in ["TCP", "UDP"]:

                src_port = (
                    raw[34] << 8
                ) + raw[35]

                dst_port = (
                    raw[36] << 8
                ) + raw[37]

            service = get_service(
                src_port,
                dst_port
            )

            # HOSTS

            for ip in [src_ip, dst_ip]:

                hosts[ip]["packets"] += 1
                hosts[ip]["bytes"] += size

            # FLOWS

            flow_key = (
                src_ip,
                dst_ip,
                proto_name,
                src_port,
                dst_port
            )

            flows[flow_key]["packets"] += 1
            flows[flow_key]["bytes"] += size
            
            # CONVERSATIONS
            
            host_a = min(src_ip, dst_ip)
            host_b = max(src_ip, dst_ip)

            conversation_key = (
                host_a,
                host_b,
                service
            )

            if src_ip == host_a:

                conversations[conversation_key]["packets_ab"] += 1
                conversations[conversation_key]["bytes_ab"] += size

            else:

                conversations[conversation_key]["packets_ba"] += 1
                conversations[conversation_key]["bytes_ba"] += size

            # SERVICES

            services[service]["packets"] += 1
            services[service]["bytes"] += size

            # PORTS

            if src_port:

                ports[src_port]["packets"] += 1
                ports[src_port]["bytes"] += size

            if dst_port:

                ports[dst_port]["packets"] += 1
                ports[dst_port]["bytes"] += size

            # ==========================================
            # DNS
            # ==========================================

            if service == "DNS":

                # DNS DOMAINS

                try:

                    payload = raw[42:200]

                    print("RAW DNS")
                    print(repr(payload[:120]))

                    domains = extract_domains_from_dns_payload(
                        payload
                    )

                    print(domains[:5])

                    for domain in domains:

                        dns_domains[domain] += 1

                except Exception:
                    pass

                # DNS QUERIES

                dns_queries.append(
                    {
                        "src": src_ip,
                        "dst": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "bytes": size
                    }
                )

                # DNS SERVER

                dns_server = None

                if src_port == 53:

                    dns_server = src_ip

                elif dst_port == 53:

                     dns_server = dst_ip

                if dns_server:

                    dns_servers[dns_server]["packets"] += 1
                    dns_servers[dns_server]["bytes"] += size

                # DNS CLIENT

                dns_client = None

                if dst_port == 53:

                    dns_client = src_ip

                elif src_port == 53:

                    dns_client = dst_ip

                if dns_client:

                    dns_clients[dns_client]["packets"] += 1
                    dns_clients[dns_client]["bytes"] += size

                # DNS CLIENT <-> SERVER

                if dns_client and dns_server:

                    dns_conversations[
                        (
                            dns_client,
                            dns_server
                        )
                    ]["packets"] += 1

                    dns_conversations[
                        (
                            dns_client,
                            dns_server
                        )
                    ]["bytes"] += size

            # ==========================================
            # SIP
            # ==========================================

            if service in ["SIP", "SIP-TLS"]:

                sip_messages.append(
                    {
                        "src": src_ip,
                        "dst": dst_ip,
                        "bytes": size
                    }
                )

            # ==========================================
            # RTP
            # ==========================================
            # Pendiente de implementar correctamente

            # ==========================================
            # TLS
            # ==========================================

            if service == "HTTPS":

                tls_sessions.append(
                    {
                        "src": src_ip,
                        "dst": dst_ip,
                        "bytes": size
                    }
                )


        except Exception:
            pass

    # ==========================================
    # RESUMEN
    # ==========================================

    avg_packet_size = 0

    if total_packets > 0:

        avg_packet_size = round(
            total_bytes / total_packets,
            2
        )

    start_time = None
    end_time = None
    duration = 0

    if timestamps:

        start_time = datetime.fromtimestamp(
            min(timestamps)
        )

        end_time = datetime.fromtimestamp(
            max(timestamps)
        )

        duration = round(
            max(timestamps) - min(timestamps),
            2
        )

    # TOP PAQUETES

    largest_packets = sorted(
        packet_sizes,
        reverse=True
    )[:10]

    # HOSTS

    host_list = sorted(
        [
            {
                "ip": ip,
                "packets": data["packets"],
                "bytes": data["bytes"]
            }
            for ip, data in hosts.items()
        ],
        key=lambda x: x["bytes"],
        reverse=True
    )[:25]

    # FLOWS

    flow_list = sorted(
        [
            {
                "src": key[0],
                "dst": key[1],
                "protocol": key[2],
                "src_port": key[3],
                "dst_port": key[4],
                "service": get_service(
                    key[3],
                    key[4]
                ),
                "packets": value["packets"],
                "bytes": value["bytes"]
            }
            for key, value in flows.items()
        ],
        key=lambda x: x["bytes"],
        reverse=True
    )[:50]

    # SERVICIOS

    service_list = sorted(
        [
            {
                "service": service,
                "packets": data["packets"],
                "bytes": data["bytes"]
            }
            for service, data in services.items()
        ],
        key=lambda x: x["bytes"],
        reverse=True
    )

    # PUERTOS

    port_list = sorted(
        [
            {
                "port": port,
                "packets": data["packets"],
                "bytes": data["bytes"]
            }
            for port, data in ports.items()
        ],
        key=lambda x: x["bytes"],
        reverse=True
    )[:25]

    # DNS

    dns_server_list = sorted(
        [
            {
                "ip": ip,
                "packets": data["packets"],
                "bytes": data["bytes"]
            }
            for ip, data in dns_servers.items()
        ],
        key=lambda x: x["bytes"],
        reverse=True
    )

    # TIMELINE

    timeline_list = []

    if timestamps:

        base_time = int(min(timestamps))

        timeline_list = sorted(
            [
                {
                    "second": second - base_time,
                    "packets": packet_count
                }
                for second, packet_count in timeline.items()
            ],
            key=lambda x: x["second"]
        )
        
    # CONVERSATIONS LIST
    
    conversation_list = sorted(
        [
            {
                "host_a": key[0],
                "host_b": key[1],
                "service": key[2],

                "packets_ab": value["packets_ab"],
                "packets_ba": value["packets_ba"],

                "bytes_ab": value["bytes_ab"],
                "bytes_ba": value["bytes_ba"],

                "packets_total":
                    value["packets_ab"] +
                    value["packets_ba"],

                "bytes_total":
                    value["bytes_ab"] +
                    value["bytes_ba"]
            }
            for key, value in conversations.items()
        ],
        key=lambda x: x["bytes_total"],
        reverse=True
    )[:25]
    #print(conversation_list[:5])


    dns_client_list = sorted(
        [
            {
                "ip": ip,
                "packets": data["packets"],
                "bytes": data["bytes"]
            }
            for ip, data in dns_clients.items()
        ],
        key=lambda x: x["packets"],
        reverse=True
    )

    dns_conversation_list = sorted(
        [
            {
                "client": key[0],
                "server": key[1],
                "packets": value["packets"],
                "bytes": value["bytes"]
            }
            for key, value in dns_conversations.items()
        ],
        key=lambda x: x["packets"],
        reverse=True
    )
    
    dns_domain_list = sorted(
        [
            {
                "domain": domain,
                "count": count
            }
            for domain, count in dns_domains.items()
        ],
        key=lambda x: x["count"],
        reverse=True
    )[:50]

    # ALERTAS

    alerts = []

    # ==========================================
    # LARGE TRANSFER
    # ==========================================

    for conv in conversation_list:

        if conv["bytes_total"] > 10_000_000:

            alerts.append(
                {
                    "severity": "INFO",
                    "type": "LARGE_TRANSFER",
                    "description":
                        f'{conv["host_a"]} <-> {conv["host_b"]} '
                        f'({format_bytes(conv["bytes_total"])})'
                }
            )
            
    # ==========================================
    # UNKNOWN HIGH VOLUME
    # ==========================================

    for conv in conversation_list:

        if (
            conv["service"] == "OTHER"
            and
            conv["bytes_total"] > 100000
        ):

            alerts.append(
                {
                    "severity": "INFO",
                    "type": "UNKNOWN_HIGH_VOLUME",
                    "description":
                        f'{conv["host_a"]} <-> {conv["host_b"]} '
                        f'({format_bytes(conv["bytes_total"])})'
                }
            )
    
    # ==========================================
    # ONE WAY TRAFFIC
    # ==========================================

    for conv in conversation_list:

        if (
            conv["packets_ab"] > 100
            and
            conv["packets_ba"] == 0
        ):

            alerts.append(
                {
                    "severity": "HIGH",
                    "type": "ONE_WAY_TRAFFIC",
                    "description":
                        f'{conv["host_a"]} -> {conv["host_b"]} '
                        f'sin respuesta'
                }
            )

        elif (
            conv["packets_ba"] > 100
            and
            conv["packets_ab"] == 0
        ):

            alerts.append(
                {
                    "severity": "HIGH",
                    "type": "ONE_WAY_TRAFFIC",
                    "description":
                        f'{conv["host_b"]} -> {conv["host_a"]} '
                        f'sin respuesta'
                }
            )

    # ==========================================
    # SERVICE CONCENTRATION
    # ==========================================

    if service_list:

        top_service = service_list[0]

        percentage = (
            top_service["bytes"] /
            total_bytes
        ) * 100

        if percentage > 80:

            alerts.append(
                {
                    "severity": "INFO",
                    "type": "SERVICE_CONCENTRATION",
                    "description":
                        f'{top_service["service"]} '
                        f'consume {percentage:.1f}% '
                        f'del tráfico'
                }
            )

    # ==========================================
    # SINGLE DNS DEPENDENCY
    # ==========================================

    if dns_server_list:

        top_dns = dns_server_list[0]

        total_dns_packets = sum(
            s["packets"]
            for s in dns_server_list
        )

        if total_dns_packets:

            percentage = (
                top_dns["packets"] /
                total_dns_packets
            ) * 100

            if percentage > 90:

                alerts.append(
                    {
                        "severity": "INFO",
                        "type": "SINGLE_DNS_DEPENDENCY",
                        "description":
                            f'{top_dns["ip"]} '
                            f'atiende {percentage:.1f}% '
                            f'del tráfico DNS'
                    }
                )
                
    # ==========================================
    # MULTIPLE DNS SERVERS
    # ==========================================

    if len(dns_server_list) > 3:

        alerts.append(
            {
                "severity": "INFO",
                "type": "MULTIPLE_DNS_SERVERS",
                "description":
                    f'{len(dns_server_list)} servidores DNS detectados'
            }
        )
        
    # print(alerts)

    # print("DNS CLIENTS")
    # print(dns_client_list[:10])

    # print("DNS CONVERSATIONS")
    # print(dns_conversation_list[:10])

    print("DNS DOMAINS LEN")
    print(len(dns_domain_list))

    print(dns_domain_list[:20])


    return {

        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_packet_size,
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration
        },

        "protocols": protocols,

        "largest_packets": largest_packets,

        "hosts": host_list,

        "services": service_list,

        "ports": port_list,

        "flows": flow_list,
        
        "conversations": conversation_list,

        "dns": {
            "enabled": len(dns_queries) > 0,

            "query_count": len(dns_queries),

            "servers": dns_server_list,

            "clients": dns_client_list,

            "conversations": dns_conversation_list,
            
            "domains": dns_domain_list,

            "queries": dns_queries[:100]
        },

        "sip": {
            "enabled": len(sip_messages) > 0,
            "messages": sip_messages[:100],
            "errors": sip_errors
        },

        "rtp": {
            "enabled": False,
            "streams": []
        },

        "tls": {
            "enabled": len(tls_sessions) > 0,
            "sessions": len(tls_sessions)
        },

        "timeline": timeline_list,

        "alerts": alerts

    }