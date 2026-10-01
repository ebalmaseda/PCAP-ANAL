from scapy.all import IP, UDP, wrpcap
from scapy.packet import Raw

def create_complex_sip_pcap(filename="complex_iv_transfer_trace.pcap"):
    packets = []
    
    # IPs de los actores en la red VoIP
    phone_client = "192.168.10.50"    # Extremo del cliente / usuario
    pbx_ivr = "10.200.100.1"          # Centralita / IVR Corporativo
    agent_extension = "192.168.10.75" # Puesto del agente receptor / transferencia
    
    # -------------------------------------------------------------------------
    # ESCENARIO 1: LLAMADA A IVR + DTMF + TRANSFERENCIA EXITOSA
    # -------------------------------------------------------------------------
    
    # 1. El cliente marca al IVR principal
    call1_id = "ivrcall-complex-998877@192.168.10.50"
    branch1 = "z9hG4bK-ivr-01"
    
    invite_ivr = (
        "INVITE sip:ivrmenu@10.200.100.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch1}\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:cliente@" + phone_client + ":5060>\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=phone_client, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=invite_ivr))
    
    # Respuesta del IVR: Trying y Ringing/Session Progress
    trying_ivr = (
        "SIP/2.0 100 Trying\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch1}\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>;tag=ivrtag11\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=pbx_ivr, dst=phone_client) / UDP(sport=5060, dport=5060) / Raw(load=trying_ivr))
    
    ok_ivr = (
        "SIP/2.0 200 OK\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch1}\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>;tag=ivrtag11\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=pbx_ivr, dst=phone_client) / UDP(sport=5060, dport=5060) / Raw(load=ok_ivr))
    
    ack_ivr = (
        f"ACK sip:ivrmenu@10.200.100.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch1}-ack\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>;tag=ivrtag11\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=phone_client, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=ack_ivr))

    # 2. El cliente interactúa con el IVR marcando la opción '2' (Simulado mediante INFO o paquete de control)
    dtmf_info = (
        "INFO sip:ivrmenu@10.200.100.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch=z9hG4bK-dtmf-2\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>;tag=ivrtag11\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 2 INFO\r\n"
        "Content-Type: application/dtmf-relay\r\n"
        "Content-Length: 12\r\n\r\n"
        "Signal= 2\r\nDuration= 160"
    )
    packets.append(IP(src=phone_client, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=dtmf_info))
    
    dtmf_200 = (
        "SIP/2.0 200 OK\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch=z9hG4bK-dtmf-2\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clienttag99\r\n"
        "To: <sip:ivrmenu@10.200.100.1>;tag=ivrtag11\r\n"
        f"Call-ID: {call1_id}\r\n"
        "CSeq: 2 INFO\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=pbx_ivr, dst=phone_client) / UDP(sport=5060, dport=5060) / Raw(load=dtmf_200))

    # 3. El IVR deriva/transfiere la llamada hacia la extensión del Agente especializado
    transfer_invite = (
        f"INVITE sip:agent_support@{agent_extension}:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.200.100.1:5060;branch=z9hG4bK-transfer-to-agent\r\n"
        "From: <sip:ivrmenu@10.200.100.1>;tag=transfertag55\r\n"
        f"To: <sip:agent_support@{agent_extension}>\r\n"
        f"Call-ID: transfer-call-id-555@10.200.100.1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=pbx_ivr, dst=agent_extension) / UDP(sport=5060, dport=5060) / Raw(load=transfer_invite))
    
    transfer_ok = (
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 10.200.100.1:5060;branch=z9hG4bK-transfer-to-agent\r\n"
        "From: <sip:ivrmenu@10.200.100.1>;tag=transfertag55\r\n"
        f"To: <sip:agent_support@{agent_extension}>;tag=agenttag77\r\n"
        f"Call-ID: transfer-call-id-555@10.200.100.1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=agent_extension, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=transfer_ok))

    # -------------------------------------------------------------------------
    # ESCENARIO 2: LLAMADA FALLIDA (KO) - EXTENSIÓN OCUPADA O RECHAZADA
    # -------------------------------------------------------------------------
    
    call2_id = "failed-call-ko-443322@192.168.10.50"
    branch2 = "z9hG4bK-fail-01"
    
    invite_ko = (
        "INVITE sip:ext_ocupada@10.200.100.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch2}\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clientfail88\r\n"
        "To: <sip:ext_ocupada@10.200.100.1>\r\n"
        f"Call-ID: {call2_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=phone_client, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=invite_ko))
    
    # La centralita responde con un código de error SIP 486 Busy Here (Esto generará la alerta roja en tu app)
    busy_ko = (
        "SIP/2.0 486 Busy Here\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch2}\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clientfail88\r\n"
        "To: <sip:ext_ocupada@10.200.100.1>;tag=destbusy99\r\n"
        f"Call-ID: {call2_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=pbx_ivr, dst=phone_client) / UDP(sport=5060, dport=5060) / Raw(load=busy_ko))
    
    ack_ko = (
        "ACK sip:ext_ocupada@10.200.100.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {phone_client}:5060;branch={branch2}-ack\r\n"
        f"From: <sip:cliente@10.200.100.1>;tag=clientfail88\r\n"
        "To: <sip:ext_ocupada@10.200.100.1>;tag=destbusy99\r\n"
        f"Call-ID: {call2_id}\r\n"
        "CSeq: 1 ACK\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packets.append(IP(src=phone_client, dst=pbx_ivr) / UDP(sport=5060, dport=5060) / Raw(load=ack_ko))

    # Guardar traza compleja
    wrpcap(filename, packets)
    print(f"[+] Archivo PCAP complejo generado con éxito: {filename}")

if __name__ == "__main__":
    create_complex_sip_pcap()