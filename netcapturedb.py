from scapy.all import *
import sqlite3
import click
import colorama
import sys
from colorama import Fore, Style

# Inicializar colorama para colores en la consola
colorama.init()

control_chars = {
    b'\x00': "NUL (Null)",
    b'\x01': "SOH (Start of Heading)",
    b'\x02': "STX (Start of Text)",
    b'\x03': "ETX (End of Text)",
    b'\x04': "EOT (End of Transmission)",
    b'\x05': "ENQ (Enquiry)",
    b'\x06': "ACK (Acknowledge)",
    b'\x07': "BEL (Bell)",
    b'\x08': "BS (Backspace)",
    b'\x09': "HT (Horizontal Tabulation)",
    b'\x0A': "LF (Line Feed)",
    b'\x0B': "VT (Vertical Tabulation)",
    b'\x0C': "FF (Form Feed)",
    b'\x0D': "CR (Carriage Return)",
    b'\x0E': "SO (Shift Out)",
    b'\x0F': "SI (Shift In)",
    b'\x10': "DLE (Data Link Escape)",
    b'\x11': "DC1 (Device Control 1)",
    b'\x12': "DC2 (Device Control 2)",
    b'\x13': "DC3 (Device Control 3)",
    b'\x14': "DC4 (Device Control 4)",
    b'\x15': "NAK (Negative Acknowledge)",
    b'\x16': "SYN (Synchronous Idle)",
    b'\x17': "ETB (End of Transmission Block)",
    b'\x18': "CAN (Cancel)",
    b'\x19': "EM (End of Medium)",
    b'\x1A': "SUB (Substitute)",
    b'\x1B': "ESC (Escape)",
    b'\x1C': "FS (File Separator)",
    b'\x1D': "GS (Group Separator)",
    b'\x1E': "RS (Record Separator)",
    b'\x1F': "US (Unit Separator)",
    b'\x7F': "DEL (Delete)"
}

@click.command()
@click.option('--all', help='Captura todo el tráfico de red')
@click.option('--loop', help='Captura de tráfico en tiempo real')
@click.option('--ip', help='Filtrar por dirección IP')
@click.option('--port', help='Filtrar por puerto')
@click.option('--protocol', help='Filtrar por tipo de protocolo')
@click.option('--save-db', help='Guardar resultados en la base de datos')
@click.option('--generate-report', help='Generar reporte en formato especificado')
@click.option('--remote-capture', help='Captura de tráfico en una interfaz remota')
@click.option('--count', default=10, help='Número de paquetes a capturar')

def help():
    """Muestra ayuda sobre los comandos disponibles"""
    click.echo("Comandos disponibles:")
    click.echo("- capturar_trafico: Captura el tráfico de red con opciones de filtrado.")
    click.echo("- analizar_http: Analiza paquetes HTTP.")
    click.echo("- analizar_dns: Analiza paquetes DNS.")
    click.echo("- all: Captura todo el tráfico de red.")
    click.echo("- loop: Captura de tráfico en tiempo real.")
    click.echo("- ip: Filtrar por dirección IP.")
    click.echo("- port: Filtrar por puerto.")
    click.echo("- protocol: Filtrar por tipo de protocolo.")
    click.echo("- save-db: Guardar resultados en la base de datos.")
    click.echo("- generate-report: Generar reporte en formato especificado.")
    click.echo("- remote-capture: Captura de tráfico en una interfaz remota.")
    click.echo("- count: Número de paquetes a capturar.")

def capturar_trafico(count):
    sniff(prn=analizar_protocolos, count=count)
    sniff(prn=analizar_https, filter="tcp port 443", store=False)
    sniff(prn=analizar_ftp, filter="tcp port 21", store=False)
    sniff(prn=analizar_smtp, filter="tcp port 25", store=False)
    sniff(prn=analizar_ssh, filter="tcp port 22", store=False)
    sniff(prn=analizar_dns, filter="udp port 53", store=False)
    sniff(prn=analizar_pop3, filter="tcp port 110", store=False)
    sniff(prn=analizar_telnet, filter="tcp port 23", store=False)
    sniff(prn=analizar_snmp, filter="udp port 161", store=False)
    sniff(prn=analizar_smb, filter="tcp port 445", store=False)
    sniff(prn=analizar_ldap, filter="tcp port 389", store=False)
    sniff(prn=analizar_rdp, filter="tcp port 3389", store=False)
    sniff(prn=analizar_vnc, filter="tcp port 5900", store=False)
    sniff(prn=analizar_imap, filter="tcp port 143", store=False)
    sniff(prn=analizar_pop3, filter="tcp port 110", store=False)
    sniff(prn=analizar_irc, filter="tcp port 6667", store=False)
    sniff(prn=analizar_ntp, filter="udp port 123", store=False)
    sniff(prn=analizar_sip, filter="udp port 5060 or udp port 5061", store=False)
    sniff(prn=analizar_vpn, filter="udp port 500 or udp port 4500", store=False)
    sniff(prn=analizar_snmp_trap, filter="udp port 162", store=False)
    sniff(prn=analizar_dhcp, filter="udp port 67 or udp port 68", store=False)
    sniff(prn=analizar_icmp, filter="icmp", store=False)
    sniff(prn=analizar_bgp, filter="tcp port 179", store=False)
    sniff(prn=analizar_nfs, filter="(tcp port 2049) or (udp port 2049)", store=False)
    sniff(prn=analizar_smtp, filter="tcp port 25", store=False)
    sniff(prn=analizar_coap, filter="udp port 5683", store=False)
    sniff(prn=analizar_ftp, filter="tcp port 21", store=False)
    sniff(prn=analizar_telnet, filter="tcp port 23", store=False)    

def analizar_paquete(packet):
    if Raw in packet:
        data = packet[Raw].load
        for char in data:
            if char in control_chars:
                print(f"Caracter de control encontrado: {control_chars[char]}")

def analizar_protocolos(packet):
    analizar_http(packet)
    analizar_dns(packet)
    analizar_https(packet)
    analizar_ftp(packet)
    analizar_smtp(packet)
    analizar_ssh(packet)
    analizar_snmp(packet)
    analizar_smb(packet)
    analizar_ldap(packet)
    analizar_rdp(packet)
    analizar_vnc(packet)
    analizar_imap(packet)
    analizar_pop3(packet)
    analizar_irc(packet)
    analizar_ntp(packet)
    analizar_sip(packet)
    analizar_vpn(packet)
    analizar_snmp_trap(packet)
    analizar_dhcp(packet)
    analizar_icmp(packet)
    analizar_bgp(packet)
    analizar_nfs(packet)
    analizar_coap(packet)
    analizar_telnet(packet)
    # Agrega más funciones de análisis de protocolos según sea necesario con "analizar_(packet)".

def analizar_http(packet):
    if packet.haslayer(HTTP):
        http_packet = packet.getlayer(HTTP)
        print(Fore.GREEN + "Paquete HTTP Capturado:")
        print(http_packet.summary())
        print(Style.RESET_ALL)

def analizar_dns(packet):
    if packet.haslayer(DNS):
        dns_packet = packet.getlayer(DNS)
        print(Fore.BLUE + "Paquete DNS Capturado:")
        print(dns_packet.summary())
        print(Style.RESET_ALL)

def analizar_https(packet):
    if packet.haslayer(TLS):
        print("Paquete HTTPS Capturado:")
        print(packet.summary())

def analizar_ftp(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode("utf-8", "ignore")
        if "USER" in data or "PASS" in data:
            print("Paquete FTP Capturado:")
            print(packet.summary())

def analizar_smtp(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode("utf-8", "ignore")
        if "MAIL FROM" in data or "RCPT TO" in data:
            print("Paquete SMTP Capturado:")
            print(packet.summary())

def analizar_ssh(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode("utf-8", "ignore")
        if "SSH" in data:
            print("Paquete SSH Capturado:")
            print(packet.summary())

def analizar_snmp(packet):
    if packet.haslayer(SNMP):
        print("Paquete SNMP Capturado:")
        print(packet.summary())

def analizar_smb(packet):
    if packet.haslayer(SMB):
        print("Paquete SMB Capturado:")
        print(packet.summary())

def analizar_ldap(packet):
    if packet.haslayer(LDAP):
        print("Paquete LDAP Capturado:")
        print(packet.summary())

def analizar_rdp(packet):
    if packet.haslayer(RDP):
        print("Paquete RDP Capturado:")
        print(packet.summary())

def analizar_vnc(packet):
    if packet.haslayer(VNC):
        print("Paquete VNC Capturado:")
        print(packet.summary())

def analizar_imap(packet):
    if packet.haslayer(IMAP):
        print("Paquete IMAP Capturado:")
        print(packet.summary())

def analizar_pop3(packet):
    if packet.haslayer(POP3):
        print("Paquete POP3 Capturado:")
        print(packet.summary())

def analizar_irc(packet):
    if packet.haslayer(IRCI):
        print("Paquete IRC Capturado:")
        print(packet.summary())

def analizar_ntp(packet):
    if packet.haslayer(NTP):
        print("Paquete NTP Capturado:")
        print(packet.summary())

def analizar_sip(packet):
    if packet.haslayer(SIP):
        print("Paquete SIP Capturado:")
        print(packet.summary())

def analizar_vpn(packet):
    if packet.haslayer(VPN):
        print("Paquete VPN Capturado:")
        print(packet.summary())

def analizar_snmp_trap(packet):
    if packet.haslayer(SNMPTrap):
        print("Paquete SNMP Trap Capturado:")
        print(packet.summary())

def analizar_dhcp(packet):
    if packet.haslayer(DHCP):
        print("Paquete DHCP Capturado:")
        print(packet.summary())

def analizar_icmp(packet):
    if packet.haslayer(ICMP):
        print("Paquete ICMP Capturado:")
        print(packet.summary())

def analizar_bgp(packet):
    if packet.haslayer(BGP):
        print("Paquete BGP Capturado:")
        print(packet.summary())

def analizar_nfs(packet):
    if packet.haslayer(NFS):
        print("Paquete NFS Capturado:")
        print(packet.summary())

def analizar_coap(packet):
    if packet.haslayer(CoAP):
        print("Paquete CoAP Capturado:")
        print(packet.summary())

def analizar_telnet(packet):
    if packet.haslayer(Telnet):
        print("Paquete Telnet Capturado:")
        print(packet.summary())

def conectar_base_datos():
    conn = sqlite3.connect('trafico_red.db')
    return conn

def guardar_resultados(conn, resultado):
    cursor = conn.cursor()
    # Implementa aquí el código para guardar los resultados en la base de datos
    conn.commit()

def cerrar_conexion(conn):
    conn.close()

def generar_reporte(resultados):
    # Implementa aquí la generación del reporte
    pass

def leer_reporte(resultados):
    # Implementa aquí la generación del reporte
    pass

if __name__ == "__main__":
    capturar_trafico()
