#MICRO





import scapy.all as scapy                                   
import netifaces                                             
import time                                                
from rich.console import Console                            
from rich.table import Table                              
from datetime import datetime                               
import sqlite3                                              
from fpdf import FPDF                                       
from fpdf.enums import XPos, YPos                           
from flask import Flask, render_template_string            
import threading                                             
from colorama import Fore, Style, init                     
init(autoreset=True)                                        

console = Console()                                         


conn = sqlite3.connect("threats.db", check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS threats (
                timestamp TEXT,
                threat_type TEXT,
                src_ip TEXT,
                dst_port TEXT
            )''')
conn.commit()


def sniff_packets(interface="eth0"):
    if interface not in netifaces.interfaces():
        console.print(f"[bold red] Interface '{interface}' does not exist! - 📌'{interface}'📌الواجهة  غير موجودة![/]")
        return

    console.print(f"[bold green]The interface is being monitored.- 📡 جاري مراقبة الواجهة:[/] {interface}")
    try:
        scapy.sniff(
            iface=interface,
            store=False,
            prn=analyze_packet,
            filter="ip or arp or udp or tcp"
        )
    except PermissionError:
        console.print("[bold red]  You need to run the script with root privileges! - 📌root!📌 تحتاج لتشغيل السكربت بصلاحيات [/]")
    except Exception as e:
        console.print(f"[bold red] An error occurred while monitoring - حدث خطأ أثناء المراقبة: {e}[/]")


def analyze_packet(packet):
                                                                               
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        tcp_layer = packet[scapy.TCP]

        if tcp_layer.flags == "S":                                                 
            log_threat("Port Scan (SYN)", ip_layer.src, tcp_layer.dport)

        if tcp_layer.dport == 22:                                                 
            log_threat("Possible SSH Brute Force", ip_layer.src, 22)

                                                                               
    if packet.haslayer(scapy.ARP):
        arp_layer = packet[scapy.ARP]
        if arp_layer.op == 2:                                                      
            log_threat("ARP Spoofing", arp_layer.psrc, "ARP")

                                                                               
    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.UDP):
        udp_layer = packet[scapy.UDP]
        if udp_layer.sport == 53:                                                  
            ip_layer = packet[scapy.IP]
            log_threat("DNS Response Detected", ip_layer.src, 53)
def log_threat(threat_type, src_ip, dst_port):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    table = Table(show_header=True, header_style="bold red")
    table.add_column("الوقت(Time)")
    table.add_column("نوع التهديد(Type of threat)")
    table.add_column("IP المصدر(Source IP)")
    table.add_column("المنفذ المستهدف(Target port)")

    table.add_row(timestamp, threat_type, src_ip, str(dst_port))
    console.print(table)

    with open("threat_log.txt", "a") as file:
        file.write(f"{timestamp},{threat_type},{src_ip},{dst_port}\n")

    c.execute("INSERT INTO threats VALUES (?, ?, ?, ?)", (timestamp, threat_type, src_ip, str(dst_port)))
    conn.commit()

def generate_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", 'B', 16)  
    pdf.set_text_color(220, 50, 50)
    pdf.cell(200, 10, "Threat Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(200, 10, text=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(5)
    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(40, 10, "ID", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(50, 10, "Type", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(60, 10, "Source IP", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(40, 10, "Target Port", border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10)
    c.execute("SELECT * FROM threats")
    rows = c.fetchall()
    for row in rows:
        pdf.cell(40, 10, str(row[0]), border=1, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(50, 10, str(row[1]), border=1, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(60, 10, str(row[2]), border=1, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(40, 10, str(row[3]), border=1, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.output("threat_report.pdf")                                                                              
    console.print("[bold green]\n✅ تم توليد تقرير PDF باسم [underline]threat_report.pdf[/][/]") 
app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ar">
<head>
    <meta charset="UTF-8">
    <title>لوحة تحكم MICRO</title>
    <style>
        body { font-family: Arial; background-color: #f4f4f4; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; border: 1px solid #ccc; text-align: center; }
        th { background-color: #d32f2f; color: white; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>🔎🌐 LIST OF DETECTED THREATS <span style="color: green;">|-^MICRO^-|</span> 📊 قائمة التهديدات المكتشفة 👁️‍🗨️</h1>
    <h5>Eng.MO'MEN ISIED                          ⚓             <a href=https://www.linkedin.com/in/mo-men-isied-38092621a/>Linkedin</a>      </h5>
    <table>
    	 
        <tr><th>الوقت(Time)</th><th>نوع التهديد(Type of threat)</th><th>IP المصدر(Source IP)</th><th>المنفذ(port)</th></tr>
        {% for row in rows %}
            <tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td><td>{{ row[3] }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
'''

@app.route("/")
def dashboard():
    c.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    return render_template_string(HTML_TEMPLATE, rows=rows)
def start_web():                                                                                  
    app.run(host="0.0.0.0", port=5000)

def banner():
    print(Fore.GREEN + Style.BRIGHT + r"""
███╗   ███╗██╗ ██████╗██████╗   ╔██████╗ 
████╗ ████║██║██╔════╝██╔══█║  ██╔═══╗██╗
██╔████╔██║██║██║     ██████║  ██║   ║██║
██║╚██╔╝██║██║██║     ██╔═╗██  ██╚═══╝██║
██║ ╚═╝ ██║██║╚██████╗██║ ║██  ╚██████╔╝
╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝ ╚══╝  ╚═════╝ 
""")
    print(Fore.RED + Style.BRIGHT + "           ⚔️ Micro - Threat Analysis Toolkit⚔️\n")
    print(Fore.RED + Style.BRIGHT + "           ⚔️-----🦅 Eng.MO'MEN ISIED 🦅-----⚔️ \n")

banner()

if __name__ == "__main__":
    interface = input("Enter the name of the interface to monitor-🌐 أدخل اسم الواجهة لمراقبتها (مثلاً EX: eth0 أو(or) wlan0): ")
    console.print("[yellow] Start monitoring and then press Ctrl+C to stop it and generate the report-لإيقافها وتوليد التقرير📍Ctrl+C📍أبدأ المراقبة ثم اضغط[/]")

    t1 = threading.Thread(target=sniff_packets, args=(interface,))
    t2 = threading.Thread(target=start_web)

    t1.start()
    t2.start()

    try:
        t1.join()
    except KeyboardInterrupt:
        generate_pdf_report()
        console.print("[bold green]\nMonitoring stopped and report generated successfully-✅ تم إيقاف المراقبة وتوليد التقرير بنجاح[/]")
        conn.close()
