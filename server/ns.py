# Standard
import sys
import socket

# Crypto
from Cryptodome.Cipher import AES   # "pip install pycryptodomex" if pycryptodome doesn't work
from base64 import b64encode, b64decode

# DNS
from dns import message, name
from dns.rdatatype import TXT
from dns.rdataclass import IN
from dns.rrset import RRset


"""
Returns bytes of DNS reply for the given request using msg as the TXT record data.
request: bytes of DNS query on the wire
msg    : the data to put in the TXT record
proto  : "UDP" or "TCP"
"""
def gen_dns_reply(request, msg, proto):

    query = message.from_wire(request) if proto == "UDP" else message.from_wire(request[2:])
    response = message.make_response(query)

    label = name.from_text(msg)
    record = RRset(label, rdclass=IN, rdtype=TXT)
    response.answer.append(record)
    
    # The library is stupid and won't make the actual RR bytes, so need to cut off the last two bytes of 
    # their data and append our own data onto the end
    res = response.to_wire()
    res = res[0:-2] + (len(msg) + 1).to_bytes(2, byteorder="big") + len(msg).to_bytes(1, byteorder="big") + msg.encode()

    # TCP DNS packets start with 2 byte length field
    if proto == "TCP":
        res = len(res).to_bytes(2, byteorder="big") + res 

    return res

    
def main(IP, PORT, PROTO):

    if PROTO == "UDP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((IP, PORT))
        print(f"UDP {IP}:{PORT}")
        while True:
            # Recv data
            data, addr = sock.recvfrom(1024)

            resp = gen_dns_reply(data, "testMessage123", PROTO)
            sock.sendto(resp, addr)

    if PROTO == "TCP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((IP, PORT))
        sock.listen(2)
        print(f"TCP {IP}:{PORT}")

        while True:
            conn, addr = sock.accept()
        
            data = conn.recv(1024)

            resp = gen_dns_reply(data, "testMessage123", PROTO)
            conn.send(resp)
            conn.close()




if __name__ == "__main__":
    
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} [IP] [PORT] [PROTO]")
        print("IP   :  Address of interface to listen on")
        print("PORT :  Port to listen on")
        print("PROTO:  Protocol to use - UDP or TCP")
        exit(0)

    
    # Parse args
    ip = sys.argv[1]
    port = int(sys.argv[2])
    proto = sys.argv[3].upper()

    main(ip, port, proto)
