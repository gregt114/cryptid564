# Standard
import sys
import socket
import threading
import time

# Crypto
from Cryptodome.Cipher import AES   # "pip install pycryptodomex" if pycryptodome doesn't work
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# DNS
from dns import message, name
from dns.rdatatype import TXT
from dns.rdataclass import IN
from dns.rrset import RRset


KEY = b"A"*16
IV = b"A"*16
cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)


"""
Returns bytes of DNS reply for the given request using msg as the TXT record data.
request: bytes of DNS query on the wire
msg    : the data to put in the TXT record
proto  : "UDP" or "TCP"
"""
def gen_dns_reply(request, msg, proto):

    query = message.from_wire(request) if proto == "UDP" else message.from_wire(request[2:])
    response = message.make_response(query)

    # We can save space in the response packet by putting a bogus domain name in the reply instead of the real domain name
    # label = query.question[0].name    # how we would get the real domain name
    label = name.from_text("TeamCryptid.com")
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




def main(IP, PORT):
    # Socket setup
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP, PORT))
    sock.listen(3)
    print(f"TCP {IP}:{PORT}")


    while True:
        data = ""
        sock.settimeout(1)

        cipher_dec = AES.new(KEY, AES.MODE_CBC, iv=IV)
        cipher_enc = AES.new(KEY, AES.MODE_CBC, iv=IV)
        
        while True:
            # Accept connection
            try:
                conn, addr = sock.accept()
                conn.settimeout(None)
            except:
                break

            # Recv data
            buffer = conn.recv(1024)
            query = message.from_wire(buffer[2:])        # strip off fist 2 bytes due to TCP format
            name = query.question[0].name.to_text()[:-5] # remove .com. at end
            data += name

            # Send reply (TODO encrypt)
            resp = gen_dns_reply(buffer, "THANKS", "TCP")
            conn.send(resp)
            conn.close()

        if data != "":
            enc_bytes = bytes.fromhex(data)
            dec_bytes = cipher_dec.decrypt(enc_bytes)
            dec_bytes = unpad(dec_bytes, 16)
            print(f"RECV:\n{dec_bytes}\n")





if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} [IP] [PORT]")
        print("IP   :  Address of interface to listen on")
        print("PORT :  Port to listen on")
        exit(0)

    # Parse args
    ip = sys.argv[1]
    port = int(sys.argv[2])

    main(ip, port)
