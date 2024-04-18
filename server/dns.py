import socket


"""
Generates a DNS TXT reply.
tid   : 2 byte integer representing the transaction ID. Obtained from the request.
domain: the domain name the query was made for. Obtained from the request.
msg   : the contents of the TXT record to send back
proto : Either "UDP" or "TCP"
"""
def gen_reply(tid, domain, msg, proto):

    if proto == "UDP":
        # DNS header
        header = b"\x81\x80" # standary query response, no error
        header += b"\x00\x01" # num queries
        header += b"\x00\x01" # num answers
        header += b"\x00\x00" # num authoritative
        header += b"\x00\x00" # num additional

        # Query
        query = b"\x06"
        query += domain + b"\x00"
        query += b"\x00\x10" # Type TXT
        query += b"\x00\x01" # Class IN

        # TXT record
        record = b"\xc0\x0c"  # refers to domain name?
        record += b"\x00\x10" # Type TXT
        record += b"\x00\x01" # Class IN
        record += b"\x00\x00\x00\x00" # TTL = 0 min, 0 sec

        # Data length, 2 bytes long. Length of all TXT records combined.
        # Each RR has its own 1-byte length field, so since we have 1 RR the total length is 1 + len(RR) 
        record += (1 + len(msg)).to_bytes(2, byteorder="big")
        record += len(msg).to_bytes(1, byteorder="big") # TXT length, 1 byte
        record += msg

        packet = tid.to_bytes(2, byteorder="big") + header + query + record
        return packet

    elif proto == "TCP":
        # DNS header
        header = b"\x81\x80" # standary query response, no error
        header += b"\x00\x01" # num queries
        header += b"\x00\x01" # num answers
        header += b"\x00\x00" # num authoritative
        header += b"\x00\x00" # num additional

        # Query
        query = b"\x06"
        query += domain + b"\x00"
        query += b"\x00\x10" # Type TXT
        query += b"\x00\x01" # Class IN

        # TXT record
        record = b"\xc0\x0c"  # refers to domain name?
        record += b"\x00\x10" # Type TXT
        record += b"\x00\x01" # Class IN
        record += b"\x00\x00\x00\x00" # TTL = 0 min, 0 sec

        # Data length, 2 bytes long. Length of all TXT records combined.
        # Each RR has its own 1-byte length field, so since we have 1 RR the total length is 1 + len(RR) 
        record += (1 + len(msg)).to_bytes(2, byteorder="big")
        record += len(msg).to_bytes(1, byteorder="big") # TXT length, 1 byte
        record += msg

        # TCP DNS packets start with 2-byte length field rather than TID
        packet = tid.to_bytes(2, byteorder="big") + header + query + record
        packet = len(packet).to_bytes(2, byteorder="big") + packet
        return packet


"""
Parses a generic DNS request. Returns transaction ID and domain name.
data : the raw bytes of the DNS request.
proto: either "UDP" or "TCP"
"""
def parse_query(data, proto):

    if proto == "UDP":
        # Parse query ID
        tid = int.from_bytes(data[0:2], byteorder="big")

        # Parse domain out
        # Note: For some reason in query, \x03 is used instead of "."
        domain_bytes = data[13: data.find(b"\x00", 13)]
        return (tid, domain_bytes)
    
    elif proto == "TCP":
        tid = int.from_bytes(data[2:4], byteorder="big")
        domain_bytes = data[15: data.find(b"\x00", 15)]
        return (tid, domain_bytes)




IP = "0.0.0.0"
PORT = 53
PROTO = "UDP"

if PROTO == "UDP":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print(f"UDP {IP}:{PORT}")
    while True:
        # Recv data
        data, addr = sock.recvfrom(1024)
        ip, port = addr

        # Parse request
        tid, domain = parse_query(data, PROTO)

        resp = gen_reply(tid, domain, b"testing123", PROTO)
        sock.sendto(resp, addr)

elif PROTO == "TCP":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP, PORT))
    sock.listen(3)
    print(f"TCP {IP}:{PORT}")

    while True:
        # Recv data
        conn, addr = sock.accept()
        data = conn.recv(1024)

        # Parse request
        tid, domain = parse_query(data, PROTO)

        resp = gen_reply(tid, domain, b"testing123", PROTO)
        conn.send(resp)
        conn.close()