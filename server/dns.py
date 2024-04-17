import socket

 
UDP_IP = "0.0.0.0"
UDP_PORT = 53


def reply(query):
    identifier = query[0:2] # first 16 bits is id
    flags = b"\x81\x80" # standard query, no error
    num_questions = b"\x00\x01"
    num_answers = b"\x00\x01"
    num_auth = b"\x00\x00"
    num_add = b"\x00\x00"

    resp = identifier + flags + num_questions + num_answers + num_auth + num_add
    resp += b"\x06test.edu\x00\x10\x00\x01"     # answer
    resp += b"\xc0\x0c\x00\x10\x00\x01" + b"\x00"*3 + b"\xbb\x00\x04" + b"\x8e"*4
    return resp


print("UDP IP: %s" % UDP_IP)
print("UDP port: %s" % UDP_PORT)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)
    ip, port = addr
    resp = reply(data)
    sock.sendto(resp, addr)