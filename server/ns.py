# Standard
import sys
import socket
import threading
import time

# Crypto
from Cryptodome.Cipher import AES   # "pip install pycryptodomex" if pycryptodome doesn't work
from base64 import b64encode, b64decode

# DNS
from dns import message, name
from dns.rdatatype import TXT
from dns.rdataclass import IN
from dns.rrset import RRset


DNS_TIMEOUT = 10    # Found by manually timing

THREADS = []        # List of (thread, socket) tuples
THREAD_LOCK = threading.Lock()

MSG = ""
MSG_READY = 0
MSG_LOCK = threading.Lock()


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



def thread_handler(arg):
    global MSG, MSG_READY, MSG_LOCK
    conn = arg
    
    # Get data
    data = conn.recv(1024)

    # Check if message is ready twice per second. If after 9 seconds message 
    # is not ready, send default response
    start = time.time()
    while time.time() - start < 9:
        msg_ready = 0
        with MSG_LOCK:
            msg_ready = MSG_READY
        
        if msg_ready == 1:
            response = gen_dns_reply(data, MSG, "TCP")
            conn.send(response)
            conn.close()
            return
        else:
            time.sleep(0.5)
            continue

    # 10 seconds have passed and message not ready
    response = gen_dns_reply(data, "NOP", "TCP")
    conn.send(response)
    conn.close()
    return
    

# Handles accepting new connections
def socket_handler(arg):
    global THREADS
    sock = arg

    sock.listen(2)

    while True:
        # Accept connection
        conn, addr = sock.accept()
        t = threading.Thread(target=thread_handler, args=(conn,))
        t.start()

        # Add to thread list
        THREAD_LOCK.acquire()
        THREADS.append((t, conn))
        THREAD_LOCK.release()



def main(IP, PORT, PROTO):
    global MSG, MSG_READY, MSG_LOCK
    global THREADS, THREAD_LOCK

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP, PORT))
    print(f"{PROTO} {IP}:{PORT}")

    # Start network thread.
    # While input is blocking, we should still accept new connections 
    network_thread = threading.Thread(target=socket_handler, args=(sock,))
    network_thread.start()

    while True:
        
        # We lock MSG_READY instead of MSG since getting user-input is blocking,
        # meaning no other thread will be able to access MSG while the user decides what
        # to type. Immediately after getting input, we set MSG_READY to 1 to let other threads
        # know that MSG has been recently updated and can now be accessed
        MSG_LOCK.acquire()
        MSG_READY = 0
        MSG_LOCK.release()

        # User input
        MSG = input("> ")

        MSG_LOCK.acquire()
        MSG_READY = 1
        MSG_LOCK.release()
        

        # Join all dead threads
        THREAD_LOCK.acquire()
        tmp = [pair for pair in THREADS if pair[0].is_alive()] # make copy of list since can't remove items while iterating
        for pair in THREADS:
            t, s = pair
            if not t.is_alive():
                t.join()
                print(f"Joined {t.ident}")
        THREADS = tmp
        THREAD_LOCK.release()

        # Give time so other threads can get MSG_LOCK
        time.sleep(0.5)
        




if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} [IP] [PORT]")
        print("IP   :  Address of interface to listen on")
        print("PORT :  Port to listen on")
        #print("PROTO:  Protocol to use - UDP or TCP")
        exit(0)

    
    # Parse args
    ip = sys.argv[1]
    port = int(sys.argv[2])
    #proto = sys.argv[3].upper()
    proto = "TCP"

    main(ip, port, proto)
