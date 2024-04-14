from flask import Flask, request
from Cryptodome.Cipher import AES   # pip install pycryptodomex
from base64 import b64encode, b64decode

app = Flask(__name__)

KEY = b"A"*16
IV = b"A"*16
cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)

# Strips padding if there is any (PKCS #7 padding scheme)
def strip_padding(decrypted: str):
    char = decrypted[-1]
    padded = all([b == char for b in decrypted[-char:]])
    if padded:
        return decrypted[0:-char]
    return decrypted



@app.route('/post', methods=['POST'])
def handle_post():
    if request.method == 'POST':
        # For some reason we need two separate ciphers
        cipher_dec = AES.new(KEY, AES.MODE_CBC, iv=IV)
        cipher_enc = AES.new(KEY, AES.MODE_CBC, iv=IV)

        data = request.data
        cookie = request.cookies["data"]
        encrypted = b64decode(cookie)
        decrypted = cipher_dec.decrypt(encrypted)
        message = strip_padding(decrypted)
        
        print("Received data     : ", data)
        print("Received cookie   : ", cookie)
        print("Base64 Decoded    : ", encrypted)
        print("Decrypted         : ", decrypted)
        print("Message           : ", message)

        response = cipher_enc.encrypt(decrypted)
        response = b64encode(response)
        return response
    else:
        return "INVALID HTTP METHOD - ONLY POST ALLOWED"

if __name__ == '__main__':
    app.run(debug=True, port=80)
