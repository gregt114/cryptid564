from flask import Flask, request
from Cryptodome.Cipher import AES   # pip install pycryptodomex
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

import os

app = Flask(__name__)
app.config['SERVER_TIMEOUT'] = None

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
        message = unpad(decrypted, 16)
        
        # print("Received data     : ", data)
        # print("Received cookie   : ", cookie)
        # print("Base64 Decoded    : ", encrypted)
        # print("Decrypted         : ", decrypted)
        print("Message           : ", message.decode("utf8"))

        # Get user input.
        # We loop here to prevent us from trying to send blank messages
        user_input = b""
        while len(user_input) == 0:
            user_input = input("> ").encode()
            if user_input == b"clear":
                os.system("clear")
                user_input = b""


        response = cipher_enc.encrypt(pad(user_input, 16))
        response = b64encode(response)
        return response
    else:
        return "INVALID HTTP METHOD - ONLY POST ALLOWED"

if __name__ == '__main__':
    app.run(debug=True, port=80, host="0.0.0.0")
