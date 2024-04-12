from flask import Flask, request

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    if request.method == 'POST':
        data = request.data
        print("Received data:", data)
        print("Headers: ", request.headers)
        print("===============================")
        return data.decode()
    else:
        return "INVALID HTTP METHOD - ONLY POST ALLOWED"

if __name__ == '__main__':
    app.run(debug=True, port=80)
