from flask import Flask, request, Response, send_from_directory
import requests
import json

app = Flask(__name__)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')

    def generate():
        try:
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    'model': 'qwen:0.5b',
                    'prompt': user_message
                },
                stream=True
            )

            for chunk in response.iter_content(chunk_size=None):
                if chunk:
                    try:
                        json_chunk = json.loads(chunk)
                        yield json_chunk.get('response', '')
                    except json.JSONDecodeError:
                        pass # Ignore non-JSON chunks

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to ollama: {e}")
            yield "Sorry, I couldn't connect to the language model."

    return Response(generate(), mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
