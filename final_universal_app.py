
from flask import Flask, request, jsonify, Response, send_from_directory
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
    is_streaming_request = data.get('stream', False)

    if 'messages' in data:
        messages = data['messages']
    elif 'message' in data:
        messages = [{"role": "user", "content": data['message']}]
    else:
        return jsonify({"error": "Invalid request format"}), 400

    # --- Streaming Logic for Web UI ---
    if is_streaming_request:
        def generate():
            try:
                response = requests.post(
                    'http://localhost:11434/api/chat',
                    json={'model': 'qwen:0.5b', 'messages': messages, 'stream': True},
                    stream=True
                )
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        try:
                            json_chunk = json.loads(line)
                            content = json_chunk.get('message', {}).get('content', '')
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue
            except requests.exceptions.RequestException as e:
                yield f"Error: {e}"
        return Response(generate(), mimetype='text/plain')

    # --- Non-Streaming Logic for macOS App ---
    else:
        try:
            response = requests.post(
                'http://localhost:11434/api/chat',
                json={'model': 'qwen:0.5b', 'messages': messages, 'stream': False}
            )
            response.raise_for_status()
            response_data = response.json()
            bot_message = response_data.get('message', {}).get('content', '')
            return jsonify({"response": bot_message})
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"Could not connect to language model: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
