
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
    
    # Determine the message format and prepare the payload for Ollama
    if 'messages' in data:
        # This is from the macOS app
        messages = data['messages']
        stream = False
    elif 'message' in data:
        # This is from the web UI
        messages = [{"role": "user", "content": data['message']}]
        stream = True
    else:
        return jsonify({"error": "Invalid request format"}), 400

    # Common logic to call Ollama
    try:
        response = requests.post(
            'http://localhost:11434/api/chat',
            json={
                'model': 'qwen:0.5b',
                'messages': messages,
                'stream': stream
            },
            stream=stream
        )
        response.raise_for_status()

        if stream:
            def generate():
                for chunk in response.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk
            return Response(generate(), mimetype='application/x-json-stream')
        else:
            response_data = response.json()
            bot_message = response_data.get('message', {}).get('content', '')
            return jsonify({"response": bot_message})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Could not connect to language model: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected server error occurred: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
