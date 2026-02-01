
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    messages = data.get('messages')

    if not messages:
        return jsonify({"error": "No messages provided"}), 400

    try:
        response = requests.post(
            'http://localhost:11434/api/chat',
            json={
                'model': 'qwen:0.5b',
                'messages': messages,
                'stream': False
            }
        )
        response.raise_for_status()

        response_data = response.json()
        bot_message = response_data.get('message', {}).get('content', '')
        
        return jsonify({"response": bot_message})

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to ollama: {e}")
        return jsonify({"error": f"Sorry, I couldn't connect to the language model. {e}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": f"An unexpected server error occurred. {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
