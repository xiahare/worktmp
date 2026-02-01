
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW
import requests
import json
import threading

class MyAIFirstAgent(toga.App):
    def startup(self):
        # Main container
        main_box = toga.Box(style=Pack(direction=COLUMN, margin=10))

        # Chat display area
        self.chat_box = toga.MultilineTextInput(readonly=True, style=Pack(flex=1))

        # Input area
        input_box = toga.Box(style=Pack(direction=ROW, margin_top=10))
        self.text_input = toga.TextInput(
            style=Pack(flex=1, margin_right=10),
            on_confirm=self.handle_send
        )
        self.send_button = toga.Button('Send', on_press=self.handle_send, style=Pack(width=80))
        
        input_box.add(self.text_input)
        input_box.add(self.send_button)

        main_box.add(self.chat_box)
        main_box.add(input_box)

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = main_box
        self.main_window.show()

        self.chat_history = []

    def handle_send(self, widget):
        user_message = self.text_input.value
        if not user_message:
            return

        # Add user message to chat history and display it
        self.chat_history.append({"role": "user", "content": user_message})
        self.chat_box.value += f"You: {user_message}\n\n"
        self.text_input.value = ""
        
        # Disable button to prevent multiple sends
        self.send_button.enabled = False

        # Run the network request in a background thread
        threading.Thread(target=self.get_bot_response).start()

    def get_bot_response(self):
        bot_message_full = ""
        try:
            response = requests.post(
                "http://us.fairyao.site/chat",
                json={"messages": self.chat_history}
            )
            response.raise_for_status() # Raise an exception for bad status codes

            response_data = response.json()
            bot_message_full = response_data.get("response", "An empty response was received.")
            
            self.chat_history.append({"role": "assistant", "content": bot_message_full})

        except requests.exceptions.RequestException as e:
            bot_message_full = f"Error: Could not connect to the server. {e}"
        except Exception as e:
            bot_message_full = f"An unexpected error occurred: {e}"

        # Schedule the UI update on the main thread
        self.loop.call_soon_threadsafe(self.update_ui_with_response, bot_message_full)

    def update_ui_with_response(self, message):
        self.chat_box.value += f"Bot: {message}\n\n"
        self.chat_box.scroll_to_bottom()
        self.send_button.enabled = True


def main():
    return MyAIFirstAgent('My AI First Agent', 'org.beeware.myaifirstagent')
