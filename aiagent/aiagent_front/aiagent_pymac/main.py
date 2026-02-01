import tkinter as tk
from tkinter import scrolledtext
import requests
import json

class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Qwen Chat")
        self.geometry("600x400")

        self.chat_history = []

        self.chat_box = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_box.config(state=tk.DISABLED)

        self.input_frame = tk.Frame(self)
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)

        self.user_input = tk.Entry(self.input_frame)
        self.user_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.user_input.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

    def send_message(self, event=None):
        user_message = self.user_input.get()
        if not user_message:
            return

        self.append_message("You", user_message)
        self.chat_history.append({"role": "user", "content": user_message})
        self.user_input.delete(0, tk.END)

        self.get_bot_response()

    def get_bot_response(self):
        try:
            response = requests.post(
                "http://us.fairyao.site/chat",
                json={"messages": self.chat_history},
                stream=True
            )

            bot_message = ""
            for chunk in response.iter_content(chunk_size=None):
                if chunk:
                    try:
                        json_chunk = json.loads(chunk)
                        bot_message += json_chunk.get("response", "")
                        self.update_bot_message(bot_message)
                    except json.JSONDecodeError:
                        pass # Ignore non-JSON chunks
            
            self.chat_history.append({"role": "assistant", "content": bot_message})

        except requests.exceptions.RequestException as e:
            self.append_message("Bot", f"Error: {e}")

    def append_message(self, sender, message):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, f"{sender}: {message}\n\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)

    def update_bot_message(self, message):
        self.chat_box.config(state=tk.NORMAL)
        # Find the start of the last bot message
        last_bot_message_start = self.chat_box.search("Bot: ", "1.0", stopindex=tk.END, backwards=True)
        if last_bot_message_start:
            # Delete the old bot message
            self.chat_box.delete(last_bot_message_start, tk.END)
        self.chat_box.insert(tk.END, f"Bot: {message}\n\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
