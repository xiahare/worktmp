const chatBox = document.getElementById('chat-box');
const userInput = document.getElementById('user-input');
const sendButton = document.getElementById('send-button');

sendButton.addEventListener('click', sendMessage);
userInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

async function sendMessage() {
    const userMessage = userInput.value;
    if (!userMessage) return;

    appendMessage('user', userMessage);
    userInput.value = '';

    try {
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: userMessage, stream: true })
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let botMessage = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            botMessage += decoder.decode(value, { stream: true });
            appendMessage('bot', botMessage, true);
        }

    } catch (error) {
        console.error('Error:', error);
        appendMessage('bot', 'Sorry, something went wrong.');
    }
}

function appendMessage(sender, message, isStreaming = false) {
    const messageElement = document.createElement('div');
    messageElement.classList.add(sender === 'user' ? 'user-message' : 'bot-message');

    if (isStreaming) {
        const lastBotMessage = chatBox.querySelector('.bot-message:last-child');
        if (lastBotMessage) {
            lastBotMessage.innerHTML = message;
            chatBox.scrollTop = chatBox.scrollHeight;
            return;
        }
    }

    messageElement.innerHTML = message;
    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight;
}
