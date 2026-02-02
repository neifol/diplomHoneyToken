import requests
import json

class TelegramNotifier:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}/"

    def send_alert(self, message):
        """Отправка оповещения в Telegram"""
        url = self.base_url + "sendMessage"
        data = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                print("✅ Оповещение успешно отправлено в Telegram")
                return True
            else:
                print(f"❌ Ошибка отправки оповещения. Код: {response.status_code}")
                print(f"Ответ: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Ошибка при отправке Telegram оповещения: {e}")
            return False

    def test_connection(self):
        """Тестирование соединения с Telegram API"""
        url = self.base_url + "getMe"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                bot_info = response.json()
                print(f"✅ Бот подключен: {bot_info['result']['first_name']}")
                return True
            else:
                print(f"❌ Ошибка подключения к боту. Код: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Ошибка тестирования соединения: {e}")
            return False

# Пример использования
if __name__ == "__main__":
    # Конфигурация с вашими данными
    BOT_TOKEN = "8348079971:AAEPq0sMXZmg4SEpHcDt2sOdxbEx2Zx6sAc"
    CHAT_ID = "5537395233"

    notifier = TelegramNotifier(BOT_TOKEN, CHAT_ID)
    
    # Тестирование соединения
    if notifier.test_connection():
        # Тестовое оповещение
        notifier.send_alert("🔧 <b>Тестовое сообщение</b> 🔧\nСистема Honey Token успешно настроена и готова к работе!")