Проверка телеграмма: python main.py --test-telegram

Проверка созданных токенов: python main.py --list-tokens

Старт мониторинга: python main.py --start-monitor

pip install -r requirements.txt


5.2. Вход в дашборд
Запустите дашборд: python main.py --start-dashboard

Откройте браузер: http://127.0.0.1:5000

Используйте учетные данные по умолчанию:

Логин: admin

Пароль: HoneyToken2025!



python main.py --generate-file "C:\honey_tokens\test.txt"
python main.py --generate-file "C:\honey_tokens\financial_report.pdf"
python main.py --generate-file "C:\honey_tokens\test.xlsx"
python main.py --generate-file "C:\honey_tokens\test.word"


# Установка зависимостей
pip install aiohttp aiodns

# Запуск beacon сервера
python main.py --start-beacon-server

# Генерация файла с beacon
python main.py --generate-file "C:\honey_tokens\secret.txt"

# Запуск мониторинга
python main.py --start-monitor

# Запуск дашборда
python main.py --start-dashboard

python main.py --generate-file "С:\\honey_tokens\\test_beacon.txt"

ngrok http 8080





# Зашифровать конфиг
python main.py --encrypt-config "dasufgsahjfgasdyjuhfgsayujfgt7y8dsafjmgsafhashfgsafhafdfafdsxaaf"  (не менее 32 символов)

# Расшифровать конфиг (только для админа)
python main.py --decrypt-config "dasufgsahjfgasdyjuhfgsayujfgt7y8dsafjmgsafhashfgsafhafdfafdsxaaf"

# Использование переменной окружения
export HONEYTOKEN_KEY="dasufgsahjfgasdyjuhfgsayujfgt7y8dsafjmgsafhashfgsafhafdfafdsxaaf"
python main.py --start-dashboard

