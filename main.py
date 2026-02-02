import json
import argparse
import os
import logging
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from honeytoken_core import HoneyTokenManager
from monitor import FileSystemMonitor
from telegram_notifier import TelegramNotifier
from dashboard import start_dashboard


def derive_key(password: str, salt: bytes = None) -> tuple:
    """Создание ключа из пароля"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_config(config_data: dict, password: str) -> dict:
    """Шифрование конфигурации"""
    key, salt = derive_key(password)
    fernet = Fernet(key)
    
    # Конвертируем в JSON и шифруем
    config_json = json.dumps(config_data, ensure_ascii=False).encode('utf-8')
    encrypted_data = fernet.encrypt(config_json)
    
    return {
        'encrypted_data': base64.urlsafe_b64encode(encrypted_data).decode('ascii'),
        'salt': base64.urlsafe_b64encode(salt).decode('ascii')
    }

def decrypt_config(encrypted_config: dict, password: str) -> dict:
    """Расшифровка конфигурации"""
    try:
        salt = base64.urlsafe_b64decode(encrypted_config['salt'])
        encrypted_data = base64.urlsafe_b64decode(encrypted_config['encrypted_data'])
        
        key, _ = derive_key(password, salt)
        fernet = Fernet(key)
        
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Ошибка расшифровки: {e}")

def save_encrypted_config(config_data: dict, password: str, output_file: str = "config.json.enc"):
    """Сохранение зашифрованного конфига"""
    encrypted_config = encrypt_config(config_data, password)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(encrypted_config, f, indent=2, ensure_ascii=False)
    print(f"✅ Конфиг зашифрован и сохранен в {output_file}")

def load_encrypted_config(password: str, input_file: str = "config.json.enc") -> dict:
    """Загрузка и расшифровка конфига"""
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Зашифрованный конфиг не найден: {input_file}")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        encrypted_config = json.load(f)
    
    return decrypt_config(encrypted_config, password)

def setup_logging(config):
    """Настройка логирования с поддержкой Unicode"""
    class UnicodeFormatter(logging.Formatter):
        def format(self, record):
            message = super().format(record)
            if sys.platform == "win32":
                try:
                    return message.encode('utf-8', errors='replace').decode('utf-8')
                except:
                    return message.replace('🚀', '[START]').replace('📊', '[STATS]').replace('🔍', '[SCAN]').replace('📅', '[CAL]').replace('⏰', '[TIME]').replace('⏹️', '[STOP]')
            return message

    file_handler = logging.FileHandler(
        config['logging']['file'], 
        encoding='utf-8'
    )
    file_handler.setFormatter(UnicodeFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(UnicodeFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))

    logging.basicConfig(
        level=getattr(logging, config['logging']['level']),
        handlers=[file_handler, console_handler]
    )

def load_config():
    """Загрузка конфигурации (автоматическое определение зашифрованного конфига)"""
    # Сначала пробуем загрузить открытый конфиг
    if os.path.exists('config.json'):
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
            print("⚠️  Используется НЕЗАШИФРОВАННЫЙ config.json - рекомендуется шифрование!")
            return config
        except json.JSONDecodeError:
            print("❌ Ошибка: Неверный формат config.json!")
            exit(1)
    
    # Пробуем загрузить зашифрованный конфиг
    elif os.path.exists('config.json.enc'):
        print("🔐 Обнаружен зашифрованный конфиг")
        
        # Запрашиваем пароль
        if 'HONEYTOKEN_KEY' in os.environ:
            password = os.environ['HONEYTOKEN_KEY']
            print("✅ Используется ключ из переменной окружения HONEYTOKEN_KEY")
        else:
            password = input("Введите ключ для расшифровки конфига: ")
        
        try:
            config = load_encrypted_config(password, 'config.json.enc')
            print("✅ Конфиг успешно расшифрован")
            return config
        except ValueError as e:
            print(f"❌ Ошибка расшифровки: {e}")
            exit(1)
    
    else:
        print("❌ Ошибка: Не найден config.json или config.json.enc!")
        print("   Создайте конфиг или используйте --encrypt-config")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description='🐝 Система управления Honey Token')
    parser.add_argument('--generate-file', help='Создать файл-ловушку')
    parser.add_argument('--start-monitor', action='store_true', help='Запустить службу мониторинга (polling)')
    parser.add_argument('--start-monitor-events', action='store_true', help='Запустить событийный мониторинг (watchdog)')
    parser.add_argument('--test-telegram', action='store_true', help='Протестировать подключение к Telegram')
    parser.add_argument('--list-tokens', action='store_true', help='Показать все активные токены')
    parser.add_argument('--start-dashboard', action='store_true', help='Запустить веб-дашборд')
    parser.add_argument('--debug', action='store_true', help='Режим отладки')
    parser.add_argument('--encrypt-config', metavar='KEY', help='Зашифровать config.json с указанным ключом')
    parser.add_argument('--decrypt-config', metavar='KEY', help='Расшифровать config.json.enc с указанным ключом')
    parser.add_argument('--create-folder', metavar='FOLDER', help='Создать папку для ловушек')
    
    args = parser.parse_args()
    
    # Обработка шифрования/расшифровки
    if args.encrypt_config:
        if len(args.encrypt_config) < 32:
            print("❌ Ключ должен быть не менее 32 символов!")
            return
        
        if not os.path.exists('config.json'):
            print("❌ Файл config.json не найден! Создайте его сначала")
            return
        
        with open('config.json', 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        save_encrypted_config(config_data, args.encrypt_config)
        print("🔒 Конфиг зашифрован. Рекомендуется удалить config.json")
        return
    
    if args.decrypt_config:
        if not os.path.exists('config.json.enc'):
            print("❌ Файл config.json.enc не найден!")
            return
        
        try:
            config_data = load_encrypted_config(args.decrypt_config, 'config.json.enc')
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            print("✅ Конфиг расшифрован в config.json")
        except ValueError as e:
            print(f"❌ Ошибка расшифровки: {e}")
        return
    
    # Основная логика
    config = load_config()
    setup_logging(config)
    
    # Инициализация менеджера токенов и нотификатора
    token_mgr = HoneyTokenManager(config['database']['path'])
    notifier = TelegramNotifier(
        config['telegram']['bot_token'],
        config['telegram']['chat_id']
    )
    
    if args.generate_file:
        # Генерация файла-ловушки
        file_path = args.generate_file
        print(f"🐝 Создание файла-ловушки: {file_path}")
        token_guid = token_mgr.generate_file_token(
            file_path, 
            use_faker=config['token_generation']['use_faker'],
            obfuscate_guid=config['token_generation']['obfuscate_guid']
        )
        print(f"✅ Файл создан, GUID токена: {token_guid}")
        
    elif args.create_folder:
        # Создание папки для ловушек
        folder_path = os.path.join(config['token_generation']['default_file_path'], args.create_folder)
        try:
            os.makedirs(folder_path, exist_ok=True)
            print(f"✅ Папка создана: {folder_path}")
            
            # Добавляем в конфиг
            if 'traps_folders' not in config:
                config['traps_folders'] = []
            
            if folder_path not in config['traps_folders']:
                config['traps_folders'].append(folder_path)
                
                # Сохраняем обновленный конфиг
                with open('config.json', 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                print(f"✅ Папка добавлена в конфиг")
            
        except Exception as e:
            print(f"❌ Ошибка создания папки: {e}")
    
    elif args.start_monitor:
        # Запуск мониторинга (polling режим)
        monitor = FileSystemMonitor(
            token_mgr, 
            notifier, 
            config['monitoring']['scan_interval_seconds'],
            config
        )
        print("🐝 Запуск системы мониторинга Honey Token (polling-режим)...")
        monitor.start_monitoring()
    
    elif args.start_monitor_events:
        # Запуск событийного мониторинга (watchdog)
        monitor = FileSystemMonitor(
            token_mgr, 
            notifier, 
            config['monitoring']['scan_interval_seconds'],
            config
        )
        print("🐝 Запуск системы событийного мониторинга Honey Token (watchdog)...")
        print("⚠️  Убедитесь, что установлена библиотека: pip install watchdog")
        monitor.start_monitoring()
    
    elif args.test_telegram:
        # Тестирование Telegram
        print("🔧 Тестирование подключения к Telegram...")
        if notifier.test_connection():
            notifier.send_alert("✅ <b>Тест подключения</b>\nСистема Honey Token успешно подключена к Telegram!")
            print("✅ Тест Telegram выполнен успешно!")
        else:
            print("❌ Ошибка подключения к Telegram!")
    
    elif args.list_tokens:
        # Показать активные токены
        print("📋 Активные файловые токены:")
        active_tokens = token_mgr.get_active_file_tokens()
        if active_tokens:
            for token_guid, location in active_tokens:
                print(f"  📍 {location}")
                print(f"     GUID: {token_guid}")
            print(f"📊 Всего активных токенов: {len(active_tokens)}")
        else:
            print("ℹ️  Активные токены не найдены.")
    
    elif args.start_dashboard:
        # Запуск дашборда
        print("🌐 Запуск веб-дашборда...")
        start_dashboard(config, token_mgr)
    
    elif args.debug:
        # Режим отладки
        all_tokens = token_mgr.get_all_tokens()
        print("🔧 Режим отладки - все токены в базе:")
        print(f"📊 Всего токенов: {len(all_tokens)}")
        for token in all_tokens:
            print(f"  🔸 ID: {token[0]}, GUID: {token[1]}, Тип: {token[2]}")
            print(f"     Путь: {token[3]}, Создан: {token[4]}")
            print(f"     Сработал: {token[5]}, Время срабатывания: {token[6]}")
            print(f"     Тип события: {token[15] if len(token) > 15 else 'N/A'}")
            print("     " + "-"*40)
    
    else:
        parser.print_help()
        print("\n📋 Примеры использования:")
        print("  python main.py --generate-file \"C:\\honey_tokens\\secret.pdf\"")
        print("  python main.py --create-folder \"new_traps\"")
        print("  python main.py --start-monitor")
        print("  python main.py --start-monitor-events")
        print("  python main.py --test-telegram")
        print("  python main.py --list-tokens")
        print("  python main.py --start-dashboard")
        print("  python main.py --debug")
        print("  python main.py --encrypt-config \"суперсекретный_ключ_не_менее_32_символов\"")
        print("  python main.py --decrypt-config \"суперсекретный_ключ_не_менее_32_символов\"")

if __name__ == "__main__":
    main()