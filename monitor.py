import os
import time
import hashlib
import sqlite3
import threading
import psutil
import requests
import logging
import platform
import win32file
import win32con
from datetime import datetime
from honeytoken_core import HoneyTokenManager
from telegram_notifier import TelegramNotifier
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

logger = logging.getLogger(__name__)

class NetworkConnectionTracker:
    """Трекер сетевых подключений для определения IP"""
    
    def __init__(self):
        self.system = platform.system()
    
    def get_connections_info(self):
        """Получение информации о сетевых подключениях"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.raddr:  # Только соединения с удаленным адресом
                        conn_info = {
                            'pid': conn.pid,
                            'remote_ip': conn.raddr[0],
                            'remote_port': conn.raddr[1],
                            'status': conn.status
                        }
                        connections.append(conn_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
            return connections
        except Exception as e:
            logger.error(f"[ERROR] Ошибка получения сетевых подключений: {e}")
            return []
    
    def find_remote_ip_by_pid(self, target_pid):
        """Поиск удаленного IP по PID процесса"""
        try:
            connections = self.get_connections_info()
            for conn in connections:
                if conn['pid'] == target_pid:
                    logger.debug(f"[DEBUG] Найден IP {conn['remote_ip']} для PID {target_pid}")
                    return conn['remote_ip']
            logger.debug(f"[DEBUG] IP не найден для PID {target_pid}")
            return None
        except Exception as e:
            logger.error(f"[ERROR] Ошибка поиска IP по PID {target_pid}: {e}")
            return None
    
    def get_external_ip(self):
        """Получение внешнего IP адреса системы"""
        try:
            services = [
                'https://api.ipify.org',
                'https://ident.me',
                'https://checkip.amazonaws.com'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        logger.debug(f"[DEBUG] Получен внешний IP: {ip}")
                        return ip
                except Exception as e:
                    logger.debug(f"[DEBUG] Не удалось получить IP от {service}: {e}")
                    continue
            return None
        except Exception as e:
            logger.error(f"[ERROR] Ошибка получения внешнего IP: {e}")
            return None

class FileLockChecker:
    """Проверка блокировки файлов для определения открытия"""
    
    def __init__(self):
        self.system = platform.system()
    
    def is_file_locked(self, filepath):
        """Проверяет, заблокирован ли файл (открыт в другой программе)"""
        try:
            if self.system == "Windows":
                # Для Windows используем win32file
                try:
                    import win32file
                    import pywintypes
                    
                    # Пробуем открыть файл в эксклюзивном режиме
                    try:
                        handle = win32file.CreateFile(
                            filepath,
                            win32file.GENERIC_READ,
                            0,  # no sharing
                            None,
                            win32file.OPEN_EXISTING,
                            0,
                            None
                        )
                        
                        if handle:
                            win32file.CloseHandle(handle)
                        return False  # Файл не заблокирован
                    except pywintypes.error as e:
                        if e.winerror == 32:  # ERROR_SHARING_VIOLATION
                            return True  # Файл заблокирован
                        else:
                            return False
                except ImportError:
                    # Если нет win32file, используем альтернативный метод
                    pass
            
            # Unix/Linux или альтернативный метод для Windows
            import fcntl
            
            try:
                with open(filepath, 'rb') as f:
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return False  # Файл не заблокирован
                    except IOError:
                        return True  # Файл заблокирован
            except (IOError, OSError):
                return False
        
        except Exception as e:
            logger.debug(f"[DEBUG] Ошибка проверки блокировки файла {filepath}: {e}")
            return False
    
    def get_locking_process(self, filepath):
        """Получает информацию о процессе, блокирующем файл"""
        try:
            if self.system == "Windows":
                # Используем Handle.exe или альтернативные методы
                import subprocess
                
                try:
                    # Пытаемся использовать handle.exe из SysInternals
                    result = subprocess.run(
                        ['handle', filepath],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        # Парсим вывод handle.exe
                        for line in result.stdout.split('\n'):
                            if filepath in line:
                                parts = line.split()
                                if len(parts) > 2:
                                    pid = parts[1].split(':')[0]
                                    process_name = parts[2]
                                    return {'pid': int(pid), 'name': process_name}
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
            
            # Альтернативный метод для всех систем
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    for f in proc.info['open_files'] or []:
                        if filepath.lower() == f.path.lower():
                            return {
                                'pid': proc.info['pid'],
                                'name': proc.info['name']
                            }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return None
            
        except Exception as e:
            logger.debug(f"[DEBUG] Ошибка получения блокирующего процесса {filepath}: {e}")
            return None

class HoneytokenFileHandler(FileSystemEventHandler):
    """Обработчик файловых событий для honeytoken файлов"""
    
    def __init__(self, token_manager, notifier, config):
        super().__init__()
        self.token_manager = token_manager
        self.notifier = notifier
        self.config = config
        self.network_tracker = NetworkConnectionTracker()
        self.file_lock_checker = FileLockChecker()
        self.last_trigger_time = {}
        self.last_alert_time = {}
        self.last_trap_creation = {}
        self.file_access_history = {}
        self.file_modification_history = {}
        self.file_event_cache = {}
        self.event_cooldown = {}
        self.monitor_processes = ['python', 'python3', 'python.exe', 'python3.exe', 'monitor.py']
        self.checked_files = set()  # Множество проверенных файлов
        self.active_checks = {}  # Активные проверки файлов
    
    def is_honeytoken_file(self, file_path):
        """Проверяет, является ли файл honeytoken'ом"""
        try:
            token = self.token_manager.get_token_by_file_path(file_path)
            if token:
                logger.debug(f"[DEBUG] Файл {file_path} является honeytoken'ом. GUID: {token[1]}")
                return True
            logger.debug(f"[DEBUG] Файл {file_path} НЕ является honeytoken'ом")
            return False
        except Exception as e:
            logger.error(f"[ERROR] Ошибка проверки honeytoken файла {file_path}: {e}")
            return False
    
    def is_temporary_file(self, file_path):
        """Проверка, является ли файл временным"""
        try:
            filename = os.path.basename(file_path)
            directory = os.path.dirname(file_path).lower()
            
            # Игнорируем временные файлы Office
            if filename.startswith('~$') or filename.startswith('.~'):
                logger.debug(f"[DEBUG] Игнорируем временный Office файл: {filename}")
                return True
            
            # Игнорируем временные файлы с расширением .tmp
            if filename.endswith('.tmp') or filename.endswith('.temp'):
                logger.debug(f"[DEBUG] Игнорируем .tmp/.temp файл: {filename}")
                return True
            
            # Игнорируем системные файлы
            if filename.startswith('~') or filename.startswith('._'):
                logger.debug(f"[DEBUG] Игнорируем системный файл: {filename}")
                return True
            
            # Игнорируем файлы в папках с темп
            if 'temp' in directory or 'tmp' in directory:
                logger.debug(f"[DEBUG] Игнорируем файл в временной папке: {file_path}")
                return True
            
            # Игнорируем файлы с именем начинающимся на "Copy of"
            if filename.startswith('Copy of'):
                logger.debug(f"[DEBUG] Игнорируем копию файла: {filename}")
                return True
            
            # Проверяем, является ли файл резервной копией Office
            if filename.startswith('Backup of'):
                logger.debug(f"[DEBUG] Игнорируем резервную копию: {filename}")
                return True
            
            # Расширенная проверка для Excel временных файлов
            if 'excel' in file_path.lower() and 'xl' in directory:
                if 'temp' in filename.lower() or 'tmp' in filename.lower():
                    logger.debug(f"[DEBUG] Игнорируем Excel временный файл: {filename}")
                    return True
            
            # Игнорируем файлы, созданные системой как ловушки
            if 'backup_' in filename and filename.endswith(('.txt', '.pdf', '.docx', '.xlsx', '.xls')):
                logger.debug(f"[DEBUG] Игнорируем созданную ловушку: {filename}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"[ERROR] Ошибка проверки временного файла {file_path}: {e}")
            return False
    
    def is_office_temp_file(self, file_path):
        """Специальная проверка для временных файлов Office"""
        filename = os.path.basename(file_path)
        
        # Паттерны временных файлов Office
        office_patterns = [
            '~$',  # Excel, Word
            '.~',  # Общие временные
            '~',   # Общие
            '$',   # Excel
        ]
        
        for pattern in office_patterns:
            if filename.startswith(pattern):
                return True
        
        # Проверяем расширения временных файлов
        temp_extensions = ['.tmp', '.temp', '.cache', '.dmp']
        for ext in temp_extensions:
            if filename.endswith(ext):
                return True
        
        return False
    
    def get_accessing_process(self, file_path):
        """Получение информации о процессе, обращающемся к файлу"""
        try:
            # Сначала проверяем, заблокирован ли файл
            if self.file_lock_checker.is_file_locked(file_path):
                locking_process = self.file_lock_checker.get_locking_process(file_path)
                if locking_process:
                    process_info = {
                        'pid': locking_process.get('pid', 0),
                        'name': locking_process.get('name', 'Unknown'),
                        'username': self._get_process_username(locking_process.get('pid'))
                    }
                    
                    # Пытаемся найти удаленный IP
                    remote_ip = self.network_tracker.find_remote_ip_by_pid(process_info['pid'])
                    if remote_ip:
                        process_info['remote_ip'] = remote_ip
                    else:
                        external_ip = self.network_tracker.get_external_ip()
                        if external_ip:
                            process_info['external_ip'] = external_ip
                    
                    return process_info
            
            # Если файл не заблокирован, ищем через open_files
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    for f in proc.open_files():
                        if f.path.lower() == file_path.lower():
                            process_info = {
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'username': proc.info['username']
                            }
                            
                            remote_ip = self.network_tracker.find_remote_ip_by_pid(proc.info['pid'])
                            if remote_ip:
                                process_info['remote_ip'] = remote_ip
                            else:
                                external_ip = self.network_tracker.get_external_ip()
                                if external_ip:
                                    process_info['external_ip'] = external_ip
                            
                            return process_info
                except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
                    continue
            
            return None
            
        except Exception as e:
            logger.error(f"[ERROR] Ошибка получения информации о процессе для файла {file_path}: {e}")
            return None
    
    def _get_process_username(self, pid):
        """Получает имя пользователя для процесса"""
        try:
            if pid:
                proc = psutil.Process(pid)
                return proc.username()
        except:
            pass
        return 'Unknown'
    
    def is_monitor_process(self, process_name):
        """Проверяет, является ли процесс процессом мониторинга"""
        if not process_name:
            return False
        process_lower = process_name.lower()
        for monitor_proc in self.monitor_processes:
            if monitor_proc in process_lower:
                return True
        return False
    
    def should_debounce(self, token_guid):
        """Проверка дебаунсинга - не обрабатывать частые события"""
        current_time = time.time()
        
        if token_guid in self.last_trigger_time:
            time_diff = current_time - self.last_trigger_time[token_guid]
            if time_diff < 2:
                logger.debug(f"[DEBOUNCE] Игнорируем частый запрос для токена {token_guid}")
                return True
        
        self.last_trigger_time[token_guid] = current_time
        return False
    
    def should_send_alert(self, token_guid):
        """Проверка, нужно ли отправлять алерт"""
        current_time = time.time()
        
        if token_guid in self.last_alert_time:
            time_diff = current_time - self.last_alert_time[token_guid]
            if time_diff < 30:
                logger.debug(f"[ALERT] Пропускаем дублирующий алерт для токена {token_guid}")
                return False
        
        self.last_alert_time[token_guid] = current_time
        return True
    
    def is_in_cooldown(self, file_path, event_type, cooldown_seconds=5):
        """Проверяет, находится ли событие в кулдауне"""
        current_time = time.time()
        cache_key = f"{file_path}:{event_type}"
        
        if cache_key in self.event_cooldown:
            time_diff = current_time - self.event_cooldown[cache_key]
            if time_diff < cooldown_seconds:
                logger.debug(f"[COOLDOWN] Игнорируем событие в кулдауне: {cache_key}, {time_diff:.2f} сек")
                return True
        
        self.event_cooldown[cache_key] = current_time
        
        # Очищаем старые записи
        old_keys = [k for k, v in self.event_cooldown.items() 
                   if current_time - v > 60]
        for key in old_keys:
            del self.event_cooldown[key]
        
        return False
    
    def check_file_open(self, file_path):
        """Проверяет, открыт ли файл в другой программе"""
        try:
            # Проверяем блокировку файла
            is_locked = self.file_lock_checker.is_file_locked(file_path)
            
            if is_locked:
                logger.debug(f"[OPEN CHECK] Файл {file_path} заблокирован (открыт)")
                return True
            
            # Дополнительная проверка через время доступа
            try:
                access_time = os.path.getatime(file_path)
                current_time = time.time()
                
                # Если файл был открыт менее 10 секунд назад
                if current_time - access_time < 10:
                    logger.debug(f"[OPEN CHECK] Файл {file_path} открыт недавно ({current_time - access_time:.1f} сек)")
                    return True
            except:
                pass
            
            return False
            
        except Exception as e:
            logger.error(f"[ERROR] Ошибка проверки открытия файла {file_path}: {e}")
            return False
    
    def trigger_alert(self, token_guid, file_path, event_type='open'):
        """Обработка срабатывания токена"""
        # Проверяем дебаунсинг
        if self.should_debounce(token_guid):
            return
        
        # Проверяем, нужно ли отправлять алерт
        if not self.should_send_alert(token_guid):
            logger.debug(f"[ALERT] Пропускаем дублирующий алерт для токена {token_guid}")
            return
        
        logger.warning(f"[ALERT] Срабатывание токена {token_guid}: {event_type.upper()} - {file_path}")
        
        # Получаем информацию о процессе
        process_info = self.get_accessing_process(file_path)
        
        # Проверяем, не является ли процесс процессом мониторинга
        if process_info and self.is_monitor_process(process_info.get('name')):
            logger.info(f"[INFO] Игнорируем событие от процесса мониторинга: {process_info.get('name')}")
            return
        
        # Определяем IP адрес
        ip_address = None
        if process_info:
            ip_address = process_info.get('remote_ip') or process_info.get('external_ip')
        
        if not ip_address:
            ip_address = "127.0.0.1"
            logger.debug(f"[DEBUG] Используем локальный IP для процесса")
        
        # Помечаем токен как сработавший
        self.token_manager.mark_token_triggered(token_guid, ip=ip_address, 
                                               process_info=process_info, event_type=event_type)
        
        # Получаем геоданные по IP
        geo_data = None
        if ip_address and ip_address not in ['127.0.0.1', 'localhost', '0.0.0.0']:
            geo_data = self._get_geo_data(ip_address)
            if geo_data:
                self.token_manager.update_token_geo(token_guid, geo_data)
        
        # Создаем дополнительные ловушки (максимум 2)
        if self.config.get('traps', {}).get('levels', 0) > 0:
            self.create_trap_tokens(token_guid, file_path)
        
        # Отправляем уведомление в Telegram
        self.send_telegram_alert(token_guid, file_path, event_type, ip_address, 
                               process_info, geo_data)
        
        # Обновляем историю доступа
        self.file_access_history[file_path] = time.time()
    
    def create_trap_tokens(self, token_guid, file_path):
        """Создание дополнительных ловушек (максимум 2)"""
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            supported_extensions = ['.txt', '.pdf', '.docx', '.xlsx', '.xls']
            
            if file_ext not in supported_extensions:
                return
            
            current_time = time.time()
            if token_guid in self.last_trap_creation:
                time_diff = current_time - self.last_trap_creation[token_guid]
                if time_diff < 300:
                    logger.debug(f"[DEBUG] Ловушки уже создавались недавно для токена {token_guid}")
                    return
            
            # Получаем количество уже созданных ловушек
            existing_traps = self.count_existing_traps(file_path)
            if existing_traps >= 2:
                logger.info(f"[INFO] Для токена {token_guid} уже создано 2 ловушки, пропускаем")
                return
            
            traps_to_create = min(2 - existing_traps, self.config['traps'].get('levels', 2))
            if traps_to_create <= 0:
                return
            
            logger.info(f"[INFO] Создание {traps_to_create} ловушек для токена {token_guid}")
            
            trap_tokens = []
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            directory = os.path.dirname(file_path)
            
            for i in range(traps_to_create):
                trap_name = f"backup_{base_name}_v{i+1+existing_traps}{file_ext}"
                trap_path = os.path.join(directory, trap_name)
                
                if os.path.exists(trap_path):
                    logger.debug(f"[DEBUG] Ловушка уже существует: {trap_path}")
                    continue
                
                # Генерируем новый токен
                trap_guid = self.token_manager.generate_file_token(
                    trap_path,
                    use_faker=True,
                    obfuscate_guid=True
                )
                trap_tokens.append((trap_guid, trap_path))
                logger.info(f"[TRAP] Создана ловушка: {trap_path}, GUID: {trap_guid}")
            
            self.last_trap_creation[token_guid] = current_time
            
            if trap_tokens:
                logger.info(f"[TRAP] Сгенерировано {len(trap_tokens)} дополнительных ловушек")
                
        except Exception as e:
            logger.error(f"[ERROR] Ошибка создания ловушек для {file_path}: {e}")
    
    def count_existing_traps(self, original_file_path):
        """Подсчет существующих ловушек"""
        try:
            base_name = os.path.splitext(os.path.basename(original_file_path))[0]
            ext = os.path.splitext(original_file_path)[1].lower()
            directory = os.path.dirname(original_file_path)
            
            if not os.path.exists(directory):
                return 0
            
            trap_count = 0
            for filename in os.listdir(directory):
                if filename.startswith(f"backup_{base_name}_v") and filename.endswith(ext):
                    trap_count += 1
            
            return trap_count
        except Exception as e:
            logger.error(f"[ERROR] Ошибка подсчета ловушек: {e}")
            return 0
    
    def _get_geo_data(self, ip):
        """Получение геоданных по IP"""
        try:
            if ip in ['127.0.0.1', 'localhost', '0.0.0.0']:
                return None
                
            url = self.config['geo']['api_url'].format(ip=ip)
            response = requests.get(url, timeout=self.config['geo']['timeout'])
            if response.status_code == 200:
                data = response.json()
                loc = data.get('loc', '').split(',')
                return {
                    'city': data.get('city', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'lat': float(loc[0]) if loc and loc[0] else 0,
                    'lng': float(loc[1]) if loc and len(loc) > 1 else 0
                }
        except Exception as e:
            logger.error(f"[ERROR] Ошибка получения геоданных для IP {ip}: {e}")
        return None
    
    def send_telegram_alert(self, token_guid, file_path, event_type, ip_address, 
                          process_info, geo_data):
        """Отправка уведомления в Telegram"""
        event_type_text = {
            'open': '📖 ОТКРЫТИЕ',
            'delete': '🗑️ УДАЛЕНИЕ'
        }.get(event_type, '🚨 СОБЫТИЕ')
        
        process_text = ""
        if process_info:
            process_text = f"\n<b>Процесс:</b> {process_info.get('name', 'N/A')}"
            process_text += f"\n<b>PID:</b> {process_info.get('pid', 'N/A')}"
            process_text += f"\n<b>Пользователь:</b> {process_info.get('username', 'N/A')}"
        
        ip_text = ""
        if ip_address:
            ip_text = f"\n<b>IP адрес:</b> <code>{ip_address}</code>"
            if geo_data:
                ip_text += f"\n<b>Геолокация:</b> {geo_data.get('city', 'N/A')}, {geo_data.get('country', 'N/A')}"
                if geo_data.get('lat') and geo_data.get('lng'):
                    ip_text += f"\n<b>Координаты:</b> {geo_data['lat']}, {geo_data['lng']}"
        
        alert_msg = f"""
🚨 <b>СРАБАТЫВАНИЕ HONEY TOKEN!</b> 🚨

<b>Тип события:</b> {event_type_text}
<b>ID токена:</b> <code>{token_guid}</code>
<b>Файл:</b> <code>{os.path.basename(file_path)}</code>
<b>Путь:</b> <code>{file_path}</code>{process_text}{ip_text}
<b>Время:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

⚡ <b>Требуется немедленное реагирование!</b>
        """
        
        success = self.notifier.send_alert(alert_msg)
        if success:
            logger.info("[INFO] Оповещение отправлено администратору")
        else:
            logger.error("[ERROR] Ошибка при отправке оповещения!")
    
    def on_modified(self, event):
        """Обработчик события изменения файла"""
        if not event.is_directory:
            file_path = event.src_path
            logger.debug(f"[EVENT] Файловое событие: {file_path}")
            
            # Пропускаем временные файлы
            if self.is_temporary_file(file_path) or self.is_office_temp_file(file_path):
                logger.debug(f"[DEBUG] Пропускаем временный файл: {file_path}")
                return
            
            # Проверяем кулдаун
            if self.is_in_cooldown(file_path, 'modified', 5):
                return
            
            # Проверяем, является ли файл honeytoken'ом
            if self.is_honeytoken_file(file_path):
                token = self.token_manager.get_token_by_file_path(file_path)
                if token and len(token) > 1:
                    token_guid = token[1]
                    
                    # Проверяем, не сработал ли уже токен
                    triggered = self.token_manager.check_token_triggered(token_guid)
                    if triggered:
                        logger.debug(f"[DEBUG] Токен {token_guid} уже сработал ранее, игнорируем")
                        return
                    
                    # ДЛЯ WORD ФАЙЛОВ: Проверяем, открыт ли файл
                    file_ext = os.path.splitext(file_path)[1].lower()
                    if file_ext in ['.docx', '.doc', '.xlsx', '.xls', '.pdf']:
                        # Добавляем файл в очередь для проверки
                        self.schedule_file_check(file_path, token_guid)
                    else:
                        # Для других файлов сразу проверяем открытие
                        if self.check_file_open(file_path):
                            self.trigger_alert(token_guid, file_path, 'open')
                else:
                    logger.warning(f"[WARNING] Файл {file_path} не найден в базе токенов")
            else:
                logger.debug(f"[DEBUG] Файл {file_path} не является honeytoken'ом")
    
    def schedule_file_check(self, file_path, token_guid):
        """Планирует проверку файла на открытие"""
        try:
            # Проверяем, не проверяется ли уже этот файл
            if file_path in self.active_checks:
                return
            
            # Добавляем в активные проверки
            self.active_checks[file_path] = {
                'guid': token_guid,
                'start_time': time.time(),
                'checked': False
            }
            
            # Запускаем отложенную проверку
            threading.Timer(1.0, self.check_scheduled_file, args=(file_path,)).start()
            
        except Exception as e:
            logger.error(f"[ERROR] Ошибка планирования проверки файла {file_path}: {e}")
    
    def check_scheduled_file(self, file_path):
        """Проверяет запланированный файл на открытие"""
        try:
            if file_path not in self.active_checks:
                return
            
            check_info = self.active_checks[file_path]
            token_guid = check_info['guid']
            
            # Проверяем, открыт ли файл
            if self.check_file_open(file_path):
                logger.info(f"[OPEN DETECTED] Файл {file_path} открыт, срабатывание токена")
                
                # Проверяем, не сработал ли уже токен
                triggered = self.token_manager.check_token_triggered(token_guid)
                if not triggered:
                    self.trigger_alert(token_guid, file_path, 'open')
            
            # Удаляем из активных проверок
            del self.active_checks[file_path]
            
        except Exception as e:
            logger.error(f"[ERROR] Ошибка проверки запланированного файла {file_path}: {e}")
            if file_path in self.active_checks:
                del self.active_checks[file_path]
    
    def on_created(self, event):
        """Обработчик события создания файла"""
        if not event.is_directory:
            file_path = event.src_path
            logger.debug(f"[EVENT] Файл создан: {file_path}")
            
            if self.is_temporary_file(file_path):
                return
    
    def on_deleted(self, event):
        """Обработчик события удаления файла"""
        if not event.is_directory:
            file_path = event.src_path
            logger.debug(f"[EVENT] Файл удален: {file_path}")
            
            if self.is_temporary_file(file_path):
                return
            
            if self.is_honeytoken_file(file_path):
                token = self.token_manager.get_token_by_file_path(file_path)
                if token and len(token) > 1:
                    token_guid = token[1]
                    
                    triggered = self.token_manager.check_token_triggered(token_guid)
                    if not triggered:
                        self.trigger_alert(token_guid, file_path, 'delete')

class FileSystemMonitor:
    def __init__(self, token_manager, notifier, scan_interval=10, config=None):
        self.token_manager = token_manager
        self.notifier = notifier
        self.scan_interval = scan_interval
        self.config = config or {}
        self.network_tracker = NetworkConnectionTracker()
        self.observer = None
        self.event_handler = None
        
    def get_monitored_folders(self):
        """Получение списка папок для мониторинга"""
        monitored_folders = []
        unique_folders = set()
        
        if 'traps_folders' in self.config:
            for folder in self.config['traps_folders']:
                try:
                    norm_path = os.path.normpath(os.path.abspath(folder))
                    if os.path.exists(norm_path):
                        if norm_path not in unique_folders:
                            unique_folders.add(norm_path)
                    else:
                        logger.warning(f"[WARNING] Папка из traps_folders не существует: {norm_path}")
                except Exception as e:
                    logger.error(f"[ERROR] Ошибка обработки папки {folder}: {e}")
        
        if 'monitoring' in self.config and 'file_paths_to_monitor' in self.config['monitoring']:
            for folder in self.config['monitoring']['file_paths_to_monitor']:
                try:
                    norm_path = os.path.normpath(os.path.abspath(folder))
                    if os.path.exists(norm_path):
                        if norm_path not in unique_folders:
                            unique_folders.add(norm_path)
                    else:
                        logger.warning(f"[WARNING] Папка из file_paths_to_monitor не существует: {norm_path}")
                except Exception as e:
                    logger.error(f"[ERROR] Ошибка обработки папки {folder}: {e}")
        
        monitored_folders = sorted(list(unique_folders))
        
        logger.info(f"[STATS] Найдено {len(monitored_folders)} уникальных папок для мониторинга:")
        for folder in monitored_folders:
            logger.info(f"[STATS]   ✓ {folder}")
        
        return monitored_folders
    
    def start_monitoring(self):
        """Запуск событийного мониторинга"""
        logger.info("[START] Запуск системы событийного мониторинга")
        
        monitored_folders = self.get_monitored_folders()
        
        if not monitored_folders:
            logger.error("[ERROR] Не найдены существующие папки для мониторинга!")
            return
        
        existing_folders = []
        for folder in monitored_folders:
            if os.path.exists(folder):
                existing_folders.append(folder)
            else:
                logger.warning(f"[WARNING] Папка существует в списке, но недоступна: {folder}")
        
        if not existing_folders:
            logger.error("[ERROR] Все папки для мониторинга недоступны!")
            return
        
        logger.info(f"[STATS] Активный мониторинг {len(existing_folders)} папок:")
        for folder in existing_folders:
            logger.info(f"[STATS]   → {folder}")
        
        self.event_handler = HoneytokenFileHandler(self.token_manager, self.notifier, self.config)
        self.observer = Observer()
        
        successful_folders = 0
        for folder in existing_folders:
            try:
                self.observer.schedule(self.event_handler, folder, recursive=True)
                successful_folders += 1
                logger.debug(f"[DEBUG] Наблюдатель успешно добавлен для папки: {folder}")
            except Exception as e:
                logger.error(f"[ERROR] Ошибка добавления наблюдателя для папки {folder}: {e}")
        
        if successful_folders == 0:
            logger.error("[ERROR] Не удалось добавить ни одного наблюдателя!")
            return
        
        logger.info(f"[SUCCESS] Наблюдатели запущены для {successful_folders} папок")
        
        try:
            logger.info("[TIME] Запуск наблюдателей...")
            self.observer.start()
            logger.info("[STOP] Для остановки нажмите Ctrl+C")
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("[STOP] Мониторинг остановлен пользователем")
        except Exception as e:
            logger.error(f"[ERROR] Критическая ошибка в основном цикле: {e}")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
            logger.info("[STOP] Система мониторинга полностью остановлена")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    token_mgr = HoneyTokenManager("honeytokens.db")
    telegram_notifier = TelegramNotifier("8348079971:AAEPq0sMXZmg4SEpHcDt2sOdxbEx2Zx6sAc", "5537395233")
    
    import json
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    monitor = FileSystemMonitor(token_mgr, telegram_notifier, 10, config)
    
    monitor.start_monitoring()