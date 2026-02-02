from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired
import sqlite3
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
import folium
from honeytoken_core import HoneyTokenManager
import logging
import json
import os
from datetime import datetime
import shutil  # Добавляем импорт

logger = logging.getLogger(__name__)

class LoginForm(FlaskForm):
    """Форма входа в систему"""
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class FolderForm(FlaskForm):
    """Форма создания папки"""
    folder_name = StringField('Имя папки', validators=[DataRequired()])
    submit = SubmitField('Создать папку')

class TokenForm(FlaskForm):
    """Форма создания токена"""
    filename = StringField('Имя файла', validators=[DataRequired()])
    file_format = SelectField('Формат файла', choices=[
        ('txt', 'Текстовый файл (.txt)'),
        ('pdf', 'PDF документ (.pdf)'),
        ('xlsx', 'Excel файл (.xlsx)'),
        ('docx', 'Word документ (.docx)')
    ], validators=[DataRequired()])
    submit = SubmitField('Создать файл-ловушку')

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

def init_auth_database(db_path):
    """Инициализация базы данных для аутентификации"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Создаем таблицу пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Проверяем наличие пользователей
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    # Создаем пользователя по умолчанию, если нет пользователей
    if user_count == 0:
        default_password = "HoneyToken2025!"
        password_hash = generate_password_hash(default_password)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ('admin', password_hash)
        )
        logger.info("Создан пользователь по умолчанию: admin")
    
    conn.commit()
    conn.close()

def get_user_by_username(db_path, username):
    """Получить пользователя по имени"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1]), user_data[2]
    return None, None

def get_user_by_id(db_path, user_id):
    """Получить пользователя по ID"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1])
    return None

def start_dashboard(config, token_manager):
    """Запуск защищенного веб-дашборда"""
    app = Flask(__name__, template_folder='templates')
    app.secret_key = config['dashboard']['secret_key']
    
    # Инициализация Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'
    login_manager.login_message_category = 'warning'
    
    db_path = config['database']['path']
    
    # Инициализация базы аутентификации
    init_auth_database(db_path)
    
    @login_manager.user_loader
    def load_user(user_id):
        return get_user_by_id(db_path, user_id)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Страница входа"""
        if current_user.is_authenticated:
            return redirect(url_for('index'))
            
        form = LoginForm()
        if form.validate_on_submit():
            user, password_hash = get_user_by_username(db_path, form.username.data)
            
            if user and check_password_hash(password_hash, form.password.data):
                login_user(user)
                logger.info(f"Успешный вход пользователя: {user.username}")
                flash('Вы успешно вошли в систему!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                logger.warning(f"Неудачная попытка входа: {form.username.data}")
                flash('Неверное имя пользователя или пароль!', 'danger')
        
        return render_template('login.html', form=form)
    
    @app.route('/logout')
    @login_required
    def logout():
        """Выход из системы"""
        username = current_user.username
        logout_user()
        logger.info(f"Пользователь вышел из системы: {username}")
        flash('Вы успешно вышли из системы.', 'info')
        return redirect(url_for('login'))
    
    def safe_get_token_field(token, index, default=None):
        """Безопасное получение поля токена по индексу"""
        try:
            if len(token) > index:
                return token[index]
            return default
        except (IndexError, TypeError):
            return default
    
    @app.route('/')
    @login_required
    def index():
        """Главная страница дашборда"""
        try:
            all_tokens = token_manager.get_all_tokens()
            active_file_tokens = token_manager.get_active_file_tokens()
            
            # Обновленная статистика (без файловых токенов)
            triggered_count = 0
            
            for token in all_tokens:
                triggered = safe_get_token_field(token, 5, 0)
                if triggered:
                    triggered_count += 1
            
            stats = {
                'total': len(all_tokens),
                'active': len(active_file_tokens),
                'triggered': triggered_count
            }
            
            return render_template('index.html', stats=stats, tokens=all_tokens)
        except Exception as e:
            logger.error(f"Ошибка в главной странице: {e}")
            return f"Ошибка: {e}", 500

    @app.route('/map')
    @login_required
    def threat_map():
        """Карта угроз с геолокацией"""
        try:
            all_tokens = token_manager.get_all_tokens()
            triggered_tokens = []
            
            # Безопасно фильтруем токены с геоданными
            for token in all_tokens:
                triggered = safe_get_token_field(token, 5, 0)
                latitude = safe_get_token_field(token, 10)
                longitude = safe_get_token_field(token, 11)
                city = safe_get_token_field(token, 8)
                country = safe_get_token_field(token, 9)
                
                if triggered and latitude and longitude:
                    triggered_tokens.append(token)
            
            # Создаем карту с центром в средних координатах
            if triggered_tokens:
                lats = []
                lons = []
                for token in triggered_tokens:
                    lat = safe_get_token_field(token, 10)
                    lon = safe_get_token_field(token, 11)
                    if lat and lon:
                        lats.append(float(lat))
                        lons.append(float(lon))
                
                if lats and lons:
                    center_lat = sum(lats) / len(lats)
                    center_lon = sum(lons) / len(lons)
                else:
                    center_lat, center_lon = 55.7558, 37.6173  # Москва по умолчанию
            else:
                center_lat, center_lon = 55.7558, 37.6173  # Москва по умолчанию
                
            threat_map = folium.Map(
                location=[center_lat, center_lon], 
                zoom_start=2,
                tiles='OpenStreetMap'
            )
            
            # Добавляем маркеры для каждого срабатывания
            for token in triggered_tokens:
                lat = safe_get_token_field(token, 10)
                lon = safe_get_token_field(token, 11)
                city = safe_get_token_field(token, 8, 'Unknown')
                country = safe_get_token_field(token, 9, 'Unknown')
                ip = safe_get_token_field(token, 7, 'N/A')
                token_guid = safe_get_token_field(token, 1, 'Unknown')
                triggered_at = safe_get_token_field(token, 6, 'Unknown')
                event_type = safe_get_token_field(token, 15, 'unknown')
                
                if lat and lon:
                    try:
                        event_type_text = "Открытие" if event_type == 'open' else "Изменение"
                        popup_text = f"""
                        <div style="min-width: 200px;">
                            <h5>🚨 Срабатывание Honey Token</h5>
                            <hr>
                            <p><b>Тип события:</b> {event_type_text}</p>
                            <p><b>Token ID:</b> {token_guid[:8]}...</p>
                            <p><b>Место:</b> {city}, {country}</p>
                            <p><b>IP:</b> {ip}</p>
                            <p><b>Время:</b> {triggered_at}</p>
                        </div>
                        """
                        
                        folium.Marker(
                            [float(lat), float(lon)],
                            popup=folium.Popup(popup_text, max_width=300),
                            tooltip=f"Угроза из {city}, {country}",
                            icon=folium.Icon(color='red', icon='warning-sign', prefix='fa')
                        ).add_to(threat_map)
                    except Exception as e:
                        logger.error(f"Ошибка добавления маркера: {e}")
                        continue
            
            # Если нет данных, добавляем информационный маркер
            if not triggered_tokens:
                folium.Marker(
                    [center_lat, center_lon],
                    popup="<b>Нет данных об угрозах</b><br>Срабатываний с геоданными не обнаружено",
                    tooltip="Угроз не обнаружено",
                    icon=folium.Icon(color='green', icon='info-sign', prefix='fa')
                ).add_to(threat_map)
                
                # Добавляем круг для видимости
                folium.Circle(
                    location=[center_lat, center_lon],
                    radius=1000000,
                    popup="Зона мониторинга",
                    color='green',
                    fill=True,
                    fillOpacity=0.1
                ).add_to(threat_map)
            
            return threat_map._repr_html_()
        except Exception as e:
            logger.error(f"Ошибка в карте угроз: {e}")
            return f"""
            <html>
                <head><title>Ошибка карты</title></head>
                <body>
                    <h1>Ошибка при создании карты</h1>
                    <p>{str(e)}</p>
                    <a href="/">Вернуться на главную</a>
                </body>
            </html>
            """, 500

    @app.route('/health')
    @login_required
    def health_check():
        """Проверка здоровья приложения"""
        try:
            # Проверяем подключение к базе данных
            tokens_count = len(token_manager.get_all_tokens())
            
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'tokens_count': tokens_count,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500

    # Новые маршруты для управления папками и файлами
    @app.route('/folders', methods=['GET', 'POST'])
    @login_required
    def manage_folders():
        """Управление папками для ловушек"""
        try:
            form = FolderForm()
            
            if form.validate_on_submit():
                folder_name = form.folder_name.data
                folder_path = os.path.join(config['token_generation']['default_file_path'], folder_name)
                
                try:
                    # Создаем папку
                    os.makedirs(folder_path, exist_ok=True)
                    
                    # Добавляем в конфиг (в памяти)
                    if 'traps_folders' not in config:
                        config['traps_folders'] = []
                    
                    if folder_path not in config['traps_folders']:
                        config['traps_folders'].append(folder_path)
                        
                        # Сохраняем обновленный конфиг в файл
                        try:
                            config_file_path = 'config.json'
                            with open(config_file_path, 'w', encoding='utf-8') as f:
                                json.dump(config, f, indent=2, ensure_ascii=False)
                            logger.info(f"Конфиг обновлен: добавлена папка {folder_path}")
                            
                            # Также добавляем в пути для мониторинга
                            if 'monitoring' not in config:
                                config['monitoring'] = {}
                            if 'file_paths_to_monitor' not in config['monitoring']:
                                config['monitoring']['file_paths_to_monitor'] = []
                            
                            if folder_path not in config['monitoring']['file_paths_to_monitor']:
                                config['monitoring']['file_paths_to_monitor'].append(folder_path)
                                with open(config_file_path, 'w', encoding='utf-8') as f:
                                    json.dump(config, f, indent=2, ensure_ascii=False)
                                logger.info(f"Папка добавлена в пути мониторинга: {folder_path}")
                                
                        except Exception as e:
                            logger.error(f"Ошибка сохранения конфига: {e}")
                            flash(f'Папка создана, но конфиг не обновлен: {str(e)}', 'warning')
                
                    flash(f'Папка "{folder_name}" успешно создана и добавлена в мониторинг!', 'success')
                    logger.info(f"Создана новая папка для ловушек: {folder_path}")
                    return redirect(url_for('manage_folders'))
                    
                except Exception as e:
                    flash(f'Ошибка при создании папки: {str(e)}', 'danger')
                    logger.error(f"Ошибка создания папки: {e}")
            
            # Получаем список папок из конфига
            folders = config.get('traps_folders', [])
            
            # Добавляем папки из конфига мониторинга
            monitoring_folders = config.get('monitoring', {}).get('file_paths_to_monitor', [])
            if monitoring_folders:
                folders.extend(monitoring_folders)
            
            # Убираем дубликаты
            folders = list(set(folders))
            
            # Получаем общее количество токенов
            total_tokens = len(token_manager.get_all_tokens())
            
            return render_template('folders.html', 
                                 form=form, 
                                 folders=folders, 
                                 total_tokens=total_tokens,
                                 config=config)
            
        except Exception as e:
            logger.error(f"Ошибка в маршруте manage_folders: {e}")
            flash(f'Ошибка при загрузке страницы: {str(e)}', 'danger')
            return redirect(url_for('index'))

    @app.route('/folder/<path:folder_path>', methods=['GET', 'POST'])
    @login_required
    def view_folder(folder_path):
        """Просмотр содержимого папки и создание файлов-ловушек"""
        try:
            form = TokenForm()
            
            if form.validate_on_submit():
                filename = form.filename.data
                file_format = form.file_format.data
                file_path = os.path.join(folder_path, f"{filename}.{file_format}")
                
                try:
                    # Создаем файл-ловушку
                    token_guid = token_manager.generate_file_token(
                        file_path,
                        use_faker=True,
                        obfuscate_guid=True
                    )
                    
                    flash(f'Файл-ловушка успешно создан! ID: {token_guid}', 'success')
                    logger.info(f"Создан файл-ловушка: {file_path}")
                    return redirect(url_for('view_folder', folder_path=folder_path))
                    
                except Exception as e:
                    flash(f'Ошибка при создании файла: {str(e)}', 'danger')
                    logger.error(f"Ошибка создания файла-ловушки: {e}")
            
            # Получаем файлы в папке
            files = []
            try:
                if os.path.exists(folder_path):
                    for item in os.listdir(folder_path):
                        item_path = os.path.join(folder_path, item)
                        if os.path.isfile(item_path):
                            # Получаем информацию о токене
                            token_info = token_manager.get_token_by_file_path(item_path)
                            try:
                                created_time = datetime.fromtimestamp(os.path.getctime(item_path))
                            except:
                                created_time = datetime.now()
                                
                            files.append({
                                'name': item,
                                'path': item_path,
                                'size': os.path.getsize(item_path) if os.path.exists(item_path) else 0,
                                'created': created_time,
                                'token_info': token_info
                            })
            except Exception as e:
                flash(f'Ошибка при чтении папки: {str(e)}', 'warning')
                logger.error(f"Ошибка чтения папки {folder_path}: {e}")
            
            return render_template('folder.html', 
                                 form=form, 
                                 folder_path=folder_path, 
                                 files=files)
                                 
        except Exception as e:
            logger.error(f"Ошибка в маршруте view_folder: {e}")
            flash(f'Ошибка при загрузке страницы: {str(e)}', 'danger')
            return redirect(url_for('manage_folders'))

    @app.route('/folder-info')
    @login_required
    def folder_info():
        """API для получения информации о папке"""
        try:
            folder_path = request.args.get('path')
            if not folder_path or not os.path.exists(folder_path):
                return jsonify({'success': False, 'error': 'Папка не найдена'})
            
            # Вычисляем размер папки
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.exists(fp):
                        total_size += os.path.getsize(fp)
            
            # Форматируем размер
            if total_size < 1024:
                size_str = f"{total_size} Б"
            elif total_size < 1048576:
                size_str = f"{total_size/1024:.1f} КБ"
            else:
                size_str = f"{total_size/1048576:.1f} МБ"
            
            return jsonify({
                'success': True,
                'size': size_str,
                'bytes': total_size
            })
            
        except Exception as e:
            logger.error(f"Ошибка в folder_info: {e}")
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/monitoring')
    @login_required
    def monitoring():
        """Страница мониторинга событий"""
        try:
            logger.debug("Загрузка страницы мониторинга")
            
            # Получаем все сработавшие токены с детальной информацией
            all_tokens = token_manager.get_all_tokens()
            triggered_tokens = []
            
            for token in all_tokens:
                triggered = safe_get_token_field(token, 5, 0)
                if triggered:
                    token_data = {
                        'id': safe_get_token_field(token, 0),
                        'guid': safe_get_token_field(token, 1, 'Unknown'),
                        'location': safe_get_token_field(token, 3, 'Unknown'),
                        'event_type': safe_get_token_field(token, 15, 'unknown'),
                        'triggered_at': safe_get_token_field(token, 6, 'Unknown'),
                        'ip': safe_get_token_field(token, 7),
                        'city': safe_get_token_field(token, 8),
                        'country': safe_get_token_field(token, 9),
                        'process_name': safe_get_token_field(token, 12),
                        'process_pid': safe_get_token_field(token, 13),
                        'username': safe_get_token_field(token, 14)
                    }
                    triggered_tokens.append(token_data)
            
            # Сортируем по времени срабатывания (новые первыми)
            def get_timestamp(t):
                try:
                    return datetime.strptime(t['triggered_at'], '%Y-%m-%d %H:%M:%S') if t['triggered_at'] and t['triggered_at'] != 'Unknown' else datetime.min
                except:
                    return datetime.min
            
            triggered_tokens.sort(key=get_timestamp, reverse=True)
            
            # Статистика по типам событий
            event_stats = {
                'open': len([t for t in triggered_tokens if t['event_type'] == 'open']),
                'modify': len([t for t in triggered_tokens if t['event_type'] == 'modify']),
                'total': len(triggered_tokens)
            }
            
            logger.debug(f"Мониторинг загружен: {len(triggered_tokens)} событий")
            
            return render_template('monitoring.html', 
                                 events=triggered_tokens,
                                 event_stats=event_stats)
            
        except Exception as e:
            logger.error(f"Ошибка в мониторинге: {e}")
            return render_template('monitoring.html', events=[], error=str(e))

    @app.route('/monitoring/events')
    @login_required
    def monitoring_events_api():
        """API для получения событий мониторинга (для AJAX)"""
        try:
            logger.debug("API мониторинга: получение событий")
            
            all_tokens = token_manager.get_all_tokens()
            triggered_tokens = []
            
            for token in all_tokens:
                triggered = safe_get_token_field(token, 5, 0)
                if triggered:
                    token_data = {
                        'id': safe_get_token_field(token, 0),
                        'guid': safe_get_token_field(token, 1, 'Unknown'),
                        'location': safe_get_token_field(token, 3, 'Unknown'),
                        'event_type': safe_get_token_field(token, 15, 'unknown'),
                        'triggered_at': safe_get_token_field(token, 6, 'Unknown'),
                        'ip': safe_get_token_field(token, 7),
                        'city': safe_get_token_field(token, 8),
                        'country': safe_get_token_field(token, 9),
                        'process_name': safe_get_token_field(token, 12),
                        'process_pid': safe_get_token_field(token, 13),
                        'username': safe_get_token_field(token, 14)
                    }
                    triggered_tokens.append(token_data)
            
            # Сортируем
            def get_timestamp(t):
                try:
                    return datetime.strptime(t['triggered_at'], '%Y-%m-%d %H:%M:%S') if t['triggered_at'] and t['triggered_at'] != 'Unknown' else datetime.min
                except:
                    return datetime.min
            
            triggered_tokens.sort(key=get_timestamp, reverse=True)
            
            # Пагинация
            page = request.args.get('page', 1, type=int)
            per_page = 50
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_events = triggered_tokens[start_idx:end_idx]
            
            logger.debug(f"API мониторинга: возвращено {len(paginated_events)} событий")
            
            return jsonify({
                'status': 'success',
                'events': paginated_events,
                'count': len(triggered_tokens),
                'page': page,
                'total_pages': (len(triggered_tokens) + per_page - 1) // per_page,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Ошибка API мониторинга: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500

    # НОВЫЙ ENDPOINT: Получение детальной информации о токене
    @app.route('/monitoring/token/<string:token_guid>')
    @login_required
    def get_token_details(token_guid):
        """API для получения детальной информации о токене по GUID"""
        try:
            logger.debug(f"API деталей токена: запрос для {token_guid}")
            token = token_manager.get_token_by_guid(token_guid)
            if not token:
                logger.warning(f"Токен {token_guid} не найден")
                return jsonify({'error': 'Token not found'}), 404
            
            token_details = {
                'guid': safe_get_token_field(token, 1, 'Unknown'),
                'type': safe_get_token_field(token, 2, 'Unknown'),
                'location': safe_get_token_field(token, 3, 'Unknown'),
                'created_at': safe_get_token_field(token, 4, 'Unknown'),
                'triggered': bool(safe_get_token_field(token, 5, 0)),
                'triggered_at': safe_get_token_field(token, 6, 'Unknown'),
                'ip_address': safe_get_token_field(token, 7, 'N/A'),
                'city': safe_get_token_field(token, 8, 'N/A'),
                'country': safe_get_token_field(token, 9, 'N/A'),
                'latitude': safe_get_token_field(token, 10, 'N/A'),
                'longitude': safe_get_token_field(token, 11, 'N/A'),
                'process_name': safe_get_token_field(token, 12, 'N/A'),
                'process_pid': safe_get_token_field(token, 13, 'N/A'),
                'username': safe_get_token_field(token, 14, 'N/A'),
                'event_type': safe_get_token_field(token, 15, 'unknown')
            }
            
            logger.debug(f"API деталей токена: успешно для {token_guid}")
            return jsonify({'status': 'success', 'token': token_details})
        except Exception as e:
            logger.error(f"Ошибка получения деталей токена {token_guid}: {e}")
            return jsonify({'error': str(e)}), 500

    # НОВЫЙ ENDPOINT: Удаление папки
    @app.route('/folder/delete/<path:folder_path>', methods=['POST'])
    @login_required
    def delete_folder(folder_path):
        """Удаление папки ловушек"""
        try:
            # Проверяем, что папка находится в разрешенных директориях
            base_path = config['token_generation']['default_file_path']
            full_path = os.path.normpath(os.path.join(base_path, folder_path))
            
            # Защита от path traversal
            if not full_path.startswith(os.path.normpath(base_path)):
                flash('Недопустимый путь к папке!', 'danger')
                logger.warning(f"Попытка удаления папки вне разрешенной директории: {folder_path}")
                return redirect(url_for('manage_folders'))
            
            # Проверяем, существует ли папка в конфиге
            folders = config.get('traps_folders', [])
            monitoring_folders = config.get('monitoring', {}).get('file_paths_to_monitor', [])
            
            # Ищем папку в обоих списках
            folder_found = False
            folder_to_remove = None
            
            for folder_list_name, folder_list in [('traps_folders', folders), 
                                                 ('file_paths_to_monitor', monitoring_folders)]:
                for f in folder_list:
                    if os.path.normpath(f) == full_path:
                        folder_found = True
                        folder_to_remove = f
                        
                        # Удаляем из соответствующего списка
                        if folder_list_name == 'traps_folders':
                            config['traps_folders'].remove(f)
                            logger.info(f"Папка удалена из traps_folders: {full_path}")
                        else:
                            config['monitoring']['file_paths_to_monitor'].remove(f)
                            logger.info(f"Папка удалена из file_paths_to_monitor: {full_path}")
                        break
            
            if not folder_found:
                flash('Папка не найдена в конфигурации!', 'warning')
                logger.warning(f"Папка не найдена в конфиге: {full_path}")
                return redirect(url_for('manage_folders'))
            
            # Удаляем физическую папку с подтверждением
            if os.path.exists(full_path):
                try:
                    # Проверяем, пуста ли папка
                    if os.listdir(full_path):
                        # Если в папке есть файлы, спрашиваем подтверждение
                        confirm = request.form.get('confirm', 'false')
                        if confirm != 'true':
                            # Возвращаем страницу с подтверждением
                            return render_template('confirm_delete.html', 
                                                 folder_path=full_path,
                                                 folder_name=folder_path)
                        
                        # Удаляем токены из базы данных перед удалением файлов
                        deleted_tokens = token_manager.delete_folder_tokens(full_path)
                        logger.info(f"Удалено {deleted_tokens} токенов из базы данных для папки {full_path}")
                        
                        # Рекурсивно удаляем папку с файлами
                        shutil.rmtree(full_path)
                        logger.info(f"Папка с файлами удалена: {full_path}")
                        flash(f'Папка "{folder_path}" и все её содержимое удалены! Удалено токенов: {deleted_tokens}', 'warning')
                    else:
                        # Пустая папка - удаляем сразу
                        os.rmdir(full_path)
                        logger.info(f"Пустая папка удалена: {full_path}")
                        flash(f'Папка "{folder_path}" удалена!', 'success')
                except Exception as e:
                    logger.error(f"Ошибка удаления папки {full_path}: {e}")
                    flash(f'Ошибка удаления папки: {str(e)}', 'danger')
                    return redirect(url_for('manage_folders'))
            else:
                flash(f'Папка "{folder_path}" не существует на диске.', 'info')
            
            # Сохраняем обновленный конфиг
            config_file_path = 'config.json'
            try:
                with open(config_file_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                logger.info(f"Конфиг обновлен после удаления папки: {full_path}")
                
                # Удаляем папку из путей для мониторинга если она там есть
                if full_path in config.get('monitoring', {}).get('file_paths_to_monitor', []):
                    config['monitoring']['file_paths_to_monitor'].remove(full_path)
                    with open(config_file_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, indent=2, ensure_ascii=False)
                    logger.info(f"Папка удалена из путей мониторинга: {full_path}")
                    
            except Exception as e:
                logger.error(f"Ошибка сохранения конфига: {e}")
                flash(f'Папка удалена, но конфиг не обновлен: {str(e)}', 'warning')
            
            flash(f'Папка "{folder_path}" успешно удалена из системы!', 'success')
            logger.info(f"Папка полностью удалена: {full_path}")
            
            return redirect(url_for('manage_folders'))
            
        except Exception as e:
            logger.error(f"Ошибка в маршруте delete_folder: {e}")
            flash(f'Ошибка при удалении папки: {str(e)}', 'danger')
            return redirect(url_for('manage_folders'))

    # НОВЫЙ ENDPOINT: Подтверждение удаления папки
    @app.route('/folder/confirm-delete/<path:folder_path>')
    @login_required
    def confirm_delete_folder(folder_path):
        """Страница подтверждения удаления папки"""
        base_path = config['token_generation']['default_file_path']
        full_path = os.path.normpath(os.path.join(base_path, folder_path))
        
        # Получаем информацию о файлах в папке
        files_in_folder = []
        token_count = 0
        if os.path.exists(full_path):
            try:
                files_in_folder = os.listdir(full_path)
                # Получаем количество токенов в папке
                tokens_in_folder = token_manager.get_tokens_in_folder(full_path)
                token_count = len(tokens_in_folder)
            except:
                pass
        
        return render_template('confirm_delete.html',
                             folder_path=full_path,
                             folder_name=folder_path,
                             files_count=len(files_in_folder),
                             token_count=token_count)

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found', 'status': 'error'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

    # Запуск Flask приложения
    try:
        logger.info(f"Запуск защищенного дашборда на порту {config['dashboard']['port']}")
        print(f"🐝 Защищенный дашборд запущен: http://{config['dashboard']['host']}:{config['dashboard']['port']}")
        print("🔐 Требуется аутентификация для доступа")
        print(f"   👤 Логин: admin")
        print(f"   🔑 Пароль: HoneyToken2025!")
        print("📊 Доступные endpoints:")
        print(f"   📍 Главная: http://{config['dashboard']['host']}:{config['dashboard']['port']}/")
        print(f"   🗺️  Карта: http://{config['dashboard']['host']}:{config['dashboard']['port']}/map")
        print(f"   ❤️  Health check: http://{config['dashboard']['host']}:{config['dashboard']['port']}/health")
        print(f"   📁 Управление папками: http://{config['dashboard']['host']}:{config['dashboard']['port']}/folders")
        print(f"   🔍 Мониторинг: http://{config['dashboard']['host']}:{config['dashboard']['port']}/monitoring")
        print(f"   🗑️  Удаление папок: Доступно через интерфейс управления папками")
        
        app.run(
            host=config['dashboard']['host'],
            port=config['dashboard']['port'],
            debug=False
        )
    except Exception as e:
        logger.error(f"Ошибка запуска дашборда: {e}")

if __name__ == "__main__":
    from main import load_config
    config = load_config()
    token_mgr = HoneyTokenManager(config['database']['path'])
    start_dashboard(config, token_mgr)