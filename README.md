# OpLauncher License Server

FastAPI + SQLAlchemy. Поддерживает **SQLite** (по умолчанию, удобно для тестов) и **PostgreSQL**.

## Быстрый старт (локально)

```bash
cd license_server
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# при необходимости отредактируйте DATABASE_URL

python main.py
# или: uvicorn main:app --host 0.0.0.0 --port 8000
```

При **первом** запуске в консоль и в файл `ADMIN_KEY.txt` будет записан секретный ключ администратора.  
**Скопируйте его и удалите файл.** Ключ хранится в БД только в виде хэша.

Документация API: http://127.0.0.1:8000/docs

## API (кратко)

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/v1/activate` | Активация пользовательского ключа + привязка device_id |
| POST | `/api/v1/check` | Проверка лицензии (серверное время) |
| POST | `/api/v1/admin/login` | Вход админа → Bearer token |
| POST | `/api/v1/admin/generate` | Генерация ключей (1/2/5/10 мин) |
| GET | `/api/v1/admin/licenses` | Список / поиск |
| POST | `/api/v1/admin/block` / `unblock` / `revoke` | Управление |
| GET | `/api/v1/admin/history` | История активаций |
| PATCH | `/api/v1/admin/licenses/{key}/devices?max_devices=N` | Лимит устройств |

Срок действия начинается **только при первой успешной активации**. Повторная активация не сбрасывает таймер. Истечение, блокировка и отзыв проверяются по **времени сервера**.

## Бесплатный хостинг (тестовый)

1. **Railway / Render / Fly.io**  
   - Подключите репозиторий с `license_server`.  
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`  
   - Добавьте PostgreSQL addon и задайте `DATABASE_URL`.  
   - Включите HTTPS (по умолчанию у этих платформ).

2. **Neon / Supabase** (только БД) + любой контейнер/VPS с Python.

3. Для самого простого теста оставьте SQLite на VPS с volume (данные переживут рестарт, если файл на постоянном диске).

После деплоя укажите URL сервера в окне активации лаунчера («Настройки сервера») или измените константу `defaultLicenseServerURL` в `license.go` перед сборкой.

## Безопасность

- Админ-ключ никогда не отдаётся клиенту и не вшивается в лаунчер.  
- Пользовательские ключи не дают админ-прав.  
- Админ-токен — HMAC, TTL 8 часов.  
- Секреты (`.admin_secret`, `ADMIN_KEY.txt`) держите вне публичного репозитория.
