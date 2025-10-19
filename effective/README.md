# Система аутентификации и авторизации

Реализована собственная система аутентификации и авторизации с использованием Django REST Framework, JWT токенов и bcrypt для хеширования паролей.

## Архитектура системы

### Модели данных

1. **User** - пользователи системы
   - email (уникальный)
   - first_name, last_name, middle_name
   - is_active, is_staff, is_superuser
   - created_at, updated_at, deleted_at (мягкое удаление)

2. **Role** - роли пользователей
   - name (уникальное)
   - description

3. **BusinessElement** - бизнес-элементы системы
   - name (уникальное)
   - description

4. **AccessRoleRule** - правила доступа ролей к элементам
   - role, element (связи)
   - read_permission, read_all_permission
   - create_permission
   - update_permission, update_all_permission
   - delete_permission, delete_all_permission

5. **UserRole** - связь пользователей с ролями
   - user, role (связи)

6. **Product, Order** - mock-объекты для демонстрации

### Система прав доступа

Система основана на ролевой модели с детализированными правами:

- **read_permission** - чтение собственных объектов
- **read_all_permission** - чтение всех объектов
- **create_permission** - создание объектов
- **update_permission** - изменение собственных объектов
- **update_all_permission** - изменение всех объектов
- **delete_permission** - удаление собственных объектов
- **delete_all_permission** - удаление всех объектов

### Роли по умолчанию

1. **admin** - полные права на все элементы
2. **manager** - права на товары и заказы (кроме удаления)
3. **user** - ограниченные права (только свои объекты)
4. **guest** - только чтение товаров

## API Endpoints

### Аутентификация
- `POST /api/auth/register/` - регистрация пользователя
- `POST /api/auth/login/` - вход в систему
- `POST /api/auth/logout/` - выход из системы
- `GET /api/auth/profile/` - получение профиля
- `PUT /api/auth/profile/` - обновление профиля
- `DELETE /api/auth/delete/` - удаление аккаунта (мягкое)

### Управление ролями и правами (только для админов)
- `GET /api/admin/roles/` - список ролей
- `POST /api/admin/roles/` - создание роли
- `GET /api/admin/elements/` - список бизнес-элементов
- `POST /api/admin/elements/` - создание элемента
- `GET /api/admin/rules/` - список правил доступа
- `POST /api/admin/rules/` - создание правила

### Mock-объекты
- `GET /api/products/` - список товаров
- `POST /api/products/` - создание товара
- `GET /api/orders/` - список заказов
- `POST /api/orders/` - создание заказа

## Тестовые данные

Созданы следующие тестовые пользователи:

- **Админ**: admin@example.com / admin123
- **Менеджер**: manager@example.com / manager123
- **Пользователь 1**: user1@example.com / user123
- **Пользователь 2**: user2@example.com / user123

## Технологии

- Django 5.2.7
- Django REST Framework
- JWT (PyJWT)
- bcrypt для хеширования паролей
- SQLite (для разработки)

## Запуск

1. Активировать виртуальное окружение:
```bash
source /home/arlen/new2/venv/bin/activate
```

2. Перейти в директорию проекта:
```bash
cd /home/arlen/new2/effective
```

3. Запустить сервер:
```bash
python manage.py runserver
```

4. API доступно по адресу: http://127.0.0.1:8000/api/

## Примеры использования

### Регистрация пользователя
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "first_name": "Тест",
    "last_name": "Тестов",
    "password": "password123",
    "password_confirm": "password123"
  }'
```

### Вход в систему
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123"
  }'
```

### Получение списка товаров (с токеном)
```bash
curl -X GET http://127.0.0.1:8000/api/products/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Безопасность

- Пароли хешируются с помощью bcrypt
- JWT токены имеют срок действия (7 дней)
- Middleware проверяет аутентификацию для защищенных endpoints
- Система авторизации проверяет права доступа на уровне API
- Мягкое удаление пользователей (is_active=False)

## Обработка ошибок

- 401 Unauthorized - неверный токен или пользователь не аутентифицирован
- 403 Forbidden - недостаточно прав для выполнения действия
- 400 Bad Request - неверные данные запроса
