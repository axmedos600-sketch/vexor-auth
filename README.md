# Vexor Auth Server

Небольшой API для лоадера: проверяет логин, пароль, срок подписки, бан и привязывает первый HWID.

## 1. Supabase

Создай проект Supabase и выполни SQL из `schema.sql`.

## 2. Переменные сервера

На Vercel/Render добавь:

```env
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=service_role_key_from_supabase
JWT_SECRET=any_long_random_secret
```

`SERVICE_ROLE_KEY` нельзя вставлять в лоадер. Он должен быть только на сервере.

## 3. Создать пользователя

На своем ПК:

```powershell
cd auth-server
$env:SUPABASE_URL="https://xxxxx.supabase.co"
$env:SUPABASE_SERVICE_ROLE_KEY="service_role_key"
node scripts/create-user.mjs test 123456 2099-01-01
```

## 4. URL для лоадера

После деплоя получишь ссылку вида:

```text
https://your-project.vercel.app/api/auth/login
```

Ее нужно вставить в `_incoming/vexor-electron/electron/main.js` вместо `https://YOUR-AUTH-SERVER.example.com/api/auth/login`.
