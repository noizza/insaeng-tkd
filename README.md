
# Mi Web – MySQL + JWT + Roles + Panel Admin

Stack: **Node.js + Express + MySQL + Tailwind (CDN)**  
Seguridad: **bcryptjs** para contraseñas, **JWT** para sesión.

## 🚀 Variables de entorno (`.env`)
Crea un archivo `.env` en la raíz con:
```env
PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=tu_clave
DB_NAME=miweb
JWT_SECRET=cambia_este_secreto
# Seeder opcional para admin inicial
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ybUzEvbg8lzNbV
```

> Si no defines `ADMIN_EMAIL`/`ADMIN_PASSWORD`, el servidor creará un admin con email `admin@example.com` y una contraseña aleatoria que se imprimirá en consola al iniciar.

## ▶️ Ejecutar localmente
```bash
npm install
npm start
# http://localhost:3000
```

## 👑 Reglas
- **Registro de usuarios**: solo **administradores** mediante `POST /admin/register`.
- **Login**: `POST /login` (retorna `token`).
- **Perfil**: `GET /perfil` (requiere token).
- **Panel Admin**:
  - Listar usuarios: `GET /admin/users`
  - Cambiar rol: `PATCH /admin/users/:id/role`
  - Eliminar usuario: `DELETE /admin/users/:id`

## 📁 Estructura
```
/
├─ server.js
├─ package.json
├─ .env (no subir a git)
├─ public/
│   └─ index.html  (presentación, noticias, login y panel admin)
└─ README.md
```

## ☁️ Despliegue
- **Render/Railway**: configura las variables de entorno del `.env` en el panel.
- **GoDaddy u hosting compartido**: si no ofrecen Node.js, usá un VPS o un PaaS (Render/Railway).

## 🔐 Tips de seguridad
- Cambia `JWT_SECRET` por uno fuerte.
- Cambia la contraseña del admin inicial tras el primer login.
- Habilita HTTPS en producción.
