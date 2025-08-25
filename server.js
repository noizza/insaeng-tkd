const express = require("express");
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecreto";

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Pool MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function initDB() {
  const conn = await pool.getConnection();
  try {
	// Tabla usuarios
	await conn.query(`
	  CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		nombre VARCHAR(100) NOT NULL,
		email VARCHAR(150) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		rol ENUM('usuario','moderador','administrador') DEFAULT 'usuario',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	  )
	`);

	// Tabla noticias
	await conn.query(`
	  CREATE TABLE IF NOT EXISTS news (
		id INT AUTO_INCREMENT PRIMARY KEY,
		title VARCHAR(255) NOT NULL,
		text TEXT NOT NULL,
		imageUrl VARCHAR(500) NOT NULL,
		tipo ENUM('importante','normal') DEFAULT 'normal',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	  )
	`);
	// Tabla sedes
	await conn.query(`
	  CREATE TABLE IF NOT EXISTS sedes (
		id INT AUTO_INCREMENT PRIMARY KEY,
		nombre VARCHAR(150) NOT NULL,
		lat DECIMAL(10,7) NOT NULL,
		lng DECIMAL(10,7) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	  )
	`);


	// Seed admin si no existe
	const [rows] = await conn.query("SELECT COUNT(*) AS c FROM users WHERE rol='administrador'");
	if (rows[0].c === 0) {
	  const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
	  const adminPass = process.env.ADMIN_PASSWORD || crypto.randomBytes(8).toString("hex");
	  const hash = await bcrypt.hash(adminPass, 10);
	  await conn.query(
		"INSERT INTO users (nombre, email, password_hash, rol) VALUES (?, ?, ?, 'administrador')",
		["Administrador", adminEmail.toLowerCase(), hash]
	  );
	  console.log("🔐 Admin inicial creado:");
	  console.log("   Email:", adminEmail);
	  console.log("   Password:", adminPass);
	  console.log("⚠️  Cambia estas credenciales apenas ingreses.");
	}

	console.log("✅ Tablas listas en MySQL");
  } finally {
	conn.release();
  }
}
initDB().catch(err => { console.error("DB init error:", err); process.exit(1); });

// Middleware Auth
function auth(requiredRoles = []) {
  return (req, res, next) => {
	const authHeader = req.headers["authorization"];
	if (!authHeader) return res.status(401).send("Falta token.");
	const token = authHeader.split(" ")[1];
	try {
	  const decoded = jwt.verify(token, JWT_SECRET);
	  if (requiredRoles.length && !requiredRoles.includes(decoded.rol)) {
		return res.status(403).send("No tienes permiso.");
	  }
	  req.user = decoded;
	  next();
	} catch (err) {
	  return res.status(403).send("Token inválido.");
	}
  };
}

// Middleware de nivel mínimo para permisos jerárquicos
function authNivel(minNivel = 1) {
  return async (req, res, next) => {
	const authHeader = req.headers["authorization"];
	if(!authHeader) return res.status(401).send("Falta token.");
	const token = authHeader.split(" ")[1];
	try {
	  const decoded = jwt.verify(token, JWT_SECRET);

	  // Traer nivel del rol actual desde la DB
	  const conn = await pool.getConnection();
	  const [rows] = await conn.query("SELECT nivel FROM roles WHERE id = ?", [decoded.rol_id]);
	  conn.release();
	  if(rows.length === 0) return res.status(403).send("Rol inválido.");
	  if(rows[0].nivel < minNivel) return res.status(403).send("No tienes permiso suficiente.");

	  req.user = decoded;
	  next();
	} catch (err) {
	  return res.status(403).send("Token inválido.");
	}
  }
}

// Rutas públicas
app.get("/health", (req, res) => res.json({ status: "ok" }));

app.post("/login", async (req, res) => {
  try {
	const { email, password } = req.body;
	if (!email || !password) return res.status(400).send("Faltan datos.");

	const conn = await pool.getConnection();
	const [rows] = await conn.query(`SELECT u.*, r.id as rol_id, r.nivel FROM users u JOIN roles r ON u.rol_id = r.id WHERE email = ?`,
		[email.trim().toLowerCase()]);
	conn.release();

	if (rows.length === 0) return res.status(401).send("Usuario no encontrado.");
	const user = rows[0];
	const match = await bcrypt.compare(password, user.password_hash);
	if (!match) return res.status(401).send("Contraseña incorrecta.");

	const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol, rol_id: user.rol_id, nivel: user.nivel }, JWT_SECRET, { expiresIn: "8h" });
	res.json({ message: "✅ Login exitoso", token, rol: user.rol, nombre: user.nombre });
  } catch (err) {
	console.error(err);
	res.status(500).send("❌ Error en el servidor.");
  }
});

// Perfil
app.get("/perfil", auth(), async (req, res) => {
  res.json({ id: req.user.id, nombre: req.user.nombre, rol: req.user.rol });
});

// --- ADMIN ---
// Usuarios
app.post("/admin/register", auth(["administrador"]), async (req, res) => {
  try {
	const { nombre, email, password, rol_id } = req.body; // ahora recibimos rol_id
	if (!nombre || !email || !password || !rol_id) 
		return res.status(400).send("Faltan datos.");
	const creatorId = req.user.id; // ID del usuario que está creando el nuevo usuario
	const conn = await pool.getConnection();

	// Obtener el nivel del rol a asignar
	const [rolesRows] = await conn.query("SELECT id, nivel FROM roles WHERE id = ?", [rol_id]);
	if (rolesRows.length === 0) {
		conn.release();
		return res.status(400).send("Rol inválido.");
	}
	const rolAsignar = rolesRows[0];

	// Extraer el nivel del usuario actual desde el token
	const payload = req.user; // viene del middleware auth
	const userNivel = payload.nivel || 1;

	// Validación de jerarquía: no puede crear roles de igual o mayor nivel
	if (rolAsignar.nivel >= userNivel) {
		conn.release();
		return res.status(403).send("No puedes asignar un rol de igual o mayor nivel que el tuyo.");
	}

	const hash = await bcrypt.hash(password, 10);
	await conn.query(
	  "INSERT INTO users (nombre, email, password_hash, rol_id,superior_id) VALUES (?, ?, ?, ?, ?)",
	  [nombre.trim(), email.trim().toLowerCase(), hash, rol_id, creatorId]
	);

	conn.release();
	res.status(201).send("✅ Usuario creado por admin.");

  } catch (err) {
	if (err.code === "ER_DUP_ENTRY") return res.status(409).send("Email ya registrado.");
	console.error(err);
	res.status(500).send("❌ Error en el servidor.");
  }
});

app.get("/admin/users", auth(["administrador"]), async (req, res) => {
  const conn = await pool.getConnection();
  const [rows] = await conn.query("SELECT id, nombre, email, rol, created_at FROM users ORDER BY id DESC");
  conn.release();
  res.json(rows);
});

// Editar info de un usuario hijo
app.patch("/admin/users/:id", auth(), async (req, res) => {
	try {
		const { id } = req.params;
		const { nombre, email, rol_id, imageUrl } = req.body;
		const conn = await pool.getConnection();

		// Verificar que el usuario es hijo del que hace la petición
		const [rows] = await conn.query("SELECT * FROM users WHERE id = ?", [id]);
		if(rows.length === 0) { conn.release(); return res.status(404).send("Usuario no encontrado"); }
		const hijo = rows[0];

		if(hijo.superior_id !== req.user.id) {
			conn.release();
			return res.status(403).send("No puedes editar este usuario");
		}

		// Actualizar datos
		await conn.query(
			"UPDATE users SET nombre = ?, email = ?, rol_id = ?, url_fotop = ? WHERE id = ?",
			[nombre, email, rol_id, imageUrl, id]
		);
		conn.release();
		res.send("Usuario actualizado");

	} catch(err) {
		console.error(err);
		res.status(500).send("Error en el servidor");
	}
});

// Eliminar usuario hijo
app.delete("/admin/users/:id", auth(), async (req, res) => {
	try {
		const { id } = req.params;
		const conn = await pool.getConnection();

		// Verificar que el usuario es hijo del superior
		const [rows] = await conn.query("SELECT * FROM users WHERE id = ?", [id]);
		if(rows.length === 0) { conn.release(); return res.status(404).send("Usuario no encontrado"); }
		const hijo = rows[0];

		if(hijo.superior_id !== req.user.id && req.user.nivel != 20) {
			conn.release();
			return res.status(403).send("No puedes eliminar este usuario");
		}

		await conn.query("DELETE FROM users WHERE id = ?", [id]);
		conn.release();
		res.send("Usuario eliminado");

	} catch(err) {
		console.error(err);
		res.status(500).send("Error en el servidor");
	}
});


app.patch("/admin/users/:id/role", auth(["administrador"]), async (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  if (!["usuario","moderador","administrador"].includes(rol)) return res.status(400).send("Rol inválido.");
  const conn = await pool.getConnection();
  await conn.query("UPDATE users SET rol=? WHERE id=?", [rol, id]);
  conn.release();
  res.send("✅ Rol actualizado.");
});


// --- Noticias ---
// Obtener todas las noticias
app.get("/news", async (req, res) => {
  try {
	const conn = await pool.getConnection();

	const [rows] = await conn.query(`
	  SELECT id, title, text, imageUrl, tipo, created_at
	  FROM news
	  ORDER BY 
		CASE 
		  WHEN tipo = 1 THEN created_at 
		  ELSE NULL 
		END DESC,  -- la última noticia importante primero
		created_at DESC  -- luego el resto por fecha descendente
	`);

	conn.release();
	res.json(rows);
  } catch (err) {
	console.error(err);
	res.status(500).send("Error al obtener noticias");
  }
});

// Crear noticia (desde admin)
app.post("/admin/news", auth(["administrador"]), async (req, res) => {
  try {
	const { title, text, imageUrl, tipo } = req.body;
	if (!title || !text || (tipo !== 0 && tipo !== 1)) return res.status(400).send("Faltan datos");
	const image = (!imageUrl || imageUrl === "#") ? "#" : imageUrl;
	const conn = await pool.getConnection();
	await conn.query(
	  "INSERT INTO news (title, text, imageUrl, tipo) VALUES (?, ?, ?, ?)",
	  [title, text, image, tipo]
	);
	conn.release();
	res.status(201).send("Noticia creada");
  } catch (err) {
	console.error(err);
	res.status(500).send("Error al crear noticia");
  }
});

// Editar noticia
app.put("/admin/news/:id", auth(["administrador"]), async (req, res) => {
  try {
	const { id } = req.params;
	const { title, text, imageUrl, tipo } = req.body;
	const finalImageUrl = tipo === 1 ? "https://consejomedicolp.org.ar/wp-content/uploads/2024/02/avisoImportante3.jpg"
		: (!imageUrl || imageUrl === "#") ? "#" : imageUrl;
	const conn = await pool.getConnection();
	await conn.query(
	  "UPDATE news SET title=?, text=?, imageUrl=?, tipo=? WHERE id=?",
	  [title, text, finalImageUrl, tipo, id]
	);
	conn.release();
	res.send("Noticia actualizada");
  } catch (err) {
	console.error(err);
	res.status(500).send("Error al actualizar noticia");
  }
});

// Eliminar noticia
app.delete("/admin/news/:id", auth(["administrador"]), async (req, res) => {
  try {
	const { id } = req.params;
	const conn = await pool.getConnection();
	await conn.query("DELETE FROM news WHERE id=?", [id]);
	conn.release();
	res.send("Noticia eliminada");
  } catch (err) {
	console.error(err);
	res.status(500).send("Error al eliminar noticia");
  }
});

// --- ROLES ---
app.get("/admin/roles", auth(["administrador"]), async (req, res) => {
  const conn = await pool.getConnection();
  const [rows] = await conn.query("SELECT * FROM roles ORDER BY id ASC");
  conn.release();
  res.json(rows);
});

app.post("/admin/roles", auth(["administrador"]), async (req, res) => {
  const { nombre, nivel } = req.body;
  if(!nombre || nivel == null) return res.status(400).send("Faltan datos");
  try {
	const conn = await pool.getConnection();
	await conn.query("INSERT INTO roles (nombre, nivel) VALUES (?, ?)", [nombre, nivel]);
	conn.release();
	res.status(201).send("Rol creado");
  } catch(err) {
	if(err.code === "ER_DUP_ENTRY") return res.status(409).send("Rol ya existe");
	res.status(500).send("Error al crear rol");
  }
});

app.patch("/admin/roles/:id", auth(["administrador"]), async (req, res) => {
  const { id } = req.params;
  const { nombre, nivel } = req.body;

  if(!nombre || nivel == null) {
	return res.status(400).send("Faltan datos");
  }

  try {
	const conn = await pool.getConnection();
	const [result] = await conn.query(
	  "UPDATE roles SET nombre=?, nivel=? WHERE id=?",
	  [nombre, nivel, id]
	);
	conn.release();

	if(result.affectedRows === 0) return res.status(404).send("Rol no encontrado");

	res.send("Rol actualizado");
  } catch(err) {
	console.error(err);
	res.status(500).send("Error al actualizar rol");
  }
});

// --- ELIMINAR ROL ---
app.delete("/admin/roles/:id", auth(["administrador"]), async (req, res) => {
  const { id } = req.params;
  const conn = await pool.getConnection();

  try {
	// Revisar si algún usuario tiene este rol
	const [usuarios] = await conn.query("SELECT COUNT(*) AS c FROM users WHERE rol_id = ?", [id]);
	if (usuarios[0].c > 0) {
	  conn.release();
	  return res.status(400).send("No se puede eliminar un rol asignado a algún usuario");
	}

	// Eliminar rol
	const [result] = await conn.query("DELETE FROM roles WHERE id = ?", [id]);
	conn.release();

	if(result.affectedRows === 0) return res.status(404).send("Rol no encontrado");
	res.send("Rol eliminado correctamente");
  } catch(err) {
	conn.release();
	console.error(err);
	res.status(500).send("Error al eliminar rol");
  }
});

//---- Usuarios Anidados
app.get("/admin/children", auth(), async (req, res) => {
  try {
	const userId = req.user.id;
	const conn = await pool.getConnection();
	const [hijos] = await conn.query(
	  `SELECT u.id, u.nombre, u.email, u.url_fotop, u.rol_id, r.nombre AS rol, r.nivel AS rol_nivel
	   FROM users u
	   LEFT JOIN roles r ON u.rol_id = r.id
	   WHERE u.superior_id = ?`,
	  [userId]
	);
	conn.release();

	res.json({ hijos });
  } catch (err) {
	console.error(err);
	res.status(500).send("Error al obtener alumnos");
  }
});

// GET /user/info
app.get("/user/info", auth(), async (req, res) => {
	try {
		const conn = await pool.getConnection();
		
		// Traemos nombre del superior, nombre del rol y url de foto
		const [rows] = await conn.query(`
			SELECT u.url_fotop, sup.nombre AS superior_nombre, r.nombre AS rol_nombre
			FROM users u
			LEFT JOIN users sup ON sup.id = u.superior_id
			LEFT JOIN roles r ON r.id = u.rol_id
			WHERE u.id = ?
		`, [req.user.id]);

		conn.release();

		const superiorNombre = rows[0]?.superior_nombre ?? "Sin superior";
		const rolNombre = rows[0]?.rol_nombre ?? "Rol desconocido";
		const url_fotop = rows[0]?.url_fotop ?? "";

		res.json({ superiorNombre, rolNombre, url_fotop });

	} catch(err) {
		console.error(err);
		res.status(500).send({ superiorNombre: "Error", rolNombre: "Error", url_fotop: "" });
	}
});



//Libretas
app.get("/admin/users/:id/grades", auth(), async (req, res) => {
	let conn;
	try {
		const { id } = req.params; // el hijo que quiero ver
		const userId = req.user.id; // el superior autenticado
		conn = await pool.getConnection();

		// verificar que el hijo realmente pertenezca al superior
		const [hijo] = await conn.query(
			"SELECT id, nombre, superior_id FROM users WHERE id = ?",
			[id]
		);
		if (hijo.length === 0) {
			conn.release();
			return res.status(404).send("Usuario no encontrado");
		}
		if (hijo[0].superior_id !== userId) {
			conn.release();
			return res.status(403).send("No tienes permisos para ver este usuario");
		}

		// traer notas ordenadas por categoría
		const [notas] = await conn.query(
			`SELECT categoria, 
					desarrollo_tecnico, tul, lucha, combate, rotura,
					zafes_palancas_lances_caidas AS zafes,
					enfrentamientos, movimientos_fundamentales AS movimientos,
					teoria, actitud_marcial
			 FROM notas
			 WHERE id_usuario = ?
			 ORDER BY categoria ASC`,
			[id]
		);

		conn.release();
		res.json({ notas });
	} catch (err) {
		if (conn) conn.release();
		console.error(err);
		res.status(500).send("Error al obtener las notas");
	}
});

app.patch("/admin/users/:id/grades", auth(), async (req, res) => {
	let conn;
	try {
		const { id } = req.params; // el hijo
		const userId = req.user.id; // el superior autenticado
		const { categoria, ...campos } = req.body; // ej: { categoria: 2, tul: 1, combate: 2, observaciones: "..." }

		conn = await pool.getConnection();

		// validar que el hijo sea suyo
		const [hijo] = await conn.query(
			"SELECT superior_id FROM users WHERE id = ?",
			[id]
		);
		if (hijo.length === 0) {
			conn.release();
			return res.status(404).send("Usuario no encontrado");
		}
		if (hijo[0].superior_id !== userId) {
			conn.release();
			return res.status(403).send("No tienes permisos para editar este usuario");
		}

		// validar campos
		const camposValidos = [
			"desarrollo_tecnico", "tul", "lucha", "combate", "rotura",
			"zafes_palancas_lances_caidas", "enfrentamientos", "movimientos_fundamentales",
			"teoria", "actitud_marcial"
		];

		const camposFiltrados = {};
		for (let key in campos) {
			if (camposValidos.includes(key)) {
				camposFiltrados[key] = campos[key];
			}
		}

		if(Object.keys(camposFiltrados).length === 0) {
			conn.release();
			return res.status(400).send("No hay campos válidos para actualizar");
		}

		// verificar si la libreta de esta categoría ya existe
		const [existe] = await conn.query(
			"SELECT * FROM notas WHERE id_usuario = ? AND categoria = ?",
			[id, categoria]
		);

		if(existe.length > 0) {
			// actualizar existente
			const sets = Object.keys(camposFiltrados).map(k => `${k} = ?`).join(", ");
			const valores = Object.values(camposFiltrados);
			valores.push(id, categoria);

			await conn.query(
				`UPDATE notas SET ${sets} WHERE id_usuario = ? AND categoria = ?`,
				valores
			);
		} else {
			// insertar nueva libreta
			await conn.query(
				`INSERT INTO notas (id_usuario, categoria, ${Object.keys(camposFiltrados).join(", ")})
				 VALUES (?, ?, ${Object.keys(camposFiltrados).map(() => "?").join(", ")})`,
				[id, categoria, ...Object.values(camposFiltrados)]
			);
		}

		conn.release();
		res.send("Libretta guardada correctamente");
	} catch(err) {
		if(conn) conn.release();
		console.error(err);
		res.status(500).send("Error al guardar la libreta");
	}
});


app.get("/user/grades", auth(), async (req, res) => {
	let conn;
	try {
		const userId = req.user.id;
		conn = await pool.getConnection();
		const [notas] = await conn.query(
			`SELECT categoria, 
					desarrollo_tecnico, tul, lucha, combate, rotura,
					zafes_palancas_lances_caidas AS zafes,
					enfrentamientos, movimientos_fundamentales AS movimientos,
					teoria, actitud_marcial
			 FROM notas
			 WHERE id_usuario = ?`,
			[userId]
		);
		conn.release();
		res.json({
			notas,
			observaciones: notas.length > 0 ? notas[0].observaciones : ""
		});
	} catch (err) {
		if(conn) conn.release();
		console.error(err);
		res.status(500).send("Error al obtener las notas");
	}
});

// --- Sedes ---
// Obtener todas las sedes
app.get("/admin/sedes", auth(["administrador"]), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query("SELECT * FROM sedes ORDER BY id ASC");
    conn.release();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al obtener sedes");
  }
});

// Crear nueva sede
app.post("/admin/sedes", auth(), async (req, res) => {
  try {
    const { nombre, descripcion, lat, lng, ciudad } = req.body;
    if(!nombre || lat === undefined || lng === undefined) {
      return res.status(400).send("Faltan datos");
    }
    const conn = await pool.getConnection();
    const [result] = await conn.query(
      "INSERT INTO sedes (nombre, descripcion, lat, lng, ciudad) VALUES (?, ?, ?, ?, ?)",
      [nombre, descripcion || "", lat, lng, ciudad]
    );
    conn.release();
    res.status(201).json({ id: result.insertId, nombre, descripcion, lat, lng });
  } catch(err) {
    console.error(err);
    res.status(500).send("Error al crear sede");
  }
});


// Editar sede existente
app.put("/admin/sedes/:id", auth(["administrador"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, descripcion, lat, lng, ciudad } = req.body;
    const conn = await pool.getConnection();

    const [rows] = await conn.query("SELECT * FROM sedes WHERE id = ?", [id]);
    if(rows.length === 0) { conn.release(); return res.status(404).send("Sede no encontrada"); }

    await conn.query(
      "UPDATE sedes SET nombre = ?, descripcion = ?, lat = ?, lng = ?, ciudad = ? WHERE id = ?",
      [
        nombre || rows[0].nombre,
        descripcion !== undefined ? descripcion : rows[0].descripcion,
        lat ?? rows[0].lat,
        lng ?? rows[0].lng,
		ciudad,
        id
      ]
    );

    conn.release();
    res.send("Sede actualizada");
  } catch(err) {
    console.error(err);
    res.status(500).send("Error al actualizar sede");
  }
});

// Eliminar sede
app.delete("/admin/sedes/:id", auth(["administrador"]), async (req, res) => {
  try {
    const { id } = req.params;
    const conn = await pool.getConnection();
    const [rows] = await conn.query("SELECT * FROM sedes WHERE id = ?", [id]);
    if(rows.length === 0) { conn.release(); return res.status(404).send("Sede no encontrada"); }

    await conn.query("DELETE FROM sedes WHERE id = ?", [id]);
    conn.release();
    res.send("Sede eliminada");
  } catch(err) {
    console.error(err);
    res.status(500).send("Error al eliminar sede");
  }
});

// Obtener todas las sedes (para frontend público)
app.get("/sedes", async (req, res) => {
    try {
        const conn = await pool.getConnection();
        const [rows] = await conn.query("SELECT nombre, descripcion, lat, lng, ciudad FROM sedes ORDER BY id DESC");
        conn.release();
        res.json(rows);
    } catch(err) {
        console.error(err);
        res.status(500).send("Error al obtener sedes");
    }
});
//---- ALBUMES
// Obtener todos los álbumes con sus fotos
app.get("/albumes", async (req, res) => {
    try {
        const conn = await pool.getConnection();

        const [albums] = await conn.query("SELECT * FROM albumes ORDER BY created_at DESC");
        for (let album of albums) {
            const [fotos] = await conn.query("SELECT link FROM album_fotos WHERE album_id = ?", [album.id]);
            album.fotos = fotos.map(f => f.link);
        }

        conn.release();
        res.json(albums);
    } catch(err) {
        console.error(err);
        res.status(500).send("Error al obtener álbumes");
    }
});

// Crear álbum nuevo con fotos
app.post("/albumes", authNivel(13), async (req, res) => {
    try {
        const { nombre, descripcion, fotos } = req.body; // fotos = array de links
        if(!nombre || !Array.isArray(fotos) || fotos.length === 0) return res.status(400).send("Faltan datos");

        const conn = await pool.getConnection();

        const [result] = await conn.query("INSERT INTO albumes (nombre, descripcion) VALUES (?, ?)", [nombre, descripcion || ""]);

        for (let link of fotos) {
            await conn.query("INSERT INTO album_fotos (album_id, link) VALUES (?, ?)", [result.insertId, link]);
        }

        conn.release();
        res.status(201).json({ id: result.insertId, nombre, descripcion, fotos });
    } catch(err) {
        console.error(err);
        res.status(500).send("Error al crear álbum");
    }
});
// Eliminar álbum (y sus fotos)
app.delete("/albumes/:id", authNivel(13), async (req, res) => {
    try {
        const { id } = req.params;
        const conn = await pool.getConnection();

        // Verificar si el álbum existe
        const [rows] = await conn.query("SELECT * FROM albumes WHERE id = ?", [id]);
        if (rows.length === 0) {
            conn.release();
            return res.status(404).send("Álbum no encontrado");
        }

        // Eliminar fotos primero
        await conn.query("DELETE FROM album_fotos WHERE album_id = ?", [id]);

        // Eliminar el álbum
        await conn.query("DELETE FROM albumes WHERE id = ?", [id]);

        conn.release();
        res.send("Álbum eliminado correctamente");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error al eliminar álbum");
    }
});


// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});