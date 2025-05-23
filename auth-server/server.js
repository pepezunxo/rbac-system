import express from "express"
import https from "https"
import fs from "fs"
import cors from "cors"
import bodyParser from "body-parser"
import jwt from "jsonwebtoken"
import crypto from "crypto"
import sqlite3 from "sqlite3"
import bcrypt from "bcrypt"

const SALT_ROUNDS = 10

// --- Database Setup ---
const DBSOURCE = "auth.db" // SQLite database file
const verboseSqlite3 = sqlite3.verbose();
const db = new verboseSqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error("Error opening database", err.message)
    throw err
  } else {
    console.log("Connected to the SQLite database.")
    initializeDatabase()
  }
})

// Store active sessions and their keys (remains in memory for this example)
const memorySessions = {}

// Initial data (will be used to seed the database if empty)
const initialAuthData = {
  users: [
    { id: 1, username: "admin", password: "admin123", roles: ["admin"] },
    { id: 2, username: "manager", password: "admin123", roles: ["manager"] },
    { id: 3, username: "user", password: "admin123", roles: ["user"] },
    { id: 4, username: "poweruser", password: "admin123", roles: ["user", "manager"] },
  ],
  roles: {
    admin: {
      permissions: [
        "service1:operation1", "service1:operation2", "service1:operation3",
        "service1:callService2", "service2:operation1", "service2:operation2",
        "service2:operation3", "admin:manageUsers", "admin:manageRoles",
      ],
    },
    manager: {
      permissions: ["service1:operation1", "service1:operation2", "service2:operation1", "service2:operation2"],
    },
    user: {
      permissions: ["service1:operation1", "service2:operation1"],
    },
  },
}

function generateKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  })
}

async function initializeDatabase() {
  db.serialize(async () => {
    // Create tables
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_name TEXT UNIQUE
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      permission_name TEXT UNIQUE
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS user_roles (
      user_id INTEGER,
      role_id INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, role_id)
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS role_permissions (
      role_id INTEGER,
      permission_id INTEGER,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      PRIMARY KEY (role_id, permission_id)
    )`)

    // Check if DB is already seeded
    db.get("SELECT COUNT(*) as count FROM users", async (err, row) => {
      if (err) {
        console.error("Error checking user count:", err.message);
        return;
      }
      if (row.count === 0) {
        console.log("Seeding database with initial data...");
        // Seed roles and permissions
        const allPermissions = new Set()
        for (const roleName in initialAuthData.roles) {
          await db.run("INSERT OR IGNORE INTO roles (role_name) VALUES (?)", [roleName])
          initialAuthData.roles[roleName].permissions.forEach(p => allPermissions.add(p))
        }
        for (const permName of allPermissions) {
          await db.run("INSERT OR IGNORE INTO permissions (permission_name) VALUES (?)", [permName])
        }

        // Seed users and their relations
        for (const user of initialAuthData.users) {
          const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS)
          db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [user.username, hashedPassword], function(err) {
            if (err) { console.error("Error inserting user:", err.message); return; }
            const userId = this.lastID;
            user.roles.forEach(roleName => {
              db.get("SELECT id FROM roles WHERE role_name = ?", [roleName], (err, roleRow) => {
                if (roleRow) {
                  db.run("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleRow.id]);
                  initialAuthData.roles[roleName].permissions.forEach(permName => {
                    db.get("SELECT id FROM permissions WHERE permission_name = ?", [permName], (err, permRow) => {
                      if (permRow) {
                        db.run("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", [roleRow.id, permRow.id]);
                      }
                    });
                  });
                }
              });
            });
          });
        }
        console.log("Database seeded.");
      } else {
        console.log("Database already contains data. Skipping seed.");
      }
    });
  });
}

const app = express()

// Middleware
app.use(cors())
app.use(bodyParser.json())

function issueToken(userRow, roles, permissions, res) {
  const keyPair = generateKeyPair()
  const sessionId = crypto.randomBytes(16).toString("hex")

  memorySessions[sessionId] = { // Using memorySessions for session key storage
    userId: userRow.id,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    roles: roles, // Store roles from DB
  }

  const token = jwt.sign(
    {
      sub: userRow.id,
      username: userRow.username,
      roles,
      permissions,
      sessionId,
    },
    keyPair.privateKey,
    { algorithm: "RS256", expiresIn: "1h" }
  )

  console.log(`Login successful for ${userRow.username} with roles: ${roles.join(", ")}`)
  res.json({ token, publicKey: keyPair.publicKey, roles })
}

// Authentication endpoint
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body
  console.log(`Login attempt for user: ${username}`)

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, userRow) => {
    if (err) {
      console.error("Database error during login:", err.message)
      return res.status(500).json({ error: "Internal server error" })
    }
    if (!userRow) {
      console.log(`User not found: ${username}`)
      return res.status(401).json({ error: "Invalid credentials" })
    }

    try {
      const passwordMatch = await bcrypt.compare(password, userRow.password_hash)
      console.log(`Password match for ${username}: ${passwordMatch}`)

      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" })
      }

      // Get user roles
      db.all(`
        SELECT r.role_name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
      `, [userRow.id], (err, roleRows) => {
        if (err) {
          console.error("Error fetching roles:", err.message)
          return res.status(500).json({ error: "Internal server error" })
        }
        const roles = roleRows.map(r => r.role_name)

        // Get permissions for these roles
        if (roles.length === 0) { // Should not happen if user has roles
            issueToken(userRow, roles, [], res);
            return;
        }
        const placeholders = roles.map(() => '?').join(',');
        db.all(`
          SELECT DISTINCT p.permission_name FROM permissions p
          JOIN role_permissions rp ON p.id = rp.permission_id
          JOIN roles r ON rp.role_id = r.id
          WHERE r.role_name IN (${placeholders})
        `, roles, (err, permRows) => {
          if (err) {
            console.error("Error fetching permissions:", err.message)
            return res.status(500).json({ error: "Internal server error" })
          }
          const permissions = permRows.map(p => p.permission_name)
          issueToken(userRow, roles, permissions, res)
        })
      })
    } catch (error) {
      console.error(`Error during password comparison for ${username}:`, error)
      res.status(500).json({ error: "Authentication failed" })
    }
  })
})

// Test endpoint to check if auth server is working
app.get("/auth/test", (req, res) => {
  res.json({ message: "Auth server is working!" })
})

// Get public key for a session
app.get("/auth/certificate/:sessionId", (req, res) => {
  const { sessionId } = req.params
  if (!memorySessions[sessionId]) { // Use memorySessions
    return res.status(404).json({ error: "Session not found" })
  }
  res.json({ publicKey: memorySessions[sessionId].publicKey })
})

// Verify token and check permissions
app.post("/auth/verify", (req, res) => {
  const { token, operation } = req.body
  try {
    const decoded = jwt.decode(token)
    if (!decoded || !decoded.sessionId) {
      return res.status(401).json({ error: "Invalid token structure" })
    }
    const sessionId = decoded.sessionId
    const session = memorySessions[sessionId] // Use memorySessions

    if (!session) {
      return res.status(401).json({ error: "Session not found or expired" })
    }

    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] })

    if (operation && !verified.permissions.includes(operation)) {
      console.log(`Permission denied: ${verified.username} attempted ${operation}`)
      return res.status(403).json({ error: "Permission denied" })
    }

    console.log(`Permission granted: ${verified.username} for ${operation}`)
    res.json({ valid: true, user: verified })
  } catch (error) {
    console.error("Token verification error:", error)
    res.status(401).json({ error: "Invalid token", details: error.message })
  }
})

// Admin endpoints for user management
app.get("/admin/users", (req, res) => {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authorization header missing or malformed" });
  }
  const token = authHeader.split(" ")[1]

  try {
    const decoded = jwt.decode(token)
    if (!decoded || !decoded.sessionId) {
      return res.status(401).json({ error: "Invalid token (no sessionId)" })
    }
    const session = memorySessions[decoded.sessionId] // Use memorySessions
    if (!session) {
      return res.status(401).json({ error: "Session not found" })
    }

    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] })
    if (!verified.permissions.includes("admin:manageUsers")) {
      return res.status(403).json({ error: "Permission denied" })
    }

    // Fetch users from DB
    db.all(`
      SELECT u.id, u.username, GROUP_CONCAT(r.role_name) as roles
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.id
      GROUP BY u.id, u.username
    `, [], (err, userRows) => {
      if (err) {
        console.error("Error fetching users for admin:", err.message)
        return res.status(500).json({ error: "Failed to retrieve users" })
      }
      const safeUsers = userRows.map(u => ({
        id: u.id,
        username: u.username,
        roles: u.roles ? u.roles.split(',') : []
      }));
      res.json(safeUsers)
    })
  } catch (error) {
    console.error("Admin users access error:", error)
    res.status(401).json({ error: "Invalid token or insufficient permissions", details: error.message })
  }
})

// Create HTTPS server
const options = {
  key: fs.readFileSync("auth-server/key.pem"),
  cert: fs.readFileSync("auth-server/cert.pem"),
}

const PORT = 4000
https.createServer(options, app).listen(PORT, () => {
  console.log(`Auth server running on https://localhost:${PORT}`)
})

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      return console.error(err.message);
    }
    console.log('Closed the database connection.');
    process.exit(0);
  });
});
