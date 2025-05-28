import express from "express";
import https from "https";
import fs from "fs";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcrypt";

import { initDb } from "./initDB.js";
import { get, all } from "./db.js";

const app = express();
const PORT = 4000;

const memorySessions = {}; // In-memory session store

app.use(cors());
app.use(bodyParser.json());

await initDb(); // Initialize DB schema and seed if needed

// Generate per-session RSA key pair
function createSession(userId, username, roles, permissions) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const sessionId = crypto.randomBytes(16).toString("hex");

  memorySessions[sessionId] = {
    userId,
    publicKey,
    privateKey,
    roles,
  };

  const token = jwt.sign(
    { sub: userId, username, roles, permissions, sessionId },
    privateKey,
    { algorithm: "RS256", expiresIn: "1h" }
  );

  return { token, publicKey };
}

// Helper to fetch user roles and permissions
async function fetchUserAuthData(userId) {
  const roles = (await all(
    `SELECT r.role_name FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = ?`, [userId]
  )).map(r => r.role_name);

  if (roles.length === 0) return { roles: [], permissions: [] };

  const placeholders = roles.map(() => '?').join(',');
  const permissions = (await all(
    `SELECT DISTINCT p.permission_name FROM permissions p
     JOIN role_permissions rp ON rp.permission_id = p.id
     JOIN roles r ON r.id = rp.role_id
     WHERE r.role_name IN (${placeholders})`, roles
  )).map(p => p.permission_name);

  return { roles, permissions };
}

// --- ROUTES ---

// Login endpoint
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await get("SELECT * FROM users WHERE username = ?", [username]);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  const { roles, permissions } = await fetchUserAuthData(user.id);
  const { token, publicKey } = createSession(user.id, username, roles, permissions);

  res.json({ token, publicKey, roles });
});

// Verify token and permission
app.post("/auth/verify", (req, res) => {
  const { token, operation } = req.body;

  try {
    const decoded = jwt.decode(token);
    const session = memorySessions[decoded?.sessionId];
    if (!session) return res.status(401).json({ error: "Session not found" });

    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] });

    if (operation && !verified.permissions.includes(operation)) {
      return res.status(403).json({ error: "Permission denied" });
    }

    res.json({ valid: true, user: verified });
  } catch (err) {
    res.status(401).json({ error: "Invalid token", details: err.message });
  }
});

// Get session public key
app.get("/auth/certificate/:sessionId", (req, res) => {
  const session = memorySessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: "Session not found" });
  res.json({ publicKey: session.publicKey });
});

// Admin: list users
app.get("/admin/users", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.decode(token);
    const session = memorySessions[decoded?.sessionId];
    if (!session) return res.status(401).json({ error: "Invalid session" });

    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] });
    if (!verified.permissions.includes("admin:manageUsers"))
      return res.status(403).json({ error: "Permission denied" });

    const users = await all(`
      SELECT u.id, u.username, GROUP_CONCAT(r.role_name) AS roles
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      LEFT JOIN roles r ON r.id = ur.role_id
      GROUP BY u.id
    `);

    res.json(users.map(u => ({
      id: u.id,
      username: u.username,
      roles: u.roles ? u.roles.split(",") : []
    })));
  } catch (err) {
    res.status(401).json({ error: "Invalid token", details: err.message });
  }
});

// Test endpoint
app.get("/auth/test", (req, res) => {
  res.json({ message: "Auth server is working!" });
});

// HTTPS server
const options = {
  key: fs.readFileSync("auth-server/key.pem"),
  cert: fs.readFileSync("auth-server/cert.pem"),
};

https.createServer(options, app).listen(PORT, () => {
  console.log(`Auth server running at https://localhost:${PORT}`);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down...");
  process.exit();
});
