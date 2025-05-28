import { run, get } from "./db.js";
import bcrypt from "bcrypt";

const SALT_ROUNDS = 10;

const initialUsers = [
  { username: "admin", password: "admin123", roles: ["admin"] },
  { username: "manager", password: "admin123", roles: ["manager"] },
  { username: "user", password: "admin123", roles: ["user"] },
  { username: "poweruser", password: "admin123", roles: ["user", "manager"] },
];

const rolePermissions = {
  admin: [
    "service1:operation1", "service1:operation2", "service1:operation3",
    "service1:callService2", "service2:operation1", "service2:operation2",
    "service2:operation3", "admin:manageUsers", "admin:manageRoles",
  ],
  manager: ["service1:operation1", "service1:operation2", "service2:operation1", "service2:operation2"],
  user: ["service1:operation1", "service2:operation1"],
};

export async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);

  await run(`CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE
  )`);

  await run(`CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission_name TEXT UNIQUE
  )`);

  await run(`CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY(user_id, role_id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER,
    permission_id INTEGER,
    PRIMARY KEY(role_id, permission_id)
  )`);

  const row = await get("SELECT COUNT(*) as count FROM users");
  if (row.count > 0) return;

  console.log("Seeding initial data...");

  const roleMap = new Map();
  for (const role of Object.keys(rolePermissions)) {
    await run("INSERT OR IGNORE INTO roles (role_name) VALUES (?)", [role]);
    const { id } = await get("SELECT id FROM roles WHERE role_name = ?", [role]);
    roleMap.set(role, id);
    for (const perm of rolePermissions[role]) {
      await run("INSERT OR IGNORE INTO permissions (permission_name) VALUES (?)", [perm]);
      const { id: permId } = await get("SELECT id FROM permissions WHERE permission_name = ?", [perm]);
      await run("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", [id, permId]);
    }
  }

  for (const user of initialUsers) {
    const hash = await bcrypt.hash(user.password, SALT_ROUNDS);
    await run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [user.username, hash]);
    const { id: userId } = await get("SELECT id FROM users WHERE username = ?", [user.username]);
    for (const role of user.roles) {
      const roleId = roleMap.get(role);
      await run("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleId]);
    }
  }

  console.log("Seeding complete.");
}
