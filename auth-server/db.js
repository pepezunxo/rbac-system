import sqlite3 from "sqlite3";
const DBSOURCE = "auth.db";

const db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error("Failed to connect to SQLite:", err.message);
    throw err;
  }
  console.log("Connected to SQLite.");
});

export const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) reject(err);
    else resolve(this);
  });
});

export const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => {
    if (err) reject(err);
    else resolve(row);
  });
});

export const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => {
    if (err) reject(err);
    else resolve(rows);
  });
});

export default db;
