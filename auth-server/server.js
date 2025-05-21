import express from "express"
import https from "https"
import fs from "fs"
import cors from "cors"
import bodyParser from "body-parser"
import jwt from "jsonwebtoken"
import crypto from "crypto"

// For development, we'll use a simple plaintext password approach
// In production, you would use proper hashing
const db = {
  users: [
    {
      id: 1,
      username: "admin",
      password: "admin123", // Plain password for development
      roles: ["admin"],
    },
    {
      id: 2,
      username: "manager",
      password: "admin123", // Plain password for development
      roles: ["manager"],
    },
    {
      id: 3,
      username: "user",
      password: "admin123", // Plain password for development
      roles: ["user"],
    },
    {
      id: 4,
      username: "poweruser",
      password: "admin123", // Plain password for development
      roles: ["user", "manager"],
    },
  ],
  roles: {
    admin: {
      permissions: [
        "service1:operation1",
        "service1:operation2",
        "service1:operation3",
        "service1:callService2",
        "service2:operation1",
        "service2:operation2",
        "service2:operation3",
        "admin:manageUsers",
        "admin:manageRoles",
      ],
    },
    manager: {
      permissions: ["service1:operation1", "service1:operation2", "service2:operation1", "service2:operation2"],
    },
    user: {
      permissions: ["service1:operation1", "service2:operation1"],
    },
  },
  // Store active sessions and their keys
  sessions: {},
}

const app = express()

// Middleware
app.use(cors())
app.use(bodyParser.json())

// Generate key pair for a user session
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

// Authentication endpoint
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body

  console.log(`Login attempt for user: ${username} with password: ${password ? "provided" : "missing"}`)

  // Find user
  const user = db.users.find((u) => u.username === username)
  if (!user) {
    console.log(`User not found: ${username}`)
    return res.status(401).json({ error: "Invalid credentials" })
  }

  try {
    // For development, we'll use a simple plaintext password comparison
    // In production, you would use bcrypt.compare
    const passwordMatch = user.password === password

    console.log(`Password match for ${username}: ${passwordMatch}`)

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Generate key pair for this session
    const keyPair = generateKeyPair()

    // Get user permissions based on roles
    const permissions = []
    user.roles.forEach((role) => {
      if (db.roles[role]) {
        permissions.push(...db.roles[role].permissions)
      }
    })

    // Create unique session ID
    const sessionId = crypto.randomBytes(16).toString("hex")

    // Store session
    db.sessions[sessionId] = {
      userId: user.id,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      roles: user.roles,
    }

    // Create JWT token
    const token = jwt.sign(
      {
        sub: user.id,
        username: user.username,
        roles: user.roles,
        permissions,
        sessionId,
      },
      keyPair.privateKey,
      {
        algorithm: "RS256",
        expiresIn: "1h",
      },
    )

    console.log(`Login successful for ${username} with roles: ${user.roles.join(", ")}`)

    // Return token and public key certificate
    res.json({
      token,
      publicKey: keyPair.publicKey,
      roles: user.roles,
    })
  } catch (error) {
    console.error(`Error during login for ${username}:`, error)
    res.status(500).json({ error: "Authentication failed", details: error.message })
  }
})

// Test endpoint to check if auth server is working
app.get("/auth/test", (req, res) => {
  res.json({ message: "Auth server is working!" })
})

// Get public key for a session
app.get("/auth/certificate/:sessionId", (req, res) => {
  const { sessionId } = req.params

  if (!db.sessions[sessionId]) {
    return res.status(404).json({ error: "Session not found" })
  }

  res.json({
    publicKey: db.sessions[sessionId].publicKey,
  })
})

// Verify token and check permissions
app.post("/auth/verify", (req, res) => {
  const { token, operation } = req.body

  try {
    // Extract session ID from token without verification
    const decoded = jwt.decode(token)
    if (!decoded || !decoded.sessionId) {
      return res.status(401).json({ error: "Invalid token" })
    }

    const sessionId = decoded.sessionId
    const session = db.sessions[sessionId]

    if (!session) {
      return res.status(401).json({ error: "Session not found" })
    }

    // Verify token with public key
    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] })

    // Check if user has permission for the requested operation
    if (!verified.permissions.includes(operation)) {
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
  const token = req.headers.authorization?.split(" ")[1]

  try {
    // Extract session ID from token without verification
    const decoded = jwt.decode(token)
    if (!decoded || !decoded.sessionId) {
      return res.status(401).json({ error: "Invalid token" })
    }

    const sessionId = decoded.sessionId
    const session = db.sessions[sessionId]

    if (!session) {
      return res.status(401).json({ error: "Session not found" })
    }

    // Verify token with public key
    const verified = jwt.verify(token, session.publicKey, { algorithms: ["RS256"] })

    // Check if user has admin permission
    if (!verified.permissions.includes("admin:manageUsers")) {
      return res.status(403).json({ error: "Permission denied" })
    }

    // Return users without passwords
    const safeUsers = db.users.map(({ id, username, roles }) => ({ id, username, roles }))
    res.json(safeUsers)
  } catch (error) {
    res.status(401).json({ error: "Invalid token", details: error.message })
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
