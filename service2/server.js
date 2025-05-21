import express from "express"
import https from "https"
import fs from "fs"
import cors from "cors"
import bodyParser from "body-parser"
import axios from "axios"
import { fileURLToPath } from "url"
import path from "path"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

// Middleware
app.use(cors())
app.use(bodyParser.json())

// Middleware to verify token and check permissions
const verifyPermission = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]

  if (!token) {
    return res.status(401).json({ error: "No token provided" })
  }

  try {
    // Verify token and check permission with Auth Server
    const operation = `service2:${req.path.split("/")[1]}`
    console.log(`Checking permission for operation: ${operation}`)

    const response = await axios.post(
      "https://localhost:4000/auth/verify",
      {
        token,
        operation,
      },
      {
        httpsAgent: new https.Agent({
          rejectUnauthorized: false, // Only for development
        }),
      },
    )

    // Attach user info to request
    req.user = response.data.user
    console.log(`Permission granted for user: ${req.user.username}, operation: ${operation}`)
    next()
  } catch (error) {
    console.error(`Permission verification error:`, error.message)
    if (error.response) {
      console.error(`Auth server response:`, error.response.data)
      return res.status(error.response.status).json(error.response.data)
    }
    res.status(500).json({ error: "Failed to verify token", details: error.message })
  }
}

// Test endpoint to check if service is running
app.get("/health", (req, res) => {
  res.json({ status: "Service 2 is running" })
})

// Apply middleware to all routes except health check
app.use((req, res, next) => {
  if (req.path === "/health") {
    return next()
  }
  verifyPermission(req, res, next)
})

// Service 2 Operations
app.get("/operation1", (req, res) => {
  console.log("Executing operation1")
  res.json({
    message: "Service 2 - Operation 1 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

app.get("/operation2", (req, res) => {
  console.log("Executing operation2")
  res.json({
    message: "Service 2 - Operation 2 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

app.get("/operation3", (req, res) => {
  console.log("Executing operation3")
  res.json({
    message: "Service 2 - Operation 3 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

// Create HTTPS server
const options = {
  key: fs.readFileSync(path.join(__dirname, "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "cert.pem")),
}

const PORT = 6000
https.createServer(options, app).listen(PORT, () => {
  console.log(`Service 2 running on https://localhost:${PORT}`)
})
