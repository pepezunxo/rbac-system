import express from "express"
import https from "https"
import fs from "fs"
import cors from "cors"
import bodyParser from "body-parser"
import axios from "axios"
import path from "path"
import { fileURLToPath } from "url"

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
    const operation = `service1:${req.path.split("/")[1]}`
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

// Apply middleware to all routes
app.use(verifyPermission)

// Service 1 Operations
app.get("/operation1", (req, res) => {
  console.log("Executing operation1")
  res.json({
    message: "Service 1 - Operation 1 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

app.get("/operation2", (req, res) => {
  console.log("Executing operation2")
  res.json({
    message: "Service 1 - Operation 2 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

app.get("/operation3", (req, res) => {
  console.log("Executing operation3")
  res.json({
    message: "Service 1 - Operation 3 executed successfully",
    user: req.user.username,
    roles: req.user.roles,
  })
})

// Operation that calls Service 2
app.get("/callService2", async (req, res) => {
  console.log("Executing callService2")
  const token = req.headers.authorization?.split(" ")[1]

  try {
    // Call Service 2 Operation 1
    const response = await axios.get("https://localhost:6000/operation1", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Only for development
      }),
    })

    res.json({
      message: "Service 1 successfully called Service 2",
      service2Response: response.data,
    })
  } catch (error) {
    console.error("Error calling Service 2:", error.message)
    if (error.response) {
      console.error("Service 2 response:", error.response.data)
      return res.status(error.response.status).json(error.response.data)
    }
    res.status(500).json({ error: "Failed to call Service 2", details: error.message })
  }
})

// Create HTTPS server
try {
  const keyPath = path.join(__dirname, "key.pem")
  const certPath = path.join(__dirname, "cert.pem")

  console.log("Loading certificates from:")
  console.log("Key path:", keyPath)
  console.log("Cert path:", certPath)

  // Check if files exist
  if (!fs.existsSync(keyPath)) {
    console.error("Key file does not exist!")
  }
  if (!fs.existsSync(certPath)) {
    console.error("Cert file does not exist!")
  }

  const options = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  }

  // Changed port from 5000 to 5001
  const PORT = 5001
  https.createServer(options, app).listen(PORT, () => {
    console.log(`Service 1 running on https://localhost:${PORT}`)
  })
} catch (error) {
  console.error("Error starting HTTPS server:", error)
}
