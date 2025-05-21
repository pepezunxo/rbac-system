import express from "express"
import https from "https"
import fs from "fs"
import path from "path"
import axios from "axios"
import cookieParser from "cookie-parser"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

// Middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")))

// Set view engine
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

// Routes
app.get("/", (req, res) => {
  const token = req.cookies.token
  const username = req.cookies.username
  const roles = req.cookies.roles ? JSON.parse(req.cookies.roles) : []

  res.render("index", {
    token: token || "",
    username: username || "",
    roles: roles,
    error: "",
  })
})

app.get("/login", (req, res) => {
  res.render("login", { error: "" })
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body

  console.log(`Login attempt from client for user: ${username}`)

  try {
    // Now try to authenticate
    const response = await axios.post(
      "https://localhost:4000/auth/login",
      {
        username,
        password,
      },
      {
        httpsAgent: new https.Agent({
          rejectUnauthorized: false, // Only for development
        }),
      },
    )

    console.log(`Login successful for ${username}`)

    // Set cookies
    res.cookie("token", response.data.token, { httpOnly: true })
    res.cookie("username", username)
    res.cookie("roles", JSON.stringify(response.data.roles))

    res.redirect("/")
  } catch (error) {
    console.error("Login error:", error.message)

    let errorMessage = "Authentication failed"
    if (error.response && error.response.data) {
      errorMessage = error.response.data.error || errorMessage
      console.error("Server error response:", error.response.data)
    }

    res.render("login", { error: errorMessage })
  }
})

app.get("/logout", (req, res) => {
  res.clearCookie("token")
  res.clearCookie("username")
  res.clearCookie("roles")
  res.redirect("/login")
})

app.get("/admin", (req, res) => {
  const token = req.cookies.token
  const username = req.cookies.username
  const roles = req.cookies.roles ? JSON.parse(req.cookies.roles) : []

  if (!token) {
    return res.redirect("/login")
  }

  res.render("admin", {
    token: token,
    username: username,
    roles: roles,
    error: "",
  })
})

// API proxy routes
app.get("/api/service1/:operation", async (req, res) => {
  const { operation } = req.params
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" })
  }

  console.log(`Client calling Service 1 operation: ${operation}`)

  try {
    // Updated port from 5000 to 5001
    const response = await axios.get(`https://localhost:5001/${operation}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Only for development
      }),
      timeout: 10000, // 10 second timeout
    })

    console.log(`Service 1 ${operation} response:`, response.data)
    res.json(response.data)
  } catch (error) {
    console.error(`Error calling Service 1 ${operation}:`, error.message)
    if (error.response) {
      console.error("Service 1 error response:", error.response.data)
      return res.status(error.response.status).json(error.response.data)
    }
    res.status(500).json({ error: "Service call failed", details: error.message })
  }
})

app.get("/api/service2/:operation", async (req, res) => {
  const { operation } = req.params
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" })
  }

  console.log(`Client calling Service 2 operation: ${operation}`)

  try {
    const response = await axios.get(`https://localhost:6000/${operation}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Only for development
      }),
    })

    console.log(`Service 2 ${operation} response:`, response.data)
    res.json(response.data)
  } catch (error) {
    console.error(`Error calling Service 2 ${operation}:`, error.message)
    if (error.response) {
      console.error("Service 2 error response:", error.response.data)
      return res.status(error.response.status).json(error.response.data)
    }
    res.status(500).json({ error: "Service call failed", details: error.message })
  }
})

app.get("/api/admin/users", async (req, res) => {
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" })
  }

  try {
    const response = await axios.get("https://localhost:4000/admin/users", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Only for development
      }),
    })

    res.json(response.data)
  } catch (error) {
    if (error.response) {
      return res.status(error.response.status).json(error.response.data)
    }
    res.status(500).json({ error: "Admin operation failed", details: error.message })
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

  const PORT = 3000
  https.createServer(options, app).listen(PORT, () => {
    console.log(`Client app running on https://localhost:${PORT}`)
  })
} catch (error) {
  console.error("Error starting HTTPS server:", error)
}
