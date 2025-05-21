import { execSync } from "child_process"
import fs from "fs"

// Directories where certificates will be stored
const directories = ["auth-server", "service1", "service2", "client"]

// Create directories if they don't exist
directories.forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
})

// Generate certificates for each server
directories.forEach((dir) => {
  console.log(`Generating certificates for ${dir}...`)

  // Generate private key
  execSync(`openssl genrsa -out ${dir}/key.pem 2048`)

  // Generate certificate signing request
  execSync(
    `openssl req -new -key ${dir}/key.pem -out ${dir}/csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"`,
  )

  // Generate self-signed certificate
  execSync(`openssl x509 -req -days 365 -in ${dir}/csr.pem -signkey ${dir}/key.pem -out ${dir}/cert.pem`)

  // Remove CSR file as it's no longer needed
  fs.unlinkSync(`${dir}/csr.pem`)

  console.log(`Certificates for ${dir} generated successfully.`)
})

console.log("All certificates generated successfully!")
