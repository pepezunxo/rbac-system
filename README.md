# Role-Based Access Control (RBAC) System

This project implements a distributed application with Role-Based Access Control (RBAC) using Node.js and Express.

## System Architecture

The system consists of four web servers:
1. **Client Application** (Port 3000) - Web interface for users
2. **Authentication/Authorization Server** (Port 4000) - Handles user authentication and authorization
3. **Service 1** (Port 5000) - Provides REST API operations
4. **Service 2** (Port 6000) - Provides additional REST API operations

## Features

- User authentication with JWT tokens
- Role-based access control with three roles (admin, manager, user)
- Cryptographic key generation for secure sessions
- Cascading authorization for service-to-service calls
- Admin panel for user management
- HTTPS for secure communication

## Setup and Installation

1. Clone the repository
2. Install dependencies:
   \`\`\`
   npm install
   \`\`\`
3. Generate SSL certificates for development:
   \`\`\`
   npm run generate-certs
   \`\`\`
4. Start all servers:
   \`\`\`
   npm start
   \`\`\`
   
   Or run setup and start in one command:
   \`\`\`
   npm run setup
   \`\`\`

5. Access the application at https://localhost:3000
   - You'll need to accept the self-signed certificate warning in your browser

## Available Test Accounts

- **Admin**: Username: admin, Password: admin123
- **Manager**: Username: manager, Password: admin123
- **User**: Username: user, Password: admin123
- **Power User**: Username: poweruser, Password: admin123 (has both user and manager roles)

## Security Considerations

- All communication uses HTTPS
- Passwords are hashed using bcrypt
- JWT tokens are signed with RSA keys
- Authorization is enforced at both direct and cascading service calls
- Session keys are generated per user session

## Troubleshooting

If you encounter certificate errors:
1. Make sure you've run `npm run generate-certs` to create valid certificates
2. When accessing the application in your browser, you'll need to accept the security warning for self-signed certificates
3. For development purposes only, the application is configured to skip certificate validation between services
