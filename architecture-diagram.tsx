export default function ArchitectureDiagram() {
  return (
    <div className="p-4 bg-white rounded-lg shadow-lg">
      <h2 className="text-xl font-bold mb-4">System Architecture</h2>
      <div className="border border-gray-300 p-4 rounded-lg">
        <div className="flex flex-col md:flex-row justify-between gap-4">
          <div className="flex-1 p-4 border border-blue-300 rounded-lg bg-blue-50">
            <h3 className="font-bold text-center mb-2">Client App (Port 3000)</h3>
            <ul className="list-disc pl-5 text-sm">
              <li>User Interface</li>
              <li>Stores JWT token</li>
              <li>Makes authenticated requests</li>
            </ul>
          </div>

          <div className="flex-1 p-4 border border-green-300 rounded-lg bg-green-50">
            <h3 className="font-bold text-center mb-2">Auth Server (Port 4000)</h3>
            <ul className="list-disc pl-5 text-sm">
              <li>User authentication</li>
              <li>Role management</li>
              <li>Key generation</li>
              <li>Token issuance</li>
            </ul>
          </div>
        </div>

        <div className="flex justify-center my-4">
          <div className="w-0 h-16 border-l-2 border-gray-400 border-dashed"></div>
        </div>

        <div className="flex flex-col md:flex-row justify-between gap-4">
          <div className="flex-1 p-4 border border-purple-300 rounded-lg bg-purple-50">
            <h3 className="font-bold text-center mb-2">Service 1 (Port 5000)</h3>
            <ul className="list-disc pl-5 text-sm">
              <li>3+ REST operations</li>
              <li>Token verification</li>
              <li>Permission checking</li>
              <li>Calls to Service 2</li>
            </ul>
          </div>

          <div className="flex-1 p-4 border border-orange-300 rounded-lg bg-orange-50">
            <h3 className="font-bold text-center mb-2">Service 2 (Port 6000)</h3>
            <ul className="list-disc pl-5 text-sm">
              <li>3+ REST operations</li>
              <li>Token verification</li>
              <li>Permission checking</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="mt-4 p-4 border border-gray-300 rounded-lg">
        <h3 className="font-bold mb-2">Authentication Flow:</h3>
        <ol className="list-decimal pl-5 text-sm">
          <li>User logs in via Client App</li>
          <li>Auth Server authenticates user and generates key pair</li>
          <li>Auth Server issues signed JWT with user roles</li>
          <li>Client App stores JWT and uses it for service calls</li>
          <li>Services verify JWT and check permissions before processing</li>
        </ol>
      </div>
    </div>
  )
}
