# TrafficAnalyzer Dashboard

A real-time network traffic analysis dashboard built with Node.js and Socket.IO.

## Features

- Real-time packet monitoring
- Live traffic capture
- Traffic simulation
- Malicious traffic detection
- Interactive packet table display

## Prerequisites

- Node.js (v14 or higher)
- TrafficAnalyzer executable (must be in the correct location)

## Installation

1. Clone the repository
2. Navigate to the dashboard directory:
   ```bash
   cd dashboard
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

## Configuration

The dashboard expects the TrafficAnalyzer executable to be in the following location relative to the dashboard folder:

```
../x64/Debug/TrafficAnalyzer.exe
```

## Running the Dashboard

1. Start the server:
   ```bash
   node server.js
   ```
2. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Usage

- Click "Start Simulator" to begin traffic simulation
- Click "Start Live Capture" to begin live packet capture
- Click the buttons again to stop the respective processes
- The packet table will automatically update with new traffic data

## Project Structure

```
dashboard/
├── public/
│   ├── index.html    # Main dashboard interface
│   ├── app.js        # Frontend JavaScript
│   └── test.html     # Test page
├── server.js         # Main server application
├── package.json      # Project dependencies
└── README.md         # This file
```

## License

[Your chosen license]
