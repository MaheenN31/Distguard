const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const { spawn } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  pingTimeout: 60000,
  pingInterval: 25000,
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Store the last 1000 log entries in memory with timestamps
const logEntries = [];
const MAX_LOGS = 1000;

let currentMode = null;
let analyzerProcess = null;

// Function to start TrafficAnalyzer in simulator mode
function startSimulator() {
  if (analyzerProcess) {
    analyzerProcess.kill();
  }

  const analyzerPath = path.resolve(__dirname, '..', 'x64', 'Debug', 'TrafficAnalyzer.exe');
  console.log('Starting simulator with path:', analyzerPath);
  
  analyzerProcess = spawn(analyzerPath, [], { 
    shell: true,
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let menuChoiceSent = false;
  let packetCountSent = false;

  // Handle stdout to detect prompts and send responses
  analyzerProcess.stdout.on('data', (data) => {
    const output = data.toString();
    console.log('TrafficAnalyzer stdout (raw):', output);
    
    // Send menu choice when menu appears
    if (!menuChoiceSent && output.includes('Select a module')) {
      console.log('Sending simulator choice...');
      analyzerProcess.stdin.write('5\n');
      menuChoiceSent = true;
    }
    
    // Send packet count when prompted
    if (menuChoiceSent && !packetCountSent && output.includes('How many packets')) {
      console.log('Sending packet count...');
      analyzerProcess.stdin.write('100\n');
      packetCountSent = true;
    }

    const lines = output.trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) {
        console.log('Processing line:', line);
        addLogEntry(line);
      }
    });
  });

  analyzerProcess.stderr.on('data', (data) => {
    console.error(`TrafficAnalyzer error: ${data}`);
    addLogEntry(`[ERROR] ${data.toString().trim()}`);
  });

  analyzerProcess.on('error', (err) => {
    console.error('Failed to start TrafficAnalyzer:', err);
    addLogEntry(`[SYSTEM] Failed to start TrafficAnalyzer: ${err.message}`);
  });
}

// Function to start TrafficAnalyzer in live capture mode
function startLiveCapture() {
  if (analyzerProcess) {
    analyzerProcess.kill();
  }

  const analyzerPath = path.resolve(__dirname, '..', 'x64', 'Debug', 'TrafficAnalyzer.exe');
  console.log('Starting live capture with path:', analyzerPath);
  
  analyzerProcess = spawn(analyzerPath, [], { 
    shell: true,
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let menuChoiceSent = false;
  let interfaceChoiceSent = false;

  // Handle stdout to detect prompts and send responses
  analyzerProcess.stdout.on('data', (data) => {
    console.log('TrafficAnalyzer stdout:', data.toString());
    const output = data.toString();
    
    // Send menu choice when menu appears
    if (!menuChoiceSent && output.includes('Select a module')) {
      console.log('Sending live capture choice...');
      analyzerProcess.stdin.write('4\n');
      menuChoiceSent = true;
    }
    
    // Send interface choice when prompted
    if (menuChoiceSent && !interfaceChoiceSent && output.includes('Select interface')) {
      console.log('Sending interface choice...');
      analyzerProcess.stdin.write('1\n'); // Choose first interface
      interfaceChoiceSent = true;
    }

    const lines = output.trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) {
        addLogEntry(line);
      }
    });
  });

  analyzerProcess.stderr.on('data', (data) => {
    console.error(`TrafficAnalyzer error: ${data}`);
    addLogEntry(`[ERROR] ${data.toString().trim()}`);
  });

  analyzerProcess.on('error', (err) => {
    console.error('Failed to start TrafficAnalyzer:', err);
    addLogEntry(`[SYSTEM] Failed to start TrafficAnalyzer: ${err.message}`);
  });
}

// Function to add a log entry
function addLogEntry(message) {
  console.log('Processing log entry:', message);
  
  // Skip menu-related messages and prompts
  if (message.includes('Select a module') || 
      message.includes('Choice:') || 
      message.includes('Child Node') ||
      message.includes('Main Node') ||
      message.includes('Packet Capture') ||
      message.includes('Live Traffic') ||
      message.includes('Traffic Simulator') ||
      message.includes('Dashboard') ||
      message.includes('Exit') ||
      message.includes('How many packets') ||
      message.includes('Select interface') ||
      message.includes('Generating') ||
      message.includes('Generated')) {
    console.log('Skipping menu/prompt message');
    return;
  }
  
  // Try to parse different packet formats
  let packetInfo = null;
  
  // Format 1: [ChildNode] Received packet: sourceIP|destIP|port|flags|seq|info
  const format1Match = message.match(/\[ChildNode\] Received packet: ([\d\.]+)\|([\d\.]+)\|(\d+)\|(\d+)\|(\d+)\|(.+)/);
  
  // Format 2: [Packet] sourceIP -> destIP:port [flags] seq=seqNum info
  const format2Match = message.match(/\[Packet\] ([\d\.]+) -> ([\d\.]+):(\d+) \[(.*?)\] seq=(\d+) (.+)/);
  
  if (format1Match) {
    console.log('Matched Format 1:', format1Match);
    packetInfo = {
      sourceIp: format1Match[1],
      destIp: format1Match[2],
      port: format1Match[3],
      flags: format1Match[4],
      seq: format1Match[5],
      info: format1Match[6],
      isMalicious: message.includes('flood') || message.includes('Spoofed') || message.includes('scan'),
      reason: message.includes('flood') ? 'Flood attack detected' :
              message.includes('Spoofed') ? 'IP spoofing detected' :
              message.includes('scan') ? 'Port scan detected' : ''
    };
  } else if (format2Match) {
    console.log('Matched Format 2:', format2Match);
    packetInfo = {
      sourceIp: format2Match[1],
      destIp: format2Match[2],
      port: format2Match[3],
      flags: format2Match[4],
      seq: format2Match[5],
      info: format2Match[6],
      isMalicious: message.includes('flood') || message.includes('Spoofed') || message.includes('scan'),
      reason: message.includes('flood') ? 'Flood attack detected' :
              message.includes('Spoofed') ? 'IP spoofing detected' :
              message.includes('scan') ? 'Port scan detected' : ''
    };
  } else {
    console.log('No packet format match found');
  }
  
  if (packetInfo) {
    console.log('Emitting packet info:', packetInfo);
    const logEntry = {
      message: JSON.stringify(packetInfo),
      timestamp: new Date().toISOString()
    };
    
    logEntries.push(logEntry);
    
    // Keep only the last MAX_LOGS entries
    if (logEntries.length > MAX_LOGS) {
      logEntries.shift();
    }
    
    // Emit to all connected clients
    io.emit('log', logEntry);
  }
}

// API endpoint to receive logs
app.post('/api/log', (req, res) => {
  try {
    addLogEntry(req.body.message || 'No message provided');
    res.status(200).send({ success: true });
  } catch (error) {
    console.error('Error processing log:', error);
    res.status(500).send({ error: 'Internal server error' });
  }
});

// Get all logs
app.get('/api/logs', (req, res) => {
  res.json(logEntries);
});

// Clear all logs
app.post('/api/logs/clear', (req, res) => {
  logEntries.length = 0;
  io.emit('initialLogs', []);
  res.status(200).send({ success: true });
});

// Mode switching endpoints
app.post('/api/mode/simulator', (req, res) => {
  currentMode = 'simulator';
  startSimulator();
  res.status(200).send({ success: true });
});

app.post('/api/mode/live', (req, res) => {
  currentMode = 'live';
  startLiveCapture();
  res.status(200).send({ success: true });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send({ 
    status: 'ok', 
    connections: io.engine.clientsCount,
    mode: currentMode
  });
});

// Socket connection handling
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Send existing logs to new client
  socket.emit('initialLogs', logEntries);
  
  // Handle client errors
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
  
  socket.on('disconnect', (reason) => {
    console.log('Client disconnected:', socket.id, 'Reason:', reason);
  });
});

// Error handling for the server
server.on('error', (error) => {
  console.error('Server error:', error);
});

// Cleanup on server shutdown
process.on('SIGINT', () => {
  if (analyzerProcess) {
    analyzerProcess.kill();
  }
  process.exit();
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser`);
}); 