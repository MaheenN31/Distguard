const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

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

// Store active processes
let activeProcesses = {
    liveCapture: null,
    simulator: null
};

// Function to stop a process
function stopProcess(processType) {
    if (activeProcesses[processType]) {
        activeProcesses[processType].kill();
        activeProcesses[processType] = null;
        return true;
    }
    return false;
}

// Function to start TrafficAnalyzer
function startTrafficAnalyzer(mode) {
    // Kill existing process if any
    stopProcess(mode);

    const analyzerPath = path.resolve(__dirname, '..', 'x64', 'Debug', 'TrafficAnalyzer.exe');
    console.log(`Starting ${mode} with path: ${analyzerPath}`);
    
    const analyzer = spawn(analyzerPath, [], { 
        shell: true,
        stdio: ['pipe', 'pipe', 'pipe']
    });

    // Store the process
    activeProcesses[mode] = analyzer;

    let menuChoiceSent = false;
    let packetCountSent = false;

    // Handle stdout to detect prompts and send responses
    analyzer.stdout.on('data', (data) => {
        const output = data.toString();
        console.log(`[TrafficAnalyzer ${mode}] ${output}`);
        
        // Send menu choice when menu appears
        if (!menuChoiceSent && output.includes('Select a module')) {
            console.log(`Sending ${mode} choice...`);
            analyzer.stdin.write('5\n');
            menuChoiceSent = true;
        }
        
        // Send packet count when prompted
        if (menuChoiceSent && !packetCountSent && output.includes('How many packets')) {
            console.log(`Sending packet count...`);
            analyzer.stdin.write('100\n');
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

    analyzer.stderr.on('data', (data) => {
        console.error(`[TrafficAnalyzer ${mode} Error] ${data}`);
        io.emit('error', data.toString());
    });

    analyzer.on('error', (err) => {
        console.error(`Failed to start TrafficAnalyzer ${mode}:`, err);
        addLogEntry(`[SYSTEM] Failed to start TrafficAnalyzer ${mode}: ${err.message}`);
    });

    analyzer.on('close', (code) => {
        console.log(`[TrafficAnalyzer ${mode}] Process exited with code ${code}`);
        activeProcesses[mode] = null;
        io.emit('processStopped', mode);
    });

    // Send the mode selection
    analyzer.stdin.write(mode === 'liveCapture' ? '4\n' : '5\n');
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
  startTrafficAnalyzer('simulator');
  res.status(200).send({ success: true });
});

app.post('/api/mode/live', (req, res) => {
  currentMode = 'live';
  startTrafficAnalyzer('liveCapture');
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

  socket.on('startLiveCapture', () => {
    console.log('Starting live capture...');
    startTrafficAnalyzer('liveCapture');
  });

  socket.on('stopLiveCapture', () => {
    console.log('Stopping live capture...');
    if (stopProcess('liveCapture')) {
      io.emit('log', '[Server] Live capture stopped');
    }
  });

  socket.on('startSimulator', () => {
    console.log('Starting traffic simulator...');
    startTrafficAnalyzer('simulator');
  });

  socket.on('stopSimulator', () => {
    console.log('Stopping traffic simulator...');
    if (stopProcess('simulator')) {
      io.emit('log', '[Server] Traffic simulator stopped');
    }
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

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Dashboard server listening on http://localhost:${PORT}`);
  console.log(`Send logs using POST to http://localhost:${PORT}/api/log`);
}); 