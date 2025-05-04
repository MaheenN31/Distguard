const socket = io({
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  timeout: 20000
});

const packetTableBody = document.getElementById('packetTableBody');
const packetCountEl = document.getElementById('packetCount');
const connectionStatus = document.getElementById('connectionStatus');
const statusText = document.getElementById('statusText');
const errorMessage = document.getElementById('errorMessage');
const simulatorBtn = document.getElementById('simulatorBtn');
const liveBtn = document.getElementById('liveBtn');

let packetCount = 0;
let currentMode = null;

// Connection status handling
function updateConnectionStatus(connected, message) {
  connectionStatus.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
  statusText.textContent = message;
}

// Error handling
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.classList.add('show');
  setTimeout(() => {
    errorMessage.classList.remove('show');
  }, 5000);
}

// Socket event handlers
socket.on('connect', () => {
  console.log('Socket connected');
  updateConnectionStatus(true, 'Connected');
});

socket.on('disconnect', (reason) => {
  console.log('Socket disconnected:', reason);
  updateConnectionStatus(false, 'Disconnected');
  showError('Connection lost. Attempting to reconnect...');
});

socket.on('connect_error', (error) => {
  console.log('Socket connection error:', error);
  updateConnectionStatus(false, 'Connection Error');
  showError('Failed to connect to server. Retrying...');
});

// Parse packet information from log line
function parsePacketInfo(line) {
  console.log('Attempting to parse line:', line);
  
  try {
    // Try to parse as JSON first
    const packetInfo = JSON.parse(line);
    if (packetInfo && packetInfo.sourceIp) {
      console.log('Successfully parsed JSON packet:', packetInfo);
      return packetInfo;
    }
  } catch (e) {
    console.log('Not JSON, trying regex patterns');
    
    // Format 1: [ChildNode] Received packet: sourceIP|destIP|port|flags|seq|info
    const format1Match = line.match(/\[ChildNode\] Received packet: ([\d\.]+)\|([\d\.]+)\|(\d+)\|(\d+)\|(\d+)\|(.+)/);
    
    // Format 2: [Packet] sourceIP -> destIP:port [flags] seq=seqNum info
    const format2Match = line.match(/\[Packet\] ([\d\.]+) -> ([\d\.]+):(\d+) \[(.*?)\] seq=(\d+) (.+)/);
    
    if (format1Match) {
      console.log('Matched Format 1:', format1Match);
      return {
        sourceIp: format1Match[1],
        destIp: format1Match[2],
        port: format1Match[3],
        flags: format1Match[4],
        seq: format1Match[5],
        info: format1Match[6],
        isMalicious: line.includes('flood') || line.includes('Spoofed') || line.includes('scan'),
        reason: line.includes('flood') ? 'Flood attack detected' :
                line.includes('Spoofed') ? 'IP spoofing detected' :
                line.includes('scan') ? 'Port scan detected' : ''
      };
    } else if (format2Match) {
      console.log('Matched Format 2:', format2Match);
      return {
        sourceIp: format2Match[1],
        destIp: format2Match[2],
        port: format2Match[3],
        flags: format2Match[4],
        seq: format2Match[5],
        info: format2Match[6],
        isMalicious: line.includes('flood') || line.includes('Spoofed') || line.includes('scan'),
        reason: line.includes('flood') ? 'Flood attack detected' :
                line.includes('Spoofed') ? 'IP spoofing detected' :
                line.includes('scan') ? 'Port scan detected' : ''
      };
    }
  }
  
  console.log('No packet format match found');
  return null;
}

// Handle single log line
socket.on('log', (logEntry) => {
  console.log('Received log entry:', logEntry);
  
  const message = logEntry.message || logEntry;
  console.log('Processing message:', message);
  
  const packetInfo = parsePacketInfo(message);
  
  if (packetInfo) {
    console.log('Adding packet to table:', packetInfo);
    appendPacketRow(packetInfo, logEntry.timestamp);
    updatePacketCount(1);
  }
});

// Handle initial logs array when connecting
socket.on('initialLogs', (logs) => {
  console.log('Received initial logs:', logs);
  
  // Clear existing logs first
  packetTableBody.innerHTML = '';
  
  // Add all logs in the array
  logs.forEach(logEntry => {
    const message = logEntry.message || logEntry;
    console.log('Processing initial log:', message);
    
    const packetInfo = parsePacketInfo(message);
    if (packetInfo) {
      console.log('Adding initial packet to table:', packetInfo);
      appendPacketRow(packetInfo, logEntry.timestamp);
    }
  });
  
  // Update the packet count
  updatePacketCount(logs.length);
});

// Helper function to append a packet row to the table
function appendPacketRow(packetInfo, timestamp) {
  const row = document.createElement('tr');
  
  // Format timestamp
  const time = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  
  // Format packet info with flags
  const flags = typeof packetInfo.flags === 'string' ? packetInfo.flags : packetInfo.flags.toString();
  const flagInfo = [];
  if (flags.includes('FIN')) flagInfo.push('FIN');
  if (flags.includes('SYN')) flagInfo.push('SYN');
  if (flags.includes('RST')) flagInfo.push('RST');
  if (flags.includes('PSH')) flagInfo.push('PSH');
  if (flags.includes('ACK')) flagInfo.push('ACK');
  if (flags.includes('URG')) flagInfo.push('URG');
  
  const packetInfoText = `Flags: ${flagInfo.join(',')} | Seq: ${packetInfo.seq} | ${packetInfo.info}`;
  
  row.innerHTML = `
    <td class="timestamp">${time}</td>
    <td class="source-ip">${packetInfo.sourceIp}</td>
    <td class="dest-ip">${packetInfo.destIp}</td>
    <td class="port">${packetInfo.port}</td>
    <td class="packet-info">${packetInfoText}</td>
    <td class="${packetInfo.isMalicious ? 'malicious' : 'normal'}">${packetInfo.isMalicious ? 'Malicious' : 'Normal'}</td>
    <td class="reason">${packetInfo.reason}</td>
  `;
  
  packetTableBody.insertBefore(row, packetTableBody.firstChild);
}

// Update the packet counter
function updatePacketCount(increment) {
  packetCount += increment;
  packetCountEl.textContent = `${packetCount} packets`;
}

// Function to start simulator mode
function startSimulator() {
  if (currentMode === 'simulator') return;
  
  currentMode = 'simulator';
  simulatorBtn.classList.add('active');
  liveBtn.classList.remove('active');
  
  console.log('Starting simulator mode...'); // Debug log
  
  fetch('/api/mode/simulator', { method: 'POST' })
    .then(response => {
      if (!response.ok) throw new Error('Failed to start simulator');
      console.log('Simulator started successfully'); // Debug log
    })
    .catch(error => {
      console.error('Error starting simulator:', error); // Debug log
      showError('Failed to start simulator: ' + error.message);
    });
}

// Function to start live capture mode
function startLiveCapture() {
  if (currentMode === 'live') return;
  
  currentMode = 'live';
  liveBtn.classList.add('active');
  simulatorBtn.classList.remove('active');
  
  console.log('Starting live capture mode...'); // Debug log
  
  fetch('/api/mode/live', { method: 'POST' })
    .then(response => {
      if (!response.ok) throw new Error('Failed to start live capture');
      console.log('Live capture started successfully'); // Debug log
    })
    .catch(error => {
      console.error('Error starting live capture:', error); // Debug log
      showError('Failed to start live capture: ' + error.message);
    });
}

// Function to clear all logs
function clearLogs() {
  fetch('/api/logs/clear', {
    method: 'POST'
  })
  .then(() => {
    packetTableBody.innerHTML = '';
    packetCount = 0;
    packetCountEl.textContent = '0 packets';
  })
  .catch(error => {
    showError('Failed to clear logs: ' + error.message);
  });
}

// Initial connection status
updateConnectionStatus(false, 'Connecting...'); 

// Add event listeners for buttons
document.getElementById('simulatorBtn').addEventListener('click', startSimulator);
document.getElementById('liveBtn').addEventListener('click', startLiveCapture);

// Add event listener for clear logs button if it exists
const clearLogsBtn = document.getElementById('clearLogsBtn');
if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', clearLogs); }