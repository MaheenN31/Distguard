#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_   // Prevent winsock.h from being included by windows.h
#define HAVE_REMOTE
#define WPCAP

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>   // For inet_ntop
#include <commctrl.h>
#include <string>
#include <vector>
#include <ctime>
#include <thread>
#include <mutex>
#include <atomic>
#include "rules.h"
#include "traffic_simulator.h"
#include <pcap.h>
#include <algorithm>  // For std::min

// Ethernet header structure
struct ether_header {
    u_char ether_dhost[6];  // Destination host address
    u_char ether_shost[6];  // Source host address
    u_short ether_type;     // Protocol type
};

// IP header structure
struct ip_header {
    u_char ip_vhl;                 // Version and header length
    u_char ip_tos;                 // Type of service
    u_short ip_len;                // Total length
    u_short ip_id;                 // Identification
    u_short ip_off;                // Fragment offset field
    u_char ip_ttl;                 // Time to live
    u_char ip_p;                   // Protocol
    u_short ip_sum;                // Checksum
    struct in_addr ip_src, ip_dst; // Source and dest address
};

// TCP header structure
struct tcp_header {
    u_short th_sport;  // Source port
    u_short th_dport;  // Destination port
    u_int th_seq;      // Sequence number
    u_int th_ack;      // Acknowledgement number
    u_char th_offx2;   // Data offset and reserved
    u_char th_flags;   // Flags
    u_short th_win;    // Window
    u_short th_sum;    // Checksum
    u_short th_urp;    // Urgent pointer
};

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// Global variables
HWND g_hWnd = NULL;
HWND g_hTabControl = NULL;
HWND g_hPacketCount = NULL;
HWND g_hRunButton = NULL;
HWND g_hAlertsList = NULL;
HWND g_hSummaryText = NULL;
HWND g_hInterfaceCombo = NULL;
HWND g_hStartCaptureButton = NULL;
HWND g_hStopCaptureButton = NULL;
std::atomic<bool> g_captureRunning{false};
std::thread g_captureThread;
std::mutex g_alertsMutex;

// Alert structure
struct AlertEntry {
    std::string type;
    std::string source;
    std::string target;
    int port;
    time_t timestamp;
};
std::vector<AlertEntry> g_alerts;

// Forward declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void ShowTab(int tabIndex);
void RunSimulation();
void UpdateAlertsList();
void LiveCaptureThread(pcap_t* handle);

int main6() {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccx;
    iccx.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccx.dwICC = ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&iccx);
    
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName = L"DistGuardWindow";
    
    if (!RegisterClassEx(&wc)) {
        MessageBoxW(NULL, L"Window Registration Failed!", L"Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    // Create the main window
    g_hWnd = CreateWindowExW(
        0,
        L"DistGuardWindow",
        L"DistGuard Dashboard",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );
    
    if (!g_hWnd) {
        MessageBoxW(NULL, L"Window Creation Failed!", L"Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    // Create child controls
    CreateControls(g_hWnd);
    
    // Show the window
    ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hWnd);
    
    // Message loop
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}

void CreateControls(HWND hwnd) {
    // Create tab control
    g_hTabControl = CreateWindowExW(
        0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        10, 10, 760, 540,
        hwnd, (HMENU)100, GetModuleHandle(NULL), NULL
    );
    
    // Add tabs
    TCITEMW tie;
    tie.mask = TCIF_TEXT;
    
    tie.pszText = (LPWSTR)L"Traffic Simulator";
    TabCtrl_InsertItem(g_hTabControl, 0, &tie);
    
    tie.pszText = (LPWSTR)L"Alerts";
    TabCtrl_InsertItem(g_hTabControl, 1, &tie);
    
    tie.pszText = (LPWSTR)L"Live Capture";
    TabCtrl_InsertItem(g_hTabControl, 2, &tie);
    
    // Create simulator controls
    g_hPacketCount = CreateWindowExW(
        0,
        L"EDIT",
        L"100",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
        50, 70, 100, 25,
        hwnd, (HMENU)101, GetModuleHandle(NULL), NULL
    );
    
    g_hRunButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Run Simulation",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 70, 150, 30,
        hwnd, (HMENU)102, GetModuleHandle(NULL), NULL
    );
    
    g_hSummaryText = CreateWindowExW(
        0,
        L"STATIC",
        L"",
        WS_CHILD | WS_VISIBLE,
        50, 110, 600, 80,
        hwnd, (HMENU)103, GetModuleHandle(NULL), NULL
    );
    
    // Create alerts list view
    g_hAlertsList = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_BORDER | LVS_REPORT,
        50, 70, 700, 450,
        hwnd, (HMENU)104, GetModuleHandle(NULL), NULL
    );
    
    // Set up list view columns
    LVCOLUMN lvc;
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"Time";
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hAlertsList, 0, &lvc);
    
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Type";
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hAlertsList, 1, &lvc);
    
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Source";
    lvc.iSubItem = 2;
    ListView_InsertColumn(g_hAlertsList, 2, &lvc);
    
    lvc.cx = 150;
    lvc.pszText = (LPWSTR)L"Target";
    lvc.iSubItem = 3;
    ListView_InsertColumn(g_hAlertsList, 3, &lvc);
    
    lvc.cx = 80;
    lvc.pszText = (LPWSTR)L"Port";
    lvc.iSubItem = 4;
    ListView_InsertColumn(g_hAlertsList, 4, &lvc);
    
    // Create live capture controls
    g_hInterfaceCombo = CreateWindowExW(
        0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        50, 70, 300, 200,
        hwnd, (HMENU)105, GetModuleHandle(NULL), NULL
    );

    g_hStartCaptureButton = CreateWindowExW(
        0, L"BUTTON", L"Start Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        360, 70, 150, 30,
        hwnd, (HMENU)106, GetModuleHandle(NULL), NULL
    );

    g_hStopCaptureButton = CreateWindowExW(
        0, L"BUTTON", L"Stop Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        520, 70, 150, 30,
        hwnd, (HMENU)107, GetModuleHandle(NULL), NULL
    );

    // Populate interface combo box
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        MessageBoxW(hwnd, L"Error finding network interfaces", L"Error", MB_ICONERROR);
        return;
    }

    for (device = alldevs; device != nullptr; device = device->next) {
        wchar_t deviceName[256];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, deviceName, sizeof(deviceName)/sizeof(wchar_t),
            device->description ? device->description : device->name, _TRUNCATE);
        SendMessage(g_hInterfaceCombo, CB_ADDSTRING, 0, (LPARAM)deviceName);
    }

    pcap_freealldevs(alldevs);
    
    // Show initial tab
    ShowTab(0);
}

void ShowTab(int tabIndex) {
    // Hide/show controls based on selected tab
    ShowWindow(g_hPacketCount, tabIndex == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hRunButton, tabIndex == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hSummaryText, tabIndex == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAlertsList, tabIndex == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hInterfaceCombo, tabIndex == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hStartCaptureButton, tabIndex == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hStopCaptureButton, tabIndex == 2 ? SW_SHOW : SW_HIDE);
    
    if (tabIndex == 1) {
        UpdateAlertsList();
    }
}

void RunSimulation() {
    // Get packet count from edit control
    wchar_t buffer[16];
    GetWindowTextW(g_hPacketCount, buffer, sizeof(buffer) / sizeof(wchar_t));
    int packetCount = _wtoi(buffer);
    
    if (packetCount <= 0) {
        packetCount = 100; // Default
    }
    
    // Run traffic simulation
    TrafficAnalyzer analyzer;
    std::vector<Packet> packets = TrafficSimulator::generateTraffic(packetCount);
    
    g_alerts.clear();
    int alertCount = 0;
    
    for (const auto& packet : packets) {
        std::pair<bool, std::string> result = analyzer.analyze(packet);
        
        if (result.first) {
            alertCount++;
            AlertEntry alert;
            alert.type = result.second;
            alert.source = packet.src_ip;
            alert.target = packet.dst_ip;
            alert.port = packet.port;
            alert.timestamp = time(nullptr);
            g_alerts.push_back(alert);
        }
    }
    
    // Update summary text
    wchar_t summary[256];
    swprintf(summary, sizeof(summary) / sizeof(wchar_t), 
            L"Simulation complete!\n- Generated packets: %d\n- Alerts detected: %d\n- Detection rate: %.1f%%", 
            (int)packets.size(), alertCount, ((float)alertCount / packets.size()) * 100.0f);
    
    SetWindowTextW(g_hSummaryText, summary);
    
    // Show message box with results
    wchar_t resultMsg[256];
    swprintf(resultMsg, sizeof(resultMsg) / sizeof(wchar_t), 
            L"Simulation complete!\nGenerated %d packets\nDetected %d alerts", 
            (int)packets.size(), alertCount);
    
    MessageBoxW(g_hWnd, resultMsg, L"Simulation Results", MB_OK | MB_ICONINFORMATION);
    
    // Switch to alerts tab
    TabCtrl_SetCurSel(g_hTabControl, 1);
    ShowTab(1);
}

void UpdateAlertsList() {
    // Clear existing items
    ListView_DeleteAllItems(g_hAlertsList);
    
    // Add alerts to list view
    for (size_t i = 0; i < g_alerts.size(); i++) {
        const AlertEntry& alert = g_alerts[i];
        
        LVITEM lvi;
        ZeroMemory(&lvi, sizeof(LVITEM));
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.iSubItem = 0;
        
        // Format time
        char timeBuf[32];
        struct tm timeinfo;
        localtime_s(&timeinfo, &alert.timestamp);
        strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &timeinfo);
        
        // We need to convert narrow strings to wide strings for Windows API
        wchar_t wTimeBuf[32];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, wTimeBuf, sizeof(wTimeBuf) / sizeof(wchar_t), timeBuf, _TRUNCATE);
        
        int index = ListView_InsertItem(g_hAlertsList, &lvi);
        
        // Add other columns
        wchar_t wBuf[256];
        
        // Alert type
        mbstowcs_s(&convertedChars, wBuf, sizeof(wBuf) / sizeof(wchar_t), alert.type.c_str(), _TRUNCATE);
        ListView_SetItemText(g_hAlertsList, index, 1, wBuf);
        
        // Source IP
        mbstowcs_s(&convertedChars, wBuf, sizeof(wBuf) / sizeof(wchar_t), alert.source.c_str(), _TRUNCATE);
        ListView_SetItemText(g_hAlertsList, index, 2, wBuf);
        
        // Target IP
        mbstowcs_s(&convertedChars, wBuf, sizeof(wBuf) / sizeof(wchar_t), alert.target.c_str(), _TRUNCATE);
        ListView_SetItemText(g_hAlertsList, index, 3, wBuf);
        
        // Port
        swprintf(wBuf, sizeof(wBuf) / sizeof(wchar_t), L"%d", alert.port);
        ListView_SetItemText(g_hAlertsList, index, 4, wBuf);
    }
}

void LiveCaptureThread(pcap_t* handle) {
    TrafficAnalyzer analyzer;
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (g_captureRunning) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // Timeout
        if (res < 0) break;     // Error

        // Use the existing packet_handler logic but modified for the dashboard
        const ether_header* eth_header = reinterpret_cast<const ether_header*>(packet);
        if (ntohs(eth_header->ether_type) != 0x0800) continue;

        const ip_header* ip_hdr = reinterpret_cast<const ip_header*>(packet + sizeof(ether_header));
        int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
        if (ip_hdr->ip_p != 6) continue;

        const tcp_header* tcp_hdr = reinterpret_cast<const tcp_header*>(packet + sizeof(ether_header) + ip_header_len);

        Packet pkt;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.src_port = ntohs(tcp_hdr->th_sport);
        pkt.port = ntohs(tcp_hdr->th_dport);
        pkt.tcp_flags = tcp_hdr->th_flags;
        pkt.tcp_seq = ntohl(tcp_hdr->th_seq);

        int payload_offset = sizeof(ether_header) + ip_header_len + ((tcp_hdr->th_offx2 >> 4) * 4);
        int payload_length = header->len - payload_offset;

        if (payload_length > 0) {
            int bytes_to_copy = (std::min)(payload_length, 100);
            pkt.payload = std::string(reinterpret_cast<const char*>(packet + payload_offset), bytes_to_copy);
        } else {
            pkt.payload = "[No Data]";
        }

        std::pair<bool, std::string> result = analyzer.analyze(pkt);
        if (result.first) {
            AlertEntry alert;
            alert.type = result.second;
            alert.source = pkt.src_ip;
            alert.target = pkt.dst_ip;
            alert.port = pkt.port;
            alert.timestamp = time(nullptr);

            {
                std::lock_guard<std::mutex> lock(g_alertsMutex);
                g_alerts.push_back(alert);
            }
            
            // Post a message to the main window to update the display
            PostMessage(g_hWnd, WM_USER + 1, 0, 0);
        }
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 102: // Run simulation button
                    if (HIWORD(wParam) == BN_CLICKED) {
                        RunSimulation();
                    }
                    break;

                case 106: // Start capture button
                    if (HIWORD(wParam) == BN_CLICKED) {
                        int selectedInterface = SendMessage(g_hInterfaceCombo, CB_GETCURSEL, 0, 0);
                        if (selectedInterface == CB_ERR) {
                            MessageBoxW(hwnd, L"Please select an interface", L"Error", MB_ICONERROR);
                            break;
                        }

                        pcap_if_t* alldevs;
                        pcap_if_t* device;
                        char errbuf[PCAP_ERRBUF_SIZE];

                        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                            MessageBoxW(hwnd, L"Error finding network interfaces", L"Error", MB_ICONERROR);
                            break;
                        }

                        // Find selected device
                        device = alldevs;
                        for (int i = 0; i < selectedInterface && device; i++) {
                            device = device->next;
                        }

                        if (!device) {
                            pcap_freealldevs(alldevs);
                            MessageBoxW(hwnd, L"Selected interface not found", L"Error", MB_ICONERROR);
                            break;
                        }

                        // Open the device
                        pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
                        pcap_freealldevs(alldevs);

                        if (!handle) {
                            MessageBoxW(hwnd, L"Could not open interface", L"Error", MB_ICONERROR);
                            break;
                        }

                        // Set up filter
                        struct bpf_program fcode;
                        if (pcap_compile(handle, &fcode, "tcp", 1, PCAP_NETMASK_UNKNOWN) < 0 ||
                            pcap_setfilter(handle, &fcode) < 0) {
                            pcap_close(handle);
                            MessageBoxW(hwnd, L"Could not set capture filter", L"Error", MB_ICONERROR);
                            break;
                        }

                        // Start capture thread
                        g_captureRunning = true;
                        g_captureThread = std::thread(LiveCaptureThread, handle);

                        // Update UI
                        EnableWindow(g_hStartCaptureButton, FALSE);
                        EnableWindow(g_hStopCaptureButton, TRUE);
                        EnableWindow(g_hInterfaceCombo, FALSE);
                    }
                    break;

                case 107: // Stop capture button
                    if (HIWORD(wParam) == BN_CLICKED) {
                        g_captureRunning = false;
                        if (g_captureThread.joinable()) {
                            g_captureThread.join();
                        }

                        // Update UI
                        EnableWindow(g_hStartCaptureButton, TRUE);
                        EnableWindow(g_hStopCaptureButton, FALSE);
                        EnableWindow(g_hInterfaceCombo, TRUE);
                    }
                    break;
            }
            break;

        case WM_USER + 1: // Custom message for updating alerts
            UpdateAlertsList();
            break;

        case WM_NOTIFY:
            switch (((LPNMHDR)lParam)->idFrom) {
                case 100: // Tab control
                    if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
                        int tabIndex = TabCtrl_GetCurSel(g_hTabControl);
                        ShowTab(tabIndex);
                    }
                    break;
            }
            break;
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
    return 0;
}
