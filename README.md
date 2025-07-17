# NetCom7

The fastest communications possible.

This is an updated version of the NetCom7 package, now with enhanced **UDP** & **IPV6** support, improved cross-platform capabilities, **high-performance threaded socket components**, **universal socket components with dual protocol support and thread pool processing**, and **TLS/SSL security support**!

⚠️ **Note**: TLS/SSL implementation is currently available for **basic raw socket components** (TncTCPClient/TncTCPServer), **raw threaded socket components** (TncServer/TncClient), and **universal socket components** (TncTCPProClient/TncTCPProServer) on Windows platforms through SChannel integration.

## 📊 **NetCom7 Socket Components Comparison**

| Feature | **ncSockets** | **ncSources** | **ncSocketsPro** ⭐ | **ncTSockets** |
|---------|---------------|---------------|---------------------|----------------|
| **Architecture** | Basic Raw Sockets | Command Protocol | **Universal Hybrid** | Raw + Thread Pool |
| **Socket Access** | ✅ Direct Raw | ❌ Command-Only | ✅ Direct Raw | ✅ Direct Raw |
| **Custom Protocols** | ✅ Full Freedom | ❌ NetCom7 Only | ✅ Full Freedom | ✅ Full Freedom |
| **Command Protocol** | ❌ Manual | ✅ Built-in | ✅ Built-in | ❌ Manual |
| **Protocol Detection** | ❌ Manual | ❌ Single Protocol | ✅ **Automatic** | ❌ Manual |
| **Thread Pool Processing** | ❌ Manual | ✅ Commands Only | ✅ **Commands + Raw** | ✅ Raw Data Only |
| **Best For** | Simple protocols | RPC/Commands | **Universal** | High-throughput |

### **Component Selection Guide**
- **ncSockets**: Learning, simple protocols, full control
- **ncSources**: RPC-style command execution, structured protocols  
- **ncSocketsPro**: **Universal solution - handles any requirement** ⭐
- **ncTSockets**: High-performance custom protocol processing

## Recent Updates

### 🌟 **Universal Socket Components with Dual Protocol Support + Thread Pool** ⭐
**TncTCPProClient** and **TncTCPProServer** represent the **ultimate NetCom7 components**, combining the flexibility of ncSockets, the performance of ncSources, and intelligent protocol handling into one powerful solution.

#### Features
- **Dual Protocol Support**: Handle both raw data and structured commands simultaneously
- **Thread Pool Command Processing**: Commands execute in high-performance worker threads (like ncSources)
- **Automatic Protocol Detection**: Uses magic header (`$ACF0FF00`) to intelligently route data
- **Guaranteed Message Delivery**: `SendCommand()` method ensures complete message transmission
- **Full Backward Compatibility**: Existing custom protocols work exactly like ncSockets

#### Intelligent Architecture
```pascal
Network → Reader Thread → Protocol Detection → {
  Raw Data → OnReadData (Reader/Main Thread)
  Commands → Thread Pool → OnCommand (Worker Threads)
}
```
#### Easy Integration
The **TncTCPProServer** and **TncTCPProClient** components can be dragged from the palette and customized in the object inspector.

![alt text](image-6.png)

![alt text](image-7.png) ![alt text](image-8.png)

![alt text](image-9.png) ![alt text](image-10.png)


### 🚀 **High-Performance Threaded Socket Components (ncTSockets)**
**TncServer** and **TncClient** provide raw socket functionality with built-in thread pools for extreme performance:

- **Built-in Thread Pool**: Automatically manages worker threads for concurrent request processing
- **Raw Socket Performance**: Direct socket access without protocol overhead
- **TLS/SSL Security Support**: Full TLS encryption support with thread pool processing
- **Scalable Architecture**: Handles thousands of concurrent connections efficiently  
- **Simple API**: Easy-to-use interface similar to traditional NetCom7 components

#### Performance Benefits
- **Up to 3x Performance Improvement**: Compared to traditional single-threaded socket processing
- **Concurrent Processing**: Multiple client requests handled simultaneously
- **Efficient Resource Usage**: Thread reuse eliminates expensive thread creation/destruction
- **High Throughput**: Optimized for high-frequency, low-latency communications

#### Benchmark Results (100 Client Requests)

| Metric | TncServer (Thread Pool) | Basic Socket (No Thread Pool) | Improvement |
|--------|-------------------------|-------------------------------|-------------|
| **Requests Completed** | 85 | 30 | **2.8x more** |
| **Peak Req/Sec** | 39 | 16 | **2.4x faster** |
| **Average Req/Sec** | 14.2 | 5.0 | **2.8x faster** |
| **Test Duration** | 6.0s | 6.0s | Same |
| **Processing Threads** | 16 pool threads | 1 reader thread | **16x resources** |
| **Success Rate** | 85% | 30% | **2.8x better** |

**Test Scenario**: Client sends 100 rapid requests to both servers simultaneously.

**Key Findings**:
- **Thread Pool Advantage**: TncServer's 16 worker threads process requests concurrently, while basic socket is limited to sequential processing in a single reader thread
- **Higher Throughput**: Thread pool completed 85/100 requests vs 30/100 for basic socket
- **Better Performance**: Consistently higher peak and average request rates
- **Scalability**: Thread pool architecture scales with available CPU cores (4 threads per CPU)

#### Easy Integration
The **TncServer** and **TncClient** components can be dragged from the palette and customized in the object inspector with thread pool settings and connection properties.

![alt text](image-3.png)

![alt text](image-4.png) ![alt text](image-5.png)

### Enhanced UDP Support
The **UDP** components can be dragged from the palette and customized in the object inspector with the following properties:
- Broadcast capabilities
- Buffer size customization

![alt text](image-1.png)

### 🔐 TLS/SSL Security Support
NetCom7 now includes **TLS/SSL encryption** support for secure communications:

- **Windows SChannel Integration**: Native TLS support using Windows Secure Channel API (Windows only)
- **Universal Coverage**: TLS support across all socket component types
- **Easy Configuration**: Simple `UseTLS` property to enable secure communications
- **Certificate Management**: Built-in support for X.509 certificates and PFX files
- **Secure Handshake**: Automatic TLS handshake handling with proper certificate validation

#### Supported Components
- **Basic Raw Sockets**: TncTCPClient and TncTCPServer components
- **Threaded Raw Sockets**: TncServer and TncClient components  
- **Universal Sockets**: TncTCPProClient and TncTCPProServer components

#### Key Features
- **Transport Layer Security**: Industry-standard TLS encryption for data protection
- **Native Windows API**: Uses Windows SChannel for optimal performance and security
- **Seamless Integration**: TLS functionality integrated into existing NetCom7 architecture
- **OnBeforeConnected Events**: TLS handshake occurs before connection establishment

⚠️ **Note**: TLS support is currently available for Windows platforms only through SChannel integration.

### IPV6

TCP v4 / TCP v6 / UDP v4 / UDP v6 are now avaible.

⚠️ Client and Server must use the same familly version (no dual-stack sockets).

![alt text](image-2.png)

### Demo Updates
- Added new `SimpleThreadedSockets` demo
- Added new `SimpleSockets_UDP` demo
- Added new `SimpleSockets_TLS` demo for TLS/SSL secure communications (basic raw sockets)
- Added new `SimpleThreadedSockets_TLS` demo for TLS/SSL secure communications (raw threaded sockets)
- Updated the `SimpleSockets` demo
- Added new `ThreadedSocketsBenchmark` demo for performance testing and comparison
- Added new `Multi-Socket_ncSocketsPro` demo showcasing dual protocol support, thread pool processing, and guaranteed message delivery