# NetCom7 – High-Performance Network & Encryption Library for Delphi

NetCom7 is a high-performance, modern Delphi networking and encryption library. It combines **thread-efficient networking**, a **rich set of encryption algorithms**, and **easy component-based usage**—ideal for building scalable servers and secure clients with minimal overhead.

---

## 🚀 Features

### 🔌 Networking
- Thread pool architecture: one thread **per command**, not per client.
- Scales to **thousands of simultaneous connections** on Windows, MacOS, Android, iOS and Linux.
- Built-in support for TCP, client/server modes, and raw streams.
- Works with **events or callbacks**, no thread management needed.

### 🔐 Encryption
- **30+ encryption & hashing algorithms** (more than DCPcrypt):
  - AES (Rijndael), Blowfish, Twofish, Serpent, Mars, RC6, and more.
  - Stream cipher: RC4 (legacy).
  - Hashes: SHA-256, SHA-512, RIPEMD-160, Haval, MD5, Tiger, etc.
- Fully modular and extensible design.

---
### 🕸️ Scalable Network Communications

NetCom7’s networking engine uses a **unique, scalable threading model** that solves the classic thread-per-connection limitation:

- **Thread Pool per Command Request**:
  - Instead of assigning a dedicated thread per client connection (which limits Windows servers to ~500 threads/connections), NetCom7 uses a small pool of worker threads.
  - These threads process commands asynchronously from any number of connected clients, enabling tens of thousands of concurrent connections.
- **Efficient Resource Usage**:
  - Keeps the server lightweight and performant even under heavy loads.
- **Command-Driven Model**:
  - Incoming commands from clients are queued and dispatched efficiently.
- **Ideal for High-Concurrency Servers**:
  - Perfect for real-time communication apps, games, and any server needing to handle massive simultaneous clients.

---

### 🛠️ Why Choose NetCom7?

- **Delphi Native**: Written entirely in Object Pascal for seamless integration.
- **Modern Architecture**: Modular, clean, and maintainable codebase.
- **Broad Crypto Coverage**: Supports many encryption standards used in industry.
- **Scalability**: Supports massive concurrent client loads without thread exhaustion.
- **Optimised**: Inlining and code profiling for each function for performance and low overhead.
- **Multiplatform**: Compiles for all known Delphi target platforms: Windows, MacOS, iOS, Android, Linux
- **Open Source**: Available on GitHub for review, contributions, and customization.

---

## 📦 Installation

1. Clone or download this repo.
2. Add the '\Source' and '\Source\Encryption' folder to your Delphi library path.
3. Open and run any of the provided demos under '\Demos'.

---

## 🧑‍💻 Quick Start Example

Here’s how easy it is to build a TCP server:

```pascal
var Server: TNetComServer;

Server := TNetComServer.Create(nil);
Server.Port := 8000;
Server.OnCommandReceived := HandleCommand;
Server.Start;
```

No threads, no socket juggling — just drop and go.

---

## 📂 Folder Structure

- `/Source/Encryption`: 30+ encryption & hash algorithms.
- `/Source/NetCom`: Core networking engine and components.
- `/Demos`: Ready-to-run client/server examples.
- `/Docs`: API notes, usage details, and reference.

---

## 📌 Notes

This is version 7.2 of the NetCom package, the fastest communications possible. In this version, the NetCom package is now multi-platform! 
You can compile your apps under all platforms in FireMonkey!

This set of components is the fastest possible implementation of socket communications, in any language; this is an extremely optimised code on TCP/IP sockets. Forget using a thread per connection: With this suite you can have as many concurrent connections to your server as you like. Threads are used per request and not per connection, and are maintained in a very fast thread pool class.

The implementation begins with TncTCPServer and TncTCPClient which implements the basic socket communications.
You can use TncTCPClient and TncTCPServer if all you want is to implement standard (but very fast) socket comms.

On top of the TCP/IP sockets, a lightweight protocol is implemented to be able to pack and unpack buffers (simple TCP/IP is streaming and has no notion of a well defined buffer). The set of components implementing this functionality is TncServerSource and TncClientSource. Both of these components implement an ExecCommand (aCmd, aData) which triggers an OnHandleCommand event on the other side (a client can ExecCommand to a server, or a server can ExecCommand to any client). ExecCommand can be blocking or non-blocking (async) depending on how you set its aRequiresResult parameter. If you use the blocking behaviour, the component still handles incoming requests from its peer(s). For example, a ClientSource could be waiting on an ExecCommand to the server, but while waiting it can serve ExecCommand requests from the server!

Simple senario:
  Server:
  
    - You put a TncServerSource on your form.
    If you want you can change the port it is listening to via the 
    Port property.
    
    - You implement an OnHandleCommand event handler and, 
    depending on aCmd parameter (integer), you respond the result of
    the command via setting the Result of the OnHandleCommand to 
    anything you like (TBytes). If an exception is raised while in 
    HandleCommand, it is trapped, packed, transfered accross to the 
    calling peer, and raised at the peer's issued ExecCommand. 
    This way exceptions can be handled as if they were raised locally.
      
    - You set the Active property to true. Your server is ready.
    
  Client:
  
    - You put a TncClientSource on your form. 
    You can set Host and Port to whatever you want. 
    
    - You set Active property to true. 
    Your client is now connected to the server.
    
    - You call ExecCommand (on your TncClientSource), with any 
    command number and data that you like. This will send your 
    command and data over to the server, call its OnHandleCommand, 
    pack the response, and return it as a result to your ExecCommand. 
      
    - ExecCommand is blocking (if aRequiresResult parameter is set to true), 
    but only for the current command issued.
    The TncClientSource's OnHandleCommand still executes, so, 
    while waiting for a command to return, your client socket may be 
    processing requests from your server (a server can also 
    ExecCommand to a client).
      
    - If you have forgotten to set Active to true and call ExecCommand, 
    the TncClientSource will first try to connect, so you can ommit 
    setting this property. It will also try to connect if it knows 
    it has been disconnected (and the Reconnect property is set to true).
      
This set of components promises unrivalled speed and that is not just in words:

A simple timing test with the NetComVSIndy demo gives the following results:

* Testing Indy... Time taken: 32468 msec
* Testing NetCom... Time taken: 25109 msec

Starting with the base unit, ncSockets.pas, you will see that the implementation does not suffer from slack code, it is rather immediate. The **inline** calling convention has been used wherever deemed appropriate. The very core functions have been tested and optimised by monitoring the performance via timing of large loops and assembly inspection to squeeze out every last bit of performance. 

The biggest difference though in speed gain is due to the architecture. Unlike most typical sockets: 

**this set of sockets does neither spawn nor use a thread per connection.**

This means **you can have as many live connections as you like and you will see NO difference in performance!** A thread pool just waits for any requests; if a thread was to be created per request or per connection, the speed would suffer a lot, as creating a thread is quite heavy time-wise. If the number of requests per second cannot be handled by the thread pool, the thread pool grows up to a maximum defined size, and if it still cannot cope, the client just waits until the server gets a ready thread to process its request.

Particular attention has been given to connection issues also. For example, the disconnects are picked up immediately, and if a line is so bad that the disconnect cannot be picked up, it tackles this by a keep alive packet by which it gets to know the actual status. There is a **Reconnect property** and a KeepAlive property. When a client gets disconnected, for whatever reason, it tries to reconnect transparently and without affecting the main application's performance. This way you do not have to worry about keeping your clients connected.

Compression and encryption are also standard with these components with no extra libraries required. Ofcourse you can use your own compression or encryption if you prefer, but it is rather handy to have just a property you can set on the component.

This set of components can also deal with garbage data thrown at them, they have been used and tested in huge, country-wide projects where all sorts of attacks can be seen.

The effort a programmer has to make to use these components is minimal compared to other frameworks. Please refer to the demos for a better understanding on how to use these components.

Written by Bill Anastasios Demos. 
Special thanks to Daniel Mauric, Tommi Prami, Roland Bengtsson for the extensive testing and suggestions. Thank you so much!

VasDemos[at]yahoo[dot]co[dot]uk

---

## 🔗 License

MIT — free to use and modify.

---
