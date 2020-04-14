# NetCom7
The fastest communications possible.

This is version 7 of the NetCom package.

This set of components is the fastest possible implementation of socket communications, in any language; this is an extremely optimised code on TCP/IP sockets. 

The implementation begins with TncTCPServer and TncTCPClient which implements the basic socket communications.
You can use TncTCPClient and TncTCPServer if all you want is to implement standard (but very fast) socket comms.

On top of the TCP/IP sockets, a lightweight protocol is implemented to be able to pack and unpack buffers (simple TCP/IP is streaming and has no notion of a well defined buffer). The set of components implementing this functionality is TncServerSource and TncClientSource. Both of these components implement an ExecCommand (aCmd, aData) which triggers an OnHandleCommand event on the other side (a client can ExecCommand to a server, or a server can ExecCommand to any client). ExecCommand can be blocking or non-blocking (async) depending on how you set its aRequiresResult parameter. If you use the blocking behaviour, the component still handles incoming requests from its peer(s). For example, a ClientSource could be waiting on an ExecCommand to the server, but while waiting it can serve ExecCommand requests from the server!

This set of components can handle as many as 2000 requests per second on my testing machine, compared to 10 requests per second with Indy. 

Simple senario:
  Server:
  
    - You put a TncServerSource on your form. If you want you can change the port it is listening to via the 
    Port property.
    
    - You implement an OnHandleCommand event handler and, depending on aCmd parameter (integer), you respond the result of
    this command via setting the Result to anything you like (TBytes). If an exception is raised, it is trapped, packed, 
    transfered accross to the calling peer, and raised at the peer's issued ExecCommand. This way exceptions can be 
    handled as if they were raised locally.
      
    - You set the Active property to true. Your server is ready.
    
  Client:
  
    - You put a TncClientSource on your form. You can set Host and Port to whatever you want. 
    
    - You set Active property to true. Your client is now connected to the server.
    
    - You call ExecCommand (on your TncClientSource), with any command number and data that you like. This will 
    send your command and data over to the server, call its OnHandleCommand, pack the response, and return it as a 
    result to your ExecCommand. 
      
    - ExecCommand is blocking (if aRequiresResult parameter is set to true), but only for the current command issued. 
    The TncClientSource's OnHandleCommand still executes, so, while waiting for a command to return, your client socket
    may be processing requests from your server (a server can also ExecCommand to a client).
      
    - If you have forgotten to set Active to true and call ExecCommand, the TncClientSource will first try to connect,
    so you can ommit setting this property. It will also try to connect if it knows it has been disconnected.
      
This set of components promises unrivalled speed and that is not just in words:

Starting with the base unit, ncSockets.pas, you will see that the implementation does not suffer from slack code, it is rather immediate. The register calling convention has been used wherever deemed appropriate. The very core functions have been tested and optimised in a very tight timed loop to squeeze out every last bit of performance. 

The biggest difference though in speed gain is due to the architecture. Unlike most typical sockets, this set of sockets does not spawn a thread per connection. This means you can have as many live connections as you like and you will see NO difference in performance! A thread pool just waits for any requests; if a thread was to be created per request or per connection, the speed would suffer a lot, as creating a thread is quite heavy time-wise. If the number of requests per second cannot be handled by the thread pool, the thread pool grows up to a maximum defined size, and if it still cannot cope, the client just waits.

Particular attention has been given to connection issues also. For example, the disconnects are picked up immediately, and if a line is so bad that the disconnect cannot be picked up, it tackles this by a keep alive packet by which it gets to know the actual status. There is a Reconnect property and a KeepAlive property. Compression and encryption are also standard with these components with no extra libraries required. This set of components can also deal with garbage data sent to them, they have been used and tested in huge, country-wide projects where all sorts of attacks can be seen.

The effort a programmer has to make to use these components is minimal compared to other frameworks. Please refer to the demos for a better understanding on how to use these components.

Written by Bill Anastasios Demos.

VasDemos[at]yahoo[dot]co[dot]uk

* Delphi RULES *
