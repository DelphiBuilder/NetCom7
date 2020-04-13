# NetCom7
The fastest communications possible.

This is version 7 of the NetCom package. 
This set of components is the fastest possible implementation of socket communications, in any language; 
this is an extremely optimised code on TCP/IP sockets. 

The implementation begins with TncTCPServer and TncTCPClient which implements the basic socket communications.
You can use TncTCPClient and TncTCPServer if all you want is to implement standard (but very fast) socket comms.

On top of the TCP/IP sockets, a lightweight protocol is implemented to be able to pack and unpack buffers
(simple TCP/IP is streaming and has no notion of a well defined buffer). The set of components implementing
this functionality is TncServerSource and TncClientSource. Both of these components implement an
ExecCommand (aCmd, aData) which triggers an OnHandleCommand event on the other side (a client can ExecCommand to a server, 
or a server can ExecCommand to any client). This set of components can handle as many as 2000 requests per second!!!
Also, the TncServerSource handles requests via a thread-ready pool so that it is as fast as possible 
(creating a thread on the fly is expensive on Windows, so a thread pool is created with threads ready to execute
any request as fast as possible).

Simple senario:
  Server:
  
    - You put a TncServerSource on your form. If you want you can change the port it is listening to via the Port property.
    
    - You implement an OnHandleCommand event handler and, depending on aCmd parameter (integer), you respond the result 
      of this command via setting the Result to anything you like (TBytes). If an exception is raised, it is trapped and
      raised at the peer's TncClientSource ExecCommand.
      
    - You set the Active property to true. Your server is ready.
    
  Client:
  
    - You put a TncClientSource on your form. You can set Host and Port to whatever you want. 
    
    - You set Active property to true. Your client is now connected to the server.
    
    - You call ExecCommand (on your TncClientSource), with any command number and data that you like.
      This will send your command and data over to the server, call its OnHandleCommand, pack the response, 
      and return it as a result to your ExecCommand. 
      
    - ExecCommand is blocking (if aRequiresResult parameter is set to true), but only for the current command issued.
      The TncClientSource's OnHandleCommand still executes, so, while waiting for a command to return, your client
      socket may be processing requests from your server (a server can also ExecCommand to a client).
      
    - If you have forgotten to set Active to true and call ExecCommand, the TncClientSource will first try to connect, 
      so you can ommit setting this property. It will also try to connect if it knows it has been disconnected.
      
Please refer to the demos for a better understanding on how to use these components.

Written by Bill Anastasios Demos.

VasDemos[at]yahoo[dot]co[dot]uk

* Delphi RULES *
