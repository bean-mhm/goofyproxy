# Goofy Ahh Proxy

goofyproxy is a Python package allows you to share your internet connection with
a friend through weird means of data transfer.

# `GoofyIo`

`GoofyIo` is an abstract class for transferring data through a goofy ahh
channel or medium. It has `send()`, `receive()`, and a few simple rules mentioned
in `goofyio.py`.

goofyproxy provides the following subclasses for `GoofyIo` out of the box:

- `SocketIo`: Uses pre-connected sockets to send and receive data.

- `StorageBasedGoofyIo`: A base class for `GoofyIo`s that use a file storage
system for data transfer (by creating and reading files), whether local or on
the cloud. It uses packet indices, timestamps, and length metadata to ensure
correct ordering and avoid reading incomplete files. gzip compression is used
only when it actually reduces the size of the packet.

- `TxtFileIo`: Creates, reads, and deletes .txt files with base85 encoding and
gzip compression to send and receive data.

# `GoofyServer`

The **Goofy Ahh Proxy Server** is run by the lucky volunteer with normal
internet access. It works with any well-implemented `GoofyIo`.

See `goofy_server.py` for more details. It's human-readable code.

# `GoofyClient`

The **Goofy Ahh Proxy Client** is run by the unfortunate person with no proper
internet access. It works with any well-implemented `GoofyIo` as long as the
server is already running on the other side.

The **Goofy Ahh Proxy Client** runs a local SOCKS5 proxy server that other
devices or programs on the LAN can connect to. It then communicates with the
**Goofy Ahh Proxy Server** by sending commands (open socket, bind, etc.) and
receiving events (update socket status, bind info, etc.). Once a socket is
connected, the **Goofy Ahh Proxy Client and Server** both start relaying data
by sending socket IO packets.

See `goofy_client.py` for more details. It's human-readable code.

> [!NOTE]
> The word "packet" here is referring to `GoofyPacket` to be precise. See
> `common.py` to learn more.

# Disclaimer

1. I do not encourage illegal activities. Please stay within legal bounds.
2. Anything you do with this project is solely your responsibility.
