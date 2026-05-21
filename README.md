# Goofy Ahh Proxy

Picture this. You're living in a place with a very limited internet connection
where only a handful of local websites work and all VPNs, proxies, V2Ray,
HTTP Injector, SlipNet, NetMod, Psiphon, OpenVPN, Npv Tunnel, or whatever the
heck are effectively useless. You've been looking for a reliable way to connect
to the internet for months. You're exhausted...

...but all hope is not lost! Some of those local websites that work for you,
might work for people outside your region as well. And some of them indirectly
allow you to transfer data to and from a person with full internet access. It
could be a local messenger that allows you to make a video call with your friend
outside your location, a cloud storage service that allows you and your friend
to create and read files for data transfer, and so on.

The goal is to modulate internet traffic through goofy ahh data channels. You
could flash colorful squares in a video call, play sine tones with different
frequencies in a voice call, send botted text messages, read and write files,
flicker a light really fast, embed data in DNS queries, transmit pulses to an
unused radio frequnecy with a software-defined radio dongle, the list goes on!

Now let's see what this project provides.

# goofyproxy

[goofyproxy](./goofyproxy) is the backbone of the project. It provides three
fundumental classes we can build upon: `GoofyIo`, `GoofyServer` and
`GoofyClient`.

# bincall-io

[bincall-io](./bincall-io) uses a [bincall Server](./bincall) to transfer bytes
through "binary calls" and runs goofyproxy on top of that.

# s3io
[s3io](./s3io) creates and reads files on an AWS S3 Bucket for data transfer
and runs goofyproxy on top of that.

# VideoIo

[VideoIo](./videoio) allows data transfer over video calls by showing colorful
squares and runs goofyproxy on top of that.

# Disclaimer

1. I do not encourage illegal activities. Please stay within legal bounds.
2. Anything you do with this project is solely your responsibility.
