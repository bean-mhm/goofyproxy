# bincall-io

`BincallIo` is a child class of `GoofyIo` that uses a
[bincall Server](../bincall) to transfer bytes through "binary calls".

The main script (`main.py`) provides a command line program that runs
[goofyproxy](../goofyproxy) on top of bincall calls.

Run `python ./main.py -h` to see a detailed and human-readable help message.

# Using Google Apps Script as a Relay

Check out [this example](./google-apps-script-relay) to see how you can use a
Google Apps Script Web App as a relay to a bincall server that you can't access
directly.

# Disclaimer

1. I do not encourage illegal activities. Please stay within legal bounds.
2. Anything you do with this project is solely your responsibility.
