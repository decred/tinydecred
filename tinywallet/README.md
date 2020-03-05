# TinyWallet

TinyWallet is a light [Decred](https://decred.org/) wallet GUI application
based on PyQt5.

**The light wallet is experimental, and should not be used on mainnet.**

To start the wallet install the `tinywallet` package from the Python Package
Index and run the `tinywallet` command.

The wallet runs as a system-tray application, of which the major difference is
that "closing" the wallet actually just removes the entry from the taskbar and
minimizes the window "to the system tray".
The wallet can then be "opened" again through the icon in the system tray.

![alt text][screenshot]

TinyWallet is pretty small.
Like Decred, it's meant to be an omnipresent yet largely invisible and
unobtrusive part of your digital environment.
The small dialog size keeps user interactions focused.
Bells and whistles are minimized in favor of simplicity whenever possible.
Blockchain mechanics are invisible.
The goal is to make using Decred easier than pulling change out of your pocket.

[screenshot]:
https://user-images.githubusercontent.com/6109680/62095772-08b4ce80-b247-11e9-81ae-66931ebb07be.png
