🌊 Cascade Client: A Proof-of-Concept File Distribution Program
===

A modern, simple client application demonstrating a basic decentralized file distribution model, built using C++17 and the GTK4 GUI toolkit. This project serves as a minimal, educational implementation of core peer-to-peer concepts like file chunking, piece verification (SHA-256), and simultaneous seeding/downloading, heavily inspired by the UI of popular torrent clients.

✨ Features
===

    Peer-to-Peer Core: Implements basic networking logic for peer handshaking, piece requests, and data transfer.

    File Distribution: Supports both creating cascade files (.cascade) and downloading files based on those files.

    Simultaneous Seeding: Automatically transitions a successfully downloaded file into a seeding state.

    GTK4 Modern UI: Uses GtkColumnView and GListStore for a responsive, list-based interface to manage active cascades.

    Cross-Platform Ready: Built on standard C++17 and the GLib/GTK framework.

    Data Integrity: Verifies file chunks using SHA-256 hashes defined in the .cascade metadata.

🏗️ Technology Stack
===

Component	Purpose	Details
Language	C++17	Used for performance-critical P2P logic and threading.
GUI Framework	GTK4	Modern, list-based UI for managing active transfers.
Build System	pkg-config	Standard method for linking GTK4, GLib, and GObject.
Networking	POSIX Sockets	Low-level TCP networking for peer communication.
Cryptography	OpenSSL (-lssl, -lcrypto)	Used for SHA-256 piece hashing.
Data Format	nlohmann/json	Lightweight C++ library for parsing and generating .cascade metadata files.
Threading	std::thread, std::mutex, std::atomic	Used for concurrent downloads and the persistent seeder server.

🚀 Getting Started
===

Prerequisites

You will need a C++ compiler supporting C++17 (like GCC or Clang) and the necessary development libraries for GTK4, GLib, and OpenSSL.

On a Debian/Ubuntu-based system:

# Install GTK4, GLib, and GObject development files
sudo apt install libgtk-4-dev libglib2.0-dev libgmodule-2.0-dev

# Install OpenSSL development files
sudo apt install libssl-dev

# Install the nlohmann/json dependency (or clone it into your project)
# Note: If you don't use a package manager, you must include the header manually.
# For simplicity, we assume the header is placed in a known location (e.g., nlohmann/json.hpp).

Build and Run
    
```g++ cascade_gui.cpp -o cascade_gui     `pkg-config --cflags --libs gtk4 glib-2.0 gmodule-2.0`     -lssl -lcrypto -pthread -std=c++17```

Execute the program:

    ./cascade_gui

Make sure to create a "./downloads" folder in the same directory as the executable as downloads are currently set to go there for this proof-of-concept copy.

💡 How to Use
===
The client supports two main workflows accessible via the header bar buttons:

1. Create and Seed a New File

    Click the "Create New Cascade and Seed" button (document-new icon).

    Select any local file you wish to share (e.g., my_large_file.zip).

    The client will immediately:

        Chunk the file and calculate the SHA-256 hash for each piece.

        Generate a metadata file named my_large_file.zip.cascade in the same directory.

        Start a seeder thread for that file on port 6881 and display its status in the list.

2. Download a Cascade File

    Obtain a .cascade file from a friend or a distribution source.

    Click the "Add Cascade (.cascade file)" button (list-add icon).

    Select the .cascade file.

    The client will:

        Start a multi-threaded downloader.

        Connect to the peers listed in the metadata.

        Begin downloading and verifying pieces.

    Upon successful completion, the full file will be saved in the local ./downloads directory, and the cascade will automatically transition to "Seeding" mode.

📘 Project Structure
===

File/Directory	Description
cascade_gui.cpp	The entire source code. Contains the GTK4 UI setup, GObject definitions (CascadeItem), the CascadeCreator, MultiPeerDownloader, and CascadeSeeder classes.
downloads/	Default directory where successfully downloaded files are saved.
*.cascade	The metadata file format (JSON) containing file size, piece size, piece hashes (for integrity), and initial peer contact information.
Makefile (optional)	Recommended to simplify the compilation command.

🤝 Contributing
===

This is a proof-of-concept, and many aspects (peer discovery, NAT traversal, robust error handling) are intentionally simplified.
Things such as a proper GUI are not complete, such as Pause,Stop,Remove,Etc. This is a base proof-of-concept and many elements need updated logic/coding.
The code is not separated apart into multiple .cpp/h for ease either at the moment.

Feel free to fork the repository and explore improvements! Ideas for future work include:

    Implementing a decentralized tracker or DHT for peer discovery.

    Adding proper disconnection/reconnection logic for failed downloads.

    Refactoring the cascade_gui.cpp into separate header and source files.
    
    Automatic port forwarding is UPnP (Universal Plug and Play) and NAT-PMP (NAT Port Mapping Protocol)

    If you expand it with peer discovery, NAT traversal, prioritization, and swarm management, it could start to operate in a real-world network like a lightweight torrent client.

    For example: MiniUPnP (libminiupnpc and libnatpmp)	UPnP and NAT-PMP	C (with C++ wrappers available)	The gold standard. Widely used in torrent clients like qBittorrent and Transmission.

Mimics the style of use in P2P torrenting programs. Many of the above ideas for future work would be needed to allow users to use this outside of their local-network.

Share and attempt to extend this concept into a fully usable copy I would love to see it. 

I do not have the skill to properly scale this up into something people would enjoy.

If updated to the extent of many popular torrenting programs, who knows this could be an alternative style and base to build off of.
