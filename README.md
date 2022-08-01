# HyperDoor

HyperDoor is an attempt to create a simple, yet powerful, backdoor implementation to spy on Windows machines. It's implementation is built uppon the [VINC](https://github.com/JoaoAJMatos/VINC) project, and contains a set of feauteres imported from [MalarPY](https://github.com/JoaoAJMatos/MalarPY).

The backdoor contains multiple features aimed for spionage and information hunting, as well as exploitation. The command and control center can interact with each individual backdoor session, as well as executing commands on all the nodes simultaneously; giving the admin the ability to control a multitude of machines at once, like in a Botnet.

## Features

As of now, HyperDoor contains the following features:
 - **file sharing**: The endpoints (the backdoor & the server) can exchange files with each other.
 - **system info report:** The server has access to all of the information about the target's PC.
 - **location report:** The server has access to the target's location (2/3km accuracy radius).
 - **screenshoting:** The server can take screenshots of the target's PC.
 - **screenshare:** The server can see the target's PC screen in real time.
 - **chrome-passwords:** Show all the Chrome passwords stored on the target's PC (decrypted).
 - **wifi-passwords:** Show all the Wifi passwords to all the networks the target has already connected to.
 - **connected machines report:** List all the hosts connected to the same network as the target, and attempt to fetch their name.
 - **reverse shell:** Execute commands on the target's PC remotely.
