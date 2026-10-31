Columba – Python Terminal Messenger
A lightweight command-line messaging application written in Python. Columba allows users to communicate through a terminal interface using a client-server architecture.

About the Project
Columba is a terminal-based messenger that provides text communication between multiple users. The application uses a server to manage connections and supports both public broadcast messaging and private communication.

The project was created to improve Python programming skills, explore network communication and gain practical experience with databases, client-server architecture and cryptography.

Features:
Terminal-based user interface
Real-time text messaging
Public broadcast communication
Private messaging
Peer-to-peer (P2P) connections
User management through a database
Password management

Technologies:
Python – main programming language
SQLite / Database – user data storage (if applicable)
Virtual Environment (venv) – dependency isolation

Clone the repository:

bash
git clone https://github.com/AdamBalicki/Columba.git
cd Columba
Usage
1. Create and manage the database
Before starting the messenger, you need to initialize the database and create user accounts.

Navigate to the server directory:


bash
cd columba/server
source venv/bin/activate
python3 adminDB.py
The administration script allows you to:

Create a new database
Add new users
Display existing users
Delete users
Change user passwords
Note: Users must be registered in the database before they can connect to the messenger.

2. Start the server
Navigate to the server directory and activate the virtual environment:


bash
cd columba/server
source venv/bin/activate
python3 server.py

3. Connect a client
Open another terminal and navigate to the client directory:


bash
cd columba/client
source .venv/bin/activate
python3 client.py
Repeat this step to connect additional users.

Command List

Command	Description
/all <message>	Send a broadcast message to all connected users (default communication mode).
/users	Display a list of users.
/connect <login>	Start a P2P connection with a selected user.
/private <message>	Send a private message to a user.
/back	Return to broadcast communication.
/quit	Disconnect and exit the application.
Project Status
Work in Progress

Columba is currently under development. New features and security improvements are planned.

Planned Features (To Do)
TLS encryption for login and password transmission
End-to-end encryption (E2EE) for P2P connections
Encryption for broadcast communication
Purpose
The main goal of this project is to develop practical programming skills in Python and explore network programming, client-server architecture, database management and cryptographic security.

The project also serves as an opportunity to learn about secure communication protocols and the challenges of implementing encrypted messaging systems.
