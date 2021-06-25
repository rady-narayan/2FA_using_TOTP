# 2FA_using_TOTP
Two-Factor Authentication using TOTP

Features implemented:
1. Command line tool for user registration and user login
2. Client and server communicate over a TLS socket
3. Self signed cert for TLS
4. SRP protocol for password based authentication
5. 2FA registration and QR code generation
6. TOTP token generation and verification
7. Database encryption/decryption using AES

Requirements:

The code was tested on Ubuntu 20.04 with python3. To run, use:
python3 server_tls.py
python3 client_tls.py

To install dependencies run:
sudo apt install python3-crypto python-typing python3-pandas python3-qrcode python3-srp

Packages installed above provide:
For import Crypto.Cipher:			python3-crypto
For import typing:					python-typing
For import pandas:					python3-pandas
For import qrcode, 'qr'command:		python3-qrcode
For import srp:						python3-srp

For ssl package:
I think 'import ssl' is provided by default in ubuntu, it is installed by libpython3.8-minimal package.

For TOTP:
Google authenticator app installed on any phone/tab
 
How to run: (Steps which need user inputs are marked with > )

1. Run "server_tls.py" first in a terminal. Command : "python3 server_tls.py" 
2. Server prompts for admin password. This is because database is being AES encrypted. Enter a password for the first time and remember it, as it is required for running server again.
3. If password is lost, delete "registered_users.enc" and start again.
4. In another window, run "client_tls.py". Command : "python3 client_tls.py". For client to work, server should be running and admin password should be verified
5.  Client prompts to select 1 for User registration and 2 for User login. For new user, select 1
6. Enter username and password (minimum length sepcified, max set to 50 characters)
7.  A secure TLS connection is formed between client and server. SRP protocol is followed where client only sends username, verifier key and salt.
8.  Server decrypts .csv file and checks if user already exists. If the file does not exists, new file gets created.
9.  Server registers using SRP protocol where it stores verification key, salt and username for new user in an encrypted file. 
10. Once this registration is successful, server will generate a TOTP secret using a random number generator.
11. This is shared with client which displays secret as QR code.
12. Use Google Authenticator to scan this QR code

Login:
13. Once a new user is created, option 2 can be selected for login.
14. Enter user name and password of a registered user.
15. If user credential is invalid, error is displayed. (Server verifies user from the encrypted database) 
16. Once username and password is entered, authentication is done based on SRP. Client generates "A" and sends this to server along with username.
17. Server decrypts the database, retrieves user details from database (verification key, salt, secret)
18. SRP protocol is followed as below:

	  Client => Server: username, A
	  Server => Client: s, B
	  Client => Server: M
	  Server => Client: HAMK
	  See https://pythonhosted.org/srp/srp.html for more details
19.  Once all of the steps in the protocol are done, authentication process is marked complete. Client displays success message to user.
20.> Now client prompts to enter 6 digit TOTP token. This is the current token being displayed in Google Authenticator.
21.> Enter those 6 digits. Server then generates TOTP using current timestamp and secret, and matches with the 6 digits entered by user.
22.  If the tokens match, two factor authentication is successful
23.  Login successful message is displayed.
24.> Ctrl+C command can be used to stop the client and server applications.








