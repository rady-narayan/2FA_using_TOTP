import socket
import ssl
import srp
import os

from libtotp import *

HOST, PORT = 'localhost', 8080


def interrupt(sock):
    if sock:
        print("Keyboard interrupt, exit")
        sock.close()
    exit(0)


def main():
    # client socket creation
    sock = socket.socket(socket.AF_INET)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # TLS 1.0 is old, don't use it
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # This is needed cause server uses self-signed cert
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    conn = context.wrap_socket(sock, server_hostname=HOST)

    try:
        conn.connect((HOST, PORT))
        print("TLS connection established.")

        while True:
            print("\nWelcome User! Enter 1 for Register, 2 for Login\n")
            input1 = input()
            if input1.isdigit() and (int(input1) == 1 or int(input1) == 2):
                input1 = int(input1)
                pass
            else:
                print("Invalid selection")
                continue

            if input1 == 1:
                print("Registering new user:\n")
                # User selected register
                print("Please enter a Username (minimum 4 char):")
                uname = input()
                if 4 <= len(uname) < 50:
                    pass
                else:
                    print("Username length does not match the requirement")
                    continue
                print("Please enter a password (minimum 4 char):")
                password = input()
                if 4 <= len(password) < 50:
                    pass
                else:
                    print("Password length does not match the requirement")
                    continue

                # create salt and verifier key and send it to server to be stored
                salt, vkey = srp.create_salted_verification_key(uname, password)
                send = "REGISTER:" + uname + ":" + salt.hex() + ":" + vkey.hex()
                conn.send(send.encode())

                # receiving registration details : success/failure, secret
                data = conn.recv(4096)
                data = str(data.decode())
                if data.startswith('REGISTER'):
                    # Check for success
                    (intent, result, secret) = data.split(':')
                    if result == 'SUCCESS':
                        print("Registration Complete, Thank you!")
                        # 2FA registration
                        print("\n\nScan this QR Code in Google Authenticator:\n")

                        # display QR code
                        qr_string = 'otpauth://totp/' + uname + '@umassd.edu?secret=' + secret + '&issuer=2FA_Project'
                        os.system("qr '" + qr_string + "'")
                        print("Select option 2 for login")
                    else:
                        print("User already exists")

            elif input1 == 2:
                # User selected Login
                print("\nLogin for existing users")
                print("\nPlease enter your Username:")
                uname = input()
                if 4 <= len(uname) < 50:
                    pass
                else:
                    print("Username invalid")
                    continue
                print("Please enter your password :")
                password = input()
                if 4 <= len(password) < 50:
                    pass
                else:
                    print("Password invalid")
                    continue

                # ~~~ Begin Authentication ~~~
                usr = srp.User(uname, password)
                uname, A = usr.start_authentication()

                '''
                   The authentication process can fail at each step from this
                   point on. To comply with the SRP protocol, the authentication
                   process should be aborted on the first failure.
                '''
                # Sending username and A to server
                send = "LOGIN:" + uname + ":" + A.hex()
                conn.send(send.encode())

                # Receive (s, B) or error, in case user does not exist
                data = conn.recv(4096)
                data = str(data.decode())
                if data.startswith('Error'):
                    print("Authentication Failed, wrong username or password")
                    continue

                if data.startswith('Authentication'):
                    # Receiving s, B
                    (intent, s, B) = data.split(':')
                    s = bytes.fromhex(s)
                    B = bytes.fromhex(B)

                    # Process the challenge returned by Verifier.get_challenge()
                    # on success this method returns bytes_M
                    M = usr.process_challenge(s, B)

                    if M is None:
                        print("Authentication failed")
                        continue

                    # Sending M to server
                    send = "Verify:" + M.hex()
                    conn.send(send.encode())

                    data = conn.recv(4096)
                    # receiving HAMK data
                    data = str(data.decode())

                    if data.startswith('Verify'):
                        (intent, status, HAMK) = data.split(':')
                        if status != "PASS":
                            print("Authentication Failed, wrong username or password")
                            continue

                        HAMK = bytes.fromhex(HAMK)
                        usr.verify_session(HAMK)

                        # user authentication successful
                        assert usr.authenticated()
                        print("User authenticated")

                    #  ~~~ Begin 2 Factor Authentication ~~~
                    # Verify TOTP
                    print("Please enter 6 digit TOTP token from Google authenticator: ")
                    token = input()
                    send = "totp:" + token
                    conn.send(send.encode())
                    # receive totp success/failure
                    data = conn.recv(4096)
                    data = str(data.decode())
                    if data.startswith('TOTP'):
                        (intent, msg) = data.split(':')
                        if msg == 'Failed':
                            print("Entered TOTP did not match, please try again!")
                            continue
                        print("Token verified successfully")
                        print("Login successful")

            else:
                print("Error! Invalid entry, try again!")
    except KeyboardInterrupt:
        interrupt(sock)

    # except ssl.SSLCertVerificationError:
    finally:
        print("Closing connection")
        conn.close()


if __name__ == '__main__':
    main()
