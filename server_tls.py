import secrets
import socket
import hashlib
import ssl
import srp
import csv
import pandas as pd
import os
from Crypto.Cipher import AES
from io import StringIO
from libtotp import *


# User registration
def register(data, df):
    (intent, username, salt, vkey) = data.split(':')
    salt = bytes.fromhex(salt)
    vkey = bytes.fromhex(vkey)
    secret = ''

    print("Server received user", username)
    # check if user exists
    if username not in df.values:
        # generate new shared secret for TOTP
        secret = generate_secret()

        # insert
        new_row = {'username': username, 'salt': salt.hex(), 'vkey': vkey.hex(), 'secret': secret}
        df = df.append(new_row, ignore_index=True)

        print("Storing user data in database..")
        writeDB(df)
        res = 'success'
    else:
        print("User already exists")
        res = 'exists'
    return res, secret, df


def login(data, df):
    (intent, username, A) = data.split(':')
    A = bytes.fromhex(A)
    print("Checking if user exists")
    found = False
    for i in df.index:
        elem = df.loc[i]
        if elem['username'] == username:
            found = True
            salt = bytes.fromhex(elem['salt'])
            vkey = bytes.fromhex(elem['vkey'])
            secret = elem['secret']
            print("User found: ")

    if not found:
        print("User not found")
        return 0, 0, None, None

    svr = srp.Verifier(username, salt, vkey, A)
    s, B = svr.get_challenge()
    print("Generated B")

    if s is None or B is None:
        print("Authentication failed in login()")
        return 0, 0, None, None

    return s, B, svr, secret


def verifyM(data, svr):
    (intent, M) = data.split(':')
    M = bytes.fromhex(M)
    print("receiving M\n")
    HAMK = svr.verify_session(M)

    if HAMK is None:
        print("Authentication Failed in VerifyM")
        return None
    return HAMK


def readDB():
    if os.path.exists(path_enc):
        f = open(path_enc, 'rb')
        enc = f.read()
        f.close()

        try:
            dec = from_aes(enc)
        except UnicodeDecodeError:
            print("ERROR: Incorrect admin password")
            exit(-1)

        if not dec.startswith('username'):
            print("ERROR: Incorrect admin password")
            exit(-1)

        df = pd.read_csv(StringIO(dec))

        return df
    else:
        return None


def writeDB(df):
    if df is None:
        print("Error in writeDB()")
        return

    dec = df.to_csv(index=False)
    enc = to_aes(dec)

    f = open(path_enc, 'wb')
    f.write(enc)
    f.close


def createDB():
    if not os.path.exists(path_enc):
        d = {'username': [], 'salt': [], 'vkey': [], 'secret': []}
        df = pd.DataFrame(data=d)
        writeDB(df)


def interrupt(sock):
    if sock:
        print("Keyboard interrupt, exit")
        sock.close()
    exit(0)


def get_md5(admin_pass):
    if admin_pass is None:
        return None

    md5 = hashlib.md5(admin_pass.encode('utf-8'))
    return md5.digest().hex()


def to_aes(data):
    if data is None or type(data) is not str:
        return None

    aes = AES.new(aes_key, AES.MODE_CFB, aes_iv)
    return aes.encrypt(data)


def from_aes(data):
    if data is None or type(data) is not bytes:
        return None

    aes = AES.new(aes_key, AES.MODE_CFB, aes_iv)
    return aes.decrypt(data).decode('utf-8')


def main():
    global addr, ssock, aes_key, aes_iv, source_dir, CERT, path_enc

    # if this does not work, please hard code the path to source directory
    source_dir = os.path.dirname(os.path.realpath(__file__))
    HOST, PORT, CERT = 'localhost', 8080, source_dir + '/cert.pem'
    path_enc = source_dir + "/registered_users.enc"

    if os.path.exists(path_enc):
        print("Existing database found")
        print("If you forgot password, delete database and try again")
    else:
        print("Database not found, password entered below will be used to create DB")

    print("Enter Admin Password (minimum 4 char):")
    admin_pass = input()
    if 4 <= len(admin_pass) < 50:
        pass
    else:
        print("Password length does not match the requirement")
        return

    aes_key = get_md5(admin_pass)
    aes_iv = 'ac1ca400396586d2'
    createDB()

    sock = socket.socket()
    sock.bind((HOST, PORT))
    sock.listen(5)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT)  # 1. key, 2. cert, 3. intermediates
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
    while True:
        # reading dataframe from db
        df = readDB()

        print("waiting for incoming connections...")
        conn = None
        svr = None
        try:
            ssock, addr = sock.accept()
        except KeyboardInterrupt:
            interrupt(sock)

        print("TLS client connected: {}:{}".format(addr[0], addr[1]))
        conn = context.wrap_socket(ssock, server_side=True)
        try:
            while True:
                data = conn.recv(4096)
                if data:
                    data = str(data.decode())
                    if data.startswith('REGISTER'):
                        (res, secret, df) = register(data, df)
                        if res == 'success':
                            print("Sending registration success")
                            send = 'REGISTER:' + 'SUCCESS:' + secret
                        else:
                            # Existing user
                            send = 'REGISTER:' + 'EXISTS:NA'
                        conn.send(send.encode())
                        continue

                    elif data.startswith('LOGIN'):
                        s, B, svr, secret = login(data, df)

                        if svr is None:
                            send = "Error:" + "User does not exists"
                            conn.send(send.encode())
                            continue

                        send = "Authentication:" + s.hex() + ":" + B.hex()
                        conn.send(send.encode())

                        # receiving M after challenge is processed with (s,B)
                        data = conn.recv(4096)
                        data = str(data.decode())

                        if data.startswith('Verify'):
                            HAMK = verifyM(data, svr)

                            if HAMK is None:
                                print("Authentication Failed")
                                send = "Verify:FAIL:NA"
                                conn.send(send.encode())
                                continue

                            send = "Verify:PASS:" + HAMK.hex()
                            print("sending HAMK")
                            conn.send(send.encode())

                            assert svr.authenticated()
                            print("User authenticated")

                        # Now validate TOTP, receive token
                        data = conn.recv(4096)
                        data = str(data.decode())
                        if data.startswith('totp'):
                            (intent, client_totp) = data.split(':')
                            print("TOTP received from client: ", client_totp)
                            server_totp = generate_totp(secret)
                            print("TOTP generated by server:  ", server_totp)

                            if client_totp == server_totp:
                                print("TOTP successfully verified")
                                send = "TOTP:" + "Success"
                            else:
                                print("TOTP did not match")
                                send = "TOTP:" + "Failed"
                            conn.send(send.encode())

                    else:
                        print("Error")
                else:
                    # No more data from client,close connection.
                    print("Client closed")
                    break
        except ssl.SSLError as e:
            print(e)
        except KeyboardInterrupt:
            interrupt(sock)
        except ConnectionResetError:
            print("Client closed")
            continue
        except Exception:
            print("Unknown Error")
            continue
        finally:
            if conn:
                print("Closing connection")
                conn.close()


if __name__ == '__main__':
    main()
