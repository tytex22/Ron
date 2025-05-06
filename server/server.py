import socket
import threading
import hashlib
import sqlite3
import ssl
import os
import time ############################################
from collections import defaultdict######################

INACTIVITY_LIMIT = 60  # Seconds

client_requests = defaultdict(list)  # Tracks request timestamps per IP###################3
blacklist = {}  # Temporarily blocks IPs######################3
#
REQUEST_LIMIT = 20       # Max requests per minute###################
TIME_WINDOW = 60         # Time window in seconds#######################
BLACKLIST_DURATION = 300  # Time to block abusive IPs (seconds) #################

def is_blacklisted(ip): ####################
    if ip in blacklist: ########################
        if time.time() > blacklist[ip]: #############################
            del blacklist[ip]  # Unblock after duration ########################
            return False ##########################3
        return True #####################33
    return False ############################3

def is_request_allowed(ip): #####################################33
    now = time.time() ##############################33 ##################33
    timestamps = client_requests[ip] ############################3333333333
    # Keep only recent timestamps ####################################333
    client_requests[ip] = [t for t in timestamps if now - t < TIME_WINDOW] #########################33
 ###################
    if len(client_requests[ip]) >= REQUEST_LIMIT: #######################################3
        blacklist[ip] = now + BLACKLIST_DURATION #################################333
        print(f"[BLACKLISTED] {ip} for {BLACKLIST_DURATION} seconds") ############################3
        return False

    client_requests[ip].append(now) ###############################################3
    return True ###########################################



HOST = '127.0.0.1'
PORT = 8888
MAX_CONNECTIONS = 50
active_clients = {}

def handle_client(conn, addr):
    ip = addr[0] #########################################
    client_id = f"{ip}:{addr[1]}"
 #######################################################################3
    if is_blacklisted(ip): ################################################################################3
        print(f"[BLOCKED] {ip} is currently blacklisted") ###########################################################3
        conn.close_app()  #############################################################################################
        return ###############################################################################################3
 #############################################################################################################3
    if not is_request_allowed(ip): ################################################################################
        print(f"[RATE LIMIT] Too many requests from {ip}") ###################################################3333
        try:
            conn.send("ERROR|Too many requests. Try again later.".encode()) ###################################################
        except Exception as e:
            print(f"[ERROR] {e}")
        conn.close_app()  ##############################################################################3
        return ######################################################################################

    print(f"[NEW CONNECTION] {addr} connected.")
    cert = conn.getpeercert()
    print(f"[CLIENT CERTIFICATE] Subject: {cert.get('subject')}") if cert else print("[CLIENT CERTIFICATE] None provided")


    active_clients[client_id] = (conn, time.time())
    print(f"[ACTIVE CLIENTS] {list(active_clients.keys())}")

    with conn:
        try:
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break

                active_clients[client_id] = (conn, time.time())

                parts = data.strip().split('|')
                if len(parts) < 1:
                    conn.send("ERROR|Invalid message format".encode())
                    continue
                command = parts[0]
                print(command)

                if command == "LOGIN": #===========================================================================================
                    try:
                        username, password = parts[1], parts[2]
                        with sqlite3.connect("db.db") as db:
                            cur = db.cursor()
                            cur.execute("SELECT * FROM auth WHERE username = ?", (username, ))
                            user = cur.fetchone()
                            if user: # user[0], user[1], user[2] and user[3] is username, hashed password, salt and isAdmin in the table
                                if hashlib.sha256(bytes.fromhex(user[2])+password.encode()).hexdigest() == user[1]:
                                    role = "admin" if user[3] == 1 else "student"
                                    conn.send(f"OK|{role}".encode())
                                else:
                                    conn.send(f"FAIL|fail".encode())
                            else:
                                print("fail")
                                conn.send(f"FAIL|fail".encode())
                    except Exception as e:
                        conn.send(f"ERROR|Server database error: {e}".encode())

                elif command == "SIGNUP": # ============================================================================================
                    try:
                        username, password = parts[1], parts[2]
                        salt = os.urandom(32)
                        hashed_p = hashlib.sha256(salt+password.encode()).hexdigest()

                        with sqlite3.connect("db.db") as db:
                            cur = db.cursor()
                            cur.execute("SELECT * FROM auth WHERE username = ?", (username, ))
                            if cur.fetchone():
                                conn.send(f"FAIL|fail".encode())
                            else:
                                cur.execute("INSERT INTO auth (username, password, salt) VALUES (?, ?, ?)", (username, hashed_p, salt.hex()))
                                db.commit()
                                conn.send(f"OK|success".encode())
                    except Exception as e:
                        conn.send(f"ERROR|Server database error: {e}".encode())

                else:
                    print("ERROR: UNKNOWN COMMAND")

        except Exception as e:
            print(f"[ERROR] Client {addr} caused an exception: {e}")
            try:
                conn.send("ERROR|Internal server error".encode())
            except (OSError, ConnectionError):
                pass

def cleanup_inactive_clients():
    while True:
        now = time.time()
        inactive = [cid for cid, (_, last_seen) in active_clients.items() if now - last_seen > INACTIVITY_LIMIT] #######################################
        for cid in inactive:
            print(f"[TIMEOUT] Disconnecting inactive client {cid}")
            conn, _ = active_clients.pop(cid, (None, None))
            ip = cid.split(":")[0]  # Extract IP part from "IP:PORT"
            client_requests.pop(ip, None)
            blacklist.pop(ip, None)
            if conn:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    conn.close()

        time.sleep(10)

def start_server():
    print("[STARTING] Server is starting...")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('certs/client.crt')  # Or use a CA that signed it

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CONNECTIONS)

    with context.wrap_socket(server, server_side=True) as ssock:
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
        threading.Thread(target=cleanup_inactive_clients, daemon=True).start()

        while True:
            conn, addr = ssock.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 2}")


if __name__ == "__main__":
    start_server()