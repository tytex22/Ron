import ssl
import socket
import time
from authorization import UserAuth
from admin import AdminApp



class SecureClient:
    def __init__(self):
        self.host = 'localhost'
        self.port = 8888

        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations('certs/server.crt')
        self.context.load_cert_chain(certfile='certs/client.crt', keyfile='certs/client.key')
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED

        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=5)
            self.ssock = self.context.wrap_socket(self.sock, server_hostname=self.host)
            self.connected = True
        except socket.timeout:
            print("ERROR|Connection timed out")
            self.connected = False
        except ConnectionRefusedError:
            print("ERROR|Server is not running")
            self.connected = False
        except ssl.SSLError as e:
            print(f"ERROR|SSL error: {e}")
            self.connected = False
        except socket.gaierror:
            print("ERROR|Cannot resolve server address")
            self.connected = False
        except ConnectionResetError:
            print("WARNING|Connection closed by server (possible rate limit)")
            self.connected = False
        except Exception as e:
            print(f"ERROR|Unexpected error: {e}")
            self.connected = False

    def send(self, message: str):
        if not self.connected:
            print("[SEND ERROR] Not connected to server")
            return f"ERROR|Not connected to server"
        try:
            self.ssock.send(message.encode())
            response = self.ssock.recv(1024).decode()
            if not response:
                self.reconnect()
            return response
        except (socket.error, ssl.SSLError):
            print("[DISCONNECTED] Trying to reconnect...")
            if not self.reconnect():
                print("[ERROR] Reconnect failed, giving up")
        except Exception as e:
            return f"ERROR|{e}"

    def reconnect(self, retries=3, delay=5):
        for attempt in range(retries):
            try:
                self.sock = socket.create_connection((self.host, self.port), timeout=5)
                self.ssock = self.context.wrap_socket(self.sock, server_hostname=self.host)
                self.connected = True
                print("[RECONNECTED] Client successfully reconnected")
                return True
            except Exception as e:
                print(f"[RECONNECT ATTEMPT {attempt + 1}] Failed: {e}")
                time.sleep(delay)
        self.connected = False
        print("[FAILED] Could not reconnect to server")
        return False

    def close_app(self, the_root):
        if self.connected:
            try:
                self.ssock.close()
            except (OSError, ssl.SSLError) as e:
                print(f"[WARNING] Failed to close connection: {e}")
        the_root.destroy()



def open_admin_app(client):
    print(f"open admin app for {client}")
    AdminApp(client)

def open_student_app(client):
    print(f"open student app for {client}")
    pass

if __name__ == '__main__':
    client = SecureClient()  # Global persistent connection
    if client.connected:
        auth = UserAuth(client)
        if auth.result == "admin":
            AdminApp(client)
        elif auth.result == "student":
            open_student_app(client)
        else:
            print("Login failed or unexpected role.")
    else:
        print("ERROR | Failed to connect to server.")

















