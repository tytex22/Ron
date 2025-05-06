import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
import re


class UserAuth:
    def __init__(self, client):
        self.client = client
        self.ssock = client.ssock
        self.result = None
        # LOGIN ====================================================================================
        self.root = ctk.CTk()
        self.root.geometry("260x440")
        self.root.title("Login application")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.frame_login = ctk.CTkFrame(self.root)
        self.frame_login.pack(fill="both", expand=True)

        self.frame_signup = ctk.CTkFrame(self.root)

        ctk.CTkLabel(self.frame_login, text="Username").pack(pady=(15, 0))
        self.username_entry_login = ctk.CTkEntry(self.frame_login)
        self.username_entry_login.pack(pady=(0, 15))

        self.username_entry_login.bind("<Return>", lambda event: self.password_entry_login.focus())

        ctk.CTkLabel(self.frame_login, text="Password").pack()
        self.password_entry_login = ctk.CTkEntry(self.frame_login, show="•")
        self.password_entry_login.pack(pady=(0, 15))

        self.password_entry_login.bind("<Return>", lambda event: self.check())

        self.login_button = ctk.CTkButton(self.frame_login, text="Login", command=self.check)
        self.login_button.pack()

        self.link = ctk.CTkLabel(self.frame_login, text="Don't have an account? Create one!")
        self.link.pack(side="bottom", pady=15)
        self.link.bind("<Button>", lambda event: self.sign_up_window())

        # SIGNUP ====================================================================================
        ctk.CTkLabel(self.frame_signup, text="Username").pack(pady=(15, 0))
        self.username_entry_signup = ctk.CTkEntry(self.frame_signup)
        self.username_entry_signup.pack(pady=(0, 15))

        ctk.CTkLabel(self.frame_signup, text="Password").pack()
        self.password_entry_signup1 = ctk.CTkEntry(self.frame_signup, show="•")
        self.password_entry_signup1.pack(pady=(0, 15))

        ctk.CTkLabel(self.frame_signup, text="Password again").pack()
        self.password_entry_signup2 = ctk.CTkEntry(self.frame_signup, show="•")
        self.password_entry_signup2.pack(pady=(0, 15))

        self.signup_button = ctk.CTkButton(self.frame_signup, text="Sign Up", command=self.registration)
        self.signup_button.pack()

        self.link = ctk.CTkLabel(self.frame_signup, text="Already have an account? Go back!")
        self.link.pack(side="bottom", pady=(0, 15))
        self.link.bind("<Button>", lambda event: self.login_window())

        self.error_label = None

        self.root.mainloop()

    def sign_up_window(self):  # ====================================================================================
        self.username_entry_login.delete(0, "end")
        self.password_entry_login.delete(0, "end")

        self.frame_login.forget()
        self.frame_signup.pack(fill="both", expand=True)

    def login_window(self):
        self.username_entry_signup.delete(0, "end")
        self.password_entry_signup1.delete(0, "end")
        self.password_entry_signup2.delete(0, "end")

        self.frame_signup.forget()
        self.frame_login.pack(fill="both", expand=True)

    def on_close(self):
        self.client.close_app(self.root)

    def check(self):  # ==============================================================================================
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        if self.error_label:
            self.error_label.destroy()

        response = self.client.send(f"LOGIN|{username}|{password}")
        if not response:
            response = self.client.send(f"LOGIN|{username}|{password}")
        print(f"auth: {response}")
        status, message = response.split("|", 1)

        if status == "ERROR":
            CTkMessagebox(message=message, title="Network error", icon="cancel")
            return
        elif status == "WARNING":
            CTkMessagebox(message=message, title="Connection warning", icon="warning")
            return
        elif status == "FAIL":
            self.error_label = ctk.CTkLabel(self.frame_login, text="Invalid username or password", text_color="red")
            self.error_label.pack(pady=10)
        elif status == "OK":
            self.root.withdraw()
            self.result = message
            self.root.quit()
        else:
            self.error_label = ctk.CTkLabel(self.frame_login, text=message, text_color="red")
            self.error_label.pack(pady=10)


    def registration(self): # =============================================================================================
        username = self.username_entry_signup.get()
        password1 = self.password_entry_signup1.get()
        password2 = self.password_entry_signup2.get()

        if self.error_label:
            self.error_label.destroy()

        if password1 != password2 or password1 == "":
            self.error_label = ctk.CTkLabel(self.frame_signup, text="Both passwords should attach", text_color="red")
            self.error_label.pack(pady=10)
        else:
            valid, message = is_password_valid(password1)
            if not valid:
                self.error_label = ctk.CTkLabel(self.frame_signup, text=message, text_color="red", wraplength=200)
                self.error_label.pack(pady=10)
            else:
                response = self.client.send(f"SIGNUP|{username}|{password1}")
                if not response:
                    response = "EMPTY|Empty response"
                status, message = response.split("|", 1)

                if status == "ERROR":
                    CTkMessagebox(message=message, title="Network error", icon="cancel")
                    return
                if status == "EMPTY":
                    CTkMessagebox(message=message, title="Network error", icon="cancel")
                    self.error_label = ctk.CTkLabel(self.frame_signup, text="wait...", text_color="red")
                    self.error_label.pack(pady=10)
                    return
                elif status == "WARNING":
                    CTkMessagebox(message=message, title="Connection warning", icon="warning")
                    return
                elif status == "FAIL":
                    self.error_label = ctk.CTkLabel(self.frame_signup, text="This username already exists", text_color="red")
                    self.error_label.pack(pady=10)
                elif status == "OK":
                    CTkMessagebox(title="Congratulations", message="Thank you for registering", icon="check")
                    self.login_window()
                else:
                    self.error_label = ctk.CTkLabel(self.frame_signup, text=message, text_color="red", wraplength=200)
                    self.error_label.pack(pady=10)

def is_password_valid(password):
    common_passwords = ["123456", "password", "123456789", "12345", "12345678", "qwerty", "abc123", "password1"]
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must include a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include an uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include a number."
    if not re.search(r"[!@#$%^&*(),.]", password): #?\":{}|<>]
        return False, "Password must include one of the following special characters: !@#$%^&*(),."
    if re.search(r"[?\":'{}|<>[]]", password):
        return False, "Password cannot include one of the following special characters: ?:\"{}|<>[]'\"'\\."
    if password in common_passwords:
        return False, "Password is common."
    return True, "Password is strong."

