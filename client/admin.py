import customtkinter as ctk


class AdminApp:
    def __init__(self, client):

        self.client = client
        self.root2 = ctk.CTkToplevel()
        self.root2.geometry("800x600")
        self.root2.title("App - Admin")
        self.root2.protocol("WM_DELETE_WINDOW", self.on_close)

        self.frame_home = ctk.CTkFrame(self.root2)
        self.frame_home.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.frame_home, text="You entered as Admin", font=("Arial", 20)).pack(pady=(0, 10))

        self.root2.mainloop()

    def on_close(self):
        self.root2.quit()
        self.client.close_app(self.root2)
