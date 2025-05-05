import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import git
import os
import requests
import webbrowser
import http.server
import socketserver
import urllib.parse
import threading
import base64
import re
import logging
from tkinter import filedialog, messagebox
import socket
import uuid
import math

# Set up logging to file and console
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("github_tool.log"),
        logging.StreamHandler()
    ]
)

# Define OAuthHandler globally to avoid PyInstaller issues
class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        logging.debug(f"Received OAuth callback: {self.path}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        code = params.get("code", [None])[0]
        self.server.code = code
        self.wfile.write(b"<h1>Authentication successful! You can close this window.</h1>")

class GitHubApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GitHub Push/Pull Tool")
        self.style = ttk.Style(theme="litera")
        self.access_token = None
        self.username = None
        self.client_id = "Ov23li5IFR3ANFKQhLph"  # Replace with your GitHub OAuth App Client ID
        self.client_secret = "7de4e928d821642357021d438dc2f37e0093527d"  # Replace with your GitHub OAuth App Client Secret
        self.redirect_uri = "http://localhost:8080"
        self.upload_mode = tk.StringVar(value="file")  # Track file or folder mode
        self.chunk_size = 10 * 1024 * 1024  # 10 MB chunks
        self.max_file_size = 50 * 1024 * 1024  # 50 MB threshold for chunking
        self.style.configure("TButton", font=("Segoe UI", 12))
        self.style.configure("primary.TButton", background="#007bff", foreground="white")
        self.style.configure("danger.TButton", background="#dc3545", foreground="white")
        self.style.configure("success.TProgressbar", troughcolor="#e9ecef", background="#28a745")
        self.setup_login_screen()

    def setup_login_screen(self):
        """Set up the GitHub OAuth login screen with a gradient background."""
        self.clear_window()
        canvas = tk.Canvas(self.root, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.create_gradient(canvas, "#ffffff", "#e3f2fd")

        main_frame = ttk.Frame(canvas, padding=20, bootstyle="light", relief="raised", borderwidth=2)
        main_frame.place(relx=0.5, rely=0.5, anchor="center", width=400)

        ttk.Label(main_frame, text="🔒 GitHub Push/Pull Tool", font=("Segoe UI", 18, "bold"), bootstyle="primary").pack(pady=10)
        ttk.Label(main_frame, text="Sign in to manage your repositories with ease!", font=("Segoe UI", 12)).pack(pady=5)

        login_button = ttk.Button(main_frame, text="Sign in with GitHub ", style="primary.TButton", command=self.start_oauth)
        login_button.pack(pady=20, fill="x")
        ToolTip(login_button, text="Authenticate via GitHub's secure login page")

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 10), bootstyle="secondary", anchor="w")
        status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def create_gradient(self, canvas, color1, color2):
        """Create a gradient background on the canvas."""
        canvas.delete("all")
        width = self.root.winfo_screenwidth()
        height = self.root.winfo_screenheight()
        canvas.config(width=width, height=height)
        limit = height
        r1, g1, b1 = self.root.winfo_rgb(color1)
        r2, g2, b2 = self.root.winfo_rgb(color2)
        r_ratio = (r2 - r1) / limit
        g_ratio = (g2 - g1) / limit
        b_ratio = (b2 - b1) / limit

        for i in range(limit):
            nr = int(r1 + (r_ratio * i))
            ng = int(g1 + (g_ratio * i))
            nb = int(b1 + (b_ratio * i))
            color = f"#{nr//256:02x}{ng//256:02x}{nb//256:02x}"
            canvas.create_line(0, i, width, i, fill=color)

    def start_oauth(self):
        """Initiate GitHub OAuth flow using REST API."""
        logging.debug("Starting OAuth flow")
        self.status_var.set("Opening GitHub login...")
        auth_url = (
            f"https://github.com/login/oauth/authorize?"
            f"client_id={self.client_id}&redirect_uri={self.redirect_uri}&scope=repo user"
        )
        webbrowser.open(auth_url)
        self.run_oauth_server()

    def run_oauth_server(self):
        """Run a local server to capture OAuth callback with retry logic."""
        logging.debug("Attempting to start OAuth server")
        port = 8080
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                server = socketserver.TCPServer(("localhost", port), OAuthHandler)
                server.timeout = 30
                logging.debug(f"OAuth server started on port {port}")

                threading.Thread(target=server.handle_request, daemon=True).start()

                def check_code():
                    if hasattr(server, "code") and server.code:
                        logging.debug(f"Received OAuth code: {server.code}")
                        self.exchange_code_for_token(server.code)
                        try:
                            server.server_close()
                            logging.debug("OAuth server closed")
                        except Exception as e:
                            logging.error(f"Error closing server: {e}")
                    else:
                        self.root.after(100, check_code)

                self.root.after(100, check_code)
                break

            except socket.error as e:
                retry_count += 1
                logging.error(f"Failed to start server on port {port} (attempt {retry_count}/{max_retries}): {e}")
                if retry_count < max_retries:
                    port += 1
                    self.redirect_uri = f"http://localhost:{port}"
                    logging.debug(f"Retrying with port {port}")
                else:
                    logging.error("Max retries reached. Failed to start OAuth server.")
                    messagebox.showerror("Error", f"Failed to start OAuth server after {max_retries} attempts: {e}", icon="error")
                    self.status_var.set("Authentication failed.")
                    break
            except Exception as e:
                logging.error(f"Unexpected error starting OAuth server: {e}")
                messagebox.showerror("Error", f"Failed to start OAuth server: {e}", icon="error")
                self.status_var.set("Authentication failed.")
                break

    def exchange_code_for_token(self, code):
        """Exchange OAuth code for access token and fetch username."""
        logging.debug("Exchanging code for token")
        try:
            headers = {"Accept": "application/json"}
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            }
            response = requests.post(
                "https://github.com/login/oauth/access_token",
                headers=headers,
                data=data,
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            self.access_token = data.get("access_token")
            if self.access_token:
                user_response = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {self.access_token}", "Accept": "application/vnd.github+json"},
                    timeout=10,
                )
                user_response.raise_for_status()
                self.username = user_response.json().get("login", "User")
                logging.debug(f"Token exchange successful, username: {self.username}")
                self.status_var.set("Login successful!")
                self.root.after(0, self.setup_main_menu)
            else:
                logging.error("No access token in response")
                messagebox.showerror("Error", "Failed to authenticate: No access token received.", icon="error")
                self.status_var.set("Authentication failed.")
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error during token exchange: {e}")
            messagebox.showerror("Error", f"Authentication failed: {e}", icon="error")
            self.status_var.set("Authentication failed.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error during token exchange: {e}")
            messagebox.showerror("Error", f"Authentication failed: Network error - {e}", icon="error")
            self.status_var.set("Authentication failed.")
        except Exception as e:
            logging.error(f"Unexpected error during token exchange: {e}")
            messagebox.showerror("Error", f"Authentication failed: Unexpected error - {e}", icon="error")
            self.status_var.set("Authentication failed.")

    def setup_main_menu(self):
        """Set up the main menu with a personalized welcome."""
        logging.debug("Setting up main menu")
        self.clear_window()
        canvas = tk.Canvas(self.root, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.create_gradient(canvas, "#ffffff", "#e3f2fd")

        main_frame = ttk.Frame(canvas, padding=20, bootstyle="light", relief="raised", borderwidth=2)
        main_frame.place(relx=0.5, rely=0.5, anchor="center", width=400)

        ttk.Label(main_frame, text=f"Welcome, {self.username}! 📂", font=("Segoe UI", 18, "bold"), bootstyle="primary").pack(pady=10)
        ttk.Label(main_frame, text="Manage your GitHub repositories with style.", font=("Segoe UI", 12)).pack(pady=5)

        ttk.Button(main_frame, text="Push File/Folder to Repository ", style="primary.TButton", command=self.setup_push_screen).pack(pady=10, fill="x")
        ttk.Button(main_frame, text="Pull Repository ", style="outline.TButton", command=self.setup_pull_screen).pack(pady=10, fill="x")
        ttk.Button(main_frame, text="Logout ", style="danger.TButton", command=self.setup_login_screen).pack(pady=10, fill="x")

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 10), bootstyle="secondary", anchor="w")
        status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def setup_push_screen(self):
        """Set up the push operation screen with file and folder support."""
        logging.debug("Setting up push screen")
        self.clear_window()
        canvas = tk.Canvas(self.root, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.create_gradient(canvas, "#ffffff", "#e3f2fd")

        main_frame = ttk.Frame(canvas, padding=20, bootstyle="light", relief="raised", borderwidth=2)
        main_frame.place(relx=0.5, rely=0.5, anchor="center", width=500)

        ttk.Label(main_frame, text="⬆️ Push to GitHub", font=("Segoe UI", 16, "bold"), bootstyle="primary").pack(pady=10)

        # Upload mode selection
        mode_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        mode_frame.pack(fill="x", pady=5)
        ttk.Label(mode_frame, text="Upload Mode:", font=("Segoe UI", 12)).pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="File", value="file", variable=self.upload_mode).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Folder", value="folder", variable=self.upload_mode).pack(side="left", padx=5)

        # File/Folder selection
        file_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        file_frame.pack(fill="x", pady=5)
        ttk.Label(file_frame, text="File/Folder to Upload:", font=("Segoe UI", 12)).pack(anchor="w")
        self.file_dir_entry = ttk.Entry(file_frame, font=("Segoe UI", 10))
        self.file_dir_entry.insert(0, "Select file or folder to upload...")
        self.file_dir_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.file_dir_entry, "Select file or folder to upload..."))
        self.file_dir_entry.pack(fill="x", pady=5)
        button_subframe = ttk.Frame(file_frame)
        button_subframe.pack(fill="x")
        ttk.Button(button_subframe, text="Browse File 📄", style="secondary.TButton", command=self.browse_file).pack(side="left", padx=5, pady=2)
        ttk.Button(button_subframe, text="Browse Folder 📂", style="secondary.TButton", command=self.browse_folder).pack(side="left", padx=5, pady=2)
        ToolTip(self.file_dir_entry, text="Select a file or folder to upload to GitHub")

        # Repository URL
        url_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        url_frame.pack(fill="x", pady=5)
        ttk.Label(url_frame, text="Repository URL:", font=("Segoe UI", 12)).pack(anchor="w")
        self.repo_url_entry = ttk.Entry(url_frame, font=("Segoe UI", 10))
        self.repo_url_entry.insert(0, "https://github.com/...")
        self.repo_url_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.repo_url_entry, "https://github.com/..."))
        self.repo_url_entry.pack(fill="x", pady=5)
        ToolTip(self.repo_url_entry, text="Enter the GitHub repository URL (e.g., https://github.com/user/repo.git)")

        # Repository base path
        path_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        path_frame.pack(fill="x", pady=5)
        ttk.Label(path_frame, text="Repository Base Path:", font=("Segoe UI", 12)).pack(anchor="w")
        self.repo_file_path_entry = ttk.Entry(path_frame, font=("Segoe UI", 10))
        self.repo_file_path_entry.insert(0, "Enter base path in repository...")
        self.repo_file_path_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.repo_file_path_entry, "Enter base path in repository..."))
        self.repo_file_path_entry.pack(fill="x", pady=5)
        ToolTip(self.repo_file_path_entry, text="Specify the base path for the file or folder (e.g., src/)")

        # Commit message
        commit_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        commit_frame.pack(fill="x", pady=5)
        ttk.Label(commit_frame, text="Commit Message:", font=("Segoe UI", 12)).pack(anchor="w")
        self.commit_message_entry = ttk.Entry(commit_frame, font=("Segoe UI", 10))
        self.commit_message_entry.insert(0, "Enter commit message...")
        self.commit_message_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.commit_message_entry, "Enter commit message..."))
        self.commit_message_entry.pack(fill="x", pady=5)
        ToolTip(self.commit_message_entry, text="Provide a descriptive message for your commit")

        # Progress label
        self.progress_var = tk.StringVar(value="")
        self.progress_label = ttk.Label(main_frame, textvariable=self.progress_var, font=("Segoe UI", 10))
        self.progress_label.pack(pady=5)

        self.progress_bar = ttk.Progressbar(main_frame, mode="indeterminate", bootstyle="success")
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Push ", style="primary.TButton", command=self.confirm_push).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear 🗑", style="warning.TButton", command=self.clear_push_fields).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back ", style="outline.TButton", command=self.setup_main_menu).pack(side="right", padx=5)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 10), bootstyle="secondary", anchor="w")
        status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def setup_pull_screen(self):
        """Set up the pull operation screen with a modern layout."""
        logging.debug("Setting up pull screen")
        self.clear_window()
        canvas = tk.Canvas(self.root, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.create_gradient(canvas, "#ffffff", "#e3f2fd")

        main_frame = ttk.Frame(canvas, padding=20, bootstyle="light", relief="raised", borderwidth=2)
        main_frame.place(relx=0.5, rely=0.5, anchor="center", width=500)

        ttk.Label(main_frame, text="⬇️ Pull from GitHub", font=("Segoe UI", 16, "bold"), bootstyle="primary").pack(pady=10)

        url_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        url_frame.pack(fill="x", pady=5)
        ttk.Label(url_frame, text="Repository URL:", font=("Segoe UI", 12)).pack(anchor="w")
        self.pull_repo_url_entry = ttk.Entry(url_frame, font=("Segoe UI", 10))
        self.pull_repo_url_entry.insert(0, "https://github.com/...")
        self.pull_repo_url_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.pull_repo_url_entry, "https://github.com/..."))
        self.pull_repo_url_entry.pack(fill="x", pady=5)
        ToolTip(self.pull_repo_url_entry, text="Enter the GitHub repository URL to clone")

        dir_frame = ttk.Frame(main_frame, padding=10, bootstyle="light")
        dir_frame.pack(fill="x", pady=5)
        ttk.Label(dir_frame, text="Directory to Clone To:", font=("Segoe UI", 12)).pack(anchor="w")
        self.clone_dir_entry = ttk.Entry(dir_frame, font=("Segoe UI", 10))
        self.clone_dir_entry.insert(0, "Select clone directory...")
        self.clone_dir_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.clone_dir_entry, "Select clone directory..."))
        self.clone_dir_entry.pack(fill="x", pady=5)
        ttk.Button(dir_frame, text="Browse 📂", style="secondary.TButton", command=self.browse_clone_dir).pack(fill="x", pady=2)
        ToolTip(self.clone_dir_entry, text="Select the directory to clone the repository")

        self.progress_bar = ttk.Progressbar(main_frame, mode="indeterminate", bootstyle="success")
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Pull ", style="primary.TButton", command=self.confirm_pull).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear 🗑", style="warning.TButton", command=self.clear_pull_fields).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back ", style="outline.TButton", command=self.setup_main_menu).pack(side="right", padx=5)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 10), bootstyle="secondary", anchor="w")
        status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def clear_placeholder(self, entry, placeholder):
        """Clear placeholder text when entry is focused."""
        if entry.get() == placeholder:
            entry.delete(0, tk.END)

    def browse_file(self):
        """Open file explorer to select file to upload."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_dir_entry.delete(0, tk.END)
            self.file_dir_entry.insert(0, file_path)
            self.status_var.set("File selected.")
            self.upload_mode.set("file")
            base_path = os.path.basename(file_path)
            self.repo_file_path_entry.delete(0, tk.END)
            self.repo_file_path_entry.insert(0, base_path)

    def browse_folder(self):
        """Open file explorer to select folder to upload."""
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.file_dir_entry.delete(0, tk.END)
            self.file_dir_entry.insert(0, folder_path)
            self.status_var.set("Folder selected.")
            self.upload_mode.set("folder")
            base_path = os.path.basename(folder_path)
            self.repo_file_path_entry.delete(0, tk.END)
            self.repo_file_path_entry.insert(0, base_path)

    def browse_clone_dir(self):
        """Open file explorer to select directory to clone repository."""
        directory = filedialog.askdirectory()
        if directory:
            self.clone_dir_entry.delete(0, tk.END)
            self.clone_dir_entry.insert(0, directory)
            self.status_var.set("Clone directory selected.")

    def validate_url(self, url):
        """Validate if the URL is a valid GitHub repository URL."""
        pattern = r'^https://github\.com/[\w-]+/[\w-]+\.git$'
        return bool(re.match(pattern, url))

    def extract_repo_info(self, url):
        """Extract owner and repo name from GitHub URL."""
        match = re.match(r'https://github\.com/([\w-]+)/([\w-]+)\.git$', url)
        if match:
            return match.groups()
        return None, None

    def clear_push_fields(self):
        """Clear all input fields in the push screen."""
        self.file_dir_entry.delete(0, tk.END)
        self.file_dir_entry.insert(0, "Select file or folder to upload...")
        self.repo_url_entry.delete(0, tk.END)
        self.repo_url_entry.insert(0, "https://github.com/...")
        self.repo_file_path_entry.delete(0, tk.END)
        self.repo_file_path_entry.insert(0, "Enter base path in repository...")
        self.commit_message_entry.delete(0, tk.END)
        self.commit_message_entry.insert(0, "Enter commit message...")
        self.upload_mode.set("file")
        self.progress_var.set("")
        self.status_var.set("Fields cleared.")

    def clear_pull_fields(self):
        """Clear all input fields in the pull screen."""
        self.pull_repo_url_entry.delete(0, tk.END)
        self.pull_repo_url_entry.insert(0, "https://github.com/...")
        self.clone_dir_entry.delete(0, tk.END)
        self.clone_dir_entry.insert(0, "Select clone directory...")
        self.status_var.set("Fields cleared.")

    def confirm_push(self):
        """Confirm and execute push operation."""
        if messagebox.askyesno("Confirm Push", "Are you sure you want to upload the selected file/folder to the repository?"):
            threading.Thread(target=self.push_content, daemon=True).start()

    def confirm_pull(self):
        """Confirm and execute pull operation."""
        if messagebox.askyesno("Confirm Pull", "Are you sure you want to clone the repository to the selected directory?"):
            self.clone_repo()

    def push_content(self):
        """Handle file or folder upload based on mode."""
        path = self.file_dir_entry.get().strip()
        repo_url = self.repo_url_entry.get().strip()
        repo_base_path = self.repo_file_path_entry.get().strip()
        commit_message = self.commit_message_entry.get().strip()

        if any(entry in ["Select file or folder to upload...", "https://github.com/...", "Enter base path in repository...", "Enter commit message...", ""] for entry in [path, repo_url, repo_base_path, commit_message]):
            self.root.after(0, lambda: messagebox.showerror("Error", "All fields are required.", icon="error"))
            self.root.after(0, lambda: self.status_var.set("Error: Missing fields."))
            return
        if not self.validate_url(repo_url):
            self.root.after(0, lambda: messagebox.showerror("Error", "Invalid GitHub repository URL.", icon="error"))
            self.root.after(0, lambda: self.status_var.set("Error: Invalid URL."))
            return

        self.root.after(0, lambda: self.status_var.set("Preparing upload..."))
        self.root.after(0, lambda: self.progress_bar.pack(fill="x", pady=5))
        self.root.after(0, lambda: self.progress_bar.start())

        try:
            owner, repo = self.extract_repo_info(repo_url)
            if not owner or not repo:
                raise ValueError("Could not parse repository URL.")

            if self.upload_mode.get() == "file":
                if not os.path.isfile(path):
                    raise ValueError("Selected file does not exist.")
                self.push_file(path, repo_base_path, commit_message, owner, repo)
            else:
                if not os.path.isdir(path):
                    raise ValueError("Selected folder does not exist.")
                self.push_folder(path, repo_base_path, commit_message, owner, repo)

            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.root.after(0, lambda: messagebox.showinfo("Success", "Upload completed successfully!", icon="info"))
            self.root.after(0, lambda: self.status_var.set("Upload successful!"))
            self.root.after(0, lambda: self.progress_var.set(""))
        except Exception as e:
            logging.error(f"Error during upload: {e}")
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_bar.pack_forget())
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to upload: {e}", icon="error"))
            self.root.after(0, lambda: self.status_var.set("Upload failed."))
            self.root.after(0, lambda: self.progress_var.set(""))

    def push_file(self, file_path, repo_file_path, commit_message, owner, repo):
        """Upload a single file, chunking if necessary."""
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            self.push_large_file(file_path, repo_file_path, commit_message, owner, repo)
        else:
            self.root.after(0, lambda: self.progress_var.set(f"Uploading {os.path.basename(file_path)}"))
            with open(file_path, "rb") as f:
                content = base64.b64encode(f.read()).decode("utf-8")

            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{repo_file_path}"
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            data = {
                "message": commit_message,
                "content": content,
                "branch": "main",
            }

            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data["sha"] = response.json().get("sha")
                logging.debug(f"File exists, SHA: {data['sha']}")

            response = requests.put(url, headers=headers, json=data, timeout=10)
            response.raise_for_status()
            logging.debug(f"File {file_path} uploaded successfully")

    def push_large_file(self, file_path, repo_file_path, commit_message, owner, repo):
        """Upload a large file in chunks using a temporary branch."""
        branch_name = f"upload-{uuid.uuid4().hex}"
        self.root.after(0, lambda: self.progress_var.set(f"Preparing large file upload for {os.path.basename(file_path)}"))

        # Create temporary branch
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        main_sha = requests.get(f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/main", headers=headers, timeout=10).json()["object"]["sha"]
        branch_data = {"ref": f"refs/heads/{branch_name}", "sha": main_sha}
        requests.post(f"https://api.github.com/repos/{owner}/{repo}/git/refs", headers=headers, json=branch_data, timeout=10).raise_for_status()
        logging.debug(f"Created temporary branch: {branch_name}")

        try:
            # Split file into chunks
            file_size = os.path.getsize(file_path)
            num_chunks = math.ceil(file_size / self.chunk_size)
            with open(file_path, "rb") as f:
                for i in range(num_chunks):
                    self.root.after(0, lambda: self.progress_var.set(f"Uploading chunk {i+1}/{num_chunks} for {os.path.basename(file_path)}"))
                    chunk = f.read(self.chunk_size)
                    chunk_path = f"{repo_file_path}.part{i}"
                    content = base64.b64encode(chunk).decode("utf-8")
                    data = {
                        "message": f"{commit_message} (chunk {i+1}/{num_chunks})",
                        "content": content,
                        "branch": branch_name,
                    }
                    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{chunk_path}"
                    response = requests.put(url, headers=headers, json=data, timeout=10)
                    response.raise_for_status()
                    logging.debug(f"Uploaded chunk {i+1}/{num_chunks}")

            # Create pull request to merge chunks
            pr_data = {
                "title": f"Upload {os.path.basename(file_path)}",
                "head": branch_name,
                "base": "main",
                "body": f"Upload large file {os.path.basename(file_path)} in chunks.",
            }
            response = requests.post(f"https://api.github.com/repos/{owner}/{repo}/pulls", headers=headers, json=pr_data, timeout=10)
            response.raise_for_status()
            pr_number = response.json()["number"]
            logging.debug(f"Created pull request #{pr_number}")

            # Merge pull request
            merge_data = {"commit_message": commit_message}
            response = requests.put(f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/merge", headers=headers, json=merge_data, timeout=10)
            response.raise_for_status()
            logging.debug(f"Merged pull request #{pr_number}")

            # Clean up chunk files
            for i in range(num_chunks):
                chunk_path = f"{repo_file_path}.part{i}"
                url = f"https://api.github.com/repos/{owner}/{repo}/contents/{chunk_path}"
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    sha = response.json()["sha"]
                    delete_data = {
                        "message": f"Clean up chunk {i}",
                        "sha": sha,
                        "branch": "main",
                    }
                    requests.delete(url, headers=headers, json=delete_data, timeout=10).raise_for_status()
                    logging.debug(f"Deleted chunk file: {chunk_path}")

        except Exception as e:
            # Delete temporary branch on failure
            requests.delete(f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch_name}", headers=headers, timeout=10)
            logging.error(f"Error uploading large file: {e}")
            raise

    def push_folder(self, folder_path, repo_base_path, commit_message, owner, repo):
        """Upload all files in a folder recursively."""
        files_to_upload = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, folder_path)
                repo_file_path = os.path.join(repo_base_path, rel_path).replace("\\", "/")
                files_to_upload.append((file_path, repo_file_path))

        total_files = len(files_to_upload)
        for i, (file_path, repo_file_path) in enumerate(files_to_upload, 1):
            self.root.after(0, lambda: self.progress_var.set(f"Uploading file {i}/{total_files}: {os.path.basename(file_path)}"))
            self.push_file(file_path, repo_file_path, commit_message, owner, repo)
            logging.debug(f"Uploaded file {i}/{total_files}: {file_path}")

    def clone_repo(self):
        """Clone repository from GitHub to local directory."""
        logging.debug("Starting repository clone")
        repo_url = self.pull_repo_url_entry.get().strip()
        clone_dir = self.clone_dir_entry.get().strip()

        if any(entry in ["https://github.com/...", "Select clone directory...", ""] for entry in [repo_url, clone_dir]):
            messagebox.showerror("Error", "All fields are required.", icon="error")
            self.status_var.set("Error: Missing fields.")
            return
        if not self.validate_url(repo_url):
            messagebox.showerror("Error", "Invalid GitHub repository URL.", icon="error")
            self.status_var.set("Error: Invalid URL.")
            return

        self.status_var.set("Cloning repository...")
        self.progress_bar.pack(fill="x", pady=5)
        self.progress_bar.start()
        try:
            git.Repo.clone_from(repo_url, clone_dir)
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            messagebox.showinfo("Success", f"Repository cloned to {clone_dir}", icon="info")
            self.status_var.set("Clone successful!")
        except Exception as e:
            logging.error(f"Error cloning repository: {e}")
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            messagebox.showerror("Error", f"Failed to clone repository: {e}", icon="error")
            self.status_var.set("Clone failed.")

    def clear_window(self):
        """Clear all widgets from the window."""
        for widget in self.root.winfo_children():
            widget.destroy()

def main():
    root = ttk.Window()
    app = GitHubApp(root)
    root.geometry("800x600")
    root.mainloop()

if __name__ == "__main__":
    main()