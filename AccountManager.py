import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import tkinter.font as tkfont
import sqlite3
import logging
import json
import os
from cryptography.fernet import Fernet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from datetime import datetime
import webbrowser
import bcrypt
from PIL import Image, ImageTk

try:
    import ttkbootstrap as ttk
    from ttkbootstrap.constants import *
    USE_TTKBOOTSTRAP = True
except ImportError:
    import tkinter.ttk as ttk
    USE_TTKBOOTSTRAP = False
    messagebox.showwarning("Aviso", "Módulo ttkbootstrap não encontrado. Usando ttk padrão.")

logging.basicConfig(filename='account_manager.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseManager:
    def __init__(self, db_file='accounts.db'):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()
       
    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_file)
            self.cursor = self.conn.cursor()
            logging.info("Conexão com o banco de dados estabelecida")
        except sqlite3.Error as e:
            logging.error(f"Erro ao conectar ao banco de dados: {e}")

    def create_tables(self):
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    more_info TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
            self.conn.commit()
            logging.info("Tabelas criadas com sucesso")
        except sqlite3.Error as e:
            logging.error(f"Erro ao criar tabelas: {e}")

    def add_account(self, email, password, more_info):
        try:
            self.cursor.execute('''
                INSERT INTO accounts (email, password, more_info)
                VALUES (?, ?, ?)
            ''', (email, password, more_info))
            self.conn.commit()
            logging.info(f"Conta adicionada: {email}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Erro ao adicionar conta: {e}")
            return False

    def get_accounts(self, page=1, per_page=50):
        try:
            offset = (page - 1) * per_page
            self.cursor.execute('''
                SELECT * FROM accounts
                LIMIT ? OFFSET ?
            ''', (per_page, offset))
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Erro ao buscar contas: {e}")
            return []

    def update_account(self, id, email, password, more_info):
        try:
            self.cursor.execute('''
                UPDATE accounts
                SET email = ?, password = ?, more_info = ?
                WHERE id = ?
            ''', (email, password, more_info, id))
            self.conn.commit()
            logging.info(f"Conta atualizada: {email}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Erro ao atualizar conta: {e}")
            return False

    def delete_account(self, id):
        try:
            self.cursor.execute('DELETE FROM accounts WHERE id = ?', (id,))
            self.conn.commit()
            logging.info(f"Conta deletada: ID {id}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Erro ao deletar conta: {e}")
            return False

    def search_accounts(self, query):
        try:
            self.cursor.execute('''
                SELECT * FROM accounts
                WHERE email LIKE ? OR more_info LIKE ?
            ''', (f'%{query}%', f'%{query}%'))
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Erro ao pesquisar contas: {e}")
            return []

    def get_total_accounts(self):
        try:
            self.cursor.execute('SELECT COUNT(*) FROM accounts')
            return self.cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Erro ao contar total de contas: {e}")
            return 0

    def add_user(self, username, password):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            self.cursor.execute('''
                INSERT INTO users (username, password)
                VALUES (?, ?)
            ''', (username, hashed_password))
            self.conn.commit()
            logging.info(f"Usuário adicionado: {username}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Erro ao adicionar usuário: {e}")
            return False

    def verify_user(self, username, password):
        try:
            self.cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = self.cursor.fetchone()
            if result:
                return bcrypt.checkpw(password.encode('utf-8'), result[0])
            return False
        except sqlite3.Error as e:
            logging.error(f"Erro ao verificar usuário: {e}")
            return False

    def change_user_password(self, username, new_password):
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        try:
            self.cursor.execute('''
                UPDATE users
                SET password = ?
                WHERE username = ?
            ''', (hashed_password, username))
            self.conn.commit()
            logging.info(f"Senha alterada para o usuário: {username}")
            return True
        except sqlite3.Error as e:
            logging.error(f"Erro ao alterar senha do usuário: {e}")
            return False

    def close(self):
        if self.conn:
            self.conn.close()
            logging.info("Conexão com o banco de dados fechada")

class EncryptionManager:
    def __init__(self, key_file='encryption_key.key'):
        self.key_file = key_file
        self.key = self.load_or_generate_key()
        self.fernet = Fernet(self.key)

    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as file:
                file.write(key)
            return key

    def encrypt(self, data):
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, data):
        return self.fernet.decrypt(data.encode()).decode()

class EditAccountWindow:
    def __init__(self, master, account_manager, index):
        self.master = master
        self.account_manager = account_manager
        self.index = index

        self.window = tk.Toplevel(master)
        self.window.title("Editar Conta")
        self.window.geometry("400x250")
        self.window.resizable(False, False)

        item = self.account_manager.tree.get_children()[index]
        account_id, email, encrypted_password, more_info = self.account_manager.tree.item(item, "values")

        ttk.Label(self.window, text="ID:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.id_entry = ttk.Entry(self.window, width=30)
        self.id_entry.insert(0, account_id)
        self.id_entry.grid(row=0, column=1, padx=10, pady=5)
        self.id_entry.config(state='readonly')

        ttk.Label(self.window, text="Email:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.email_entry = ttk.Entry(self.window, width=30)
        self.email_entry.insert(0, email)
        self.email_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(self.window, text="Senha:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.window, width=30, show="*")
        decrypted_password = self.account_manager.encryption.decrypt(encrypted_password)
        self.password_entry.insert(0, decrypted_password)
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(self.window, text="Informações:").grid(row=3, column=0, padx=10, pady=5, sticky="ne")
        self.info_text = tk.Text(self.window, width=30, height=5)
        self.info_text.insert(tk.END, more_info)
        self.info_text.grid(row=3, column=1, padx=10, pady=5)

        save_button = ttk.Button(self.window, text="Salvar", command=self.save_changes, style="TButton")
        save_button.grid(row=4, column=0, columnspan=2, pady=20)

        self.window.transient(master)
        self.window.grab_set()

        self.email_entry.bind("<Return>", lambda event: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda event: self.info_text.focus())
        self.info_text.bind("<Return>", lambda event: self.save_changes())

class AccountManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Account Manager")
        self.master.geometry("800x600")

        if USE_TTKBOOTSTRAP:
            self.style = ttk.Style(theme='darkly')
        else:
            self.style = ttk.Style()
            self.style.theme_use('clam')

        self.configure_styles()

        self.db = DatabaseManager()
        self.encryption = EncryptionManager()

        self.current_page = 1
        self.accounts_per_page = 50
        self.current_user = None

        self.load_icon()
        self.show_login()
        
    def configure_styles(self):
        self.style.configure('TButton', background='#3085ff', foreground='white')
        self.style.map('TButton',
                       background=[('active', '#1152bc')],
                       foreground=[('active', 'white')])
        self.style.configure('Small.TButton', background='#3085ff', foreground='white')
        self.style.map('Small.TButton',
                       background=[('active', '#1152bc')],
                       foreground=[('active', 'white')])
        self.style.configure("Placeholder.TEntry", foreground="gray")

    def load_icon(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            try:
                self.icon = Image.open(icon_path)
                self.icon = self.icon.resize((150, 150), Image.LANCZOS)
                self.icon = ImageTk.PhotoImage(self.icon)
                print(f"Ícone carregado com sucesso: {icon_path}")
            except Exception as e:
                print(f"Erro ao carregar o ícone: {e}")
                self.icon = None
        else:
            print(f"Arquivo de ícone não encontrado: {icon_path}")
            self.icon = None

    def show_login(self):
        for widget in self.master.winfo_children():
            widget.destroy()

        self.login_frame = ttk.Frame(self.master)
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        center_frame = ttk.Frame(self.login_frame)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        if self.icon:
            icon_label = ttk.Label(center_frame, image=self.icon)
            icon_label.pack(pady=(0, 20))
        else:
            print("Ícone não disponível para a tela de login")

        login_form = ttk.Frame(center_frame)
        login_form.pack()

        style = ttk.Style()
        style.configure("Placeholder.TEntry", foreground="gray")

        self.username_entry = ttk.Entry(login_form, font=("Arial", 10), width=30, style="Placeholder.TEntry")
        self.username_entry.insert(0, "Login")
        self.username_entry.pack(pady=5)
        self.username_entry.bind("<FocusIn>", lambda e: self.on_entry_click(self.username_entry, "Login"))
        self.username_entry.bind("<FocusOut>", lambda e: self.on_focusout(self.username_entry, "Login"))

        self.password_entry = ttk.Entry(login_form, font=("Arial", 10), width=30, style="Placeholder.TEntry")
        self.password_entry.insert(0, "Senha")
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<FocusIn>", lambda e: self.on_entry_click(self.password_entry, "Senha"))
        self.password_entry.bind("<FocusOut>", lambda e: self.on_focusout(self.password_entry, "Senha"))

        button_frame = ttk.Frame(login_form)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Login", command=self.login, style='TButton').pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Registrar", command=self.show_register, style='TButton').pack(side=tk.LEFT, padx=10)
        
        def open_github(event):
            webbrowser.open_new_tab("https://github.com/thiagollage")

        credits_label = ttk.Label(self.login_frame, text="by Thiago Lage", font=("Arial", 10), foreground="gray")
        credits_label.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        credits_label.bind("<Button-1>", open_github)
        
        self.master.bind('<Return>', lambda event: self.login())
        
    def on_entry_click(self, entry, placeholder, is_password=False):
        if entry.get() == placeholder:
            entry.delete(0, "end")
            entry.insert(0, '')
            if is_password:
                entry.config(show="*")
            entry.config(style="TEntry")

    def on_focusout(self, entry, placeholder, is_password=False):
        if entry.get() == '':
            entry.insert(0, placeholder)
            if is_password:
                entry.config(show="")
            entry.config(style="Placeholder.TEntry")

    def show_register(self):
        for widget in self.master.winfo_children():
            widget.destroy()

        self.register_frame = ttk.Frame(self.master)
        self.register_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Button(self.register_frame, text="Voltar", command=self.show_login, style='Small.TButton').pack(anchor='ne', padx=10, pady=10)

        center_frame = ttk.Frame(self.register_frame)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        if self.icon:
            icon_label = ttk.Label(center_frame, image=self.icon)
            icon_label.pack(pady=(0, 20))
        else:
            print("Ícone não disponível para a tela de registro")

        register_form = ttk.Frame(center_frame)
        register_form.pack()

        style = ttk.Style()
        style.configure("Placeholder.TEntry", foreground="gray")

        self.reg_username_entry = ttk.Entry(register_form, font=("Arial", 10), width=30, style="Placeholder.TEntry")
        self.reg_username_entry.insert(0, "Login")
        self.reg_username_entry.pack(pady=5)
        self.reg_username_entry.bind("<FocusIn>", lambda e: self.on_entry_click(self.reg_username_entry, "Login"))
        self.reg_username_entry.bind("<FocusOut>", lambda e: self.on_focusout(self.reg_username_entry, "Login"))

        self.reg_password_entry = ttk.Entry(register_form, font=("Arial", 10), width=30, style="Placeholder.TEntry", show="")
        self.reg_password_entry.insert(0, "Senha")
        self.reg_password_entry.pack(pady=5)
        self.reg_password_entry.bind("<FocusIn>", lambda e: self.on_entry_click(self.reg_password_entry, "Senha", True))
        self.reg_password_entry.bind("<FocusOut>", lambda e: self.on_focusout(self.reg_password_entry, "Senha", True))

        self.reg_confirm_password_entry = ttk.Entry(register_form, font=("Arial", 10), width=30, style="Placeholder.TEntry", show="")
        self.reg_confirm_password_entry.insert(0, "Confirme a Senha")
        self.reg_confirm_password_entry.pack(pady=5)
        self.reg_confirm_password_entry.bind("<FocusIn>", lambda e: self.on_entry_click(self.reg_confirm_password_entry, "Confirme a Senha", True))
        self.reg_confirm_password_entry.bind("<FocusOut>", lambda e: self.on_focusout(self.reg_confirm_password_entry, "Confirme a Senha", True))

        ttk.Button(register_form, text="Registrar", command=self.register, style='TButton').pack(pady=20)
        
        def open_github(event):
            webbrowser.open_new_tab("https://github.com/thiagollage")

        credits_label = ttk.Label(self.login_frame, text="by Thiago Lage", font=("Arial", 10), foreground="gray")
        credits_label.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=10)
        credits_label.bind("<Button-1>", open_github)
        
        self.master.bind('<Return>', lambda event: self.login())

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.db.verify_user(username, password):
            self.current_user = username
            self.create_main_window()
        else:
            messagebox.showerror("Erro", "Usuário ou senha inválidos")

    def register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm_password = self.reg_confirm_password_entry.get()

        if password != confirm_password:
            messagebox.showerror("Erro", "As senhas não coincidem")
            return

        if self.db.add_user(username, password):
            messagebox.showinfo("Sucesso", "Usuário registrado com sucesso")
            self.show_login()
        else:
            messagebox.showerror("Erro", "Falha ao registrar usuário")

    def create_main_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.accounts_frame = ttk.Frame(self.notebook)
        self.settings_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.accounts_frame, text="Contas")
        self.notebook.add(self.settings_frame, text="Configurações")

        self.create_accounts_tab()
        self.create_settings_tab()

    def create_accounts_tab(self):
        top_frame = ttk.Frame(self.accounts_frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.LEFT)

        buttons = [
            ("Editar", self.edit_selected_account),
            ("Remover", self.remove_account),
            ("Atualizar", self.refresh_accounts),
            ("📄 PDF", self.export_pdf),
        ]

        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command, style="TButton").pack(side=tk.LEFT, padx=2)

        search_frame = ttk.Frame(top_frame)
        search_frame.pack(side=tk.RIGHT, padx=(0, 10))

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.perform_search)

        lupa_label = ttk.Label(search_frame, text="🔍", font=("Segoe UI Emoji", 11))
        lupa_label.pack(side=tk.LEFT, padx=(5, 0))

        tree_frame = ttk.Frame(self.accounts_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(tree_frame, columns=("ID", "Email", "Senha", "Informações"), show="headings", style="Custom.Treeview")
        self.style.configure("Treeview", rowheight=30, padding=(0, 5))
        self.tree.heading("ID", text="ID", anchor=tk.CENTER)
        self.tree.heading("Email", text="Email", anchor=tk.CENTER)
        self.tree.heading("Senha", text="Senha", anchor=tk.CENTER)
        self.tree.heading("Informações", text="Informações", anchor=tk.CENTER)
        
        # Ajustando a largura das colunas
        self.tree.column("ID", anchor=tk.CENTER, width=50)
        self.tree.column("Email", anchor=tk.CENTER, width=200)
        self.tree.column("Senha", anchor=tk.CENTER, width=100)
        self.tree.column("Informações", anchor=tk.CENTER, width=250)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind('<Double-1>', self.on_double_click)
        self.tree.bind('<ButtonRelease-1>', self.toggle_password_visibility)

        pagination_frame = ttk.Frame(self.accounts_frame)
        pagination_frame.pack(side=tk.BOTTOM, anchor='e', padx=5, pady=5)

        self.previous_button = ttk.Button(pagination_frame, text="<", command=self.previous_page, width=3)
        self.previous_button.pack(side=tk.LEFT)

        self.page_label = ttk.Label(pagination_frame, text="1")
        self.page_label.pack(side=tk.LEFT, padx=5)

        self.next_button = ttk.Button(pagination_frame, text=">", command=self.next_page, width=3)
        self.next_button.pack(side=tk.LEFT)

        self.create_add_form()
        self.refresh_accounts()

    def create_add_form(self):
        self.form_frame = ttk.Frame(self.accounts_frame)
        self.form_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(self.form_frame, text="Email:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.email_entry = ttk.Entry(self.form_frame, width=30)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.form_frame, text="Senha:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.form_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.form_frame, text="Informações:").grid(row=0, column=2, padx=5, pady=5, sticky="ne")
        self.info_entry = tk.Text(self.form_frame, width=30, height=3)
        self.info_entry.grid(row=0, column=3, rowspan=2, padx=5, pady=5)

        save_button = ttk.Button(self.form_frame, text="Adicionar", command=self.save_account, style="TButton")
        save_button.grid(row=0, column=4, rowspan=2, padx=10, pady=5)

        self.email_entry.bind("<Return>", lambda event: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda event: self.info_entry.focus())
        self.info_entry.bind("<Return>", lambda event: self.save_account())

    def save_account(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        more_info = self.info_entry.get("1.0", tk.END).strip()

        if not email or not password:
            messagebox.showerror("Erro", "Email e senha são obrigatórios!")
            return

        encrypted_password = self.encryption.encrypt(password)
        if self.db.add_account(email, encrypted_password, more_info):
            messagebox.showinfo("Sucesso", "Conta adicionada com sucesso!")
            self.refresh_accounts()
            self.clear_add_form()
        else:
            messagebox.showerror("Erro", "Falha ao adicionar conta.")

    def clear_add_form(self):
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.info_entry.delete("1.0", tk.END)

    def edit_selected_account(self):
        selected = self.tree.selection()
        if selected:
            index = self.tree.index(selected[0])
            EditAccountWindow(self.master, self, index)
        else:
            messagebox.showwarning("Aviso", "Selecione uma conta para editar.")
           
    def on_double_click(self, event):
        item = self.tree.identify('item', event.x, event.y)
        if item:
            values = self.tree.item(item, "values")
            if values:
                account_id, email, encrypted_password, more_info = values
                
                edit_window = tk.Toplevel(self.master)
                edit_window.title("Editar Conta")
                edit_window.geometry("400x250")
                edit_window.resizable(False, False)

                ttk.Label(edit_window, text="Email:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
                email_entry = ttk.Entry(edit_window, width=30)
                email_entry.insert(0, email)
                email_entry.grid(row=0, column=1, padx=10, pady=5)

                ttk.Label(edit_window, text="Senha:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
                password_entry = ttk.Entry(edit_window, width=30, show="*")
                decrypted_password = self.encryption.decrypt(encrypted_password)
                password_entry.insert(0, decrypted_password)
                password_entry.grid(row=1, column=1, padx=10, pady=5)

                ttk.Label(edit_window, text="Informações:").grid(row=2, column=0, padx=10, pady=5, sticky="ne")
                info_text = tk.Text(edit_window, width=30, height=5)
                info_text.insert(tk.END, more_info)
                info_text.grid(row=2, column=1, padx=10, pady=5)

                def save_changes():
                    new_email = email_entry.get()
                    new_password = password_entry.get()
                    new_info = info_text.get("1.0", tk.END).strip()

                    if not new_email or not new_password:
                        messagebox.showerror("Erro", "Email e senha são obrigatórios!")
                        return

                    encrypted_new_password = self.encryption.encrypt(new_password)
                    
                    if self.db.update_account(account_id, new_email, encrypted_new_password, new_info):
                        messagebox.showinfo("Sucesso", "Conta atualizada com sucesso!")
                        edit_window.destroy()
                        self.refresh_accounts()
                    else:
                        messagebox.showerror("Erro", "Falha ao atualizar conta.")

                save_button = ttk.Button(edit_window, text="Salvar", command=save_changes, style="TButton")
                save_button.grid(row=3, column=0, columnspan=2, pady=20)

                edit_window.transient(self.master)
                edit_window.grab_set()

                email_entry.bind("<Return>", lambda event: password_entry.focus())
                password_entry.bind("<Return>", lambda event: info_text.focus())
                info_text.bind("<Return>", lambda event: save_changes())
    
    def create_settings_tab(self):
        settings_frame = ttk.Frame(self.settings_frame)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Gerenciamento de Dados
        ttk.Label(settings_frame, text="Gerenciamento de Dados", font=("Arial", 14, "bold")).grid(row=0, column=0, pady=10, sticky="w")
        ttk.Label(settings_frame, text="Faça backup ou exporte seus dados").grid(row=1, column=0, pady=5, sticky="w")
        
        button_frame = ttk.Frame(settings_frame)
        button_frame.grid(row=0, column=1, rowspan=2, padx=20, sticky="e")
        
        ttk.Button(button_frame, text="Backup", command=self.backup_data, style="TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Exportar Lista", command=self.export_json, style="TButton").pack(side=tk.RIGHT, padx=5)

        ttk.Separator(settings_frame, orient='horizontal').grid(row=2, columnspan=2, sticky="ew", pady=10)

        # Conta
        ttk.Label(settings_frame, text="Conta", font=("Arial", 14, "bold")).grid(row=3, column=0, pady=10, sticky="w")
        ttk.Label(settings_frame, text="Gerencie sua conta").grid(row=4, column=0, pady=5, sticky="w")

        account_button_frame = ttk.Frame(settings_frame)
        account_button_frame.grid(row=3, column=1, rowspan=2, padx=20, sticky="e")

        ttk.Button(account_button_frame, text="Logout", command=self.logout, style="TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(account_button_frame, text="Alterar Senha", command=self.change_password, style="TButton").pack(side=tk.RIGHT, padx=5)

        ttk.Separator(settings_frame, orient='horizontal').grid(row=5, columnspan=2, sticky="ew", pady=10)

        # Configurar as colunas para expandir corretamente
        settings_frame.columnconfigure(0, weight=1)
        settings_frame.columnconfigure(1, weight=0)

        # Adicionar espaço extra na parte inferior
        settings_frame.rowconfigure(6, weight=1)
        
        def open_github(event):
            webbrowser.open_new_tab("https://github.com/thiagollage")

        def on_enter(event):
            link_label.config(font=("Arial", 9, "underline"))

        def on_leave(event):
            link_label.config(font=("Arial", 9))

        # Direitos autorais
        copyright_text = "©2024 THIAGO LAGE. TODOS OS DIREITOS RESERVADOS."
        thin_font = tkfont.Font(family="Arial", size=9, weight="normal")

        copyright_frame = ttk.Frame(settings_frame)
        copyright_frame.grid(row=7, column=0, columnspan=2, pady=20, sticky="s")

        copyright_label = ttk.Label(copyright_frame, 
                                    text="© 2024",
                                    font=thin_font,
                                    foreground="#808080")
        copyright_label.pack(side=tk.LEFT)

        link_label = ttk.Label(copyright_frame,
                            text="THIAGO LAGE.",
                            font=thin_font,
                            foreground="#808080",
                            cursor="hand2")
        link_label.pack(side=tk.LEFT)
        link_label.bind("<Button-1>", open_github)
        link_label.bind("<Enter>", on_enter)
        link_label.bind("<Leave>", on_leave)

        rest_label = ttk.Label(copyright_frame,
                            text="TODOS OS DIREITOS RESERVADOS.",
                            font=thin_font,
                            foreground="#808080")
        rest_label.pack(side=tk.LEFT)
    
    def remove_account(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Selecione uma conta para remover.")
            return

        if messagebox.askyesno("Confirmar", "Tem certeza que deseja remover esta conta?"):
            item = self.tree.item(selected[0])
            account_id = item['values'][0]
            if self.db.delete_account(account_id):
                messagebox.showinfo("Sucesso", "Conta removida com sucesso!")
                self.refresh_accounts()
            else:
                messagebox.showerror("Erro", "Falha ao remover conta.")

    def refresh_accounts(self):
        self.tree.delete(*self.tree.get_children())
        accounts = self.db.get_accounts(self.current_page, self.accounts_per_page)
        for account in accounts:
            masked_password = '*' * len(account[2])
            self.tree.insert("", tk.END, values=(account[0], account[1], masked_password, account[3]))
        self.update_pagination()

    def update_pagination(self):
        total_accounts = self.db.get_total_accounts()
        total_pages = (total_accounts + self.accounts_per_page - 1) // self.accounts_per_page
        self.page_label.config(text=f"{self.current_page}/{total_pages}")
        self.previous_button['state'] = 'normal' if self.current_page > 1 else 'disabled'
        self.next_button['state'] = 'normal' if self.current_page < total_pages else 'disabled'

    def previous_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.refresh_accounts()

    def next_page(self):
        self.current_page += 1
        self.refresh_accounts()

    def perform_search(self, event=None):
        query = self.search_var.get()
        results = self.db.search_accounts(query)
        self.tree.delete(*self.tree.get_children())
        for result in results:
            masked_password = '*' * len(result[2])
            self.tree.insert("", tk.END, values=(result[0], result[1], masked_password, result[3]))

    def toggle_password_visibility(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            if column == "#3":
                item = self.tree.identify("item", event.x, event.y)
                values = self.tree.item(item, "values")
                if values:
                    current_password = values[2]
                    if '*' in current_password:
                        decrypted_password = self.encryption.decrypt(self.db.get_accounts(1, 1000)[int(values[0])-1][2])
                        self.tree.set(item, column=2, value=decrypted_password)
                    else:
                        self.tree.set(item, column=2, value='*' * len(current_password))
                        
    def export_json(self):
        current_date = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"account_manager_export_{current_date}.json"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=default_filename
        )
        if not file_path:
            return

        accounts = self.db.get_accounts(page=1, per_page=1000000)  # Pega todas as contas
        export_data = []
        for account in accounts:
            decrypted_password = self.encryption.decrypt(account[2])
            export_data.append({
                "id": account[0],
                "email": account[1],
                "password": decrypted_password,
                "more_info": account[3]
            })

        try:
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=4)
            messagebox.showinfo("Sucesso", f"Dados exportados para {file_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar dados: {str(e)}")                        

    def export_pdf(self):
        current_date = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"account_manager_export_{current_date}.pdf"
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], initialfile=default_filename)
        if not file_path:
            return
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        elements = []

        data = [["ID", "Email", "Senha", "Mais Info"]]
        accounts = self.db.get_accounts(1, 1000)
        for account in accounts:
            decrypted_password = self.encryption.decrypt(account[2])
            data.append([account[0], account[1], decrypted_password, account[3]])

        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(table)
        doc.build(elements)
        messagebox.showinfo("Sucesso", f"PDF exportado para {file_path}")

    def backup_data(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        accounts = self.db.get_accounts(page=1, per_page=1000000)
        backup_data = []
        for account in accounts:
            decrypted_password = self.encryption.decrypt(account[2])
            backup_data.append({
                "id": account[0],
                "email": account[1],
                "password": decrypted_password,
                "more_info": account[3]
            })

        try:
            with open(file_path, 'r') as f:
                backup_data = json.load(f)

            self.db.cursor.execute("DELETE FROM accounts")

            for account in backup_data:
                encrypted_password = self.encryption.encrypt(account['password'])
                self.db.add_account(account['email'], encrypted_password, account['more_info'])

            self.db.conn.commit()
            messagebox.showinfo("Sucesso", "Dados restaurados com sucesso!")
            self.refresh_accounts()
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao restaurar dados: {str(e)}")

    def change_password(self):
        old_password = simpledialog.askstring("Alterar Senha", "Digite a senha atual:", show='*')
        if not old_password:
            return

        if not self.db.verify_user(self.current_user, old_password):
            messagebox.showerror("Erro", "Senha atual incorreta")
            return

        new_password = simpledialog.askstring("Alterar Senha", "Digite a nova senha:", show='*')
        if not new_password:
            return

        confirm_password = simpledialog.askstring("Alterar Senha", "Confirme a nova senha:", show='*')
        if new_password != confirm_password:
            messagebox.showerror("Erro", "As senhas não coincidem.")
            return

        if self.db.change_user_password(self.current_user, new_password):
            messagebox.showinfo("Sucesso", "Senha alterada com sucesso!")
        else:
            messagebox.showerror("Erro", "Falha ao alterar a senha")

    def logout(self):
        self.current_user = None
        self.show_login()

    def run(self):
        self.master.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = AccountManager(root)
    app.run()