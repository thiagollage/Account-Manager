"""
Account Manager
Criado por Thiago Lage - https://github.com/thiagollage
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from datetime import datetime

class AccountManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Account Manager by Thiago Lage")
        self.master.geometry("800x500")

        self.accounts = []
        self.load_accounts()
        self.passwords_visible = False

        self.create_widgets()
        self.apply_style()

    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(main_frame, columns=("ID", "Email", "Senha"), show="headings")
        self.tree.heading("ID", text="Conta (ID)", anchor="center")
        self.tree.heading("Email", text="Email", anchor="center")
        self.tree.heading("Senha", text="Senha", anchor="center")
        self.tree.column("ID", width=100, anchor="center")
        self.tree.column("Email", width=350, anchor="center")
        self.tree.column("Senha", width=300, anchor="center")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(self.master, padding="10")
        button_frame.pack(fill=tk.X)

        buttons = [
            ("Adicionar", self.add_account),
            ("Remover", self.remove_account),
            ("Editar", self.edit_account),
            ("Exportar PDF", self.print_pdf),
            ("Revelar/Esconder Senhas", self.toggle_all_passwords)
        ]

        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

        # Center the buttons
        button_frame.pack_configure(anchor="center")

        self.update_treeview()

    def apply_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure Treeview
        style.configure("Treeview", 
                        background="#f0f0f0", 
                        foreground="black", 
                        rowheight=25, 
                        fieldbackground="#f0f0f0",
                        borderwidth=0,
                        font=('Helvetica', 10))
        style.map('Treeview', background=[('selected', '#007AFF')])
        
        # Configure Treeview Heading
        style.configure("Treeview.Heading",
                        background="#e0e0e0",
                        foreground="black",
                        relief="flat",
                        font=('Helvetica', 11, 'bold'))
        style.map("Treeview.Heading",
                  background=[('active', '#d0d0d0')])
        
        # Configure Button
        style.configure("TButton", 
                        padding=6, 
                        relief="flat", 
                        background="#101214", 
                        foreground="white",
                        font=('Helvetica', 10),
                        borderwidth=0,
                        focusthickness=3,
                        focuscolor='none')
        style.map("TButton",
                  background=[('active', '#0a0c0d')],
                  relief=[('pressed', 'flat'),
                          ('!pressed', 'flat')])

        # Configure Entry
        style.configure("TEntry",
                        fieldbackground="white",
                        background="white",
                        relief="flat",
                        borderwidth=1)
        style.map("TEntry",
                  fieldbackground=[('readonly', 'white')],
                  background=[('readonly', 'white')])

        # Round corners for buttons (Note: This requires the azure.tcl file)
        try:
            self.master.tk.call("source", "azure.tcl")
            style.theme_use("azure")
        except tk.TclError:
            print("azure.tcl file not found. Using default button style.")

    def load_accounts(self):
        try:
            with open("Accounts.json", "r") as file:
                self.accounts = json.load(file)
        except FileNotFoundError:
            self.accounts = []

    def save_accounts(self):
        with open("Accounts.json", "w") as file:
            json.dump(self.accounts, file)

    def update_treeview(self):
        self.tree.delete(*self.tree.get_children())
        for account in self.accounts:
            password_display = account['password'] if self.passwords_visible else '*' * len(account['password'])
            self.tree.insert("", tk.END, values=(account.get("id", "N/A"), account["email"], password_display))

    def add_account(self):
        AddAccountWindow(self.master, self)

    def remove_account(self):
        selected_item = self.tree.selection()
        if selected_item:
            index = self.tree.index(selected_item)
            self.accounts.pop(index)
            self.save_accounts()
            self.update_treeview()
        else:
            messagebox.showwarning("Aviso", "Selecione uma conta para remover.")

    def edit_account(self):
        selected_item = self.tree.selection()
        if selected_item:
            index = self.tree.index(selected_item)
            EditAccountWindow(self.master, self, index)
        else:
            messagebox.showwarning("Aviso", "Selecione uma conta para editar.")

    def toggle_all_passwords(self):
        self.passwords_visible = not self.passwords_visible
        self.update_treeview()

    def print_pdf(self):
        if not self.accounts:
            messagebox.showwarning("Aviso", "Não há contas para exportar.")
            return

        current_date = datetime.now().strftime("%Y-%m-%d")
        default_filename = f"AccountManager-{current_date}.pdf"
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], initialfile=default_filename)
        if not file_path:
            return

        try:
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            elements = []

            data = [["Conta (ID)", "Email", "Senha"]]
            for account in self.accounts:
                data.append([account.get("id", "N/A"), account["email"], account["password"]])

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
            messagebox.showinfo("Sucesso", f"PDF exportado com sucesso para {file_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao exportar o PDF: {str(e)}")

class AddAccountWindow:
    def __init__(self, master, account_manager):
        self.window = tk.Toplevel(master)
        self.window.title("Adicionar Conta")
        self.window.geometry("400x200")
        self.account_manager = account_manager

        main_frame = ttk.Frame(self.window, padding="20 20 20 0")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Conta (ID):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.id_entry = ttk.Entry(main_frame, width=30)
        self.id_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(main_frame, text="Email:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.email_entry = ttk.Entry(main_frame, width=30)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(main_frame, text="Senha:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(main_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.show_password = tk.BooleanVar()
        self.show_password_check = ttk.Checkbutton(main_frame, text="Mostrar senha", variable=self.show_password, command=self.toggle_password_visibility)
        self.show_password_check.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Adicionar", command=self.add_account).pack()

    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def add_account(self):
        id = self.id_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        if id and email and password:
            self.account_manager.accounts.append({"id": id, "email": email, "password": password})
            self.account_manager.save_accounts()
            self.account_manager.update_treeview()
            self.window.destroy()
        else:
            messagebox.showwarning("Aviso", "Por favor, preencha todos os campos obrigatórios.")

class EditAccountWindow(AddAccountWindow):
    def __init__(self, master, account_manager, index):
        super().__init__(master, account_manager)
        self.window.title("Editar Conta")
        self.index = index

        account = self.account_manager.accounts[self.index]
        self.id_entry.insert(0, account.get("id", ""))
        self.email_entry.insert(0, account["email"])
        self.password_entry.insert(0, account["password"])

        button_frame = self.window.winfo_children()[-1].winfo_children()[-1]
        button_frame.winfo_children()[0].destroy()  # Remove the "Adicionar" button
        ttk.Button(button_frame, text="Atualizar", command=self.update_account).pack()

    def update_account(self):
        id = self.id_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        if id and email and password:
            self.account_manager.accounts[self.index] = {"id": id, "email": email, "password": password}
            self.account_manager.save_accounts()
            self.account_manager.update_treeview()
            self.window.destroy()
        else:
            messagebox.showwarning("Aviso", "Por favor, preencha todos os campos obrigatórios.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AccountManager(root)
    root.mainloop()