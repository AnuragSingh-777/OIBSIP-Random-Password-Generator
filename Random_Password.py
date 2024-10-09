import tkinter as tk
from tkinter import ttk
import random
import string

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Password Generator")
        master.geometry("400x350")  # Set the window size to 400x350

        # Create main frame
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Create input frame
        input_frame = ttk.Frame(main_frame, padding="5")
        input_frame.pack(fill="x")

        # Create password length label and entry
        self.length_label = ttk.Label(input_frame, text="Password Length:")
        self.length_label.pack(side="left")
        self.length_entry = ttk.Entry(input_frame, width=5)
        self.length_entry.pack(side="left")

        # Create options frame
        options_frame = ttk.Frame(main_frame, padding="5")
        options_frame.pack(fill="x")

        # Create checkboxes for password complexity options
        self.uppercase_var = tk.IntVar()
        self.uppercase_checkbox = ttk.Checkbutton(options_frame, text="Uppercase Letters", variable=self.uppercase_var)
        self.uppercase_checkbox.pack(side="left")

        self.lowercase_var = tk.IntVar()
        self.lowercase_checkbox = ttk.Checkbutton(options_frame, text="Lowercase Letters", variable=self.lowercase_var)
        self.lowercase_checkbox.pack(side="left")

        self.digits_var = tk.IntVar()
        self.digits_checkbox = ttk.Checkbutton(options_frame, text="Digits", variable=self.digits_var)
        self.digits_checkbox.pack(side="left")

        self.special_chars_var = tk.IntVar()
        self.special_chars_checkbox = ttk.Checkbutton(options_frame, text="Special Characters", variable=self.special_chars_var)
        self.special_chars_checkbox.pack(side="left")

        # Create generate password button
        self.generate_button = tk.Button(main_frame, text="Generate Password", command=self.generate_password, bg="#4CAF50", fg="#ffffff", font=("Arial", 10))
        self.generate_button.pack(fill="x")

        # Create password label and entry
        self.password_label = ttk.Label(main_frame, text="Generated Password:")
        self.password_label.pack(fill="x")
        self.password_entry = ttk.Entry(main_frame, width=40)
        self.password_entry.pack(fill="x")

        # Create password strength label
        self.password_strength_label = ttk.Label(main_frame, text="Password Strength:")
        self.password_strength_label.pack(fill="x")

        # Create copy to clipboard button
        self.copy_button = tk.Button(main_frame, text="Copy to Clipboard", command=self.copy_to_clipboard, bg="#03A9F4", fg="#ffffff", font=("Arial", 10))
        self.copy_button.pack(fill="x")

        # Create clear button
        self.clear_button = tk.Button(main_frame, text="Clear", command=self.clear_fields, bg="#FF9800", fg="#ffffff", font=("Arial", 10))
        self.clear_button.pack(fill="x")

        # Create exit button
        self.exit_button = tk.Button(main_frame, text="Exit", command=self.exit_program, bg="#FF0000", fg="#ffffff", font=("Arial", 10))
        self.exit_button.pack(fill="x")

        # Create help menu
        self.help_menu = tk.Menu(self.master)
        self.master.config(menu=self.help_menu)
        self.help_menu.add_command(label="Help", command=self.show_help)

    def calculate_password_strength(self, password):
        strength = 0
        if len(password) < 8:
            strength += 1
        elif len(password) < 12:
            strength += 2
        else:
            strength += 3

        if any(char.isupper() for char in password):
            strength += 1
        if any(char.islower() for char in password):
            strength += 1
        if any(char.isdigit() for char in password):
            strength += 1
        if any(char in string.punctuation for char in password):
            strength += 1

        return strength

    def generate_password(self):
        length = int(self.length_entry.get())
        password = ""

        if self.uppercase_var.get():
            password += random.choice(string.ascii_uppercase)
        if self.lowercase_var.get():
            password += random.choice(string.ascii_lowercase)
        if self.digits_var.get():
            password += random.choice(string.digits)
        if self.special_chars_var.get():
            password += random.choice(string.punctuation)

        for _ in range(length - 4):
            password += random.choice(string.ascii_letters + string.digits + string.punctuation)

        password = ''.join(random.sample(password, len(password)))

        self.password_entry.delete(0, tk .END)
        self.password_entry.insert(0, password)

        strength = self.calculate_password_strength(password)
        if strength < 3:
            self.password_strength_label.config(text="Password Strength: Weak")
        elif strength < 6:
            self.password_strength_label.config(text="Password Strength: Medium")
        else:
            self.password_strength_label.config(text="Password Strength: Strong")

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        self.master.clipboard_clear()
        self.master.clipboard_append(password)

    def clear_fields(self):
        self.length_entry.delete(0, tk.END)
        self.uppercase_var.set(0)
        self.lowercase_var.set(0)
        self.digits_var.set(0)
        self.special_chars_var.set(0)
        self.password_entry.delete(0, tk.END)
        self.password_strength_label.config(text="Password Strength:")

    def exit_program(self):
        self.master.destroy()

    def show_help(self):
        help_window = tk.Toplevel(self.master)
        help_window.title("Help")
        help_window.geometry("300x200")
        help_text = tk.Text(help_window)
        help_text.pack(fill="both", expand=True)
        help_text.insert(tk.END, "This is a password generator program.\n\n")
        help_text.insert(tk.END, "To use the program, follow these steps:\n")
        help_text.insert(tk.END, "1. Enter the desired password length in the 'Password Length' field.\n")
        help_text.insert(tk.END, "2. Select the desired password complexity options (uppercase letters, lowercase letters, digits, and special characters).\n")
        help_text.insert(tk.END, "3. Click the 'Generate Password' button to generate a password.\n")
        help_text.insert(tk.END, "4. The generated password will be displayed in the 'Generated Password' field.\n")
        help_text.insert(tk.END, "5. You can copy the password to the clipboard by clicking the 'Copy to Clipboard' button.\n")
        help_text.insert(tk.END, "6. You can clear the fields by clicking the 'Clear' button.\n")
        help_text.insert(tk.END, "7. You can exit the program by clicking the 'Exit' button.\n")

root = tk.Tk()
password_generator = PasswordGenerator(root)
root.mainloop()
