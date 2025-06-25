import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QFileDialog,
    QVBoxLayout, QLabel, QMessageBox, QTextEdit, 
    QHBoxLayout, QLineEdit, QFormLayout, QStackedWidget, QKeySequenceEdit
)
from PyQt6.QtCore import Qt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from encryptor1 import encrypt_file
import base64

class FileEncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryption App")
        self.setGeometry(100, 100, 500, 300)
        
        self.main_layout = QVBoxLayout()
        self.stacked_widget = QStackedWidget()
        
        self.create_navbar()
        
        self.create_login_screen()
        self.create_main_app_screen()
        
        self.main_layout.addWidget(self.navbar)
        self.main_layout.addWidget(self.stacked_widget)
        self.setLayout(self.main_layout)
        
        self.stacked_widget.setCurrentIndex(0)

    def create_navbar(self):
        self.navbar = QWidget()
        navbar_layout = QHBoxLayout()
        navbar_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.setDefault(True)
        self.login_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        self.app_btn = QPushButton("Encrypt Files")
        self.app_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        self.app_btn.setEnabled(False)
        
        
        navbar_layout.addWidget(self.login_btn)
        navbar_layout.addWidget(self.app_btn)
        
        
        self.navbar.setLayout(navbar_layout)
        self.navbar.setStyleSheet("""
            background-color: #660033 ;
            padding: 10px;
            border-bottom: 1px solid #34495e;
        """)

    def create_login_screen(self):
        """Create the login form screen"""
        self.login_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        #Loginform
        form = QFormLayout()
        form.setSpacing(15)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setMinimumWidth(250)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumWidth(250)
        
        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)
        
        #Login
        login_submit_btn = QPushButton("Login")
        login_submit_btn.setDefault(True)
        login_submit_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        login_submit_btn.clicked.connect(self.authenticate)
        login_submit_btn.setDefault(True)

        self.password_input.returnPressed.connect(self.authenticate)
        
        layout.addLayout(form)
        layout.addWidget(login_submit_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.login_screen.setLayout(layout)
        
        self.stacked_widget.addWidget(self.login_screen)

    def create_main_app_screen(self):
        """Create the main application screen"""
        self.main_screen = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        

        self.label = QLabel("Select a file to encrypt (Max 5MB):")
        self.label.setStyleSheet("font-size: 14px;")
        
        self.encrypt_button = QPushButton("Choose File and Encrypt")
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.encrypt_button.clicked.connect(self.encrypt)
        
        self.result_label = QLabel("")
        self.result_label.setStyleSheet("font-size: 12px; color: #555;")
        
        self.key_box = QTextEdit()
        self.key_box.setReadOnly(True)
        self.key_box.setPlaceholderText("Encryption key will appear here.")
        self.key_box.setVisible(False)
        self.key_box.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                padding: 8px;
                font-family: monospace;
            }
        """)
        
        self.copy_button = QPushButton("Copy Key to Clipboard")
        self.copy_button.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.copy_button.clicked.connect(self.copy_key)
        self.copy_button.setVisible(False)
        
        layout.addWidget(self.label)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.key_box)
        layout.addWidget(self.copy_button)
        
        self.main_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.main_screen)

    def authenticate(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if username == "admin" and password == "Pass@123":  #Demo credentials
            self.app_btn.setEnabled(True)
            self.stacked_widget.setCurrentIndex(1)
            QMessageBox.information(self, "Success", "Logged in successfully!")
        
        elif username == "Saurabh" and password == "Saurabh@123":
            self.app_btn.setEnabled(True)
            self.stacked_widget.setCurrentIndex(1)
            QMessageBox.information(self, "Success", "Logged in successfully!")
        
        elif username == "Bytesafe" and password == "Bytesafe@123":
            self.app_btn.setEnabled(True)
            self.stacked_widget.setCurrentIndex(1)
            QMessageBox.information(self, "Success", "Logged in successfully!")
        
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password")
        

    def encrypt(self):
        """Encrypt the selected file"""
        file_Path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not file_Path:
            return

        if os.path.getsize(file_Path) > 5 * 1024 * 1024:
            QMessageBox.warning(self, "File Too Large", "Please select a file smaller than 5 MB.")
            return

        try:
            encrypted_path, key = encrypt_file(file_Path)
            self.result_label.setText(f"✅ Encrypted file saved at:\n{encrypted_path}")
            self.key_box.setVisible(True)
            self.copy_button.setVisible(True)
            self.key_box.setPlainText(key)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed:\n{str(e)}")

    def copy_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.key_box.toPlainText())
        QMessageBox.information(self, "Copied", " Encryption key copied to clipboard!")
        
    def mro(self):
        return super().mro()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec())