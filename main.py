# main.py
import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QFileDialog,
    QVBoxLayout, QLabel, QMessageBox, QTextEdit, QHBoxLayout
)
from PyQt6.QtGui import QClipboard
from Include.encryptor import encrypt_file
from cryptography.fernet import Fernet

class FileEncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryption App")
        self.setGeometry(100, 100, 500, 300)
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()

        self.label = QLabel("Select a file to upload (Max 5MB):")
        self.layout.addWidget(self.label)

        self.encrypt_button = QPushButton("Choose File")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.layout.addWidget(self.encrypt_button)

        self.result_label = QLabel("")
        self.layout.addWidget(self.result_label)

        self.key_box = QTextEdit()
        self.key_box.setReadOnly(True)
        self.key_box.setPlaceholderText("Encryption key will appear here.")
        self.key_box.setVisible(False)
        self.layout.addWidget(self.key_box)

        self.copy_button = QPushButton("Copy Key to Clipboard")
        self.copy_button.clicked.connect(self.copy_key)
        self.copy_button.setVisible(False)
        self.layout.addWidget(self.copy_button)

        self.setLayout(self.layout)

    def encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not file_path:
            return

        if os.path.getsize(file_path) > 5 * 1024 * 1024:
            QMessageBox.warning(self, "File Too Large", "Please select a file smaller than 5 MB.")
            return

        try:
            encrypted_path, key = encrypt_file(file_path)

            self.result_label.setText(f"Encrypted file saved at:\n{encrypted_path}")
            self.key_box.setVisible(True)
            self.copy_button.setVisible(True)
            self.key_box.setPlainText(key)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed:\n{str(e)}")

    def copy_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.key_box.toPlainText())
        QMessageBox.information(self, "Copied", "Encryption key copied to clipboard!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec())

    