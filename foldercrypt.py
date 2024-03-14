import sys
import os
import shutil
import tempfile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QFileDialog,
    QMessageBox, QInputDialog, QLineEdit, QHBoxLayout, QPushButton, QProgressBar,
    QSizePolicy
)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QPixmap
import pyAesCrypt

bufferSize = 64 * 1024
encryption_ext = ".aes"
default_folder_path = os.path.expanduser("~")
logo_path = os.path.join(os.path.dirname(__file__), 'logo.png')

class WorkerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, file_path, password, is_encrypting):
        super().__init__()
        self.file_path = file_path
        self.password = password
        self.is_encrypting = is_encrypting

    def run(self):
        try:
            if self.is_encrypting:
                self.encryptFolder()
            else:
                self.decryptFile()
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, "Operation failed.")

    def encryptFolder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = shutil.make_archive(os.path.join(temp_dir, "archive"), 'zip', self.file_path)
            self.progress.emit(33)
            encrypted_file_path = archive_path + encryption_ext
            pyAesCrypt.encryptFile(archive_path, encrypted_file_path, self.password, bufferSize)
            self.progress.emit(66)
            shutil.move(encrypted_file_path, os.path.join(os.path.dirname(self.file_path), os.path.basename(self.file_path) + encryption_ext))
            self.progress.emit(100)
            self.finished.emit(True, "Folder encrypted successfully.")

    def decryptFile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            decrypted_file_path = os.path.join(temp_dir, "decrypted")
            pyAesCrypt.decryptFile(self.file_path, decrypted_file_path, self.password, bufferSize)
            self.progress.emit(33)
            shutil.unpack_archive(decrypted_file_path, os.path.splitext(self.file_path)[0], 'zip')
            self.progress.emit(100)
            self.finished.emit(True, "File decrypted successfully.")

class FolderCryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('FolderCrypt')
        self.setFixedSize(QSize(600, 400))
        self.setAcceptDrops(True)
        self.setupStyles()
        self.layoutSetup()

    def setupStyles(self):
        self.setStyleSheet("""
        QWidget { background-color: #2c3e50; color: #ecf0f1; }
        QLabel, QPushButton { font-size: 16px; }
        QPushButton {
            background-color: #34495e; border: 2px solid #ecf0f1; border-radius: 10px;
            padding: 5px; font-weight: bold;
        }
        QPushButton:hover { background-color: #2980b9; }
        QPushButton:pressed { background-color: #16a085; }
        QProgressBar {
            border: 2px solid #ecf0f1; border-radius: 5px; text-align: center;
        }
        QProgressBar::chunk {
            background-color: #27ae60; width: 20px; margin: 0.5px;
        }
        """)

    def layoutSetup(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        self.logo_label = QLabel(self)
        pixmap = QPixmap(logo_path)
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)

        self.info_label = QLabel("Drag and Drop a folder or press the buttons below to encrypt or decrypt.", self)
        self.info_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.info_label, alignment=Qt.AlignCenter)

        spacer_top = QWidget(self)
        spacer_top.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(spacer_top)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setRange(0, 100)
        main_layout.addWidget(self.progress_bar)

        buttons_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.clicked.connect(self.encryptFolder)
        buttons_layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.clicked.connect(self.decryptFolder)
        buttons_layout.addWidget(self.decrypt_button)

        main_layout.addLayout(buttons_layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isdir(file_path):
                self.startEncryption(file_path)
            elif file_path.endswith(encryption_ext):
                self.startDecryption(file_path)

    def encryptFolder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder", default_folder_path)
        if folder_path:
            self.startEncryption(folder_path)

    def decryptFolder(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", default_folder_path, "AES files (*.aes)")
        if file_path:
            self.startDecryption(file_path)

    def startEncryption(self, folder_path):
        password, ok = QInputDialog.getText(self, "Password Input", "Enter a password to encrypt the folder:", QLineEdit.Password)
        if ok and password:
            confirm_password, confirm_ok = QInputDialog.getText(self, "Password Confirmation", "Confirm your password:", QLineEdit.Password)
            if confirm_ok and password == confirm_password:
                self.setupThread(folder_path, password, True)
            else:
                QMessageBox.warning(self, 'Password Mismatch', 'The passwords do not match. Please try again.')

    def startDecryption(self, file_path):
        print("Starting decryption for file:", file_path)
        password, ok = QInputDialog.getText(self, "Password Input", "Enter a password to decrypt the file:",
                                            QLineEdit.Password)
        if ok and password:
            print("Password entered:", password)
            self.setupThread(file_path, password, False)
        else:
            print("Password input canceled.")

    def setupThread(self, file_path, password, is_encrypting):
        self.thread = WorkerThread(file_path, password, is_encrypting)
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.finished.connect(self.onFinished)
        self.thread.error.connect(self.onError)
        self.thread.start()

    def onFinished(self, success, message):
        QMessageBox.information(self, "Success" if success else "Failed", message)
        self.progress_bar.setValue(0)

    def onError(self, message):
        QMessageBox.critical(self, "Error", message)
        self.progress_bar.setValue(0)

    def closeEvent(self, event):
        if self.isThreadRunning():
            reply = QMessageBox.question(self, 'Exit', "A process is still running. Are you sure you want to exit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

    def isThreadRunning(self):
        if hasattr(self, 'thread') and isinstance(self.thread, QThread):
            return self.thread.isRunning()
        return False


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = FolderCryptApp()
    ex.show()
    sys.exit_code = app.exec_()
    sys.exit(sys.exit_code)
