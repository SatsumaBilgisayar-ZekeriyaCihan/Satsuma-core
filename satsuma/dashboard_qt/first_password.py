"""First administrator password, authorized by polkit and sent only over a pipe."""
import getpass
try:
    from PyQt6.QtWidgets import QDialog,QVBoxLayout,QLabel,QLineEdit,QPushButton
    from PyQt6.QtCore import QProcess
except ImportError:
    from PyQt5.QtWidgets import QDialog,QVBoxLayout,QLabel,QLineEdit,QPushButton
    from PyQt5.QtCore import QProcess


class FirstPassword(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setWindowTitle('Satsuma — ilk yönetici parolası')
        layout=QVBoxLayout(self)
        layout.addWidget(QLabel('Yeni Satsuma yönetici parolası (en az 12 karakter)'))
        self.password=QLineEdit();self.confirm=QLineEdit()
        for field in (self.password,self.confirm):
            field.setEchoMode(QLineEdit.EchoMode.Password if hasattr(QLineEdit,'EchoMode') else QLineEdit.Password)
            layout.addWidget(field)
        self.confirm.setPlaceholderText('Parolayı tekrar girin')
        self.status=QLabel('İşlem için sistem yönetici onayı istenir.');self.status.setWordWrap(True);layout.addWidget(self.status)
        self.button=QPushButton('Parolayı oluştur');layout.addWidget(self.button);self.button.clicked.connect(self.save)
        self.process=QProcess(self);self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(lambda *_:self.failed())

    def save(self):
        value=self.password.text()
        if not 12<=len(value)<=1024 or value!=self.confirm.text():
            self.status.setText('Parolalar aynı ve 12–1024 karakter uzunluğunda olmalı.');return
        self.password.clear();self.confirm.clear();self.button.setEnabled(False)
        self.process.start('/usr/bin/pkexec',['/usr/bin/satsuma-enroll-desktop','--user',getpass.getuser(),'--password-stdin'])
        self.process.write(value.encode('utf-8'));self.process.closeWriteChannel()

    def _finished(self,code,*_):
        if code==0:
            self.status.setText('Parola oluşturuldu. Yönetici girişi bölümünden oturum açabilirsiniz.')
        else:self.failed()

    def failed(self):
        self.button.setEnabled(True)
        self.status.setText('Parola oluşturulamadı veya sistem onayı iptal edildi. Mevcut parola varsa Yönetici girişi bölümünü kullanın.')

    def closeEvent(self,event):
        stopped=QProcess.ProcessState.NotRunning if hasattr(QProcess,'ProcessState') else QProcess.NotRunning
        if self.process.state()!=stopped:
            self.status.setText('Yetkilendirme tamamlanana veya iptal edilene kadar bekleyin.');event.ignore();return
        super().closeEvent(event)
