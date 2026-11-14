"""The guard as a real Windows service ("Satsuma Core"), hosted by the Windows service manager.

The service manager starts it at boot as LocalSystem and, through the recovery
settings written at install, starts it again a minute after a failure. A stop
request ends the loop cleanly and is recorded; the record shows that a stop
was requested, not who requested it.

Bekçi gerçek bir Windows hizmeti olarak ("Satsuma Core"), Windows hizmet
yöneticisi tarafından barındırılır. Hizmet yöneticisi onu açılışta
LocalSystem olarak başlatır ve kurulumda yazılan kurtarma ayarlarıyla bir
hata sonrası bir dakika içinde yeniden başlatır. Durdurma isteği döngüyü
temiz biçimde bitirir ve kaydedilir; kayıt durdurma istendiğini gösterir,
kimin istediğini göstermez.
"""
import servicemanager
import win32event
import win32service
import win32serviceutil

from .guard import Guard, run_loop

SERVICE_NAME = 'SatsumaCore'


class SatsumaService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = 'Satsuma Core'
    _svc_description_ = 'Satsuma Core ag ve sistem korumasi'

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        # Stopping includes the ClamAV scan thread and clamd (up to about 15 seconds).
        # Durma, ClamAV tarama iş parçacığını ve clamd'yi de kapsar (yaklaşık 15 saniyeye kadar).
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=60000)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        guard = Guard(echo=lambda *_: None)
        guard.start()
        run_loop(guard, lambda seconds: win32event.WaitForSingleObject(
            self.stop_event, int(seconds * 1000)) == win32event.WAIT_OBJECT_0)


def run():
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(SatsumaService)
    servicemanager.StartServiceCtrlDispatcher()
