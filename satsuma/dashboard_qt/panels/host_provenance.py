"""Deployment and package exposure; no mutations from the panel."""
from . import register
from ._module import ReadOnlyModulePanel, QLabel


@register
class HostProvenancePanel(ReadOnlyModulePanel):
    PANEL_ID = 'host_provenance'
    PANEL_TITLE = 'SİSTEM KÖKENİ VE PAKET RİSKİ'
    PANEL_GROUP = 'system'
    PANEL_ORDER = 15
    PANEL_SUBTITLE = 'Fedora / OSTree / bootc · sistem denetimi · Python ve paket riskleri (salt okunur)'
    METHOD = 'host_provenance'
    KEY = 'items'
    COLUMNS = (('Tür', 'kind'), ('Nesne', 'name'), ('İşaret', 'signal'), ('Ayrıntı', 'detail'))

    def _build(self):
        super()._build()
        self.summary = QLabel('Sistem kökeni henüz sorgulanmadı')
        self.summary.setWordWrap(True)
        self._layout.insertWidget(2, self.summary)

    def refresh(self, *args):
        super().refresh(*args)
        if not self._last_render:
            return
        data = self._last_render[1]
        release = data.get('os_release') or {}
        pkg = data.get('packages') or {}
        risk = data.get('integrated_risk') or {}
        advisory = risk.get('advisories') or {}
        scripts = risk.get('python_audit') or {}
        self.summary.setText(
            'Sistem: ' + str(release.get('PRETTY_NAME') or 'Bilinmiyor') +
            ' · Deployment: ' + str(data.get('mode') or 'Bilinmiyor') +
            '\nPID1: ' + str((data.get('supervision') or {}).get('pid1') or 'Bilinmiyor') +
            ' · Gözlenen RPM: ' + str(pkg.get('count_observed', 0)) +
            '\nFedora guvenlik onbellegi: ' + str(advisory.get('status', 'BILINMIYOR')) +
            ' · Guncelleme adaylari: ' + str(len(advisory.get('items') or [])) +
            ' · Python sezgisel kaydi: ' + str(scripts.get('status', 'BILINMIYOR')) +
            '\nCVE surum dogrulamasi: ' + str((data.get('cve_evidence') or {}).get('status', 'BILINMIYOR')) +
            ' · CVE eslesmesi: ' + str(len((data.get('cve_evidence') or {}).get('items') or [])) +
            '\nOSTree imza raporu: ' + str((data.get('ostree_signature_evidence') or {}).get('status','BILINMIYOR')) +
            ' · ISO imzasi: ' + str((data.get('iso_signature_evidence') or {}).get('status', 'BILINMIYOR')) +
            '\nBagimsiz deployment referansi: ' + str((data.get('signed_deployment_reference') or {}).get('status','BILINMIYOR')) +
            ' · bootc imza politikasi: ' + str((data.get('bootc_policy_evidence') or {}).get('status','BILINMIYOR')) +
            '\nSecure Boot: ' + str(((data.get('boot_chain_evidence') or {}).get('secure_boot') or {}).get('status','BILINMIYOR')) +
            ' · TPM: ' + str(((data.get('boot_chain_evidence') or {}).get('tpm') or {}).get('status','BILINMIYOR')) +
            ' · PCR gunlugu: ' + str(((data.get('boot_chain_evidence') or {}).get('pcr_log') or {}).get('status','BILINMIYOR')) +
            ' · TPM quote: ' + str((data.get('tpm_quote_evidence') or {}).get('status', 'BILINMIYOR')) +
            '\nTPM EK/AK kimlik kaniti: ' + str((data.get('tpm_ek_identity_evidence') or {}).get('status', 'BILINMIYOR')) +
            '\nTPM AK/EK credential activation: ' + str((data.get('tpm_credential_activation_evidence') or {}).get('status', 'BILINMIYOR')) +
            '\nTPM kalici nesne envanteri: ' + str((data.get('tpm_integrity_evidence') or {}).get('status', 'BILINMIYOR')) +
            ' · TPM acik nesne kimligi: ' + str((data.get('tpm_public_evidence') or {}).get('status', 'BILINMIYOR')) +
            '\nYerel RPM veritabanı güvenilir kaynak olarak doğrulanmadı. '
            'Paket sayısı güvenlik açığı sayısı değildir. Python sezgisel ve imza '
            'taramaları mevcut ayrı motorlar üzerinden çalışır. '
            'Manipüle edilmiş ISO dışarıdan güvenilir referans olmadan aklanamaz.'
        )
