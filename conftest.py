"""Repository test collection: Satsuma's tests live in tests/.

satsuma-video-recovery and satsuma-core-windows are separate products with its own tests, run in its
own directory by tests/test_video_recovery_project.py; its file names (for
example test_engine.py) would otherwise collide with Satsuma's.

Depo test toplama: Satsuma testleri tests/ altındadır. satsuma-video-recovery
ayrı bir üründür; testleri kendi klasöründe tests/test_video_recovery_project.py
ile çalıştırılır, aksi halde dosya adları Satsuma'nınkilerle çakışırdı.
"""
collect_ignore = ['satsuma-video-recovery', 'satsuma-core-windows']
