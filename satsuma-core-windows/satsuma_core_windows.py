"""Entry point of satsuma-core-windows.exe: the Windows service, or the guard and its commands.

satsuma-core-windows.exe giriş noktası: Windows hizmeti ya da bekçi ve komutları.
"""
import sys

if __name__ == '__main__':
    if sys.argv[1:] == ['--service']:
        from satsuma_win.winservice import run
        run()
        sys.exit(0)
    from satsuma_win.guard import main
    sys.exit(main())
