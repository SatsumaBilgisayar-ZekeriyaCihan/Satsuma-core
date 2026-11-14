import sys
sys.exit(0 if sys.stdin.buffer.read()==b'test-only-correct' else 1)
