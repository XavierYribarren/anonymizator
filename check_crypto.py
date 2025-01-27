import sys
import cryptography

print("Python executable:", sys.executable)
print("Cryptography version:", cryptography.__version__)
print("Cryptography location:", cryptography.__file__)

print("\nPython sys.path:")
for path in sys.path:
    print(path)