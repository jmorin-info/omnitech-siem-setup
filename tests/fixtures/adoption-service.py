"""Harmless long-running fixture used only by the isolated adoption acceptance VM."""
import time

if __name__ == "__main__":
    while True:
        time.sleep(1)
