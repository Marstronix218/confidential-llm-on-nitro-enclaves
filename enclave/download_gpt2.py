# Downloads the original GPT-2 (124M) base model into ./model.
# Equivalent to: python download_model.py gpt2
import subprocess
import sys
from pathlib import Path

subprocess.check_call([sys.executable, str(Path(__file__).with_name("download_model.py")), "gpt2", *sys.argv[1:]])
