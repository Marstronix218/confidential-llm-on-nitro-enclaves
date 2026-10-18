# Downloads the lightweight DistilGPT-2 (82M) base model into ./model.
# Equivalent to: python download_model.py distilgpt2
import subprocess
import sys
from pathlib import Path

subprocess.check_call([sys.executable, str(Path(__file__).with_name("download_model.py")), "distilgpt2", *sys.argv[1:]])
