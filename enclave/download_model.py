"""Download a Hugging Face causal LM (tokenizer + weights) into ./model for the enclave image.

    python download_model.py                          # Qwen/Qwen2.5-0.5B-Instruct (default)
    python download_model.py distilgpt2               # the original lightweight GPT-2
    python download_model.py gpt2
    python download_model.py HuggingFaceTB/SmolLM2-360M-Instruct

vsock_server.py loads whatever is in MODEL_DIR. Instruction-tuned models (with a chat template)
are prompted as a chat; base models such as GPT-2 fall back to plain text continuation.
"""
import sys
from pathlib import Path

from transformers import AutoModelForCausalLM, AutoTokenizer

DEFAULT_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"

model_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd() / "model"

print(f"Downloading {model_id} -> {out_dir}")
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id)

tokenizer.save_pretrained(out_dir)
model.save_pretrained(out_dir)
print("Done")
