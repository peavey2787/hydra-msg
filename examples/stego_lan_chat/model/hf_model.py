#!/usr/bin/env python3
"""Persistent deterministic Hugging Face backend for the HYDRA stego demo."""

from __future__ import annotations

import argparse
from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import sys


_last_progress: tuple[int, str] | None = None


DISALLOWED_WORDS = {
    "analysis", "assistant", "example", "format", "input", "instruction",
    "instructions", "message", "messages", "metadata", "output", "prompt",
    "recipient", "response", "role", "sender", "system", "transcript", "user",
}


def encode_hex(value: str) -> str:
    return value.encode("utf-8").hex()


def decode_hex(value: str) -> str:
    return bytes.fromhex(value).decode("utf-8")


def reply(value: str = "") -> None:
    print("ok" if not value else f"ok\t{value}", flush=True)


def fail(error: Exception) -> None:
    print(f"err\t{encode_hex(str(error))}", flush=True)


def emit_progress(percent: int, message: str) -> None:
    global _last_progress
    progress = (max(0, min(100, int(percent))), message)
    if progress == _last_progress:
        return
    _last_progress = progress
    print(f"progress\t{progress[0]}\t{encode_hex(progress[1])}", flush=True)


def parse_tokens(value: str) -> list[int]:
    return [] if not value else [int(token) for token in value.split(",")]


def ordinary_visible_token(text: str) -> bool:
    if not text or any(character in text for character in "\r\n\t0123456789#{}[]()<>*`|\\\":~&=+_^%$@/"):
        return False
    if any(
        character == "\u2063"
        or "\ufe00" <= character <= "\ufe0f"
        or "\U000e0100" <= character <= "\U000e01ef"
        for character in text
    ):
        return False
    return text.lower().strip(" .,!?;'-_") not in DISALLOWED_WORDS


def snapshot_fingerprint(snapshot: Path, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8"))
    digest.update(Path(__file__).read_bytes())
    suffixes = {".bin", ".json", ".model", ".safetensors", ".tiktoken", ".txt"}
    for path in sorted(path for path in snapshot.rglob("*") if path.is_file()):
        if path.suffix.lower() not in suffixes:
            continue
        relative = path.relative_to(snapshot).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    return "hf-sha256:" + digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--dtype", choices=("float32", "float16", "bfloat16"), default="float32")
    args = parser.parse_args()

    import torch
    import transformers
    from huggingface_hub import snapshot_download
    from tqdm.auto import tqdm
    from transformers import AutoModelForCausalLM, AutoTokenizer

    download_progress_enabled = True

    class ProtocolProgress(tqdm):
        """Render Hugging Face progress as machine-readable protocol events."""

        def display(self, msg=None, pos=None) -> None:
            if not download_progress_enabled:
                return
            total = float(self.total or 0)
            ratio = 0.0 if total <= 0 else min(1.0, float(self.n) / total)
            description = str(self.desc or "model files").strip().rstrip(":")
            percent = 8 + round(ratio * 52)
            if total > 0:
                status = f"{description}: {int(self.n)}/{int(total)}"
            else:
                status = description
            emit_progress(percent, status)

    torch.use_deterministic_algorithms(True)
    if args.device == "cpu":
        torch.set_num_threads(1)
    emit_progress(3, "starting local model runtime")
    emit_progress(6, "checking the local model cache")
    snapshot = Path(
        snapshot_download(
            repo_id=args.model,
            revision=args.revision,
            tqdm_class=ProtocolProgress,
        )
    )
    download_progress_enabled = False
    emit_progress(64, "model files are available locally")
    emit_progress(68, "loading tokenizer")
    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True)
    dtype = getattr(torch, args.dtype)
    emit_progress(74, "loading model weights into memory")
    try:
        model = AutoModelForCausalLM.from_pretrained(
            snapshot, local_files_only=True, dtype=dtype
        )
    except TypeError:
        model = AutoModelForCausalLM.from_pretrained(
            snapshot, local_files_only=True, torch_dtype=dtype
        )
    model.to(args.device)
    model.eval()
    emit_progress(90, "configuring deterministic inference")

    resolved_revision = snapshot.name
    identity = "|".join((
        "hydra-hf-process-v1",
        args.model,
        resolved_revision,
        tokenizer.__class__.__name__,
        str(len(tokenizer)),
        args.dtype,
        args.device,
        torch.__version__,
        transformers.__version__,
    ))
    emit_progress(94, "fingerprinting model and tokenizer artifacts")
    fingerprint = snapshot_fingerprint(snapshot, identity)
    special = set(tokenizer.all_special_ids)
    for token, token_id in tokenizer.get_vocab().items():
        if token.startswith("<|") and token.endswith("|>"):
            special.add(token_id)

    token_text_cache: dict[int, str] = {}
    cached_ids: list[int] = []
    cached_logits = None
    cached_past = None
    candidate_cache: OrderedDict[tuple, str] = OrderedDict()
    emit_progress(99, "local model is ready")

    def token_text(token_id: int) -> str:
        if token_id not in token_text_cache:
            token_text_cache[token_id] = tokenizer.decode(
                [token_id], skip_special_tokens=False, clean_up_tokenization_spaces=False
            )
        return token_text_cache[token_id]

    def next_logits(ids: list[int]):
        nonlocal cached_ids, cached_logits, cached_past
        if not ids:
            raise ValueError("model prompt cannot tokenize to an empty context")
        maximum = getattr(model.config, "max_position_embeddings", None)
        if maximum is not None and len(ids) >= int(maximum):
            raise ValueError(
                f"model context limit reached at {len(ids)} tokens (maximum {maximum}); "
                "use a shorter message or a longer-context model"
            )
        if ids == cached_ids and cached_logits is not None:
            return cached_logits
        with torch.inference_mode():
            if cached_past is not None and ids[:-1] == cached_ids:
                input_ids = torch.tensor([[ids[-1]]], device=args.device)
                output = model(input_ids=input_ids, past_key_values=cached_past, use_cache=True)
            else:
                input_ids = torch.tensor([ids], device=args.device)
                output = model(input_ids=input_ids, use_cache=True)
            cached_ids = list(ids)
            cached_logits = output.logits[0, -1].float()
            cached_past = output.past_key_values
            return cached_logits

    for line in sys.stdin:
        try:
            parts = line.rstrip("\r\n").split("\t")
            operation = parts[0]
            if operation == "info" and len(parts) == 1:
                reply(fingerprint)
            elif operation == "tokenize" and len(parts) == 2:
                tokens = tokenizer.encode(decode_hex(parts[1]), add_special_tokens=False)
                reply(",".join(str(token) for token in tokens))
            elif operation == "detokenize" and len(parts) == 2:
                text = tokenizer.decode(
                    parse_tokens(parts[1]),
                    skip_special_tokens=False,
                    clean_up_tokenization_spaces=False,
                )
                reply(encode_hex(text))
            elif operation == "next" and len(parts) == 4:
                top_n = int(parts[1])
                ids = parse_tokens(parts[2])
                visible_tokens = parse_tokens(parts[3])
                # Hash the serialized context instead of retaining a cumulative
                # token tuple for every position (which would grow quadratically).
                cache_key = (
                    hashlib.sha256(parts[2].encode("ascii")).digest(),
                    tuple(visible_tokens[-12:]),
                    top_n,
                )
                cached_candidates = candidate_cache.get(cache_key)
                if cached_candidates is not None:
                    candidate_cache.move_to_end(cache_key)
                    reply(cached_candidates)
                    continue
                logits = next_logits(ids).clone()
                if special:
                    logits[list(special)] = -torch.inf
                pool_n = min(logits.shape[-1], max(top_n * 16, top_n + 128))
                values, indices = torch.topk(logits, k=pool_n, sorted=True)
                candidates: list[tuple[int, float]] = []
                tail = visible_tokens[-12:]
                for token_id, score in zip(indices.tolist(), values.tolist()):
                    token_id = int(token_id)
                    text = token_text(token_id)
                    if not ordinary_visible_token(text):
                        continue
                    probe = tail + [token_id]
                    probe_text = tokenizer.decode(
                        probe, skip_special_tokens=False, clean_up_tokenization_spaces=False
                    )
                    if tokenizer.encode(probe_text, add_special_tokens=False) != probe:
                        continue
                    candidates.append((token_id, float(score)))
                    if len(candidates) == top_n:
                        break
                if len(candidates) != top_n:
                    raise ValueError(
                        f"only {len(candidates)} copy-safe visible candidates are available; "
                        f"the arithmetic codec requested {top_n}"
                    )
                encoded_candidates = ",".join(
                    f"{token_id}:{score!r}" for token_id, score in candidates
                )
                candidate_cache[cache_key] = encoded_candidates
                if len(candidate_cache) > 4096:
                    candidate_cache.popitem(last=False)
                reply(encoded_candidates)
            else:
                raise ValueError("invalid model protocol request")
        except Exception as error:
            fail(error)


if __name__ == "__main__":
    # Avoid tokenizer helper-thread variability and noisy warnings.
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    main()
