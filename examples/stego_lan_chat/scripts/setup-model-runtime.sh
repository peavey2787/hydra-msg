#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."
runtime_dir="target/stego-model-runtime"
python_path="$runtime_dir/bin/python"

if [[ ! -x "$python_path" ]]; then
  python3 -m venv "$runtime_dir"
fi

"$python_path" -m pip install --upgrade pip
"$python_path" -m pip install \
  'torch>=2.4,<3' \
  'transformers>=4.45,<6' \
  'huggingface-hub>=0.25,<2' \
  'safetensors>=0.4,<1'

echo "Model runtime ready at $python_path"
echo "Model weights are downloaded when you select a model in the browser demo."
