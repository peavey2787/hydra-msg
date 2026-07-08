# HYDRA-MSG fuzzing workspace

Status: reserved QA workspace.

This directory is reserved for dedicated fuzzing infrastructure such as cargo-fuzz/libFuzzer targets, fuzz corpora, crash reproducers, sanitizer configs, and minimization artifacts.

Current active Rust tests live inside the active workspace crates. P12 removed the old excluded test scaffold from the production branch because it was not active QA evidence.

Do not treat this directory as evidence that dedicated fuzzing has been implemented or run.

AI coding agents may add files here only when creating real fuzzing infrastructure. They must not mark fuzzing complete until runnable fuzz targets, corpus policy, and CI/manual run instructions exist.
