# HYDRA-MSG QA workspace

This directory contains validation, evidence, and quality-assurance
infrastructure for HYDRA-MSG.

`qa/` is not protocol specification and not runtime/library implementation
source. Protocol authority lives in `docs/spec/`. Runtime/reference
implementation source lives in `crates/`.

QA artifacts may be release-critical. Passing CI, reproducible vectors, fuzzing
results, manifests, and provenance records can become part of the production
release evidence. However, the existence of files in `qa/` does not by itself
prove that a check passed.

## Contents

```text
qa/
├── ci/       # reusable CI/local-check scripts
├── fuzz/     # dedicated fuzzing infrastructure, targets, corpora, artifacts
├── vectors/  # generated vectors, manifests, provenance, frozen/candidate evidence
└── tools/    # validation and vector-generation tooling
```

## Authority model

docs/spec/ defines the HYDRA-MSG protocol.
docs/impl/ defines required implementation profiles.
docs/validation/ defines evidence, vector, interoperability, and release criteria.
docs/roadmap.md defines roadmap/progress tracking.
crates/ contains runtime/reference implementation source.
qa/ contains executable validation infrastructure and release evidence.

## Rules for AI coding agents

AI coding agents may add or update files under qa/ only when doing validation,
testing, vector generation, fuzzing, CI, provenance, or release-evidence work.

AI coding agents must not:

change protocol semantics from this directory;
treat candidate vectors as frozen vectors;
claim fuzzing, CI, backend reproduction, or vector validation passed merely
because files exist;
move protocol specification files into qa/;
move runtime/reference implementation source into qa/.

When in doubt, check docs/roadmap.md and resume from
the first incomplete milestone.
