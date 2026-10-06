Infrastructure Notes
====================

Public infrastructure and execution model
------------------------------------------

The default artifact checks are designed to run on a minimal Linux VM with
1 CPU, 2 GB RAM, and 10 GB of disk space. No GPU, GUI, network access, Docker,
or paid API is required.

No external allocation is required for the default offline checks. The
artifact can be executed in a standard Linux VM or container with Python
3.10 or later and Bash. The artifact repository URL supplied in the ACSAC
submission system is the public source location for the package.

Constraints and access
----------------------

The package does not require the original fuzzing campaign environments, full
CASR replay environments, or live LLM/API services. These components are
outside the default offline evaluation package. The package includes processed
evidence-card slices, ranked outputs, cached LLM responses, and supporting logs
for claim verification. No private reviewer account or special remote access
is required.

Required for quick checks:

  - bash
  - Python >= 3.10 using only the Python standard library

Not required for the submitted quick checks:

  - network access
  - live LLM/API credentials
  - Docker
  - LaTeX

Optional: Docker and replay environments are only relevant for reconstructing
selected CASR/MAGMA component replays from original environments. The submitted
artifact instead includes processed evidence-card slices, ranked outputs, CASR
reports/logs, and cached LLM responses so that reviewers can exercise the paper
claims offline.

Runtime guidance:

  - all default paper-claim checks: typically a few seconds;
  - 77-variant weight sensitivity: typically several minutes;
  - 20,000-round global bootstrap/permutation: potentially several minutes.

The default verifier writes to reproduced/ and leaves canonical outputs intact.
