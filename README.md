# Authenticated Diffie-Hellman Classroom Project

A Python 3 local simulation of Alice and Bob exchanging a shared secret using
custom square-and-multiply, library-generated primes, primitive generators,
trusted Ed25519 signatures, and fresh nonces. Eve's demonstrations show what
changes when public values are authenticated.

## Start here on Windows

1. Extract the project ZIP into a folder.
2. Open that folder. Double-click **RUN_PROJECT.bat** to set up and run the project.
3. The window runs the demonstration, tests, and nine timing trials. Read the
   labeled results in that window and in the `results` folder.

Python 3.9 or newer must be installed and available as `py` or `python`.
Dependency installation needs an internet connection the first time.
The recorded verification used Python 3.12.14 on Windows 11.

## Manual setup

Open a terminal in the project folder and run:

```text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
```

On macOS/Linux, use `.venv/bin/python` for the last two commands.
Pinned, tested dependencies: **cryptography 50.0.2** and **PyCryptodome 4.2.0**.
Only the standard library and these two packages are needed to run/test the project.

## Run individual parts

Commands below assume the virtual environment is activated, or that `python`
is replaced by the appropriate virtual-environment Python path above.

```text
python main.py
python main.py --mode authenticated --bits 16
python main.py --mode authenticated --bits 24
python main.py --mode authenticated --bits 32
python main.py --mode authenticated --fixture --debug
python main.py --mode attacks
python main.py --mode benchmark --trials 3
python -m unittest discover -v
```

The default size is 16 bits. Every integer size from 16 through 32 is supported.
`--fixture` is the explicit small-example path using p=23, g=5, a=6, b=15.
It is never the default generated run. `--debug` reveals the local shared secret
under a classroom debug label. Normal generated exchanges hide private values.
The attack demonstration explicitly labels its tiny fixture secrets as debug output.

Running only `python des.py` was silent in the earlier DES assignment because
that file defined functions. Here, run **main.py** to see the demonstration.

## What each file does

| File | Purpose |
|---|---|
| modular_math.py | Custom square-and-multiply |
| parameters.py | Prime generation/validation, trial division, generator checks, DH keypairs |
| participant.py | Local identity keys, trusted setup, and session state |
| authentication.py | Strict JSON parsing, canonical encoding, Ed25519 signing/verification |
| protocol.py | Three authenticated messages and local secret calculation |
| eve.py | Tampering helpers and the unauthenticated fixture |
| main.py | Demonstrations, timing, and command-line options |
| tests/ | Mathematical, integration, validation, and exchange tests |
| results/ | Actual sample output, test log, timing CSV, and environment |
| REPORT.md | Algorithm explanations, examples, results, and limitations |
| RESEARCH.md | 300-500-word finite-field DH / ECDH comparison and references |
| CHECKLIST.md | Mapping of the assignment steps to the completed files |
| report.pdf | Dark-background readable report, research, and timing appendix |

## How to read the output

The successful run prints the public p, g, A, B, nonces, and all three signed JSON
messages. It then prints valid signatures, authenticated transcript status, and
the local shared-secret comparison. The messages never contain private exponents,
signing private keys, or raw shared secrets.

The attack run prints Eve's fixture substitutions. Without authentication, Alice
gets 6 and Bob gets 15 while Eve can calculate both. With authentication, changing
B from 19 to 17 invalidates Bob's original signature and Alice aborts.

The automated tests must end in **OK**. The saved verification log records **54
passing test methods**, with additional subtests inside many methods.
`results/performance.csv` records three successful exchanges at each required size,
and `results/performance.md` summarizes the actual durations and variation.
Regenerating results changes random parameters, signatures, nonces, and timings.

## Security and scope

This is the specified classroom simulation. Its 16-32-bit groups are intentionally
too small for confidentiality. A signature authenticates the signed transcript;
it does not establish that the peer computed the DH secret. The program reports
**Explicit key confirmation: NOT IMPLEMENTED** separately from the local secret
comparison. Sockets, application-message encryption, and ECDH implementation are
optional extensions and are not included.

Alice and Bob have separate long-term signing keys that remain in memory across
exchanges. A trusted setup binds each identity to its real signing public key
before any simulated network message is processed. Incoming messages cannot
replace those trusted bindings. One session per participant is active at a time.

## Put this project on GitHub later

1. Create your GitHub repository when you are ready.
2. On the repository page choose **Add file -> Upload files**.
3. Upload the extracted project contents, including the `tests` and `results`
   folders, the report, README, and requirements file. Keep the same folder layout.
4. Review the files and commit the upload.

Upload the files inside the extracted folder, rather than only uploading the ZIP,
so GitHub can display the code and README. Do not upload `.venv`, `__pycache__`,
or private key files. No real private keys are saved in this project.

## References

- [PyCryptodome prime utilities](https://www.pycryptodome.org/src/util/util#module-Crypto.Util.number)
- [Python secrets](https://docs.python.org/3/library/secrets.html)
- [cryptography Ed25519](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/)
- [cryptography ECDH](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm)
- [RFC 9528, EDHOC](https://www.rfc-editor.org/rfc/rfc9528.html)

The implementation follows the photographed project handout supplied for this
assignment. Detailed citations for the comparison appear in RESEARCH.md.
