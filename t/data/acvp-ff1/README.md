# ACVP test vectors for FF1

`internalProjection.json` is a copy of the FF1 test vectors of the NIST ACVP server. The file is not changed: it has the same bytes as the upstream file.

- Repository: https://github.com/usnistgov/ACVP-Server
- Path: `gen-val/json-files/ACVP-AES-FF1-1.0/internalProjection.json`
- Upstream commit: `b97fa5aeb6b5fce8540021b16bdaa32937089aab` (2023-06-01, "RELEASE/v1.1.0.29"). This is the last commit that changed the file. On 2026-11-24 it was still the current version.
- Git blob: `39faea241274305417050ac2b75f599d89ff1334`
- SHA-256: `63cd6642095fbb1ce7af3fa53d7d720d725a58fe331d35ced1540b5e433668ee`

The file has 30 test groups of 25 cases, 750 cases in total. Each case has a key, a tweak, a plaintext and a ciphertext. The groups cover AES-128, AES-192 and AES-256, encryption and decryption, and radix 2, 4, 16, 32 and 64 with the alphabet of each group.

`t/URI-Shortener-FF1-vectors.t` reads this file. By default it runs some cases of each group. If `RELEASE_TESTING` is set, it runs all 750 cases.

## License of the file

The README of the ACVP-Server repository gives this notice. The notice is copied here in full, as it asks:

```text
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
```

The source of these test vectors is the National Institute of Standards and Technology.
