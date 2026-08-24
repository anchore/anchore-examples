# Contributing to Anchore Examples Repository

First off, thank you for considering contributing! It is people like you who make this a valuable resource for the entire community.

By contributing to this repository, you help other users solve complex environment issues and edge cases that fall outside our core product.

---

## ⚖️ The Legal Bit (Important!)

By submitting a Pull Request (PR) to this repository, you agree to the following:

1.  **Licensing:** Your contribution will be licensed under the [Apache License 2.0](LICENSE).
2.  **Rights:** You represent that you are the rightful owner of the contribution or have the express permission of the owner to submit it under this license.
3.  **No Compensation:** You understand that contributions are voluntary and no compensation (financial or otherwise) will be provided.

---

## ✍️ Signing Your Contribution (DCO)

We've chosen to use the Developer's Certificate of Origin (DCO) method that is employed by the Linux Kernel Project, which provides a simple way to contribute to the Anchore project. **Every commit in your Pull Request must be signed off** — the DCO check will fail otherwise.

The process is to certify the DCO 1.1 text below:

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then, when it comes time to submit a contribution, include the following text in your contribution commit message:

```text
Signed-off-by: Joan Doe <joan.doe@email.com>
```

This message can be entered manually, or if you have configured git with the correct `user.name` and `user.email`, you can use the `-s` option to `git commit` to automatically include the signoff message. If you forgot to sign off commits already on your branch, you can fix them with `git rebase --signoff main` and force-push.

---

## 🚀 How to Contribute

### 1. Find or Create an Issue
Before writing code, check the **Issues** tab to see if someone else is already working on a similar script. If not, feel free to open a "Proposal" issue to discuss your idea.

### 2. Fork and Clone
Fork this repository to your own GitHub account and clone it locally:
```bash
git clone https://github.com/YOUR-USERNAME/anchore-examples.git
```

## 3. Script Requirements
To ensure the scripts remain safe and readable for all customers, please adhere to these guidelines:

Safety First: Scripts should never delete data without a `--force` flag or a clear user confirmation prompt.

Documentation: Include a comment block at the top explaining what the script does, any prerequisites (like kubectl or python3), and example usage.

Header Disclaimer: Every script must include the standard legal header found in the README.

## 4. Testing
Since Anchore does not officially maintain these scripts, we rely on contributors to verify their work.

Test your script in a non-production environment.

Check for hardcoded paths or credentials—always use variables or environment flags instead.

## 5. Submit a Pull Request
Once your script is ready:

Sign off every commit (`git commit -s`) — see [Signing Your Contribution (DCO)](#%EF%B8%8F-signing-your-contribution-dco).

Push your changes to your fork.

Open a Pull Request against our main branch.

Provide a clear description of the problem the script solves and any risks associated with it.

## 🛠 Review Process
Our support engineers will review Pull Requests periodically. We look for:

Adherence to the legal header requirement.

General code safety (no obvious "malicious" or destructive patterns).

Clarity of instructions.

Note: Merging a script does not imply that Anchore will maintain it in the future. Once merged, the script becomes a community-maintained asset.

Thank you for helping us build a better ecosystem for Anchore users!