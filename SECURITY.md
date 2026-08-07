# Security policy

## Reporting a vulnerability

Email **security@convira.ai**. Please do not open a public issue for a security report.

Our full vulnerability disclosure policy, including scope and safe-harbour terms, is at
<https://www.convira.ai/vulnerability-disclosure>.

Include whatever you have: affected package and version, the platform and OS version, steps to
reproduce, and what an attacker gains. A rough report you are unsure about is worth more to us
than one you never send.

## What we commit to

- We acknowledge receipt within 3 working days.
- We tell you our assessment, including if we disagree that it is a vulnerability and why.
- We credit you in the fix unless you prefer otherwise.
- We will not pursue legal action over good-faith research conducted under the disclosure
  policy linked above.

We do not currently run a paid bounty programme.

## Scope

In scope: anything in this repository that lets a process escape the confinement this code is
meant to apply, or that causes a capability to be reported as enforced when it is not.

The second one matters as much as the first. This layer's contract is that it never claims a
protection it is not providing, so a false positive in the capability report is a real finding,
not a cosmetic one.

Out of scope here: the rest of the Convira product, our servers, and the marketing site. Those
are covered by the policy linked above and should go to the same address.

## What this code is and is not

This repository is the OS confinement layer only. Publishing it does not establish that a
released Convira build contains this exact source; we do not yet produce reproducible builds.
No third-party audit has been performed on this code. If you are assessing Convira's security
posture, please weigh it on that basis.
