# Security policy

## Supported versions

Only the latest tagged release is supported. This repository contains a safe numeric telemetry emulator; it does not contain ransomware, exploit code, production credentials, or vendor control-plane integrations.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature for security-sensitive findings. For non-sensitive defects, open a GitHub issue. Do not include real customer data, credentials, malware samples, or private manuscript content in either channel.

## Research safety boundary

The emulator creates numeric feature vectors in memory. It does not read, modify, encrypt, rename, delete, snapshot, replicate, or restore user data. Before publication, CI scans the current tree and Git history for manuscripts, local paths, private keys, common GitHub token formats, private email domains, and unapproved authorship markers.
