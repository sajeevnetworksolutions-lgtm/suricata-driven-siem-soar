# Contributing to Suricata-Driven SIEM + SOAR

Thank you for your interest in contributing to the **Suricata-Driven SIEM + SOAR** project! We welcome contributions ranging from bug fixes and detection engineering rules to new SOAR playbooks and documentation.

---

## 🛠️ Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please treat all contributors with respect, courtesy, and constructive collaboration.

---

## 🚀 How to Contribute

### 1. Reporting Bugs
- Search the [Issues](https://github.com/sajeevnetworksolutions-lgtm/suricata-driven-siem-soar/issues) page to check if the bug has already been reported.
- If not, open a new issue with a descriptive title, steps to reproduce, expected behavior, system OS, and logs.

### 2. Suggesting New Detection Signatures or Playbooks
- We follow the **MITRE ATT&CK Framework** mapping.
- Propose new Suricata rules under `config/suricata/rules/<category>.rules`.
- Ensure each rule contains:
  - Unique SID (starting from `1000000+`).
  - Clear message tag (`msg:"SIEM-<CATEGORY>: Description"`).
  - Proper `classtype:` and `metadata:mitre_tactic_id, mitre_technique_id`.
  - Realistic rate-limiting thresholds where appropriate to prevent false positives.

### 3. Submitting Pull Requests
1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Implement your changes following standard PEP 8 formatting.
3. Test your changes locally using the test suite:
   ```bash
   python run_and_test.py
   ```
4. Commit your changes with clear, structured commit messages:
   ```bash
   git commit -m "feat(soar): add Telegram webhook notification playbook"
   ```
5. Push to your fork and submit a Pull Request.

---

## 🧪 Testing Guidelines

Before opening a PR, ensure all verification suites pass:
```bash
# Verify all 6 attack scenarios
python attack_simulator/run_attack_suite.py --scenario all

# Run full SOAR verification
python test_verification.py
```

---

## 📜 License
By contributing, you agree that your contributions will be licensed under the project's [Apache 2.0 License](LICENSE).
