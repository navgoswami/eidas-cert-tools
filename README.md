# EIDAS Certificate Validator (Java)

A lightweight Java utility for extracting **PSD2 / eIDAS roles** from X.509 Qualified Certificates (QCStatements) using **Bouncy Castle**.

It parses the ETSI PSD2 QCStatement (`0.4.0.19495.2`) and detects the corresponding Payment Service Provider (PSP) roles:

| OID                         | Role  |
|-----------------------------|-------|
| `0.4.0.19495.1.1`           | ASPSP |
| `0.4.0.19495.1.2`           | PISP  |
| `0.4.0.19495.1.3`           | AISP  |
| `0.4.0.19495.1.4`           | CBPII |

This is useful for identity providers, trust service consumers, and financial platforms validating PSD2/eIDAS certificates issued to payment institutions.

---

## Features
- Extracts PSD2 roles from an X.509 certificate
- Uses QCStatements as defined by ETSI standards
- Simple to integrate into existing Java security flows
- Zero dependencies besides Bouncy Castle

---

## 📌 Usage
### 1. Add Dependencies
Ensure Bouncy Castle is on your classpath:

**Maven:**
```xml
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcprov-jdk18on</artifactId>
  <version>1.78</version>
</dependency>
