<div align="center">

# 🇳🇵 TrustFeed Nepal
### A PKI-based Cryptographic Tool for Verifying Threat Intelligence Feeds

</div>

> **🎓 Academic Submission Notice:** 
> This repository is maintained as an open-source project but is being submitted for the **ST6051CEM Practical Cryptography** module. 
> **Student Name:** Aakriti Shrestha
 
> **Date:** June 2026

---

##  Overview
**TrustFeed Nepal** is a command-line cryptographic tool designed to ensure the integrity, authenticity, and non-repudiation of threat intelligence feeds. 

While global threat feeds are abundant, there is a distinct lack of structured, cryptographically verifiable threat intelligence tailored for the Nepali cybersecurity ecosystem (covering local ISPs, NTC/Ncell ranges, and local banking threats). TrustFeed Nepal addresses this gap by implementing a lightweight Public Key Infrastructure (PKI) to secure the distribution of localized threat data.

##  Cryptographic Architecture
To achieve distinction-level security and performance, the tool utilizes modern, rigorously evaluated cryptographic primitives:

*   **Digital Signatures (Ed25519):** Chosen over RSA/ECDSA for its deterministic signatures, smaller key sizes, and immunity to nonce-reuse (k-value) vulnerabilities.
*   **Symmetric Encryption (AES-256-GCM):** Provides Authenticated Encryption with Associated Data (AEAD), ensuring both confidentiality and integrity while avoiding padding oracle attacks inherent in AES-CBC.
*   **Key Encapsulation (RSA-OAEP):** Used to securely wrap symmetric keys for feed distribution, mitigating Bleichenbacher attacks associated with older PKCS#1 v1.5 padding.

##  Video Demonstration
A full walkthrough of the tool's functionality, including the tamper-detection demonstration and test suite execution, can be found here:

**This will be available soon**

##  Prerequisites
Before you begin, ensure you have the following installed:
*   **Python:** Version 3.8 or higher
*   **pip:** Python package installer

##  Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/shrestha13/TrustFeed.git
   cd TrustFeed
