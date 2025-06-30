---

**Student Name**: [Yazhini Venkatraman]  
**Student ID**: [V01049681]  
**Assignment**: [Assignment 2]  
**Date**: [12 July 2025]  
**GitHub Repository**: [https://github.com/yazhinivenkatraman/ECE572_Summer2025_SecureText.git]

---

## Executive Summary

<!-- 
Provide a brief overview of what you accomplished in this assignment. 
For Assignment 1: Focus on vulnerabilities found and security improvements made
For Assignment 2: Focus on authentication enhancements and Zero Trust implementation  
For Assignment 3: Focus on cryptographic protocols and end-to-end security
Keep this section to 1-2 paragraphs.
-->

[Write your executive summary here]

---

## Table of Contents

1. [Introduction](#introduction)
2. [Task Implementation](#task-implementation)
   - [Task X](#task-x)
   - [Task Y](#task-y)
   - [Task Z](#task-z)
3. [Security Analysis](#security-analysis)
4. [Attack Demonstrations](#attack-demonstrations)
5. [Performance Evaluation](#performance-evaluation)
6. [Lessons Learned](#lessons-learned)
7. [Conclusion](#conclusion)
8. [References](#references)

---

---

## 2. Task Implementation

### 2.1 Task 4: [Multi-Factor Authentication with TOTP]

#### Part A: TOTP Implementation
- To strengthen the User authentication mechanism, I have implemented a Time based One-Time Password methon.
- In this mechanism, when the new user is created, TOTP secret is enabled which is securely stored with the password and salt. 
- Using **pyotp** python library, TOTP secret is generated and URI is in the below format:

```
otpauth://totp/SecureText:<username>?secret=<base32_secret>&issuer=SecureText
```

- Python library named **qrcode** is used to enclode this URI in QR code image. Then the encoded QR code is displayed directly in the server terminal using ASCII format. 

![QR Code ASCII image in terminal](images/task4_partA_img1.png)

- After account creation users can scan the QR code using an authenticator app and the TOTP will be generated.
- I have used an Authenticator application from app store compatible for iPhones. Which generates TOTP every 30 seconds.

![Authenticator App](images/task4_partA_img2.jpeg)

- task4_partA_img1.png shows that the QR code is generated on the server side when a new user account is created. 
- During the time of login with user name and password, it prompts for OTP secret, meanwhile the Authenticator mobile app, generates TOPT every 30 seconds. 

![TOTP successful login](images/task4_partA_img3.png)

- After entering the TOTP, user is successfully logged in to created user account.

![users.json file](images/task4_partA_img4.png)

#### Part B: Security Analysis and Attack Demonstrations
**1. Demonstrate Authentication Bypass:**
**Scenario:**
Let us take a scenario of a user's password is compromised via phishing or with data breach.

**Without TOTP:**
An attacker who only has the password could login and take the possession of the user login.

**With TOTP:**
Even with the correct username and password, the attacker cannot login into user account. They need the current valid TOTP code generated on the user’s authenticator app. This could prevent the attack from happening.

**Conclusion:**
This demonstrates that TOTP prevents unauthorized login attacks, even when the user account passwords are compromised. This TOTP method effectively mitigating many common password-based attacks. 

**2. TOTP Security Analysis:**
**Cryptographic Basis:**
- HMAC-SHA1 is used to build TOTP.
- During account creation a shared secret is been established.
- TOTP works by hashing the secret with a moving timestamp generally in 30-second windows, ensuring that codes are time-based one-time use.

**Time Synchronization Issues:**
- TOTP depends mostly on the system time on both the client and the server.
- Python libraries like pyotp allow 1-step window tolerance to handle slight time drifts.
- It is very important to keep the system clock in sync with Network Time Protocol.

**Backup & Recovery:**
- TOTP is always device-bound (30 seconds). If the user loses their phone, access is completely lost unless they have some backup codes included with account during the time of setup.
- An account recovery process might be needed in place.


**3. Attack Vectors and Mitigations:**
**SIM Swapping:**
- In a SIM-swap attack an SMS-based two-factor authentication, an attacker might convinces the telecom provider to port your number to their SIM.
- Any SMS based OTP sent for 2FA could be intercepted.
- TOTP-based apps are more immune to SIM swapping because phone numbers are not included in the authenticator apps.

| Factor               | SMS-based 2FA     | TOTP-based 2FA     |
|----------------------|-------------------|---------------------|
| Delivery method      | Over carrier network | On-device app     |
| Vulnerable to SIM swap | Yes              | No                  |
| Internet required     | No               | No                  |
| Setup complexity      | Easy             | Moderate (QR scan)  |
| Security              | Medium           | High                |

**Phishing Resistance:**
- Normal phishing pages can able to request the OTP from authenticator app, but it’s usable only for a short window basically 30 seconds.
- More secure variants such as WebAuthn or U2F are more phishing-resistant.
- TOTP improves user account security significantly over just username and passwords but is not fully phishing-proof.

#### Part C: User Experience Considerations

**Security vs. Usability:**

- **Rate Limiting:** Although this is not implemented in this version, it is very important to limit the number of TOTP attempts using authenticator app during a single login to prevent brute-force attacks. During this implementation we should avoid user lockouts due to simple mistakes.
   
- **Time Window Tolerance:** TOTP inherently allows a small time window 30 seconds in most cases, to account for slight clock drift between the client and server. This improves usability without significantly weakening security.
   
- **Helpful Error Messages:** The system provides user-friendly error messages during login, e.g., "Invalid TOTP code", "Missing TOTP code". This helps in reducing the information leakage like username is incorrect or password is incorrect. 

---

### 2.2 Task 5: [OAuth Integration]

#### Part A: Console-Compatible OAuth 2.0 Implementation

#### Part B: Security Features

#### Part C: Security Analysis


---


### 2.3 Task 6: [Zero Trust Implementation]

#### Part A: Challenge-Response Authentication

#### Part B: Role-Based Access Control (RBAC) and Session Security

#### Part C: Logging and Basic Monitoring

---