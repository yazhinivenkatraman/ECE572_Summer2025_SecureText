# Report for ECE 572

---

**Course**: ECE 572; Summer 2025
**Instructor**: Dr. Ardeshir Shojaeinasab
**Student Name**: Yazhini Venkatraman  
**Student ID**: V01049681
**Assignment**: Assignment 1  
**Date**: 18 June 2025  
**GitHub Repository**: https://github.com/yazhinivenkatraman/ECE572_Summer2025_SecureText.git

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
   - [Task 1: Security Vulnerability Analysis](#task-x)
   - [Task 2: Securing Passwords at Rest](#task-y)
   - [Task 3: Network Security and Message Authentication](#task-z)
3. [Security Analysis](#security-analysis)
4. [Attack Demonstrations](#attack-demonstrations)
5. [Performance Evaluation](#performance-evaluation)
6. [Lessons Learned](#lessons-learned)
7. [Conclusion](#conclusion)
8. [References](#references)

---

## 1. Introduction
This report analyzes security and privacy vulnerabilities in the SecureText application, an intentionally insecure console-based messaging app. The primary focus is to identify fundamental security flaws, understand their implications, and lay the groundwork for secure design principles. The work done in this assignment will guide further tasks related to password storage and network message authentication.

### 1.1 Objective
<!-- Describe the main objectives of this assignment -->
To identify and document at least five major security and privacy vulnerabilities in the SecureText messenger application through manual testing and code analysis.

### 1.2 Scope
<!-- Define what you implemented and what you focused on -->
This report focuses on running and exploring the SecureText application and analyzing its vulnerabilities. Subsequent tasks on secure password storage and secure messaging will be completed later.

### 1.3 Environment Setup
<!-- Briefly describe your development environment -->
- **Operating System**: Linux (5.15.0-kali2)
- **Python Version**: 3.10.4
- **Key Libraries Used**: 
- **Development Tools**: Wireshark, TCPdump, Python

---

## 2. Task Implementation

### 2.1 Task 1: Security Vulnerability Analysis

#### 2.1.1 Explore the Application:

The SecureText console application was launched and interacted using the terminal.
- Created multiple user accounts with weak passwords (including single-character passwords).
- Logged in, logged out, and attempted to log back in.
- Sent messages between users.
- Attempted to send messages to non-existent users.
- Triggered password reset flow.
- Tested user listing and interface behavior after messaging.<br>
This exploration revealed several functional and security-related issues, which are detailed below.

#### 2.1.2 Vulnerability Analysis: Identify and document at least 5 major security and privacy vulnerabilities in the application. For each vulnerability:

**Describe the vulnerability and its location in the code**
**Explain the potential impact if exploited by an attacker**
**Reference relevant security principles from course materials**
**Categorize the vulnerability (e.g., authentication, authorization, data protection, etc.)**

#### Vulnerability 1: Weak Password Policy
**Vulnerability and its location in the code:**
Passwords can be as short as 1 character. No password strength checks exist in create_account().

**Potential impact if exploited by an attacker:**
Makes it easy for attackers to brute-force passwords and compromise accounts.

**Relevant security principles from course materials:**
Secure Defaults, Authentication

**Category:**
Authentication

#### Vulnerability 2: Insecure Password Reset
**Vulnerability and its location in the code:**
In reset_password(), only the username is required to reset a password. The current password is not verified.

**Potential impact if exploited by an attacker:**
An attacker can hijack any account by resetting the password with just the username.

**Relevant security principles from course materials:**
Authentication, Data Protection

**Category:**
Authentication

#### Vulnerability 3: No Username Validation Before Messaging
**Vulnerability and its location in the code:**
In the send_message() function, the recipient username is not validated before sending a message.

**Potential impact if exploited by an attacker:**
Messages could be silently dropped or used to probe for valid usernames, potentially leaking metadata.

**Relevant security principles from course materials**
Input Validation, Authorization

**Category:**
Authorization

#### Vulnerability 4: Broken Login/Logout Session Flow
**Vulnerability and its location in the code:**
After a user logs out, attempting to log in again does not work as expected. Likely a bug in session state handling within the client loop.

**Potential impact if exploited by an attacker:**
Prevents legitimate re-logins, leading to denial-of-service for valid users.

**Relevant security principles from course materials:**
Session Management

**Category:**
Authentication / Availability

#### Vulnerability 5. User Listing Not Working
**Vulnerability and its location in the code:**
The LIST_USERS command does not return any user data, despite accounts being created. Server-side logic fails to display users.

**Potential impact if exploited by an attacker:**
Users cannot discover or connect with others, disrupting communication flow.

**Relevant security principles from course materials:**
Least Privilege, Secure Feedback

**Category:**
Authorization

#### Vulnerability 6. Application Freezes After Sending Message
**Vulnerability and its location in the code:**
After using the send_message() feature, the user cannot return to the menu. The UI remains unresponsive and traps the input.

**Potential impact if exploited by an attacker:**
Prevents user from performing further actions like logging out or listing users; effectively acts as a denial of service.

**Relevant security principles from course materials:**
Fail Secure, Robustness

**Category:**
Usability


#### 2.1.3 Attack Scenarios: For each identified vulnerability, describe a realistic client-server attack scenario explaining:

**What they would need to carry out the attack**
**What they could achieve if successful**
**Final thoughts and consideration**

Deliverables
Vulnerability Report: Detailed analysis of identified weaknesses
Attack Scenarios: Realistic exploitation scenarios

### 2.2 Task 2: Securing Passwords at Rest

#### 2.2.1 Objective
<!-- What was the goal of this task? -->

#### 2.2.2 Implementation Details
<!-- Describe your implementation approach -->

#### 2.2.3 Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### 2.2.4 Testing and Validation
<!-- How did you test that your implementation works correctly? -->

---

### 2.3 Task 3: Network Security and Message Authentication

#### 2.3.1 Objective
<!-- What was the goal of this task? -->

#### 2.3.2 Implementation Details
<!-- Describe your implementation approach -->

#### 2.3.3 Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### 2.3.4 Testing and Validation
<!-- How did you test that your implementation works correctly? -->

---

## 3. Security Analysis

### 3.1 Vulnerability Assessment
<!-- For Assignment 1: Document vulnerabilities found in the base application -->
<!-- For Assignment 2/3: Analyze security improvements made -->

**Identified Vulnerabilities** (Assignment 1):
| Vulnerability | Severity | Impact | Location(function/action) | Mitigation |
|---------------|----------|---------|----------|------------|
| N/A | N/A | N/A | N/A | N/A |
| N/A | N/A | N/A | N/A | N/A |
| N/A | N/A | N/A | N/A | N/A |

### 3.2 Security Improvements
<!-- Document the security enhancements you implemented -->

**Before vs. After Analysis**:
- **Authentication**: [If applicable otherwise remove][How it improved]
- **Authorization**: [If applicable otherwise remove][How it improved]  
- **Data Protection**: [If applicable otherwise remove][How it improved]
- **Communication Security**: [If applicable otherwise remove][How it improved]

### 3.3 Threat Model
<!-- Describe the threats your implementation addresses -->

**Use the following security properties and threat actors in your threat modeling. You can add extra if needed.**

**Threat Actors**:
1. **Passive Network Attacker**: Can intercept but not modify traffic
2. **Active Network Attacker**: Can intercept and modify traffic
3. **Malicious Server Operator**: Has access to server and database
4. **Compromised Client**: Attacker has access to user's device

**Security Properties Achieved**:
- [ ] Confidentiality
- [ ] Integrity  
- [ ] Authentication
- [ ] Authorization
- [ ] Non-repudiation
- [ ] Perfect Forward Secrecy
- [ ] Privacy

---

## 4. Attack Demonstrations

### 4.1 Attack 1: [Attack Name]

#### 4.1.1 Objective
<!-- What vulnerability does this attack exploit? -->

#### 4.1.2 Attack Setup
<!-- Describe your attack setup and tools used -->

**Tools Used**:
- Tool 1: [Purpose]
- Tool 2: [Purpose]

#### 4.1.3 Attack Execution
<!-- Step-by-step description of the attack -->

1. Step 1: [Description]
2. Step 2: [Description]
3. Step 3: [Description]

#### 4.1.4 Results and Evidence
<!-- Show evidence of successful attack -->

**Evidence**:
![Attack Screenshot](images/attack_1_evidence.png)

```
Attack Output:
[Include relevant logs or outputs]
```

#### 4.1.5 Mitigation
<!-- How did you fix this vulnerability? -->

---

### 4.2 Attack 2: [Attack Name]

#### 4.2.1 Objective
#### 4.2.2 Attack Setup  
#### 4.2.3 Attack Execution
#### 4.2.4 Results and Evidence
#### 4.2.5 Mitigation

---

## 5. Performance Evaluation
Basic test results in terms of resources used in terms of hardware and time. Also, if the test has limitations and fix worked properly(test passed or failed)

**Measurement Setup**:
- Test Environment: [Descriptions+Screenshots]
- Test Data: [Descriptions+Screenshots]
- Measurement Tools/Methods: [Descriptions+Screenshots]
- Test Results: [Descriptions+Screenshots]

---

## 6. Lessons Learned

### 6.1 Technical Insights
<!-- What did you learn about security implementations? -->

1. **Insight 1**: [Description]
2. **Insight 2**: [Description]
.
.
.
N. **Insight N**: [Description]

### 6.2 Security Principles
<!-- How do your implementations relate to fundamental security principles? -->

**Applied Principles**:
- **Defense in Depth**: [How you applied this]
- **Least Privilege**: [How you applied this]
- **Fail Secure**: [How you applied this]
- **Economy of Mechanism**: [How you applied this]

---

## 7. Conclusion

### 7.1 Summary of Achievements
<!-- Summarize what you accomplished -->

### 7.2 Security and Privacy Posture Assessment
<!-- How secure is your final implementation? -->

**Remaining Vulnerabilities**:
- Vulnerability 1: [Description and justification]
- Vulnerability 2: [Description and justification]

**Suggest an Attack**: In two lines mention a possible existing attack to your current version in abstract

### 7.3 Future Improvements
<!-- What would you do if you had more time? -->

1. **Improvement 1**: [Description]
2. **Improvement 2**: [Description]

---

## 8. References

<!-- 
Include all sources you referenced, including:
- Course materials and lecture notes
- RFCs and standards
- Academic papers
- Documentation and libraries used
- Tools and software references
-->

---

## Submission Checklist

Before submitting, ensure you have:

- [ ] **Complete Report**: All sections filled out with sufficient detail
- [ ] **Evidence**: Screenshots, logs, and demonstrations included
- [ ] **Code**: Well-named(based on task and whether it is an attack or a fix) and well-commented and organized in your GitHub repository deliverable directory of the corresponding assignment
- [ ] **Tests**: Security and functionality tests implemented after fix
- [ ] **GitHub Link**: Repository link included in report and Brightspace submission
- [ ] **Academic Integrity**: All sources properly cited, work is your own

---

**Submission Instructions**:
1. Save this report as PDF: `[StudentID]_Assignment[X]_Report.pdf`
2. Submit PDF to Brightspace
3. Include your GitHub repository fork link in the Brightspace submission comments
4. Ensure your repository is private until after course completion otherwise you'll get zero grade

**Final Notes**:
- Use **GenAI** for help but do not let **GenAI** to do all the work and you should understand everything yourself
- If you used any **GenAI** help make sure you cite the contribution of **GenAI** properly
- Be honest about limitations and challenges
- Focus on demonstrating understanding, not just working code
- Proofread for clarity and technical accuracy

Good luck!
