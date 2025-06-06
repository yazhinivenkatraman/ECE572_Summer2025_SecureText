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

<!-- Replace Task X, Y, Z with actual task numbers and names  -->

### 2.1 Task 1: Security Vulnerability Analysis

#### 2.1.2 Implementation Details
<!-- Describe your implementation approach and include the corresponding screenshots -->
The SecureText application was explored by running the server and multiple client instances. Actions performed:
- **Created accounts with usernames and passwords**
- **Sent messages between users**
- **Attempted password resets**
- **Observed system behavior during login, logout, messaging, and error handling**

**Key Components**:
- Component 1: Authentication and Account Management
Handled via create_account() and authenticate() functions. Issues such as weak password handling, insecure reset, and broken login flow were observed here.
- Component 2: Messaging and User Interface Flow
Message sending logic using send_message() revealed broken input handling and UI lock after sending messages, preventing further actions.
- Component 3: User Management and Feedback
The list_users() function failed to return the expected list of users, and login/logout feedback was missing or ineffective.

**Code Snippet** (Key Implementation):
```python
# Include only the most important code snippets
# Do not paste entire files as the actual attack or security-fixed codes are included in the deliverables directory
def key_function():
    # Your implementation
    pass
```
This snippet demonstrates a critical flaw: no verification of current user credentials before resetting the password.

#### 2.1.3 Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->
Challenge 1: After sending a message and pressing Enter, message is sent, but not able to come back to the options menu to send message, list users and logout. Cursor just stops after sending message and create new line for every Enter.
Solution: Restarted the client; identified the lack of input flow control in send_message() as the root cause.

Challenge 2: Multiple accounts were allowed to create with weak and identical passwords.
Solution: Documented as a critical authentication weakness due to lack of password policy enforcement.

Challenge 3: Reset password option is not secure enough. It lacks identity verification, asks for the username and directly asking for a new password, instead of current password.
Solution: Flagged as a critical vulnerability requiring immediate reimplementation using authentication checks.

Challenge 4: When entered an incorrect password, no error message is displayed, instead cursor shows a new line when pressed Enter.
Solution: Highlighted the need for secure and clear feedback mechanisms.

Challenge 5: Session issues after logout prevented re-login. Not able to login second time, when already logged in to an user account, logout and login again.
Solution: Identified faulty session reset logic, to be fixed in upcoming tasks.

Challenge 6: List users option is not working as expected, not listing any available users.
Solution: Noted as a user enumeration and access control flaw.

#### 2.1.4 Testing and Validation
<!-- How did you test that your implementation works correctly? -->
The application was tested manually across multiple terminals with varying user behaviors. The following test cases were executed:

TC1: Created accounts using short, common passwords (e.g., "12345") → Allowed without restriction.
TC2: Reset password for another user without login or verification → Success, no checks performed.
TC3: Logged in with invalid credentials → No error message shown, only cursor moves to a new line.
TC4: Sent message to a non-existent user → Application accepts it; no validation.
TC5: Attempted to log in again after logging out → No response from system; session seems broken.
TC6: Used list_users command → Returned empty list even though users existed.
TC7: Sent a message and pressed Enter repeatedly → Menu did not return; stuck in a loop.

**Test Cases**
**Evidence**:
<!-- Include extra screenshots, logs, or other evidence -->

---

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
