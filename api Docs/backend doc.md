
# **Documentation for Testers**

This document provides a comprehensive guide for testers to verify the functionality of the **Admin System API**. It includes steps for testing, expected behaviors, and example scenarios to ensure the system works as intended.

---

## **Table of Contents**
1. [Testing Environment](#1-testing-environment)
2. [Test Prerequisites](#2-test-prerequisites)
3. [Test Scenarios and Steps](#3-test-scenarios-and-steps)
    - [Login Endpoint](#login-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Send Invitation Code](#send-invitation-code)
    - [Validate Invitation Code](#validate-invitation-code)
    - [Create Password](#create-password)
4. [Expected Behaviors](#4-expected-behaviors)
5. [Reporting Issues](#5-reporting-issues)

---

## **1. Testing Environment**

### **Technologies Used**
- Backend: Django REST Framework (DRF)
- Authentication: JWT
- Database: SQLite (for local testing)

### **Environment Setup**
1. Clone the project repository:
   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. Create a virtual environment:
   ```bash
   python -m venv env
   source env/bin/activate  # Use `env\Scripts\activate` on Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run database migrations:
   ```bash
   python manage.py migrate
   ```

5. Start the development server:
   ```bash
   python manage.py runserver
   ```

6. Obtain or create a **superuser** for testing:
   ```bash
   python manage.py createsuperuser
   ```

---

## **2. Test Prerequisites**

- Ensure the backend server is running.
- Install a tool like **Postman** or **cURL** to test API endpoints.
- Ensure the database is initialized with a superuser account for the `send-invitation-code` functionality.

---

## **3. Test Scenarios and Steps**

### **Login Endpoint**
#### **Endpoint**: `/api/login/`
#### **Method**: `POST`

#### **Steps**:
1. Provide a valid email and password of an existing user.
2. Verify that the response contains a `refresh` and `access` token.
3. Test with incorrect credentials to verify the error message.

#### **Expected Responses**:
- **Valid Credentials**: 200 OK with tokens.
- **Invalid Credentials**: 401 Unauthorized.

---

### **Logout Endpoint**
#### **Endpoint**: `/api/logout/`
#### **Method**: `POST`

#### **Steps**:
1. Obtain a valid `refresh` token from the login endpoint.
2. Submit the token in the request payload.
3. Verify that the response confirms successful logout.

#### **Expected Responses**:
- **Valid Token**: 200 OK.
- **Missing/Invalid Token**: 400 Bad Request.

---

### **Send Invitation Code**
#### **Endpoint**: `/api/send-invitation-code/`
#### **Method**: `POST`

#### **Steps**:
1. Log in with a **superuser** account to obtain a token.
2. Include the token in the `Authorization` header.
3. Submit a valid email address in the request payload.
4. Check if the response confirms that the invitation code was sent.

#### **Expected Responses**:
- **Superuser Access**: 200 OK with a success message.
- **Non-Superuser Access**: 403 Forbidden.
- **Invalid/Missing Token**: 401 Unauthorized.

---

### **Validate Invitation Code**
#### **Endpoint**: `/api/validate-invitation-code/`
#### **Method**: `POST`

#### **Steps**:
1. Submit the email and invitation code sent to the new admin.
2. Test scenarios with:
   - A valid email and code.
   - An expired code.
   - A code that has already been used.

#### **Expected Responses**:
- **Valid Code**: 200 OK with a success message.
- **Expired Code**: 400 Bad Request.
- **Invalid Email/Code**: 404 Not Found.
- **Already Used Code**: 400 Bad Request.

---

### **Create Password**
#### **Endpoint**: `/api/create-password/`
#### **Method**: `POST`

#### **Steps**:
1. Submit a valid email, password, and confirm password in the payload.
2. Verify that the passwords match.
3. Test scenarios where:
   - The invitation code is not validated.
   - The passwords do not match.

#### **Expected Responses**:
- **Successful Account Creation**: 201 Created.
- **Passwords Do Not Match**: 400 Bad Request.
- **Invalid Email**: 404 Not Found.

---

## **4. Expected Behaviors**

| **Test Case**                         | **Expected Behavior**                                       |
|---------------------------------------|------------------------------------------------------------|
| Login with valid credentials          | Returns access and refresh tokens.                         |
| Login with invalid credentials        | Returns 401 Unauthorized.                                  |
| Logout with valid token               | Logs out successfully, token blacklisted.                  |
| Send invitation code as superuser     | Sends code via email and returns success message.          |
| Send invitation code as non-superuser | Returns 403 Forbidden.                                     |
| Validate a valid invitation code      | Returns 200 OK.                                            |
| Validate an expired code              | Returns 400 Bad Request.                                   |
| Create password with valid details    | Creates the admin account and returns success message.     |
| Create password with mismatched data  | Returns 400 Bad Request for mismatched passwords.          |

---

## **5. Reporting Issues**

### **Steps to Report an Issue**
1. Provide a detailed description of the issue.
2. Include the steps to reproduce the issue.
3. Provide screenshots or logs if applicable.
4. Share the payload and response (mask sensitive data).

### **Example Issue Report**:
- **Endpoint**: `/api/send-invitation-code/`
- **Method**: `POST`
- **Payload**:
  ```json
  {
      "email": "new_admin@example.com"
  }
  ```
- **Response**:
  ```json
  {
      "error": "Authentication credentials were not provided."
  }
  ```












### **Contact**
Reach out to the development team for support or clarification.

---
