
# API Testers Documentation

This documentation is designed to guide API testers on how to test the endpoints effectively. It includes endpoint descriptions, request formats, sample responses, and tips for troubleshooting.

---

## Base URL
```
http://127.0.0.1:8000/
```

---

## Endpoints

### 1. Fetch All Testimonies
- **Method**: `GET`
- **Endpoint**: `api/text-testimonies/`
- **Description**: Retrieves a list of all testimonies, with optional filters.
- **Query Parameters**:
  - `status` (optional): Filter by status (`Pending`, `Approved`, `Rejected`).
  - `category` (optional): Filter by category (e.g., `Healing`, `Deliverance`).
  - `start_date` (optional): Start date for filtering (format: `YYYY-MM-DD`).
  - `end_date` (optional): End date for filtering (format: `YYYY-MM-DD`).

#### Example Request
```
GET api/text-testimonies/?status=Approved&category=Healing
GET api/text-testimonies/?status=Approved&category=Deliverance
GET api/text-testimonies/?status=Approved
```

#### Example Response
```json
{
    "count": 2,
    "results": [
        {
            "id": 1,
            "name": "John Doe",
            "category": "Healing",
            "content": "I was healed from sickness.",
            "date_submitted": "2025-01-18T10:00:00Z",
            "likes": 15,
            "comments": 5,
            "shares": 2,
            "status": "Approved"
        }
    ]
}
```

---

### 2. Approve or Reject a Testimony
- **Method**: `POST`
- **Endpoint**: `api/text-testimonies/<testimony_id>/review/`
- **Description**: Approves or rejects a testimony based on admin action.
- **Headers**:
  - `Content-Type`: `application/json`
- **Payload**:
  - **Approve**:
    ```json
    {
        "action": "approve"
    }
    ```
  - **Reject**:
    ```json
    {
        "action": "reject",
        "rejection_reason": "Inappropriate content"
    }
    ```

#### Example Request
```
POST api/text-testimonies/1/review/
```

#### Example Response
- **Success**:
  ```json
  {
      "message": "Testimony updated successfully."
  }
  ```
- **Error**:
  ```json
  {
      "error": "Testimony not found."
  }
  ```

---

### 3. Fetch Global Settings
- **Method**: `GET`
- **Endpoint**: `api/settings/`
- **Description**: Retrieves the global settings for testimonies.

#### Example Request
```
GET api/settings/
```

#### Example Response
```json
{
    "likes_enabled": true,
    "comments_enabled": true,
    "shares_enabled": false,
    "notification_settings": true
}
```

---

### 4. Update Global Settings
- **Method**: `PATCH`
- **Endpoint**: `api/settings/`
- **Description**: Updates the global settings for testimonies.
- **Headers**:
  - `Content-Type`: `application/json`
- **Payload**:
  ```json
  {
      "likes_enabled": true,
      "comments_enabled": false,
      "shares_enabled": true
  }
  ```

#### Example Request
```
PATCH api/settings/
```

#### Example Response
```json
{
    "message": "Settings updated successfully."
}
```

---

## Testing Guidelines

### Prerequisites
1. Ensure the server is running and accessible via the base URL.
2. Use appropriate authentication tokens if required.
3. Have a tool like Postman, VSCode REST Client, or similar to test API requests.

### Notes
- Validate that all fields in the payload are properly formatted.
- Check for edge cases, such as:
  - Submitting empty or invalid payloads.
  - Using invalid IDs for testimonies.
- Ensure filters like `start_date` and `end_date` are working correctly.

---

## Troubleshooting
1. **401 Unauthorized**: Ensure valid authentication tokens are included in the headers.
2. **404 Not Found**: Check if the resource (e.g., testimony ID) exists.
3. **500 Server Error**: Report the issue to the development team with request details.

---

## Pagination
Endpoints like `api/text-testimonies/` support pagination. Use the following query parameters:
- `page`: The page number (e.g., `?page=2`).
- `page_size`: Number of items per page (e.g., `?page_size=10`).

Example:
```
GET api/text-testimonies/?page=1&page_size=5
```

---

Happy Testing! 🚀
