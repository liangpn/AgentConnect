# Requirements

The API is designed to retrieve a user's education history. It supports fetching details such as school name, major, degree, achievements, start and end dates. The API must handle errors appropriately and validate input parameters.

# Protocol Flow

## Interaction Flow

1. The client sends a request to the server with the user's ID and an optional parameter to include detailed information.
2. The server processes the request, validates the parameters, and retrieves the education history for the specified user.
3. The server responds with the education history data in a paginated format or an error message if the request fails.

# Data Format

## Request Message Format

The request message must be in JSON format and encoded in UTF-8. The JSON Schema is as follows:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducationHistory"
    },
    "messageId": {
      "type": "string",
      "description": "Unique identifier for the request"
    },
    "userId": {
      "type": "string",
      "description": "User ID"
    },
    "includeDetails": {
      "type": "boolean",
      "description": "Whether to include detailed information",
      "default": false
    },
    "page": {
      "type": "integer",
      "description": "Page number for pagination",
      "minimum": 1
    },
    "pageSize": {
      "type": "integer",
      "description": "Number of records per page",
      "minimum": 1,
      "default": 10
    }
  },
  "required": ["messageType", "messageId", "userId"],
  "additionalProperties": false
}
```

## Response Message Format

The response message will also be in JSON format, encoded in UTF-8. The JSON Schema is as follows:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducationHistory"
    },
    "messageId": {
      "type": "string",
      "description": "Unique identifier matching the request"
    },
    "code": {
      "type": "integer",
      "description": "HTTP status code indicating success or failure"
    },
    "educationHistory": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "institution": { "type": "string" },
          "major": { "type": "string" },
          "degree": { "type": "string", "enum": ["Bachelor", "Master", "Doctorate"] },
          "achievements": { "type": "string" },
          "startDate": { "type": "string", "format": "date" },
          "endDate": { "type": "string", "format": "date" }
        },
        "required": ["institution", "major", "degree", "startDate", "endDate"]
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "currentPage": { "type": "integer" },
        "pageSize": { "type": "integer" },
        "totalPages": { "type": "integer" },
        "totalRecords": { "type": "integer" }
      },
      "required": ["currentPage", "pageSize", "totalPages", "totalRecords"]
    },
    "error": {
      "type": "object",
      "properties": {
        "code": { "type": "integer" },
        "message": { "type": "string" }
      },
      "required": ["code", "message"]
    }
  },
  "required": ["messageType", "messageId", "code"],
  "additionalProperties": false
}
```

# Error Handling

The API adheres to standard HTTP status codes for error handling. Here are the specifics:

- **2xx Success**: When the request is successful and data is returned.
- **4xx Client Errors**: 
  - **400 Bad Request**: Invalid request due to malformed syntax.
  - **404 Not Found**: When user_id does not exist.
  - **422 Unprocessable Entity**: Validation errors of input parameters.
- **5xx Server Errors**: 
  - **500 Internal Server Error**: Unexpected server-side error.

Each error will include a clear description message in the `error` object of the response.