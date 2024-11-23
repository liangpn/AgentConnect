# Requirements

Design an API interface for retrieving a user's education history, including the following information for each record: school name, major, degree, achievements, start time, and end time. Incorporate error handling and parameter validation mechanisms.

# Protocol Flow

## Interaction Flow

1. **Client Request**: The client sends a request to the server with the user's ID and an optional parameter to include detailed information about the education history.

2. **Server Processing**: The server validates the request parameters. Upon successful validation, it retrieves the education history data for the specified user.

3. **Server Response**: The server sends back a response with the user's education history, formatted according to the specified data structure. In case of validation error or other failures, an appropriate error message and status code are returned.

# Data Format

## Request Message Format

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "retrieveUserEducationHistory"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "userId": {
      "type": "string",
      "description": "Unique identifier of the user"
    },
    "includeDetails": {
      "type": "boolean",
      "description": "Flag indicating whether to include detailed information",
      "default": false
    },
    "page": {
      "type": "integer",
      "description": "Page number for pagination",
      "minimum": 1,
      "default": 1
    },
    "pageSize": {
      "type": "integer",
      "description": "Number of records per page",
      "minimum": 1,
      "default": 10
    }
  },
  "required": ["messageType", "messageId", "userId"]
}
```

## Response Message Format

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "retrieveUserEducationHistory"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "code": {
      "type": "integer",
      "description": "HTTP standard status code indicating the result of the request"
    },
    "message": {
      "type": "string",
      "description": "Description of the response code"
    },
    "educationHistory": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "institution": {
            "type": "string",
            "description": "Name of the educational institution"
          },
          "major": {
            "type": "string",
            "description": "Major of study"
          },
          "degree": {
            "type": "string",
            "enum": ["Bachelor", "Master", "Doctorate"],
            "description": "Type of degree obtained"
          },
          "achievements": {
            "type": "string",
            "description": "Notable achievements"
          },
          "startDate": {
            "type": "string",
            "format": "date",
            "description": "Start date of the education period"
          },
          "endDate": {
            "type": "string",
            "format": "date",
            "description": "End date of the education period"
          }
        },
        "required": ["institution", "major", "degree", "startDate", "endDate"]
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "page": {
          "type": "integer",
          "description": "Current page number"
        },
        "pageSize": {
          "type": "integer",
          "description": "Number of records per page"
        },
        "totalPages": {
          "type": "integer",
          "description": "Total number of pages available"
        },
        "totalRecords": {
          "type": "integer",
          "description": "Total number of records available"
        }
      },
      "required": ["page", "pageSize", "totalPages", "totalRecords"]
    }
  },
  "required": ["messageType", "messageId", "code", "message", "educationHistory", "pagination"]
}
```

# Error Handling

1. **Success (200 OK)**: The request is successful, and the user's education history is returned.

2. **Client Error (400 Bad Request)**: Returned when the request is missing required parameters or includes invalid values. Includes a descriptive error message.

3. **Unauthorized (401 Unauthorized)**: Returned when the user is not authenticated to access the requested resource.

4. **Not Found (404 Not Found)**: Returned when the specified user ID does not exist.

5. **Server Error (500 Internal Server Error)**: Returned for unhandled exceptions on the server, along with an error description message.