from fastapi import HTTPException
from fastapi.responses import JSONResponse

class SMSException(HTTPException):
    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(status_code=status_code, detail=message)

    def to_dict(self):
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "status": self.status_code
            }
        }

def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "status": status_code
            }
        }
    )
