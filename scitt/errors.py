class ResponseError(Exception):
    """Raised for non 20x api responses"""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code

    def __str__(self):
        if self.status_code:
            return f"Status {self.status_code}: {self.args[0]}"
        return self.args[0]


class ResponseContentError(Exception):
    """Raised when the responce content is not as expected"""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code

    def __str__(self):
        if self.status_code:
            return f"Status {self.status_code}: {self.args[0]}"
        return self.args[0]
