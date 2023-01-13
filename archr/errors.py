class ArchrError(Exception):
    pass

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"{self.message}"


class ArchrValueError(ArchrError, ValueError):
    pass
