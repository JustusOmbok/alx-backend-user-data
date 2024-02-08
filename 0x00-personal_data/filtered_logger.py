#!/usr/bin/env python3
"""Module for obfuscation.
"""
import re
import logging
from typing import List

patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

PII_FIELDS = ("name", "email", "phone", "ssn", "password", "date_of_birth")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """
    Filters specified fields in a log message
    with the provided redaction string.

    Args:
        fields: A list of strings representing all fields to obfuscate.
        redaction: A string representing
        what the field will be obfuscated with.
        message: A string representing the log line.
        separator: A string representing the character
        separating all fields in the log line.

    Returns:
        A string representing the log line with specified fields obfuscated.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes RedactingFormatter with a list of fields to redact.

        Args:
            fields: A list of strings representing fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats a LogRecord, redacting sensitive information.

        Args:
            record: Log record to be formatted.

        Returns:
            A string representing the formatted log record.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt
