#!/usr/bin/env python
import os
import sys
from django.core.management.commands.runserver import Command as runserver

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    from django.core.management import execute_from_command_line
    runserver.default_addr = '0.0.0.0'
    runserver.default_port = '9999'
    #runserver.default_ipv6 = False
    #runserver.default_ssl_certificate = None
    #runserver.default_ssl_private_key = None
    #runserver.default_ws_endpoint = None
    execute_from_command_line(sys.argv)

