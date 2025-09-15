#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    # Add custom commands for bug bounty automation
    from django.core.management.commands.runserver import Command as RunserverCommand

    # Override runserver to start both Django and FastAPI
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        # Check if we should run in hybrid mode (Django + FastAPI)
        if '--fastapi' in sys.argv:
            sys.argv.remove('--fastapi')
            run_fastapi_server()
        else:
            execute_from_command_line(sys.argv)
    else:
        execute_from_command_line(sys.argv)


def run_fastapi_server():
    """Run FastAPI server alongside Django."""
    import uvicorn
    from api.main import app

    # Get host and port from command line args or use defaults
    host = "127.0.0.1"
    port = 8000

    for i, arg in enumerate(sys.argv):
        if arg.startswith('127.0.0.1:') or arg.startswith('0.0.0.0:'):
            host, port = arg.split(':')
            port = int(port)
        elif ':' in arg and arg.replace(':', '').replace('.', '').isdigit():
            parts = arg.split(':')
            if len(parts) == 2:
                host, port = parts[0], int(parts[1])

    print(f"Starting FastAPI server at http://{host}:{port}")
    print("API documentation available at http://{host}:{port}/docs")
    print("Alternative API docs at http://{host}:{port}/redoc")

    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info",
        access_log=True
    )


if __name__ == '__main__':
    main()
