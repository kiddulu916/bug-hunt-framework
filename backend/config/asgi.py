"""
ASGI config for Bug Bounty Automation Platform.

It exposes the ASGI callable as a module-level variable named ``application``.
This configuration supports both Django and FastAPI applications.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Set the default Django settings module (Docker-aware)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Get Django ASGI application early to ensure Django is set up
django_asgi_app = get_asgi_application()

# Import FastAPI app after Django setup
from api.main import app as fastapi_app

# Create the main ASGI application that combines Django and FastAPI
class ASGIApplication:
    def __init__(self, django_app, fastapi_app):
        self.django_app = django_app
        self.fastapi_app = fastapi_app

    async def __call__(self, scope, receive, send):
        # Docker health checks
        if scope["type"] == "http" and scope["path"] == "/health":
            response = {
                'type': 'http.response.start',
                'status': 200,
                'headers': [[b'content-type', b'application/json']],
            }
            await send(response)
            await send({
                'type': 'http.response.body',
                'body': b'{"status": "healthy", "service": "backend"}',
            })
            return

        # Route API requests to FastAPI
        if scope["type"] == "http" and scope["path"].startswith("/api/"):
            await self.fastapi_app(scope, receive, send)
        # Route WebSocket connections to FastAPI
        elif scope["type"] == "websocket":
            await self.fastapi_app(scope, receive, send)
        # Route everything else to Django
        else:
            await self.django_app(scope, receive, send)

# Create the combined application
application = ASGIApplication(django_asgi_app, fastapi_app)

# Alternative simple configuration for development
# If you want to run only FastAPI:
# application = fastapi_app

# If you want to run only Django:
# application = django_asgi_app
