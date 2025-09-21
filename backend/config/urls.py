"""
URL Configuration for Bug Bounty Automation Platform
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.http import JsonResponse
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'Bug Bounty Automation Platform',
        'version': '1.0.0'
    })


def api_root(request):
    """API root endpoint with basic information"""
    return JsonResponse({
        'message': 'Bug Bounty Automation Platform API',
        'version': '1.0.0',
        'endpoints': {
            'vulnerabilities': '/api/v1/vulnerabilities/',
            'targets': '/api/v1/targets/',
            'reconnaissance': '/api/v1/reconnaissance/',
            'scanning': '/api/v1/scanning/',
            'exploitation': '/api/v1/exploitation/',
            'reporting': '/api/v1/reporting/',
            'docs': '/api/docs/',
            'redoc': '/api/redoc/',
        }
    })


# Main URL patterns
urlpatterns = [
    # Health check
    path('health/', health_check, name='health-check'),

    # Admin interface
    path(f'{settings.ADMIN_URL}', admin.site.urls),

    # API root
    path('api/', api_root, name='api-root'),

    # API documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/docs/', 
        SpectacularSwaggerView.as_view(url_name='schema'), 
        name='swagger-ui'
    ),
    path(
        'api/redoc/', 
        SpectacularRedocView.as_view(url_name='schema'), 
        name='redoc'
    ),

    # API v1 endpoints
    path('api/v1/vulnerabilities/', include('apps.vulnerabilities.urls')),
    path('api/v1/targets/', include('apps.targets.urls')),
    path('api/v1/reconnaissance/', include('apps.reconnaissance.urls')),
    path('api/v1/scanning/', include('apps.scanning.urls')),
    path('api/v1/exploitation/', include('apps.exploitation.urls')),
    path('api/v1/reporting/', include('apps.reporting.urls')),

    # Redirect root to API docs
    path('', RedirectView.as_view(url='/api/docs/', permanent=False)),
]

# Development-specific URLs
if settings.DEBUG:
    import debug_toolbar

    urlpatterns = [
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns

    # Silk profiling URLs
    if 'silk' in settings.INSTALLED_APPS:
        urlpatterns += [
            path('silk/', include('silk.urls', namespace='silk'))
        ]

# Static and media files serving
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Custom error handlers
handler400 = 'core.views.bad_request'
handler403 = 'core.views.permission_denied'
handler404 = 'core.views.page_not_found'
handler500 = 'core.views.server_error'

# Admin site customization
admin.site.site_header = "Bug Bounty Platform Administration"
admin.site.site_title = "Bug Bounty Platform Admin"
admin.site.index_title = "Welcome to Bug Bounty Platform Administration"
