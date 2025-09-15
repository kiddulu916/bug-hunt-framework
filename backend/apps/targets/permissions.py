"""
Target Management Permissions
backend/apps/targets/permissions.py
"""

from rest_framework import permissions
from django.contrib.auth.models import AnonymousUser

class TargetPermissions(permissions.BasePermission):
    """
    Custom permission class for target management
    
    - All authenticated users can view targets
    - All authenticated users can create targets
    - Users can modify/delete targets they created
    - Superusers can modify/delete any target
    """
    
    def has_permission(self, request, view):
        """Check if user has permission to access the view"""
        # Must be authenticated
        if not request.user or isinstance(request.user, AnonymousUser):
            return False
        
        if not request.user.is_authenticated:
            return False
        
        # Different permissions based on action
        if view.action in ['list', 'retrieve', 'summary', 'statistics']:
            # Read actions - all authenticated users
            return True
        elif view.action in ['create']:
            # Create actions - all authenticated users
            return True
        elif view.action in ['update', 'partial_update', 'destroy']:
            # Modify/delete actions - need object-level permission check
            return True
        elif view.action in ['scope', 'config', 'validate_scope', 'toggle_active']:
            # Special actions - need object-level permission check
            return True
        
        # Default to allowing authenticated users
        return True
    
    def has_object_permission(self, request, view, obj):
        """Check if user has permission to access specific target"""
        # Must be authenticated
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Read permissions for all authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Superusers can do anything
        if request.user.is_superuser:
            return True
        
        # For now, allow all authenticated users to modify targets
        # In production, you might want to add a created_by field to Target model
        # and check: return obj.created_by == request.user
        return True

class TargetConfigPermissions(permissions.BasePermission):
    """
    Permissions for target configuration endpoints
    More restrictive than general target permissions
    """
    
    def has_permission(self, request, view):
        """Only authenticated users can access config"""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Configuration access requires authentication
        return True
    
    def has_object_permission(self, request, view, obj):
        """Restrict config modifications"""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Read permissions for all authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Superusers can modify any configuration
        if request.user.is_superuser:
            return True
        
        # Regular users can modify configurations
        # In production, you might want more restrictions:
        # - Only target owner can modify config
        # - Certain config fields require admin privileges
        return True

class TargetScopePermissions(permissions.BasePermission):
    """
    Permissions for target scope management
    Scope changes are sensitive and should be restricted
    """
    
    def has_permission(self, request, view):
        """Check view-level permissions"""
        if not request.user or not request.user.is_authenticated:
            return False
        return True
    
    def has_object_permission(self, request, view, obj):
        """Check object-level permissions for scope modifications"""
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Read permissions for all authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Superusers can modify any scope
        if request.user.is_superuser:
            return True
        
        # Scope modifications should be carefully controlled
        # For now, allow authenticated users
        # In production, consider additional restrictions:
        # - Only target owner can modify scope
        # - Require approval for scope changes
        # - Log all scope modifications
        return True

class IsTargetOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of a target to edit it.
    
    Note: This assumes a 'created_by' field exists on the Target model.
    Currently commented out since the model doesn't have this field.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner of the target
        # Uncomment when Target model has created_by field:
        # return obj.created_by == request.user
        
        # For now, allow all authenticated users
        return request.user and request.user.is_authenticated