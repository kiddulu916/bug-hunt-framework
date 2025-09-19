"""
Notification Service for Bug Bounty Automation Platform
Handles in-app notifications displayed on the frontend with user preferences
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from celery import shared_task
from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship
from sqlalchemy.dialects.postgresql import UUID

from backend.models import (
    Target, ScanSession, Vulnerability, Report, ReconResult,
    VulnSeverity, ScanStatus, BugBountyPlatform, Base
)
from backend.core.database import get_db_session


class NotificationType(Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationCategory(Enum):
    VULNERABILITY = "vulnerability"
    SCAN = "scan"
    EXPLOITATION = "exploitation"
    SYSTEM = "system"
    REPORT = "report"


@dataclass
class NotificationPreferences:
    """User notification preferences"""
    critical_vulnerabilities: bool = True
    high_vulnerabilities: bool = True
    medium_vulnerabilities: bool = False
    low_vulnerabilities: bool = False
    scan_start: bool = True
    scan_completion: bool = True
    scan_failure: bool = True
    exploitation_success: bool = True
    exploitation_failure: bool = False
    exploitation_chains: bool = True
    new_subdomains: bool = False
    new_endpoints: bool = False
    report_generation: bool = True
    system_alerts: bool = True
    
    # Grouping preferences
    group_similar_notifications: bool = True
    max_notifications_per_hour: int = 50
    
    # Display preferences
    desktop_notifications: bool = False
    sound_notifications: bool = False
    auto_dismiss_info: bool = True
    auto_dismiss_timeout: int = 10  # seconds


class Notification(Base):
    """In-app notification model"""
    __tablename__ = "notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(100), nullable=False)  # researcher username
    
    # Notification content
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(SQLEnum(NotificationType), nullable=False)
    category = Column(SQLEnum(NotificationCategory), nullable=False)
    
    # Status and interaction
    is_read = Column(Boolean, default=False)
    is_dismissed = Column(Boolean, default=False)
    is_pinned = Column(Boolean, default=False)
    
    # Metadata and context
    metadata = Column(JSON, default={})  # Additional data like vulnerability_id, scan_id, etc.
    action_url = Column(String(500), nullable=True)  # Frontend route to relevant page
    
    # Grouping for similar notifications
    group_key = Column(String(100), nullable=True)  # For grouping similar notifications
    grouped_count = Column(Boolean, default=1)  # Number of similar notifications grouped
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # Auto-dismiss time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary for API response"""
        return {
            "id": str(self.id),
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "type": self.notification_type.value,
            "category": self.category.value,
            "is_read": self.is_read,
            "is_dismissed": self.is_dismissed,
            "is_pinned": self.is_pinned,
            "metadata": self.metadata,
            "action_url": self.action_url,
            "group_key": self.group_key,
            "grouped_count": self.grouped_count,
            "created_at": self.created_at.isoformat(),
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }


class UserNotificationPreferences(Base):
    """User notification preferences model"""
    __tablename__ = "user_notification_preferences"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(100), nullable=False, unique=True)
    preferences = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NotificationService:
    """Service for managing in-app notifications"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def create_notification(self, user_id: str, title: str, message: str,
                                notification_type: str, category: str = "system",
                                metadata: Optional[Dict[str, Any]] = None,
                                action_url: Optional[str] = None,
                                group_key: Optional[str] = None,
                                expires_in_minutes: Optional[int] = None) -> str:
        """Create a new notification"""
        
        # Get user preferences
        preferences = await self.get_user_preferences(user_id)
        
        # Check if this type of notification is enabled
        if not self._should_send_notification(notification_type, category, metadata, preferences):
            self.logger.debug(f"Notification filtered out by user preferences: {title}")
            return None
        
        with get_db_session() as db:
            # Check for existing similar notifications if grouping is enabled
            notification_id = None
            
            if group_key and preferences.group_similar_notifications:
                existing = db.query(Notification).filter(
                    Notification.user_id == user_id,
                    Notification.group_key == group_key,
                    Notification.is_dismissed == False,
                    Notification.created_at >= datetime.utcnow() - timedelta(hours=1)
                ).first()
                
                if existing:
                    # Update existing notification
                    existing.grouped_count += 1
                    existing.message = f"{message} ({existing.grouped_count} similar)"
                    existing.created_at = datetime.utcnow()  # Update timestamp
                    if metadata:
                        existing.metadata.update(metadata)
                    db.commit()
                    notification_id = str(existing.id)
                    self.logger.debug(f"Grouped notification: {title}")
                else:
                    # Create new notification
                    notification_id = await self._create_new_notification(
                        db, user_id, title, message, notification_type, category,
                        metadata, action_url, group_key, expires_in_minutes
                    )
            else:
                # Create new notification without grouping
                notification_id = await self._create_new_notification(
                    db, user_id, title, message, notification_type, category,
                    metadata, action_url, group_key, expires_in_minutes
                )
            
            # Clean up old notifications to prevent database bloat
            await self._cleanup_old_notifications(db, user_id, preferences)
            
            return notification_id
    
    async def _create_new_notification(self, db: Session, user_id: str, title: str, 
                                     message: str, notification_type: str, category: str,
                                     metadata: Optional[Dict[str, Any]], action_url: Optional[str],
                                     group_key: Optional[str], expires_in_minutes: Optional[int]) -> str:
        """Create a new notification record"""
        
        expires_at = None
        if expires_in_minutes:
            expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        elif notification_type == "info":
            # Auto-expire info notifications after 24 hours
            expires_at = datetime.utcnow() + timedelta(hours=24)
        
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=NotificationType(notification_type),
            category=NotificationCategory(category),
            metadata=metadata or {},
            action_url=action_url,
            group_key=group_key,
            expires_at=expires_at
        )
        
        db.add(notification)
        db.commit()
        
        self.logger.info(f"Created notification for {user_id}: {title}")
        return str(notification.id)
    
    def _should_send_notification(self, notification_type: str, category: str,
                                metadata: Optional[Dict[str, Any]], 
                                preferences: NotificationPreferences) -> bool:
        """Check if notification should be sent based on user preferences"""
        
        # Critical notifications always get sent
        if notification_type == "critical":
            return True
        
        # Check category-specific preferences
        if category == "vulnerability":
            severity = metadata.get("severity", "").lower() if metadata else ""
            if severity == "critical" and not preferences.critical_vulnerabilities:
                return False
            elif severity == "high" and not preferences.high_vulnerabilities:
                return False
            elif severity == "medium" and not preferences.medium_vulnerabilities:
                return False
            elif severity == "low" and not preferences.low_vulnerabilities:
                return False
        
        elif category == "scan":
            scan_event = metadata.get("scan_event", "") if metadata else ""
            if scan_event == "started" and not preferences.scan_start:
                return False
            elif scan_event == "completed" and not preferences.scan_completion:
                return False
            elif scan_event == "failed" and not preferences.scan_failure:
                return False
        
        elif category == "exploitation":
            exploitation_event = metadata.get("exploitation_event", "") if metadata else ""
            if exploitation_event == "success" and not preferences.exploitation_success:
                return False
            elif exploitation_event == "failure" and not preferences.exploitation_failure:
                return False
            elif exploitation_event == "chain" and not preferences.exploitation_chains:
                return False
        
        elif category == "system" and not preferences.system_alerts:
            return False
        
        elif category == "report" and not preferences.report_generation:
            return False
        
        return True
    
    async def get_user_preferences(self, user_id: str) -> NotificationPreferences:
        """Get user notification preferences"""
        with get_db_session() as db:
            prefs_record = db.query(UserNotificationPreferences).filter(
                UserNotificationPreferences.user_id == user_id
            ).first()
            
            if prefs_record:
                try:
                    prefs_dict = prefs_record.preferences
                    return NotificationPreferences(**prefs_dict)
                except Exception as e:
                    self.logger.error(f"Error loading preferences for {user_id}: {e}")
            
            # Return default preferences if none found
            return NotificationPreferences()
    
    async def update_user_preferences(self, user_id: str, 
                                    preferences: Dict[str, Any]) -> bool:
        """Update user notification preferences"""
        try:
            with get_db_session() as db:
                prefs_record = db.query(UserNotificationPreferences).filter(
                    UserNotificationPreferences.user_id == user_id
                ).first()
                
                if prefs_record:
                    prefs_record.preferences = preferences
                    prefs_record.updated_at = datetime.utcnow()
                else:
                    prefs_record = UserNotificationPreferences(
                        user_id=user_id,
                        preferences=preferences
                    )
                    db.add(prefs_record)
                
                db.commit()
                self.logger.info(f"Updated notification preferences for {user_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error updating preferences for {user_id}: {e}")
            return False
    
    async def get_notifications(self, user_id: str, page: int = 1, page_size: int = 50,
                              include_read: bool = True, include_dismissed: bool = False,
                              category: Optional[str] = None) -> Dict[str, Any]:
        """Get notifications for a user with pagination"""
        with get_db_session() as db:
            query = db.query(Notification).filter(Notification.user_id == user_id)
            
            # Apply filters
            if not include_read:
                query = query.filter(Notification.is_read == False)
            if not include_dismissed:
                query = query.filter(Notification.is_dismissed == False)
            if category:
                query = query.filter(Notification.category == NotificationCategory(category))
            
            # Remove expired notifications
            query = query.filter(
                (Notification.expires_at.is_(None)) | 
                (Notification.expires_at > datetime.utcnow())
            )
            
            # Get total count
            total_count = query.count()
            
            # Apply pagination and ordering
            notifications = query.order_by(
                Notification.is_pinned.desc(),
                Notification.created_at.desc()
            ).offset((page - 1) * page_size).limit(page_size).all()
            
            # Get unread count
            unread_count = db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.is_read == False,
                Notification.is_dismissed == False,
                (Notification.expires_at.is_(None)) | 
                (Notification.expires_at > datetime.utcnow())
            ).count()
            
            return {
                "notifications": [notif.to_dict() for notif in notifications],
                "total_count": total_count,
                "unread_count": unread_count,
                "page": page,
                "page_size": page_size,
                "total_pages": (total_count + page_size - 1) // page_size
            }
    
    async def mark_as_read(self, notification_id: str, user_id: str) -> bool:
        """Mark notification as read"""
        with get_db_session() as db:
            notification = db.query(Notification).filter(
                Notification.id == notification_id,
                Notification.user_id == user_id
            ).first()
            
            if notification:
                notification.is_read = True
                notification.read_at = datetime.utcnow()
                db.commit()
                return True
            
            return False
    
    async def mark_all_as_read(self, user_id: str, category: Optional[str] = None) -> int:
        """Mark all notifications as read for a user"""
        with get_db_session() as db:
            query = db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.is_read == False
            )
            
            if category:
                query = query.filter(Notification.category == NotificationCategory(category))
            
            count = query.count()
            query.update({
                'is_read': True,
                'read_at': datetime.utcnow()
            })
            db.commit()
            
            return count
    
    async def dismiss_notification(self, notification_id: str, user_id: str) -> bool:
        """Dismiss a notification"""
        with get_db_session() as db:
            notification = db.query(Notification).filter(
                Notification.id == notification_id,
                Notification.user_id == user_id
            ).first()
            
            if notification:
                notification.is_dismissed = True
                db.commit()
                return True
            
            return False
    
    async def pin_notification(self, notification_id: str, user_id: str, pinned: bool = True) -> bool:
        """Pin or unpin a notification"""
        with get_db_session() as db:
            notification = db.query(Notification).filter(
                Notification.id == notification_id,
                Notification.user_id == user_id
            ).first()
            
            if notification:
                notification.is_pinned = pinned
                db.commit()
                return True
            
            return False
    
    async def _cleanup_old_notifications(self, db: Session, user_id: str, 
                                       preferences: NotificationPreferences):
        """Clean up old notifications to prevent database bloat"""
        # Remove expired notifications
        db.query(Notification).filter(
            Notification.user_id == user_id,
            Notification.expires_at < datetime.utcnow()
        ).delete()
        
        # Remove old dismissed notifications (older than 30 days)
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        db.query(Notification).filter(
            Notification.user_id == user_id,
            Notification.is_dismissed == True,
            Notification.created_at < cutoff_date
        ).delete()
        
        # Limit total notifications per user (keep latest 1000)
        total_notifications = db.query(Notification).filter(
            Notification.user_id == user_id
        ).count()
        
        if total_notifications > 1000:
            old_notifications = db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.is_pinned == False
            ).order_by(Notification.created_at.asc()).limit(
                total_notifications - 1000
            ).all()
            
            for notif in old_notifications:
                db.delete(notif)
        
        db.commit()
    
    # Specific notification creators for different events
    
    async def send_vulnerability_notification(self, vulnerability: Vulnerability):
        """Send notification for new vulnerability"""
        target = vulnerability.scan_session.target
        
        severity_emoji = {
            VulnSeverity.CRITICAL: "🚨",
            VulnSeverity.HIGH: "🔴",
            VulnSeverity.MEDIUM: "🟡",
            VulnSeverity.LOW: "🟢",
            VulnSeverity.INFO: "ℹ️"
        }
        
        emoji = severity_emoji.get(vulnerability.severity, "🔍")
        
        await self.create_notification(
            user_id=target.researcher_username,
            title=f"{emoji} {vulnerability.severity.value.title()} Vulnerability Found",
            message=f"Found {vulnerability.vulnerability_name} in {target.target_name}",
            notification_type="critical" if vulnerability.severity == VulnSeverity.CRITICAL else "warning",
            category="vulnerability",
            metadata={
                "vulnerability_id": str(vulnerability.id),
                "severity": vulnerability.severity.value,
                "vulnerability_type": vulnerability.vulnerability_type,
                "target_name": target.target_name,
                "affected_url": vulnerability.affected_url
            },
            action_url=f"/vulnerabilities/{vulnerability.id}",
            group_key=f"vuln_{vulnerability.vulnerability_type}_{target.id}",
            expires_in_minutes=None if vulnerability.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH] else 1440
        )
    
    async def send_scan_notification(self, scan_session: ScanSession, event: str):
        """Send notification for scan events"""
        target = scan_session.target
        
        event_config = {
            "started": {
                "title": "🚀 Scan Started",
                "message": f"Started penetration testing scan for {target.target_name}",
                "type": "info"
            },
            "completed": {
                "title": "✅ Scan Completed",
                "message": f"Completed scan for {target.target_name}. Found {scan_session.total_vulnerabilities} vulnerabilities",
                "type": "success"
            },
            "failed": {
                "title": "❌ Scan Failed",
                "message": f"Scan failed for {target.target_name}",
                "type": "error"
            },
            "paused": {
                "title": "⏸️ Scan Paused",
                "message": f"Scan paused for {target.target_name}",
                "type": "warning"
            }
        }
        
        config = event_config.get(event, {})
        if not config:
            return
        
        await self.create_notification(
            user_id=target.researcher_username,
            title=config["title"],
            message=config["message"],
            notification_type=config["type"],
            category="scan",
            metadata={
                "scan_session_id": str(scan_session.id),
                "scan_event": event,
                "target_name": target.target_name,
                "total_vulnerabilities": scan_session.total_vulnerabilities,
                "critical_vulnerabilities": scan_session.critical_vulnerabilities,
                "high_vulnerabilities": scan_session.high_vulnerabilities
            },
            action_url=f"/scans/{scan_session.id}",
            group_key=f"scan_{event}_{target.id}",
            expires_in_minutes=60 if event == "started" else None
        )
    
    async def send_exploitation_notification(self, vulnerability: Vulnerability, 
                                           success: bool, framework_used: str = None,
                                           execution_time: float = None):
        """Send notification for exploitation events"""
        target = vulnerability.scan_session.target
        
        if success:
            title = "🎯 Successful Exploitation!"
            message = f"Successfully exploited {vulnerability.vulnerability_name}"
            if framework_used:
                message += f" using {framework_used}"
            notification_type = "success"
        else:
            title = "❌ Exploitation Failed"
            message = f"Failed to exploit {vulnerability.vulnerability_name}"
            notification_type = "warning"
        
        await self.create_notification(
            user_id=target.researcher_username,
            title=title,
            message=message,
            notification_type=notification_type,
            category="exploitation",
            metadata={
                "vulnerability_id": str(vulnerability.id),
                "exploitation_event": "success" if success else "failure",
                "framework_used": framework_used,
                "execution_time": execution_time,
                "vulnerability_type": vulnerability.vulnerability_type,
                "affected_url": vulnerability.affected_url
            },
            action_url=f"/vulnerabilities/{vulnerability.id}",
            group_key=f"exploit_{vulnerability.id}",
            expires_in_minutes=None if success else 360
        )
    
    async def send_exploitation_chain_notification(self, chain_name: str, 
                                                  successful_steps: int, total_steps: int,
                                                  target: Target, primary_vuln_id: str):
        """Send notification for exploitation chain events"""
        success_rate = successful_steps / total_steps
        
        if success_rate >= 0.8:
            title = "🔗 Exploitation Chain Successful!"
            notification_type = "success"
        elif success_rate >= 0.5:
            title = "🔗 Partial Chain Success"
            notification_type = "warning"
        else:
            title = "🔗 Chain Execution Completed"
            notification_type = "info"
        
        message = f"Chain '{chain_name}': {successful_steps}/{total_steps} steps successful"
        
        await self.create_notification(
            user_id=target.researcher_username,
            title=title,
            message=message,
            notification_type=notification_type,
            category="exploitation",
            metadata={
                "exploitation_event": "chain",
                "chain_name": chain_name,
                "successful_steps": successful_steps,
                "total_steps": total_steps,
                "success_rate": success_rate,
                "primary_vulnerability_id": primary_vuln_id,
                "target_name": target.target_name
            },
            action_url=f"/chains/{chain_name}",
            group_key=f"chain_{target.id}",
            expires_in_minutes=None
        )
    
    async def send_report_notification(self, report: Report):
        """Send notification for report generation"""
        target = report.scan_session.target
        
        await self.create_notification(
            user_id=target.researcher_username,
            title="📄 Report Generated",
            message=f"Generated {report.report_type} report for {target.target_name}",
            notification_type="success",
            category="report",
            metadata={
                "report_id": str(report.id),
                "report_type": report.report_type,
                "target_name": target.target_name,
                "total_vulnerabilities": report.total_vulnerabilities_reported,
                "critical_count": report.critical_count,
                "high_count": report.high_count
            },
            action_url=f"/reports/{report.id}",
            group_key=f"report_{target.id}",
            expires_in_minutes=None
        )
    
    async def send_recon_discovery_notification(self, scan_session: ScanSession, 
                                              discovery_type: str, count: int):
        """Send notification for significant reconnaissance discoveries"""
        if count < 10:  # Only notify for significant discoveries
            return
        
        target = scan_session.target
        
        discovery_config = {
            "subdomains": {
                "emoji": "🌐",
                "name": "subdomains"
            },
            "endpoints": {
                "emoji": "🔗",
                "name": "endpoints"
            },
            "services": {
                "emoji": "⚙️",
                "name": "services"
            }
        }
        
        config = discovery_config.get(discovery_type, {"emoji": "🔍", "name": discovery_type})
        
        await self.create_notification(
            user_id=target.researcher_username,
            title=f"{config['emoji']} Discovery Update",
            message=f"Found {count} new {config['name']} for {target.target_name}",
            notification_type="info",
            category="scan",
            metadata={
                "scan_session_id": str(scan_session.id),
                "discovery_type": discovery_type,
                "discovery_count": count,
                "target_name": target.target_name
            },
            action_url=f"/scans/{scan_session.id}/recon",
            group_key=f"recon_{discovery_type}_{target.id}",
            expires_in_minutes=120
        )
    
    @shared_task
    def send_notification_async(self, user_id: str, title: str, message: str,
                               notification_type: str, category: str = "system",
                               metadata: dict = None, action_url: str = None):
        """Celery task for sending notifications asynchronously"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                self.create_notification(
                    user_id=user_id,
                    title=title,
                    message=message,
                    notification_type=notification_type,
                    category=category,
                    metadata=metadata,
                    action_url=action_url
                )
            )
        finally:
            loop.close()
    
    async def get_notification_stats(self, user_id: str) -> Dict[str, Any]:
        """Get notification statistics for a user"""
        with get_db_session() as db:
            total = db.query(Notification).filter(Notification.user_id == user_id).count()
            
            unread = db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.is_read == False,
                Notification.is_dismissed == False
            ).count()
            
            by_category = {}
            for category in NotificationCategory:
                count = db.query(Notification).filter(
                    Notification.user_id == user_id,
                    Notification.category == category,
                    Notification.is_dismissed == False
                ).count()
                by_category[category.value] = count
            
            by_type = {}
            for notif_type in NotificationType:
                count = db.query(Notification).filter(
                    Notification.user_id == user_id,
                    Notification.notification_type == notif_type,
                    Notification.is_dismissed == False
                ).count()
                by_type[notif_type.value] = count
            
            return {
                "total_notifications": total,
                "unread_notifications": unread,
                "by_category": by_category,
                "by_type": by_type,
                "read_rate": (total - unread) / total if total > 0 else 0
            }