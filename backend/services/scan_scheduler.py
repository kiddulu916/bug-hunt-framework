"""
Scan Scheduler Service
Intelligent scheduling and orchestration of vulnerability scans
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import heapq

from celery import shared_task
from sqlalchemy import Column, String, DateTime, Boolean, JSON, Integer, Enum as SQLEnum, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Session

from backend.models import Base, Target, ScanSession, ReconResult, ScanStatus
from backend.core.database import get_db_session
from backend.services.notification_service import NotificationService
from backend.services.vulnerability_scanner import VulnerabilityScanner


class ScheduleType(Enum):
    ONE_TIME = "one_time"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_ASSET_DISCOVERY = "on_asset_discovery"
    CONTINUOUS = "continuous"


class SchedulePriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5


class ScheduleStatus(Enum):
    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class ScanJob:
    """Individual scan job"""
    job_id: str
    target_id: str
    scan_profile: str
    schedule_type: ScheduleType
    priority: SchedulePriority
    scheduled_time: datetime
    config: Dict[str, Any]
    dependencies: List[str]  # Other job IDs this job depends on
    retry_count: int = 0
    max_retries: int = 3
    
    def __lt__(self, other):
        """For priority queue ordering"""
        # Higher priority numbers come first
        if self.priority.value != other.priority.value:
            return self.priority.value > other.priority.value
        # Earlier scheduled time comes first for same priority
        return self.scheduled_time < other.scheduled_time


class ScanSchedules(Base):
    """Database model for scan schedules"""
    __tablename__ = "scan_schedules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    
    # Schedule configuration
    schedule_name = Column(String(255), nullable=False)
    schedule_type = Column(SQLEnum(ScheduleType), nullable=False)
    scan_profile = Column(String(50), nullable=False)
    
    # Timing configuration
    cron_expression = Column(String(100), nullable=True)  # For complex schedules
    interval_minutes = Column(Integer, nullable=True)     # For simple intervals
    next_run_time = Column(DateTime, nullable=True)
    last_run_time = Column(DateTime, nullable=True)
    
    # Execution configuration
    priority = Column(SQLEnum(SchedulePriority), default=SchedulePriority.NORMAL)
    max_concurrent_scans = Column(Integer, default=1)
    timeout_minutes = Column(Integer, default=120)
    retry_on_failure = Column(Boolean, default=True)
    max_retries = Column(Integer, default=3)
    
    # Conditions and triggers
    trigger_conditions = Column(JSON, default={})  # Conditions that trigger scans
    scan_config = Column(JSON, default={})         # Custom scan configuration
    
    # Status and metadata
    is_active = Column(Boolean, default=True)
    status = Column(SQLEnum(ScheduleStatus), default=ScheduleStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Execution statistics
    total_runs = Column(Integer, default=0)
    successful_runs = Column(Integer, default=0)
    failed_runs = Column(Integer, default=0)
    average_duration_minutes = Column(Float, default=0.0)
    last_error_message = Column(String(500), nullable=True)


class ScanScheduler:
    """Intelligent scan scheduler service"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.notification_service = NotificationService()
        self.vulnerability_scanner = VulnerabilityScanner()
        
        # Job queue (priority queue)
        self.job_queue = []
        self.running_jobs = {}
        self.completed_jobs = {}
        self.failed_jobs = {}
        
        # Resource management
        self.max_concurrent_scans = 5
        self.current_scan_count = 0
        self.resource_limits = {
            "cpu_threshold": 80,      # CPU usage percentage
            "memory_threshold": 85,   # Memory usage percentage
            "network_threshold": 70   # Network usage percentage
        }
        
        # Scheduler state
        self.is_running = False
        self.scheduler_task = None
        
    async def start_scheduler(self):
        """Start the scan scheduler"""
        if self.is_running:
            return
        
        self.is_running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        # Load existing schedules from database
        await self._load_scheduled_scans()
        
        self.logger.info("Scan scheduler started")
    
    async def stop_scheduler(self):
        """Stop the scan scheduler"""
        self.is_running = False
        
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Cancel running jobs
        for job_id in list(self.running_jobs.keys()):
            await self._cancel_job(job_id)
        
        self.logger.info("Scan scheduler stopped")
    
    async def create_schedule(self, target_id: str, schedule_config: Dict[str, Any]) -> str:
        """Create a new scan schedule"""
        
        with get_db_session() as db:
            # Validate target exists
            target = db.query(Target).filter(Target.id == target_id).first()
            if not target:
                raise ValueError(f"Target {target_id} not found")
            
            # Create schedule record
            schedule = ScanSchedules(
                target_id=target_id,
                schedule_name=schedule_config.get("name", f"Schedule for {target.target_name}"),
                schedule_type=ScheduleType(schedule_config["schedule_type"]),
                scan_profile=schedule_config.get("scan_profile", "comprehensive"),
                cron_expression=schedule_config.get("cron_expression"),
                interval_minutes=schedule_config.get("interval_minutes"),
                priority=SchedulePriority(schedule_config.get("priority", SchedulePriority.NORMAL.value)),
                max_concurrent_scans=schedule_config.get("max_concurrent_scans", 1),
                timeout_minutes=schedule_config.get("timeout_minutes", 120),
                retry_on_failure=schedule_config.get("retry_on_failure", True),
                max_retries=schedule_config.get("max_retries", 3),
                trigger_conditions=schedule_config.get("trigger_conditions", {}),
                scan_config=schedule_config.get("scan_config", {}),
                next_run_time=self._calculate_next_run_time(schedule_config)
            )
            
            db.add(schedule)
            db.commit()
            schedule_id = str(schedule.id)
            
            # Add to job queue if it should run soon
            if schedule.next_run_time and schedule.next_run_time <= datetime.utcnow() + timedelta(hours=24):
                await self._queue_schedule_job(schedule)
            
            self.logger.info(f"Created schedule {schedule_id} for target {target_id}")
            return schedule_id
    
    async def schedule_immediate_scan(self, target_id: str, scan_profile: str = "quick",
                                   priority: SchedulePriority = SchedulePriority.HIGH,
                                   config: Dict[str, Any] = None) -> str:
        """Schedule an immediate one-time scan"""
        
        job_id = str(uuid.uuid4())
        
        job = ScanJob(
            job_id=job_id,
            target_id=target_id,
            scan_profile=scan_profile,
            schedule_type=ScheduleType.ONE_TIME,
            priority=priority,
            scheduled_time=datetime.utcnow(),
            config=config or {},
            dependencies=[]
        )
        
        # Add to priority queue
        heapq.heappush(self.job_queue, job)
        
        self.logger.info(f"Scheduled immediate scan {job_id} for target {target_id}")
        return job_id
    
    async def schedule_conditional_scan(self, target_id: str, conditions: Dict[str, Any],
                                      scan_profile: str = "comprehensive") -> str:
        """Schedule scan based on conditions (e.g., new assets discovered)"""
        
        schedule_config = {
            "name": f"Conditional scan for new assets",
            "schedule_type": ScheduleType.ON_ASSET_DISCOVERY.value,
            "scan_profile": scan_profile,
            "trigger_conditions": conditions,
            "priority": SchedulePriority.NORMAL.value
        }
        
        return await self.create_schedule(target_id, schedule_config)
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.is_running:
            try:
                # Process job queue
                await self._process_job_queue()
                
                # Check for triggered conditions
                await self._check_conditional_triggers()
                
                # Update schedule next run times
                await self._update_recurring_schedules()
                
                # Clean up completed/failed jobs
                await self._cleanup_old_jobs()
                
                # Resource management
                await self._manage_resources()
                
                # Sleep before next iteration
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _process_job_queue(self):
        """Process jobs in the priority queue"""
        
        current_time = datetime.utcnow()
        jobs_to_process = []
        
        # Extract ready jobs from queue
        while self.job_queue and self.current_scan_count < self.max_concurrent_scans:
            if self.job_queue[0].scheduled_time <= current_time:
                job = heapq.heappop(self.job_queue)
                
                # Check dependencies
                if await self._check_job_dependencies(job):
                    jobs_to_process.append(job)
                else:
                    # Reschedule if dependencies not met
                    job.scheduled_time = current_time + timedelta(minutes=5)
                    heapq.heappush(self.job_queue, job)
            else:
                break
        
        # Execute ready jobs
        for job in jobs_to_process:
            await self._execute_job(job)
    
    async def _execute_job(self, job: ScanJob):
        """Execute a scan job"""
        
        try:
            self.logger.info(f"Executing scan job {job.job_id}")
            
            # Mark job as running
            self.running_jobs[job.job_id] = {
                "job": job,
                "started_at": datetime.utcnow(),
                "task": None
            }
            self.current_scan_count += 1
            
            # Create scan session
            scan_session_id = await self._create_scan_session(job)
            
            # Start vulnerability scan
            scan_task = asyncio.create_task(
                self._run_vulnerability_scan(scan_session_id, job)
            )
            
            self.running_jobs[job.job_id]["task"] = scan_task
            self.running_jobs[job.job_id]["scan_session_id"] = scan_session_id
            
            # Don't await here - let it run in background
            
        except Exception as e:
            self.logger.error(f"Failed to execute job {job.job_id}: {e}")
            await self._handle_job_failure(job, str(e))
    
    async def _run_vulnerability_scan(self, scan_session_id: str, job: ScanJob):
        """Run vulnerability scan for a job"""
        
        try:
            # Execute the scan
            result = await self.vulnerability_scanner.start_vulnerability_scan(
                scan_session_id, job.scan_profile, job.config
            )
            
            # Handle successful completion
            await self._handle_job_completion(job, result)
            
        except Exception as e:
            # Handle job failure
            await self._handle_job_failure(job, str(e))
        finally:
            # Clean up running job
            if job.job_id in self.running_jobs:
                del self.running_jobs[job.job_id]
            self.current_scan_count -= 1
    
    async def _create_scan_session(self, job: ScanJob) -> str:
        """Create scan session for job"""
        
        with get_db_session() as db:
            target = db.query(Target).filter(Target.id == job.target_id).first()
            if not target:
                raise ValueError(f"Target {job.target_id} not found")
            
            # Create scan session
            scan_session = ScanSession(
                target_id=job.target_id,
                session_name=f"Scheduled scan - {job.scan_profile}",
                status=ScanStatus.QUEUED,
                scan_config=job.config,
                methodology_phases=[
                    "passive_recon", "active_recon", 
                    "vulnerability_testing", "exploitation", "reporting"
                ]
            )
            
            db.add(scan_session)
            db.commit()
            
            return str(scan_session.id)
    
    async def _handle_job_completion(self, job: ScanJob, result: Dict[str, Any]):
        """Handle successful job completion"""
        
        self.completed_jobs[job.job_id] = {
            "job": job,
            "completed_at": datetime.utcnow(),
            "result": result
        }
        
        # Update schedule statistics if this was a scheduled job
        await self._update_schedule_statistics(job, success=True)
        
        self.logger.info(f"Job {job.job_id} completed successfully")
        
        # Send completion notification
        with get_db_session() as db:
            target = db.query(Target).filter(Target.id == job.target_id).first()
            if target:
                await self.notification_service.create_notification(
                    user_id=target.researcher_username,
                    title="🎯 Scheduled Scan Complete",
                    message=f"Scheduled {job.scan_profile} scan completed for {target.target_name}",
                    notification_type="success",
                    category="scan",
                    metadata={
                        "job_id": job.job_id,
                        "vulnerabilities_found": result.get("vulnerabilities_found", 0),
                        "scan_duration": result.get("scan_duration", 0)
                    }
                )
    
    async def _handle_job_failure(self, job: ScanJob, error_message: str):
        """Handle job failure"""
        
        job.retry_count += 1
        
        if job.retry_count <= job.max_retries:
            # Reschedule with backoff
            backoff_minutes = 2 ** job.retry_count  # Exponential backoff
            job.scheduled_time = datetime.utcnow() + timedelta(minutes=backoff_minutes)
            heapq.heappush(self.job_queue, job)
            
            self.logger.warning(f"Job {job.job_id} failed, retry {job.retry_count}/{job.max_retries} in {backoff_minutes} minutes")
        else:
            # Max retries reached
            self.failed_jobs[job.job_id] = {
                "job": job,
                "failed_at": datetime.utcnow(),
                "error": error_message
            }
            
            # Update schedule statistics
            await self._update_schedule_statistics(job, success=False, error=error_message)
            
            self.logger.error(f"Job {job.job_id} failed permanently: {error_message}")
            
            # Send failure notification
            with get_db_session() as db:
                target = db.query(Target).filter(Target.id == job.target_id).first()
                if target:
                    await self.notification_service.create_notification(
                        user_id=target.researcher_username,
                        title="❌ Scheduled Scan Failed",
                        message=f"Scheduled scan failed for {target.target_name}: {error_message}",
                        notification_type="error",
                        category="scan",
                        metadata={
                            "job_id": job.job_id,
                            "error": error_message,
                            "retry_count": job.retry_count
                        }
                    )
    
    async def _check_conditional_triggers(self):
        """Check for conditional scan triggers"""
        
        with get_db_session() as db:
            # Get active conditional schedules
            conditional_schedules = db.query(ScanSchedules).filter(
                ScanSchedules.is_active == True,
                ScanSchedules.schedule_type == ScheduleType.ON_ASSET_DISCOVERY
            ).all()
            
            for schedule in conditional_schedules:
                try:
                    if await self._evaluate_trigger_conditions(schedule):
                        await self._trigger_conditional_scan(schedule)
                except Exception as e:
                    self.logger.error(f"Error evaluating trigger conditions for schedule {schedule.id}: {e}")
    
    async def _evaluate_trigger_conditions(self, schedule: ScanSchedules) -> bool:
        """Evaluate if trigger conditions are met"""
        
        conditions = schedule.trigger_conditions
        
        # Check for new assets discovered
        if conditions.get("new_assets_threshold"):
            threshold = conditions["new_assets_threshold"]
            lookback_hours = conditions.get("lookback_hours", 24)
            
            cutoff_time = datetime.utcnow() - timedelta(hours=lookback_hours)
            
            with get_db_session() as db:
                new_assets_count = db.query(ReconResult).filter(
                    ReconResult.discovered_at >= cutoff_time,
                    ReconResult.is_in_scope == True
                ).count()
                
                if new_assets_count >= threshold:
                    return True
        
        # Check for specific asset types
        if conditions.get("asset_types"):
            required_types = conditions["asset_types"]
            lookback_hours = conditions.get("lookback_hours", 24)
            
            cutoff_time = datetime.utcnow() - timedelta(hours=lookback_hours)
            
            with get_db_session() as db:
                for asset_type in required_types:
                    assets = db.query(ReconResult).filter(
                        ReconResult.result_type == asset_type,
                        ReconResult.discovered_at >= cutoff_time,
                        ReconResult.is_in_scope == True
                    ).first()
                    
                    if assets:
                        return True
        
        # Check for time-based conditions
        if conditions.get("time_since_last_scan"):
            max_hours = conditions["time_since_last_scan"]
            
            if schedule.last_run_time:
                time_since_last = datetime.utcnow() - schedule.last_run_time
                if time_since_last >= timedelta(hours=max_hours):
                    return True
            else:
                # No previous scan, trigger immediately
                return True
        
        return False
    
    async def _trigger_conditional_scan(self, schedule: ScanSchedules):
        """Trigger a conditional scan"""
        
        job_id = str(uuid.uuid4())
        
        job = ScanJob(
            job_id=job_id,
            target_id=str(schedule.target_id),
            scan_profile=schedule.scan_profile,
            schedule_type=schedule.schedule_type,
            priority=schedule.priority,
            scheduled_time=datetime.utcnow(),
            config=schedule.scan_config,
            dependencies=[]
        )
        
        heapq.heappush(self.job_queue, job)
        
        # Update last run time
        with get_db_session() as db:
            db.query(ScanSchedules).filter(ScanSchedules.id == schedule.id).update({
                "last_run_time": datetime.utcnow()
            })
            db.commit()
        
        self.logger.info(f"Triggered conditional scan {job_id} for schedule {schedule.id}")
    
    async def _update_recurring_schedules(self):
        """Update next run times for recurring schedules"""
        
        with get_db_session() as db:
            # Get recurring schedules that need their next run time updated
            schedules = db.query(ScanSchedules).filter(
                ScanSchedules.is_active == True,
                ScanSchedules.schedule_type.in_([
                    ScheduleType.DAILY, ScheduleType.WEEKLY, 
                    ScheduleType.MONTHLY, ScheduleType.CONTINUOUS
                ]),
                ScanSchedules.next_run_time <= datetime.utcnow()
            ).all()
            
            for schedule in schedules:
                try:
                    # Calculate next run time
                    next_run = self._calculate_next_run_time({
                        "schedule_type": schedule.schedule_type.value,
                        "interval_minutes": schedule.interval_minutes,
                        "cron_expression": schedule.cron_expression
                    })
                    
                    if next_run:
                        # Create job for next run
                        job = ScanJob(
                            job_id=str(uuid.uuid4()),
                            target_id=str(schedule.target_id),
                            scan_profile=schedule.scan_profile,
                            schedule_type=schedule.schedule_type,
                            priority=schedule.priority,
                            scheduled_time=next_run,
                            config=schedule.scan_config,
                            dependencies=[]
                        )
                        
                        heapq.heappush(self.job_queue, job)
                        
                        # Update schedule
                        schedule.next_run_time = next_run
                        
                except Exception as e:
                    self.logger.error(f"Error updating schedule {schedule.id}: {e}")
            
            db.commit()
    
    async def _load_scheduled_scans(self):
        """Load existing schedules from database"""
        
        with get_db_session() as db:
            schedules = db.query(ScanSchedules).filter(
                ScanSchedules.is_active == True,
                ScanSchedules.next_run_time > datetime.utcnow()
            ).all()
            
            for schedule in schedules:
                job = ScanJob(
                    job_id=str(uuid.uuid4()),
                    target_id=str(schedule.target_id),
                    scan_profile=schedule.scan_profile,
                    schedule_type=schedule.schedule_type,
                    priority=schedule.priority,
                    scheduled_time=schedule.next_run_time,
                    config=schedule.scan_config,
                    dependencies=[]
                )
                
                heapq.heappush(self.job_queue, job)
            
            self.logger.info(f"Loaded {len(schedules)} scheduled scans")
    
    async def _check_job_dependencies(self, job: ScanJob) -> bool:
        """Check if job dependencies are satisfied"""
        
        if not job.dependencies:
            return True
        
        for dep_job_id in job.dependencies:
            if dep_job_id in self.completed_jobs:
                continue
            elif dep_job_id in self.failed_jobs:
                return False  # Dependency failed
            elif dep_job_id in self.running_jobs:
                return False  # Dependency still running
            else:
                return False  # Dependency not found
        
        return True
    
    async def _update_schedule_statistics(self, job: ScanJob, success: bool, error: str = None):
        """Update schedule execution statistics"""
        
        with get_db_session() as db:
            # Find the schedule (if this was a scheduled job)
            if job.schedule_type != ScheduleType.ONE_TIME:
                schedules = db.query(ScanSchedules).filter(
                    ScanSchedules.target_id == job.target_id,
                    ScanSchedules.scan_profile == job.scan_profile,
                    ScanSchedules.schedule_type == job.schedule_type
                ).all()
                
                for schedule in schedules:
                    schedule.total_runs += 1
                    
                    if success:
                        schedule.successful_runs += 1
                    else:
                        schedule.failed_runs += 1
                        if error:
                            schedule.last_error_message = error[:500]
                    
                    # Update average duration (simplified calculation)
                    if job.job_id in self.completed_jobs:
                        completed_info = self.completed_jobs[job.job_id]
                        if "started_at" in self.running_jobs.get(job.job_id, {}):
                            duration = (completed_info["completed_at"] - 
                                      self.running_jobs[job.job_id]["started_at"]).total_seconds() / 60
                            
                            if schedule.average_duration_minutes == 0:
                                schedule.average_duration_minutes = duration
                            else:
                                # Simple moving average
                                schedule.average_duration_minutes = (
                                    schedule.average_duration_minutes * 0.8 + duration * 0.2
                                )
                
                db.commit()
    
    async def _cleanup_old_jobs(self):
        """Clean up old completed and failed jobs"""
        
        current_time = datetime.utcnow()
        cleanup_threshold = current_time - timedelta(hours=24)
        
        # Clean up completed jobs
        jobs_to_remove = []
        for job_id, job_info in self.completed_jobs.items():
            if job_info["completed_at"] < cleanup_threshold:
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self.completed_jobs[job_id]
        
        # Clean up failed jobs
        jobs_to_remove = []
        for job_id, job_info in self.failed_jobs.items():
            if job_info["failed_at"] < cleanup_threshold:
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self.failed_jobs[job_id]
    
    async def _manage_resources(self):
        """Manage system resources and adjust concurrent scan limits"""
        
        try:
            import psutil
            
            # Get system resource usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Adjust concurrent scan limit based on resource usage
            if (cpu_percent > self.resource_limits["cpu_threshold"] or 
                memory_percent > self.resource_limits["memory_threshold"]):
                
                # Reduce concurrent scans if resources are high
                if self.max_concurrent_scans > 1:
                    self.max_concurrent_scans = max(1, self.max_concurrent_scans - 1)
                    self.logger.info(f"Reduced concurrent scans to {self.max_concurrent_scans} due to resource usage")
            
            elif (cpu_percent < self.resource_limits["cpu_threshold"] * 0.7 and 
                  memory_percent < self.resource_limits["memory_threshold"] * 0.7):
                
                # Increase concurrent scans if resources are available
                if self.max_concurrent_scans < 5:
                    self.max_concurrent_scans += 1
                    self.logger.info(f"Increased concurrent scans to {self.max_concurrent_scans}")
        
        except ImportError:
            # psutil not available, skip resource monitoring
            pass
        except Exception as e:
            self.logger.error(f"Resource monitoring error: {e}")
    
    def _calculate_next_run_time(self, schedule_config: Dict[str, Any]) -> Optional[datetime]:
        """Calculate next run time for a schedule"""
        
        schedule_type = ScheduleType(schedule_config["schedule_type"])
        current_time = datetime.utcnow()
        
        if schedule_type == ScheduleType.ONE_TIME:
            return current_time  # Run immediately
        
        elif schedule_type == ScheduleType.DAILY:
            return current_time + timedelta(days=1)
        
        elif schedule_type == ScheduleType.WEEKLY:
            return current_time + timedelta(weeks=1)
        
        elif schedule_type == ScheduleType.MONTHLY:
            # Add approximately 30 days
            return current_time + timedelta(days=30)
        
        elif schedule_type == ScheduleType.CONTINUOUS:
            interval = schedule_config.get("interval_minutes", 60)
            return current_time + timedelta(minutes=interval)
        
        elif schedule_type == ScheduleType.ON_ASSET_DISCOVERY:
            # No fixed schedule, triggered by conditions
            return None
        
        # Handle cron expressions (simplified)
        cron_expression = schedule_config.get("cron_expression")
        if cron_expression:
            # This would need a proper cron parser library in production
            # For now, default to daily
            return current_time + timedelta(days=1)
        
        return None
    
    async def _cancel_job(self, job_id: str) -> bool:
        """Cancel a running or queued job"""
        
        # Check running jobs
        if job_id in self.running_jobs:
            job_info = self.running_jobs[job_id]
            task = job_info.get("task")
            
            if task and not task.done():
                task.cancel()
            
            del self.running_jobs[job_id]
            self.current_scan_count -= 1
            
            self.logger.info(f"Cancelled running job {job_id}")
            return True
        
        # Check queued jobs
        updated_queue = []
        job_found = False
        
        while self.job_queue:
            job = heapq.heappop(self.job_queue)
            if job.job_id != job_id:
                updated_queue.append(job)
            else:
                job_found = True
        
        # Rebuild queue
        for job in updated_queue:
            heapq.heappush(self.job_queue, job)
        
        if job_found:
            self.logger.info(f"Cancelled queued job {job_id}")
            return True
        
        return False
    
    # Public API methods
    
    async def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        
        return {
            "is_running": self.is_running,
            "current_scan_count": self.current_scan_count,
            "max_concurrent_scans": self.max_concurrent_scans,
            "queued_jobs": len(self.job_queue),
            "running_jobs": len(self.running_jobs),
            "completed_jobs_24h": len(self.completed_jobs),
            "failed_jobs_24h": len(self.failed_jobs),
            "next_job_time": self.job_queue[0].scheduled_time.isoformat() if self.job_queue else None,
            "resource_limits": self.resource_limits
        }
    
    async def get_schedule_details(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific schedule"""
        
        with get_db_session() as db:
            schedule = db.query(ScanSchedules).filter(
                ScanSchedules.id == schedule_id
            ).first()
            
            if not schedule:
                return None
            
            return {
                "id": str(schedule.id),
                "target_id": str(schedule.target_id),
                "schedule_name": schedule.schedule_name,
                "schedule_type": schedule.schedule_type.value,
                "scan_profile": schedule.scan_profile,
                "cron_expression": schedule.cron_expression,
                "interval_minutes": schedule.interval_minutes,
                "next_run_time": schedule.next_run_time.isoformat() if schedule.next_run_time else None,
                "last_run_time": schedule.last_run_time.isoformat() if schedule.last_run_time else None,
                "priority": schedule.priority.value,
                "is_active": schedule.is_active,
                "status": schedule.status.value,
                "trigger_conditions": schedule.trigger_conditions,
                "scan_config": schedule.scan_config,
                "statistics": {
                    "total_runs": schedule.total_runs,
                    "successful_runs": schedule.successful_runs,
                    "failed_runs": schedule.failed_runs,
                    "success_rate": schedule.successful_runs / schedule.total_runs if schedule.total_runs > 0 else 0,
                    "average_duration_minutes": schedule.average_duration_minutes
                },
                "last_error": schedule.last_error_message,
                "created_at": schedule.created_at.isoformat(),
                "updated_at": schedule.updated_at.isoformat()
            }
    
    async def update_schedule(self, schedule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing schedule"""
        
        try:
            with get_db_session() as db:
                schedule = db.query(ScanSchedules).filter(
                    ScanSchedules.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                # Update allowed fields
                updatable_fields = [
                    'schedule_name', 'scan_profile', 'cron_expression', 
                    'interval_minutes', 'priority', 'max_concurrent_scans',
                    'timeout_minutes', 'retry_on_failure', 'max_retries',
                    'trigger_conditions', 'scan_config', 'is_active'
                ]
                
                for field, value in updates.items():
                    if field in updatable_fields and hasattr(schedule, field):
                        if field == 'priority':
                            setattr(schedule, field, SchedulePriority(value))
                        else:
                            setattr(schedule, field, value)
                
                # Recalculate next run time if schedule changed
                if any(field in updates for field in ['cron_expression', 'interval_minutes']):
                    schedule.next_run_time = self._calculate_next_run_time({
                        "schedule_type": schedule.schedule_type.value,
                        "cron_expression": schedule.cron_expression,
                        "interval_minutes": schedule.interval_minutes
                    })
                
                schedule.updated_at = datetime.utcnow()
                db.commit()
                
                self.logger.info(f"Updated schedule {schedule_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update schedule {schedule_id}: {e}")
            return False
    
    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule"""
        
        try:
            with get_db_session() as db:
                schedule = db.query(ScanSchedules).filter(
                    ScanSchedules.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                # Cancel any pending jobs for this schedule
                # (In a more sophisticated system, you'd track job-schedule relationships)
                
                db.delete(schedule)
                db.commit()
                
                self.logger.info(f"Deleted schedule {schedule_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to delete schedule {schedule_id}: {e}")
            return False
    
    async def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a schedule"""
        
        return await self.update_schedule(schedule_id, {
            "is_active": False,
            "status": ScheduleStatus.PAUSED.value
        })
    
    async def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused schedule"""
        
        return await self.update_schedule(schedule_id, {
            "is_active": True,
            "status": ScheduleStatus.SCHEDULED.value
        })
    
    async def get_target_schedules(self, target_id: str) -> List[Dict[str, Any]]:
        """Get all schedules for a target"""
        
        with get_db_session() as db:
            schedules = db.query(ScanSchedules).filter(
                ScanSchedules.target_id == target_id
            ).order_by(ScanSchedules.created_at.desc()).all()
            
            result = []
            for schedule in schedules:
                schedule_data = await self.get_schedule_details(str(schedule.id))
                if schedule_data:
                    result.append(schedule_data)
            
            return result
    
    async def get_job_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent job execution history"""
        
        history = []
        
        # Add completed jobs
        for job_id, job_info in list(self.completed_jobs.items())[-limit//2:]:
            job = job_info["job"]
            history.append({
                "job_id": job_id,
                "target_id": job.target_id,
                "scan_profile": job.scan_profile,
                "schedule_type": job.schedule_type.value,
                "priority": job.priority.value,
                "status": "completed",
                "scheduled_time": job.scheduled_time.isoformat(),
                "completed_at": job_info["completed_at"].isoformat(),
                "result": job_info.get("result", {})
            })
        
        # Add failed jobs
        for job_id, job_info in list(self.failed_jobs.items())[-limit//2:]:
            job = job_info["job"]
            history.append({
                "job_id": job_id,
                "target_id": job.target_id,
                "scan_profile": job.scan_profile,
                "schedule_type": job.schedule_type.value,
                "priority": job.priority.value,
                "status": "failed",
                "scheduled_time": job.scheduled_time.isoformat(),
                "failed_at": job_info["failed_at"].isoformat(),
                "error": job_info.get("error", ""),
                "retry_count": job.retry_count
            })
        
        # Sort by time (most recent first)
        history.sort(key=lambda x: x.get("completed_at", x.get("failed_at", "")), reverse=True)
        
        return history[:limit]
    
    async def get_queue_status(self) -> Dict[str, Any]:
        """Get current job queue status"""
        
        # Organize queue by priority
        queue_by_priority = {}
        for job in self.job_queue:
            priority = job.priority.value
            if priority not in queue_by_priority:
                queue_by_priority[priority] = []
            
            queue_by_priority[priority].append({
                "job_id": job.job_id,
                "target_id": job.target_id,
                "scan_profile": job.scan_profile,
                "scheduled_time": job.scheduled_time.isoformat(),
                "retry_count": job.retry_count
            })
        
        # Get running jobs info
        running_jobs_info = []
        for job_id, job_info in self.running_jobs.items():
            job = job_info["job"]
            running_jobs_info.append({
                "job_id": job_id,
                "target_id": job.target_id,
                "scan_profile": job.scan_profile,
                "started_at": job_info["started_at"].isoformat(),
                "scan_session_id": job_info.get("scan_session_id")
            })
        
        return {
            "total_queued": len(self.job_queue),
            "queued_by_priority": queue_by_priority,
            "running_jobs": running_jobs_info,
            "current_capacity": f"{self.current_scan_count}/{self.max_concurrent_scans}"
        }
    
    async def get_scheduler_metrics(self, timeframe_hours: int = 24) -> Dict[str, Any]:
        """Get scheduler performance metrics"""
        
        cutoff_time = datetime.utcnow() - timedelta(hours=timeframe_hours)
        
        # Calculate metrics from recent jobs
        completed_in_timeframe = [
            job_info for job_info in self.completed_jobs.values()
            if job_info["completed_at"] >= cutoff_time
        ]
        
        failed_in_timeframe = [
            job_info for job_info in self.failed_jobs.values()
            if job_info["failed_at"] >= cutoff_time
        ]
        
        total_jobs = len(completed_in_timeframe) + len(failed_in_timeframe)
        
        # Calculate average job duration
        durations = []
        for job_info in completed_in_timeframe:
            job = job_info["job"]
            if job.job_id in self.running_jobs:  # This should be in historical data
                continue
            # Duration calculation would need historical start times
        
        return {
            "timeframe_hours": timeframe_hours,
            "total_jobs_executed": total_jobs,
            "successful_jobs": len(completed_in_timeframe),
            "failed_jobs": len(failed_in_timeframe),
            "success_rate": len(completed_in_timeframe) / total_jobs if total_jobs > 0 else 0,
            "average_queue_wait_time": 0,  # Would need more detailed tracking
            "average_execution_time": 0,   # Would need more detailed tracking
            "peak_concurrent_scans": self.max_concurrent_scans,
            "current_resource_usage": {
                "cpu_threshold": self.resource_limits["cpu_threshold"],
                "memory_threshold": self.resource_limits["memory_threshold"]
            }
        }
    
    @shared_task
    def create_schedule_async(self, target_id: str, schedule_config: Dict[str, Any]):
        """Celery task for creating schedules"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.create_schedule(target_id, schedule_config)
            )
            return result
        finally:
            loop.close()
    
    @shared_task
    def schedule_immediate_scan_async(self, target_id: str, scan_profile: str = "quick"):
        """Celery task for scheduling immediate scans"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.schedule_immediate_scan(target_id, scan_profile)
            )
            return result
        finally:
            loop.close()


# Shared scheduler service instance
scan_scheduler = ScanScheduler()
