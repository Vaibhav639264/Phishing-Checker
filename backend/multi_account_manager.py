import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import uuid
from motor.motor_asyncio import AsyncIOMotorClient
from imap_service import IMAPService
from real_time_monitor import RealTimeEmailMonitor
import os

logger = logging.getLogger(__name__)

class MultiAccountManager:
    def __init__(self, db):
        self.db = db
        self.active_monitors = {}  # email -> monitor instance
        self.account_configs = {}  # email -> config
        
    async def add_account(self, email: str, app_password: str, employee_name: str = "", department: str = "", alert_email: str = "") -> Dict[str, Any]:
        """Add a new Gmail account for monitoring"""
        try:
            # Test IMAP connection first
            imap_service = IMAPService(email, app_password)
            test_result = await imap_service.test_connection()
            
            if test_result['status'] != 'success':
                return {
                    'success': False,
                    'message': f'Connection failed for {email}: {test_result.get("message", "Unknown error")}',
                    'account': email
                }
            
            # Store account configuration
            account_config = {
                'id': str(uuid.uuid4()),
                'email': email,
                'app_password': app_password,  # In production, encrypt this
                'employee_name': employee_name,
                'department': department,
                'alert_email': alert_email or email,
                'status': 'active',
                'monitoring_active': False,
                'added_date': datetime.utcnow(),
                'last_scan': None,
                'total_processed': 0,
                'threats_blocked': 0
            }
            
            # Save to database
            await self.db.email_accounts.insert_one(account_config)
            
            # Store in memory
            self.account_configs[email] = account_config
            
            logger.info(f"Added account: {email} ({employee_name})")
            
            return {
                'success': True,
                'message': f'Account {email} added successfully',
                'account': account_config
            }
            
        except Exception as e:
            logger.error(f"Error adding account {email}: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to add account: {str(e)}',
                'account': email
            }
    
    async def remove_account(self, email: str) -> Dict[str, Any]:
        """Remove an account from monitoring"""
        try:
            # Stop monitoring if active
            if email in self.active_monitors:
                await self.stop_monitoring(email)
            
            # Remove from database
            result = await self.db.email_accounts.delete_one({'email': email})
            
            if result.deleted_count > 0:
                # Remove from memory
                self.account_configs.pop(email, None)
                
                return {
                    'success': True,
                    'message': f'Account {email} removed successfully'
                }
            else:
                return {
                    'success': False,
                    'message': f'Account {email} not found'
                }
                
        except Exception as e:
            logger.error(f"Error removing account {email}: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to remove account: {str(e)}'
            }
    
    async def start_monitoring(self, email: str) -> Dict[str, Any]:
        """Start monitoring for a specific account"""
        try:
            if email not in self.account_configs:
                # Load from database
                account = await self.db.email_accounts.find_one({'email': email})
                if not account:
                    return {
                        'success': False,
                        'message': f'Account {email} not found'
                    }
                self.account_configs[email] = account
            
            account_config = self.account_configs[email]
            
            # Create IMAP service for this account
            imap_service = IMAPService(email, account_config['app_password'])
            
            # Create dedicated monitor for this account
            monitor = RealTimeEmailMonitor()
            monitor.gmail_service = imap_service
            monitor.alert_email = account_config['alert_email']
            monitor.account_email = email
            monitor.account_config = account_config
            
            # Start monitoring in background
            asyncio.create_task(self._monitor_account(email, monitor))
            
            # Store active monitor
            self.active_monitors[email] = monitor
            
            # Update database
            await self.db.email_accounts.update_one(
                {'email': email},
                {'$set': {'monitoring_active': True}}
            )
            
            logger.info(f"Started monitoring for: {email}")
            
            return {
                'success': True,
                'message': f'Monitoring started for {email}'
            }
            
        except Exception as e:
            logger.error(f"Error starting monitoring for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to start monitoring: {str(e)}'
            }
    
    async def stop_monitoring(self, email: str) -> Dict[str, Any]:
        """Stop monitoring for a specific account"""
        try:
            if email in self.active_monitors:
                monitor = self.active_monitors[email]
                monitor.monitoring = False
                del self.active_monitors[email]
                
                # Update database
                await self.db.email_accounts.update_one(
                    {'email': email},
                    {'$set': {'monitoring_active': False}}
                )
                
                logger.info(f"Stopped monitoring for: {email}")
                
                return {
                    'success': True,
                    'message': f'Monitoring stopped for {email}'
                }
            else:
                return {
                    'success': False,
                    'message': f'No active monitoring found for {email}'
                }
                
        except Exception as e:
            logger.error(f"Error stopping monitoring for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to stop monitoring: {str(e)}'
            }
    
    async def _monitor_account(self, email: str, monitor: RealTimeEmailMonitor):
        """Background monitoring task for a specific account"""
        try:
            await monitor.initialize_detector()
            monitor.monitoring = True
            
            logger.info(f"🔍 Starting background monitoring for {email}")
            
            # Use IMAP service for monitoring
            await monitor.gmail_service.monitor_new_emails(
                callback_func=lambda email_data: self._process_account_email(email, email_data, monitor),
                check_interval=60
            )
            
        except Exception as e:
            logger.error(f"Background monitoring failed for {email}: {str(e)}")
            monitor.monitoring = False
    
    async def _process_account_email(self, account_email: str, email_data: Dict[str, Any], monitor: RealTimeEmailMonitor):
        """Process email for specific account with enhanced logging"""
        try:
            logger.info(f"📧 Processing email for {account_email}: {email_data.get('subject', 'No subject')}")
            
            # Add account context to email data
            email_data['monitored_account'] = account_email
            email_data['account_config'] = monitor.account_config
            
            # Process with enhanced monitoring
            await monitor.process_new_email(email_data)
            
            # Update account statistics
            await self.db.email_accounts.update_one(
                {'email': account_email},
                {
                    '$inc': {'total_processed': 1},
                    '$set': {'last_scan': datetime.utcnow()}
                }
            )
            
        except Exception as e:
            logger.error(f"Error processing email for {account_email}: {str(e)}")
    
    async def get_all_accounts(self) -> List[Dict[str, Any]]:
        """Get all configured accounts with their status"""
        try:
            accounts = await self.db.email_accounts.find({}).to_list(1000)
            
            # Add real-time monitoring status
            for account in accounts:
                email = account['email']
                account['monitoring_active'] = email in self.active_monitors
                
                # Get recent statistics
                threat_count = await self.db.email_analyses.count_documents({
                    'analysis_result.monitored_account': email,
                    'threat_level': {'$in': ['HIGH', 'CRITICAL']}
                })
                account['threats_blocked'] = threat_count
            
            return accounts
            
        except Exception as e:
            logger.error(f"Error getting accounts: {str(e)}")
            return []
    
    async def get_blocked_emails(self, account_email: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get blocked emails for specific account or all accounts"""
        try:
            # Build query
            query = {
                'threat_level': {'$in': ['HIGH', 'CRITICAL']}
            }
            
            if account_email:
                query['analysis_result.monitored_account'] = account_email
            
            # Get blocked emails
            blocked_emails = await self.db.email_analyses.find(
                query,
                {'analysis_result': 1, 'threat_level': 1, 'timestamp': 1, 'filename': 1}
            ).sort('timestamp', -1).limit(limit).to_list(limit)
            
            # Enhance with account info
            for email in blocked_emails:
                monitored_account = email.get('analysis_result', {}).get('monitored_account')
                if monitored_account:
                    account_info = await self.db.email_accounts.find_one(
                        {'email': monitored_account},
                        {'employee_name': 1, 'department': 1}
                    )
                    if account_info:
                        email['employee_name'] = account_info.get('employee_name', '')
                        email['department'] = account_info.get('department', '')
            
            return blocked_emails
            
        except Exception as e:
            logger.error(f"Error getting blocked emails: {str(e)}")
            return []
    
    async def get_enterprise_stats(self) -> Dict[str, Any]:
        """Get enterprise-wide statistics"""
        try:
            # Account statistics
            total_accounts = await self.db.email_accounts.count_documents({})
            active_monitoring = len(self.active_monitors)
            
            # Email statistics
            total_processed = await self.db.email_analyses.count_documents({})
            total_threats = await self.db.email_analyses.count_documents({
                'threat_level': {'$in': ['HIGH', 'CRITICAL']}
            })
            
            # Recent activity (last 24 hours)
            yesterday = datetime.utcnow() - timedelta(days=1)
            recent_processed = await self.db.email_analyses.count_documents({
                'timestamp': {'$gte': yesterday}
            })
            recent_threats = await self.db.email_analyses.count_documents({
                'timestamp': {'$gte': yesterday},
                'threat_level': {'$in': ['HIGH', 'CRITICAL']}
            })
            
            # Department statistics
            pipeline = [
                {'$group': {
                    '_id': '$department',
                    'count': {'$sum': 1},
                    'active': {'$sum': {'$cond': [{'$eq': ['$monitoring_active', True]}, 1, 0]}}
                }}
            ]
            dept_stats = await self.db.email_accounts.aggregate(pipeline).to_list(100)
            
            return {
                'accounts': {
                    'total': total_accounts,
                    'monitoring_active': active_monitoring,
                    'monitoring_inactive': total_accounts - active_monitoring
                },
                'emails': {
                    'total_processed': total_processed,
                    'total_threats': total_threats,
                    'recent_processed': recent_processed,
                    'recent_threats': recent_threats
                },
                'departments': dept_stats,
                'threat_rate': round((total_threats / max(total_processed, 1)) * 100, 2),
                'recent_threat_rate': round((recent_threats / max(recent_processed, 1)) * 100, 2)
            }
            
        except Exception as e:
            logger.error(f"Error getting enterprise stats: {str(e)}")
            return {}
    
    async def start_all_monitoring(self) -> Dict[str, Any]:
        """Start monitoring for all configured accounts"""
        try:
            accounts = await self.get_all_accounts()
            results = []
            
            for account in accounts:
                if not account.get('monitoring_active', False):
                    result = await self.start_monitoring(account['email'])
                    results.append({
                        'email': account['email'],
                        'success': result['success'],
                        'message': result['message']
                    })
            
            return {
                'success': True,
                'message': f'Started monitoring for {len(results)} accounts',
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to start monitoring: {str(e)}'
            }
    
    async def stop_all_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring for all accounts"""
        try:
            results = []
            
            for email in list(self.active_monitors.keys()):
                result = await self.stop_monitoring(email)
                results.append({
                    'email': email,
                    'success': result['success'],
                    'message': result['message']
                })
            
            return {
                'success': True,
                'message': f'Stopped monitoring for {len(results)} accounts',
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to stop monitoring: {str(e)}'
            }

# Global instance
multi_account_manager = None

def get_multi_account_manager(db):
    global multi_account_manager
    if multi_account_manager is None:
        multi_account_manager = MultiAccountManager(db)
    return multi_account_manager