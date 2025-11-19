#!/usr/bin/env python3
"""
Option Chain Time-Series Storage

Stores option chain data with timestamps for real-time tracking and analysis.
Uses SQLite for efficient time-series storage with proper indexing.

Features:
- Append-only time-series storage
- Efficient queries by timestamp, symbol, strike
- Volume accumulation tracking
- Price history tracking
- Export to CSV/JSON for analysis
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("option_chain_storage")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(fmt)
    logger.addHandler(ch)


class OptionChainStorage:
    """
    Time-series storage for option chain data.
    
    Stores each snapshot with timestamp, allowing:
    - Real-time price tracking
    - Volume accumulation over time
    - Historical analysis
    - Efficient queries
    """
    
    def __init__(self, db_path: str = "data/option_chain.db"):
        """
        Initialize storage.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        
        # Initialize database schema
        self._init_db()
        logger.info("Initialized Option Chain Storage: %s", self.db_path)
    
    def _init_db(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Main time-series table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS option_chain_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    symbol TEXT NOT NULL,
                    strike INTEGER,
                    option_type TEXT,
                    expiry INTEGER,
                    expiry_date TEXT,
                    ltp REAL,
                    bid REAL,
                    ask REAL,
                    volume INTEGER,
                    oi INTEGER,
                    iv REAL
                )
            """)
            
            # Migration: Add new columns if they don't exist (for existing databases)
            # Must run BEFORE creating indexes
            migrations = [
                ("expiry_date", "TEXT"),
                ("date", "TEXT"),
            ]
            for col_name, col_type in migrations:
                try:
                    cursor.execute(f"ALTER TABLE option_chain_snapshots ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Added {col_name} column to existing database")
                except sqlite3.OperationalError:
                    # Column already exists, ignore
                    pass
            
            # Backfill date column for existing records
            try:
                cursor.execute("""
                    UPDATE option_chain_snapshots 
                    SET date = date(datetime(timestamp, 'unixepoch'))
                    WHERE date IS NULL OR date = ''
                """)
                if cursor.rowcount > 0:
                    logger.info(f"Backfilled date column for {cursor.rowcount} existing records")
            except sqlite3.OperationalError:
                pass
            
            # Create indexes for efficient queries (after migrations)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON option_chain_snapshots(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_date ON option_chain_snapshots(date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbol ON option_chain_snapshots(symbol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbol_strike ON option_chain_snapshots(symbol, strike)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_symbol ON option_chain_snapshots(timestamp, symbol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_date_expiry ON option_chain_snapshots(date, expiry_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_date_volume ON option_chain_snapshots(date, volume)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_expiry_date ON option_chain_snapshots(expiry_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_strike_expiry ON option_chain_snapshots(strike, expiry_date)")
            
            # Metadata table for tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            conn.commit()
            logger.debug("Database schema initialized")
    
    def _extract_expiry_date_from_symbol(self, symbol: str) -> Optional[str]:
        """
        Extract expiry date from Fyers option symbol format.
        
        Format: NSE:NIFTY25NOV25600CE
        Extracts: 25NOV -> 2025-11-25
        
        Args:
            symbol: Option symbol
        
        Returns:
            Expiry date in YYYY-MM-DD format or None
        """
        try:
            # Format: NSE:NIFTY25NOV25600CE or NSE:NIFTY25NOV25600PE
            # Extract date part: 25NOV
            parts = symbol.split(":")
            if len(parts) != 2:
                return None
            
            symbol_part = parts[1]  # NIFTY25NOV25600CE
            
            # Find date pattern: 2 digits + 3 letters (e.g., 25NOV)
            import re
            match = re.search(r'(\d{2})([A-Z]{3})', symbol_part)
            if not match:
                return None
            
            day = int(match.group(1))
            month_str = match.group(2)
            
            # Month mapping
            month_map = {
                "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
                "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12
            }
            
            month = month_map.get(month_str.upper())
            if not month:
                return None
            
            # Determine year (assume current year or next year if month has passed)
            current_year = datetime.now().year
            year = current_year
            
            # If month has passed, assume next year
            current_month = datetime.now().month
            if month < current_month:
                year = current_year + 1
            
            # Format as YYYY-MM-DD
            return f"{year:04d}-{month:02d}-{day:02d}"
        except Exception:
            return None
    
    def store_snapshot(self, options: List[Dict[str, Any]], timestamp: Optional[datetime] = None) -> int:
        """
        Store a snapshot of option chain data.
        
        Args:
            options: List of option dictionaries from API
            timestamp: Timestamp for this snapshot (default: now)
        
        Returns:
            Number of records inserted
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        timestamp_int = int(timestamp.timestamp())
        date_str = timestamp.strftime("%Y-%m-%d")  # YYYY-MM-DD format for easy date queries
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                inserted = 0
                for opt in options:
                    try:
                        # Extract expiry date and timestamp
                        expiry_date_str = None
                        expiry_timestamp = None
                        
                        # Try to get expiry_date from option data
                        if opt.get("expiry_date"):
                            expiry_date_str = opt.get("expiry_date")
                        elif opt.get("expiry"):
                            expiry_value = opt.get("expiry")
                            # If expiry is a timestamp (integer), convert to date string
                            try:
                                expiry_int = int(expiry_value)
                                expiry_date_str = datetime.fromtimestamp(expiry_int).strftime("%Y-%m-%d")
                                expiry_timestamp = expiry_int
                            except (ValueError, TypeError):
                                # If it's a date string, try to parse it
                                if isinstance(expiry_value, str):
                                    # Format: DD-MM-YYYY (from API)
                                    if len(expiry_value) == 10 and expiry_value.count("-") == 2:
                                        parts = expiry_value.split("-")
                                        if len(parts) == 3:
                                            expiry_date_str = f"{parts[2]}-{parts[1]}-{parts[0]}"
                        
                        # If still no expiry_date, try to extract from symbol
                        if not expiry_date_str:
                            symbol = opt.get("symbol", "")
                            expiry_date_str = self._extract_expiry_date_from_symbol(symbol)
                        
                        cursor.execute("""
                            INSERT INTO option_chain_snapshots 
                            (timestamp, date, symbol, strike, option_type, expiry, expiry_date, ltp, bid, ask, volume, oi, iv)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            timestamp_int,
                            date_str,
                            opt.get("symbol", ""),
                            opt.get("strike") if opt.get("strike") != "" else None,
                            opt.get("option_type", ""),
                            expiry_timestamp,
                            expiry_date_str,
                            opt.get("ltp", 0) or 0,
                            opt.get("bid", 0) or 0,
                            opt.get("ask", 0) or 0,
                            opt.get("volume", 0) or 0,
                            opt.get("oi", 0) or 0,
                            opt.get("iv", 0) or 0,
                        ))
                        inserted += 1
                    except Exception as e:
                        logger.warning("Failed to insert option %s: %s", opt.get("symbol"), e)
                
                conn.commit()
                logger.info("Stored snapshot: %d options at %s", inserted, timestamp.isoformat())
                return inserted
    
    def get_latest_snapshot(self, symbol: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get the latest snapshot of option chain data.
        
        Args:
            symbol: Filter by symbol (optional)
        
        Returns:
            List of option dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if symbol:
                cursor.execute("""
                    SELECT * FROM option_chain_snapshots
                    WHERE timestamp = (SELECT MAX(timestamp) FROM option_chain_snapshots)
                    AND symbol = ?
                    ORDER BY strike, option_type
                """, (symbol,))
            else:
                cursor.execute("""
                    SELECT * FROM option_chain_snapshots
                    WHERE timestamp = (SELECT MAX(timestamp) FROM option_chain_snapshots)
                    ORDER BY symbol, strike, option_type
                """)
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_price_history(
        self,
        symbol: str,
        strike: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get price history for a specific option.
        
        Args:
            symbol: Option symbol
            strike: Strike price (optional)
            start_time: Start timestamp (optional)
            end_time: End timestamp (optional)
            limit: Maximum number of records
        
        Returns:
            List of historical records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM option_chain_snapshots WHERE symbol = ?"
            params = [symbol]
            
            if strike is not None:
                query += " AND strike = ?"
                params.append(strike)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(int(start_time.timestamp()))
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(int(end_time.timestamp()))
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_volume_accumulation(
        self,
        symbol: str,
        strike: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get volume accumulation over time.
        
        Args:
            symbol: Option symbol
            strike: Strike price (optional)
            start_time: Start timestamp (optional)
            end_time: End timestamp (optional)
        
        Returns:
            Dictionary with volume statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    MIN(volume) as min_volume,
                    MAX(volume) as max_volume,
                    MAX(volume) - MIN(volume) as volume_change,
                    COUNT(*) as snapshots
                FROM option_chain_snapshots
                WHERE symbol = ?
            """
            params = [symbol]
            
            if strike is not None:
                query += " AND strike = ?"
                params.append(strike)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(int(start_time.timestamp()))
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(int(end_time.timestamp()))
            
            cursor.execute(query, params)
            row = cursor.fetchone()
            
            return {
                "symbol": symbol,
                "strike": strike,
                "min_volume": row[0] or 0,
                "max_volume": row[1] or 0,
                "volume_change": row[2] or 0,
                "snapshots": row[3] or 0
            }
    
    def export_to_csv(
        self,
        output_file: str,
        symbol: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> None:
        """
        Export data to CSV file.
        
        Args:
            output_file: Output CSV file path
            symbol: Filter by symbol (optional)
            start_time: Start timestamp (optional)
            end_time: End timestamp (optional)
        """
        import csv
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM option_chain_snapshots WHERE 1=1"
            params = []
            
            if symbol:
                query += " AND symbol = ?"
                params.append(symbol)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(int(start_time.timestamp()))
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(int(end_time.timestamp()))
            
            query += " ORDER BY timestamp DESC, symbol, strike"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            if not rows:
                logger.warning("No data to export")
                return
            
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "id", "timestamp", "symbol", "strike", "option_type", "expiry", "expiry_date",
                    "ltp", "bid", "ask", "volume", "oi", "iv"
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for row in rows:
                    writer.writerow(dict(row))
            
            logger.info("Exported %d records to %s", len(rows), output_file)
    
    def get_daily_high_volume_strikes(
        self,
        target_date: Optional[str] = None,
        expiry_date: Optional[str] = None,
        limit: int = 10,
        option_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get strikes with highest volume for a given day.
        
        Args:
            target_date: Date in YYYY-MM-DD format (default: today)
            expiry_date: Filter by expiry date (optional)
            limit: Number of top strikes to return (default: 10)
            option_type: Filter by option type ('CE' or 'PE', optional)
        
        Returns:
            List of strikes with aggregated volume data
        """
        if target_date is None:
            target_date = datetime.now().strftime("%Y-%m-%d")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get latest snapshot for each strike on the target date
            # Aggregate volume across all snapshots for the day
            query = """
                SELECT 
                    strike,
                    expiry_date,
                    option_type,
                    MAX(volume) as max_volume,
                    AVG(volume) as avg_volume,
                    SUM(volume) as total_volume,
                    MAX(ltp) as high_price,
                    MIN(ltp) as low_price,
                    AVG(ltp) as avg_price,
                    MAX(oi) as max_oi,
                    AVG(oi) as avg_oi,
                    COUNT(*) as snapshot_count
                FROM option_chain_snapshots
                WHERE date = ?
            """
            params = [target_date]
            
            if expiry_date:
                query += " AND expiry_date = ?"
                params.append(expiry_date)
            
            if option_type:
                query += " AND option_type = ?"
                params.append(option_type)
            
            query += """
                AND strike IS NOT NULL
                AND volume > 0
                GROUP BY strike, expiry_date, option_type
                ORDER BY total_volume DESC
                LIMIT ?
            """
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_daily_stats(
        self,
        target_date: Optional[str] = None,
        expiry_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics for a given day.
        
        Args:
            target_date: Date in YYYY-MM-DD format (default: today)
            expiry_date: Filter by expiry date (optional)
        
        Returns:
            Dictionary with aggregated statistics
        """
        if target_date is None:
            target_date = datetime.now().strftime("%Y-%m-%d")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    COUNT(DISTINCT timestamp) as snapshot_count,
                    COUNT(DISTINCT symbol) as unique_symbols,
                    COUNT(DISTINCT strike) as unique_strikes,
                    COUNT(DISTINCT expiry_date) as unique_expiries,
                    SUM(volume) as total_volume,
                    AVG(volume) as avg_volume,
                    MAX(volume) as max_volume,
                    SUM(oi) as total_oi,
                    AVG(oi) as avg_oi,
                    MAX(oi) as max_oi,
                    AVG(ltp) as avg_price,
                    MIN(ltp) as min_price,
                    MAX(ltp) as max_price
                FROM option_chain_snapshots
                WHERE date = ?
            """
            params = [target_date]
            
            if expiry_date:
                query += " AND expiry_date = ?"
                params.append(expiry_date)
            
            cursor.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else {}
    
    def get_strike_volume_history(
        self,
        strike: int,
        expiry_date: str,
        option_type: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get volume history for a specific strike.
        
        Args:
            strike: Strike price
            expiry_date: Expiry date in YYYY-MM-DD format
            option_type: Option type ('CE' or 'PE')
            start_date: Start date in YYYY-MM-DD format (optional)
            end_date: End date in YYYY-MM-DD format (optional)
        
        Returns:
            List of volume snapshots for the strike
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    timestamp,
                    date,
                    symbol,
                    strike,
                    option_type,
                    expiry_date,
                    ltp,
                    volume,
                    oi,
                    bid,
                    ask
                FROM option_chain_snapshots
                WHERE strike = ? AND option_type = ?
            """
            params = [strike, option_type]
            
            # Add expiry filter only if provided and not None
            if expiry_date and expiry_date.lower() != 'none':
                query += " AND expiry_date = ?"
                params.append(expiry_date)
            
            if start_date:
                query += " AND date >= ?"
                params.append(start_date)
            
            if end_date:
                query += " AND date <= ?"
                params.append(end_date)
            
            query += " ORDER BY timestamp ASC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_daily_volume_by_expiry(
        self,
        target_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get volume aggregated by expiry date for a given day.
        
        Args:
            target_date: Date in YYYY-MM-DD format (default: today)
        
        Returns:
            List of expiry dates with aggregated volume
        """
        if target_date is None:
            target_date = datetime.now().strftime("%Y-%m-%d")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    expiry_date,
                    COUNT(DISTINCT strike) as unique_strikes,
                    SUM(volume) as total_volume,
                    AVG(volume) as avg_volume,
                    MAX(volume) as max_volume,
                    SUM(oi) as total_oi,
                    AVG(oi) as avg_oi
                FROM option_chain_snapshots
                WHERE date = ? AND expiry_date IS NOT NULL
                GROUP BY expiry_date
                ORDER BY total_volume DESC
            """
            
            cursor.execute(query, [target_date])
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total records
            cursor.execute("SELECT COUNT(*) FROM option_chain_snapshots")
            total_records = cursor.fetchone()[0]
            
            # Unique timestamps (snapshots)
            cursor.execute("SELECT COUNT(DISTINCT timestamp) FROM option_chain_snapshots")
            total_snapshots = cursor.fetchone()[0]
            
            # Date range
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM option_chain_snapshots")
            min_ts, max_ts = cursor.fetchone()
            
            # Unique symbols
            cursor.execute("SELECT COUNT(DISTINCT symbol) FROM option_chain_snapshots")
            unique_symbols = cursor.fetchone()[0]
            
            return {
                "total_records": total_records,
                "total_snapshots": total_snapshots,
                "unique_symbols": unique_symbols,
                "first_timestamp": datetime.fromtimestamp(min_ts).isoformat() if min_ts else None,
                "last_timestamp": datetime.fromtimestamp(max_ts).isoformat() if max_ts else None,
                "db_size_mb": self.db_path.stat().st_size / (1024 * 1024) if self.db_path.exists() else 0
            }

