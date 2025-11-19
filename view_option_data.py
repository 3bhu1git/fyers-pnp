#!/usr/bin/env python3
"""
Option Chain Data Viewer

View stored option chain data from SQLite database.
Supports multiple viewing modes: latest snapshot, history, volume stats, etc.
"""

import argparse
import sys
from datetime import datetime, timedelta
from option_chain_storage import OptionChainStorage


def view_latest(storage: OptionChainStorage, symbol: str = None):
    """View latest snapshot"""
    print("\n" + "=" * 100)
    print("LATEST SNAPSHOT")
    print("=" * 100)
    
    latest = storage.get_latest_snapshot(symbol=symbol)
    
    if not latest:
        print("No data found")
        return
    
    # Get timestamp from first record
    if latest:
        ts = datetime.fromtimestamp(latest[0]['timestamp'])
        print(f"Timestamp: {ts.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Options: {len(latest)}\n")
    
    # Print header
    print(f"{'Symbol':<30} {'Strike':<10} {'Type':<5} {'Expiry':<12} {'LTP':<12} {'Bid':<12} {'Ask':<12} {'Volume':<15} {'OI':<15}")
    print("-" * 120)
    
    # Print options
    for opt in latest:
        expiry_date = opt.get('expiry_date', '') or ''
        print(
            f"{opt.get('symbol', ''):<30} "
            f"{opt.get('strike', ''):<10} "
            f"{opt.get('option_type', ''):<5} "
            f"{expiry_date:<12} "
            f"{opt.get('ltp', 0):<12.2f} "
            f"{opt.get('bid', 0):<12.2f} "
            f"{opt.get('ask', 0):<12.2f} "
            f"{opt.get('volume', 0):<15,} "
            f"{opt.get('oi', 0):<15,}"
        )


def view_history(storage: OptionChainStorage, symbol: str, limit: int = 20):
    """View price history"""
    print("\n" + "=" * 100)
    print(f"PRICE HISTORY: {symbol}")
    print("=" * 100)
    
    history = storage.get_price_history(symbol, limit=limit)
    
    if not history:
        print("No history found")
        return
    
    print(f"Showing last {len(history)} records\n")
    print(f"{'Timestamp':<20} {'LTP':<12} {'Bid':<12} {'Ask':<12} {'Volume':<15} {'OI':<15}")
    print("-" * 100)
    
    for record in history:
        ts = datetime.fromtimestamp(record['timestamp'])
        print(
            f"{ts.strftime('%Y-%m-%d %H:%M:%S'):<20} "
            f"{record.get('ltp', 0):<12.2f} "
            f"{record.get('bid', 0):<12.2f} "
            f"{record.get('ask', 0):<12.2f} "
            f"{record.get('volume', 0):<15,} "
            f"{record.get('oi', 0):<15,}"
        )


def view_volume_stats(storage: OptionChainStorage, symbol: str):
    """View volume accumulation stats"""
    print("\n" + "=" * 100)
    print(f"VOLUME STATISTICS: {symbol}")
    print("=" * 100)
    
    stats = storage.get_volume_accumulation(symbol)
    
    print(f"Symbol: {stats['symbol']}")
    if stats.get('strike'):
        print(f"Strike: {stats['strike']}")
    print(f"Min Volume: {stats['min_volume']:,}")
    print(f"Max Volume: {stats['max_volume']:,}")
    print(f"Volume Change: {stats['volume_change']:,}")
    print(f"Total Snapshots: {stats['snapshots']}")
    
    if stats['snapshots'] > 0:
        avg_change = stats['volume_change'] / stats['snapshots']
        print(f"Avg Volume Change per Snapshot: {avg_change:,.0f}")


def view_stats(storage: OptionChainStorage):
    """View storage statistics"""
    print("\n" + "=" * 100)
    print("STORAGE STATISTICS")
    print("=" * 100)
    
    stats = storage.get_stats()
    
    print(f"Total Records: {stats['total_records']:,}")
    print(f"Total Snapshots: {stats['total_snapshots']:,}")
    print(f"Unique Symbols: {stats['unique_symbols']}")
    print(f"First Timestamp: {stats['first_timestamp']}")
    print(f"Last Timestamp: {stats['last_timestamp']}")
    print(f"Database Size: {stats['db_size_mb']:.2f} MB")
    
    if stats['total_snapshots'] > 0:
        avg_records = stats['total_records'] / stats['total_snapshots']
        print(f"Avg Records per Snapshot: {avg_records:.1f}")


def view_high_volume_strikes(storage: OptionChainStorage, target_date: str = None, expiry_date: str = None):
    """View high volume strikes for a date, optionally filtered by expiry"""
    print("\n" + "=" * 100)
    title = f"HIGH VOLUME STRIKES: {target_date or 'Today'}"
    if expiry_date:
        title += f" (Expiry: {expiry_date})"
    print(title)
    print("=" * 100)
    
    strikes = storage.get_daily_high_volume_strikes(target_date=target_date, expiry_date=expiry_date, limit=50)
    
    if not strikes:
        print("No data found")
        return
    
    if expiry_date:
        # Show both CE and PE for each strike
        print(f"\n{'Rank':<6} {'Strike':<10} {'Type':<5} {'Total Vol':<15} {'Avg Vol':<15} {'Max Vol':<15} {'Avg Price':<12} {'Max OI':<15}")
    else:
        print(f"\n{'Rank':<6} {'Strike':<10} {'Expiry':<12} {'Type':<5} {'Total Vol':<15} {'Avg Vol':<15} {'Max Vol':<15} {'Avg Price':<12} {'Max OI':<15}")
    print("-" * 120)
    
    for rank, strike_data in enumerate(strikes, 1):
        expiry_date_str = strike_data.get('expiry_date') or ''
        if expiry_date:
            # Don't show expiry column if filtering by expiry
            print(
                f"{rank:<6} "
                f"{strike_data.get('strike', ''):<10} "
                f"{strike_data.get('option_type', ''):<5} "
                f"{strike_data.get('total_volume', 0) or 0:<15,} "
                f"{strike_data.get('avg_volume', 0) or 0:<15,.0f} "
                f"{strike_data.get('max_volume', 0) or 0:<15,} "
                f"{strike_data.get('avg_price', 0) or 0:<12.2f} "
                f"{strike_data.get('max_oi', 0) or 0:<15,}"
            )
        else:
            print(
                f"{rank:<6} "
                f"{strike_data.get('strike', ''):<10} "
                f"{expiry_date_str:<12} "
                f"{strike_data.get('option_type', ''):<5} "
                f"{strike_data.get('total_volume', 0) or 0:<15,} "
                f"{strike_data.get('avg_volume', 0) or 0:<15,.0f} "
                f"{strike_data.get('max_volume', 0) or 0:<15,} "
                f"{strike_data.get('avg_price', 0) or 0:<12.2f} "
                f"{strike_data.get('max_oi', 0) or 0:<15,}"
            )


def view_daily_stats(storage: OptionChainStorage, target_date: str = None):
    """View daily statistics"""
    print("\n" + "=" * 100)
    print(f"DAILY STATISTICS: {target_date or 'Today'}")
    print("=" * 100)
    
    stats = storage.get_daily_stats(target_date=target_date)
    
    if not stats:
        print("No data found")
        return
    
    print(f"\nSnapshots: {stats.get('snapshot_count', 0)}")
    print(f"Unique Symbols: {stats.get('unique_symbols', 0)}")
    print(f"Unique Strikes: {stats.get('unique_strikes', 0)}")
    print(f"Unique Expiries: {stats.get('unique_expiries', 0)}")
    print(f"\nVolume:")
    print(f"  Total: {stats.get('total_volume', 0):,}")
    print(f"  Average: {stats.get('avg_volume', 0):,.0f}")
    print(f"  Maximum: {stats.get('max_volume', 0):,}")
    print(f"\nOpen Interest:")
    print(f"  Total: {stats.get('total_oi', 0):,}")
    print(f"  Average: {stats.get('avg_oi', 0):,.0f}")
    print(f"  Maximum: {stats.get('max_oi', 0):,}")
    print(f"\nPrice:")
    print(f"  Average: {stats.get('avg_price', 0):.2f}")
    print(f"  Minimum: {stats.get('min_price', 0):.2f}")
    print(f"  Maximum: {stats.get('max_price', 0):.2f}")


def view_volume_by_expiry(storage: OptionChainStorage, target_date: str = None):
    """View volume aggregated by expiry"""
    print("\n" + "=" * 100)
    print(f"VOLUME BY EXPIRY: {target_date or 'Today'}")
    print("=" * 100)
    
    data = storage.get_daily_volume_by_expiry(target_date=target_date)
    
    if not data:
        print("No data found")
        return
    
    print(f"\n{'Expiry':<12} {'Strikes':<10} {'Total Vol':<15} {'Avg Vol':<15} {'Max Vol':<15} {'Total OI':<15}")
    print("-" * 100)
    
    for row in data:
        print(
            f"{row.get('expiry_date', ''):<12} "
            f"{row.get('unique_strikes', 0):<10} "
            f"{row.get('total_volume', 0):<15,} "
            f"{row.get('avg_volume', 0):<15,.0f} "
            f"{row.get('max_volume', 0):<15,} "
            f"{row.get('total_oi', 0):<15,}"
        )


def view_strike_history(storage: OptionChainStorage, strike: int, expiry_date: str, option_type: str, timeline: bool = False, start_date: str = None, end_date: str = None, limit: int = None):
    """View volume history for a specific strike"""
    print("\n" + "=" * 100)
    print(f"STRIKE HISTORY: {strike} {expiry_date} {option_type}")
    if start_date or end_date:
        date_range = f"Date Range: {start_date or 'start'} to {end_date or 'end'}"
        print(date_range)
    print("=" * 100)
    
    history = storage.get_strike_volume_history(strike, expiry_date, option_type, start_date=start_date, end_date=end_date)
    
    # Apply limit if specified
    if limit and limit > 0:
        history = history[:limit]
    
    if not history:
        print("No data found")
        return
    
    # Show info about total records
    total_count = len(history)
    if limit:
        print(f"\nShowing {total_count} of {total_count} records" + (f" (limited to {limit})" if limit < total_count else ""))
    else:
        print(f"\nTotal records: {total_count}")
    
    if timeline:
        # Enhanced timeline view with time differences and volume changes
        print(f"\n{'#':<4} {'Timestamp':<15} {'Time':<20} {'LTP':<10} {'Bid':<10} {'Ask':<10} {'Volume':<15} {'Vol Δ':<12} {'OI':<15} {'OI Δ':<12} {'Time Δ':<10}")
        print("-" * 140)
        
        prev_ts = None
        prev_vol = None
        prev_oi = None
        
        for i, h in enumerate(history, 1):
            ts = h['timestamp']
            dt = datetime.fromtimestamp(ts)
            ltp = h.get('ltp', 0) or 0
            bid = h.get('bid', 0) or 0
            ask = h.get('ask', 0) or 0
            vol = h.get('volume', 0) or 0
            oi = h.get('oi', 0) or 0
            
            # Calculate differences
            time_diff = ""
            if prev_ts:
                diff_seconds = ts - prev_ts
                if diff_seconds < 60:
                    time_diff = f"{diff_seconds}s"
                elif diff_seconds < 3600:
                    time_diff = f"{diff_seconds//60}m {diff_seconds%60}s"
                else:
                    hours = diff_seconds // 3600
                    mins = (diff_seconds % 3600) // 60
                    time_diff = f"{hours}h {mins}m"
            
            vol_diff = ""
            if prev_vol is not None:
                vol_delta = vol - prev_vol
                vol_diff = f"{vol_delta:+,}" if vol_delta != 0 else "0"
            
            oi_diff = ""
            if prev_oi is not None:
                oi_delta = oi - prev_oi
                oi_diff = f"{oi_delta:+,}" if oi_delta != 0 else "0"
            
            print(
                f"{i:<4} "
                f"{ts:<15} "
                f"{dt.strftime('%Y-%m-%d %H:%M:%S'):<20} "
                f"{ltp:<10.2f} "
                f"{bid:<10.2f} "
                f"{ask:<10.2f} "
                f"{vol:<15,} "
                f"{vol_diff:<12} "
                f"{oi:<15,} "
                f"{oi_diff:<12} "
                f"{time_diff:<10}"
            )
            
            prev_ts = ts
            prev_vol = vol
            prev_oi = oi
        
        print("-" * 140)
        
        # Summary statistics
        if len(history) > 1:
            first = history[0]
            last = history[-1]
            total_time = last['timestamp'] - first['timestamp']
            vol_change = (last.get('volume', 0) or 0) - (first.get('volume', 0) or 0)
            oi_change = (last.get('oi', 0) or 0) - (first.get('oi', 0) or 0)
            
            print(f"\nSummary:")
            print(f"  Total Snapshots: {len(history)}")
            print(f"  Time Range: {datetime.fromtimestamp(first['timestamp']).strftime('%H:%M:%S')} to {datetime.fromtimestamp(last['timestamp']).strftime('%H:%M:%S')}")
            print(f"  Duration: {total_time//60}m {total_time%60}s")
            print(f"  Volume Change: {vol_change:+,}")
            print(f"  OI Change: {oi_change:+,}")
            if vol_change != 0:
                print(f"  Avg Volume Change per Snapshot: {vol_change/(len(history)-1):,.0f}")
    else:
        # Standard view
        print(f"\n{'Timestamp':<20} {'Date':<12} {'LTP':<12} {'Volume':<15} {'OI':<15} {'Bid':<12} {'Ask':<12}")
        print("-" * 100)
        
        for h in history:
            ts = datetime.fromtimestamp(h['timestamp'])
            print(
                f"{ts.strftime('%Y-%m-%d %H:%M:%S'):<20} "
                f"{h.get('date', ''):<12} "
                f"{h.get('ltp', 0):<12.2f} "
                f"{h.get('volume', 0):<15,} "
                f"{h.get('oi', 0):<15,} "
                f"{h.get('bid', 0):<12.2f} "
                f"{h.get('ask', 0):<12.2f}"
            )


def view_symbols(storage: OptionChainStorage):
    """List all unique symbols"""
    print("\n" + "=" * 100)
    print("AVAILABLE SYMBOLS")
    print("=" * 100)
    
    import sqlite3
    with sqlite3.connect(storage.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT symbol FROM option_chain_snapshots ORDER BY symbol")
        symbols = [row[0] for row in cursor.fetchall()]
    
    if not symbols:
        print("No symbols found")
        return
    
    print(f"Total Unique Symbols: {len(symbols)}\n")
    for i, symbol in enumerate(symbols, 1):
        print(f"{i:3d}. {symbol}")


def main():
    parser = argparse.ArgumentParser(
        description="View Option Chain Data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # View latest snapshot
  python view_option_data.py --latest
  
  # View latest for specific symbol
  python view_option_data.py --latest --symbol "NSE:NIFTY25NOV25600CE"
  
  # View price history
  python view_option_data.py --history "NSE:NIFTY25NOV25600CE" --limit 50
  
  # View volume stats
  python view_option_data.py --volume "NSE:NIFTY25NOV25600CE"
  
  # View storage statistics
  python view_option_data.py --stats
  
  # List all symbols
  python view_option_data.py --symbols
  
  # High volume strikes for today
  python view_option_data.py --high-volume
  
  # High volume strikes for specific date
  python view_option_data.py --high-volume --date 2025-11-19
  
  # High volume strikes for specific expiry on specific date
  python view_option_data.py --high-volume --date 2025-11-19 --expiry 2025-11-25
  
  # Daily statistics
  python view_option_data.py --daily-stats --date 2025-11-19
  
  # Volume by expiry
  python view_option_data.py --volume-by-expiry --date 2025-11-19
  
  # Strike timeline (standard view)
  python view_option_data.py --strike-history 26000 2025-11-25 PE
  
  # Strike timeline (detailed timeline view with changes)
  python view_option_data.py --strike-history 26000 2025-11-25 PE --timeline
  
  # Strike timeline with date range
  python view_option_data.py --strike-history 26000 2025-11-25 PE --timeline --start-date 2025-11-19 --end-date 2025-11-20
  
  # Strike timeline with max records
  python view_option_data.py --strike-history 26000 2025-11-25 PE --timeline --max-records 100
        """
    )
    
    parser.add_argument("--db", default="data/option_chain.db", help="Database path")
    parser.add_argument("--latest", action="store_true", help="View latest snapshot")
    parser.add_argument("--history", metavar="SYMBOL", help="View price history for symbol")
    parser.add_argument("--volume", metavar="SYMBOL", help="View volume stats for symbol")
    parser.add_argument("--stats", action="store_true", help="View storage statistics")
    parser.add_argument("--symbols", action="store_true", help="List all symbols")
    parser.add_argument("--symbol", help="Filter by symbol (for --latest)")
    parser.add_argument("--limit", type=int, default=20, help="Limit records (for --history)")
    parser.add_argument("--high-volume", action="store_true", help="Show high volume strikes (use with --date and optionally --expiry)")
    parser.add_argument("--date", type=str, metavar="YYYY-MM-DD", help="Trading date for queries (default: today)")
    parser.add_argument("--expiry", type=str, metavar="YYYY-MM-DD", help="Expiry date filter (optional)")
    parser.add_argument("--daily-stats", action="store_true", help="Show daily statistics (use with --date)")
    parser.add_argument("--volume-by-expiry", action="store_true", help="Show volume by expiry (use with --date)")
    parser.add_argument("--strike-history", nargs=3, metavar=("STRIKE", "EXPIRY", "TYPE"), help="Show volume history for strike (e.g., 25800 2025-11-25 CE)")
    parser.add_argument("--timeline", action="store_true", help="Show detailed timeline view with time differences and volume changes (use with --strike-history)")
    parser.add_argument("--start-date", type=str, metavar="YYYY-MM-DD", help="Start date for strike history (use with --strike-history)")
    parser.add_argument("--end-date", type=str, metavar="YYYY-MM-DD", help="End date for strike history (use with --strike-history)")
    parser.add_argument("--max-records", type=int, help="Maximum number of records to show (use with --strike-history)")
    
    args = parser.parse_args()
    
    # Initialize storage
    try:
        storage = OptionChainStorage(db_path=args.db)
    except Exception as e:
        print(f"Error initializing storage: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Execute requested view
    if args.latest:
        view_latest(storage, symbol=args.symbol)
    elif args.history:
        view_history(storage, args.history, limit=args.limit)
    elif args.volume:
        view_volume_stats(storage, args.volume)
    elif args.stats:
        view_stats(storage)
    elif args.symbols:
        view_symbols(storage)
    elif args.high_volume:
        # For high volume strikes, date is required if expiry is specified
        if args.expiry and not args.date:
            print("Error: --date is required when using --expiry with --high-volume", file=sys.stderr)
            print("Usage: python view_option_data.py --high-volume --date YYYY-MM-DD --expiry YYYY-MM-DD", file=sys.stderr)
            sys.exit(1)
        target_date = args.date  # None if not provided, will default to today in function
        expiry_date = args.expiry  # None if not provided
        view_high_volume_strikes(storage, target_date, expiry_date=expiry_date)
    elif args.daily_stats:
        target_date = args.date  # None if not provided, will default to today in function
        view_daily_stats(storage, target_date)
    elif args.volume_by_expiry:
        target_date = args.date  # None if not provided, will default to today in function
        view_volume_by_expiry(storage, target_date)
    elif args.strike_history:
        strike, expiry, opt_type = args.strike_history
        view_strike_history(
            storage, 
            int(strike), 
            expiry, 
            opt_type, 
            timeline=args.timeline,
            start_date=args.start_date,
            end_date=args.end_date,
            limit=args.max_records
        )
    else:
        # Default: show latest
        view_latest(storage)
        view_stats(storage)


if __name__ == "__main__":
    main()

