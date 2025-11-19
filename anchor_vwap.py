#!/usr/bin/env python3
"""
Anchor VWAP Calculator

Calculates anchor VWAP from day's high for a specific strike and date.
Provides two anchor VWAP calculations:
1. Primary Anchor: VWAP source = High (from timeframe bars)
2. Secondary Anchor: VWAP source = HLC3 (High + Low + Close) / 3 (from timeframe bars)

Usage:
    python anchor_vwap.py --strike 26000 --date 2025-11-19 --expiry 2025-11-25 --type CE --timeframe 5
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from option_chain_storage import OptionChainStorage


def calculate_hlc3(high: float, low: float, close: float) -> float:
    """Calculate HLC3 (High + Low + Close) / 3"""
    return (high + low + close) / 3.0


def group_into_timeframe_bars(
    data_points: List[Dict],
    timeframe_minutes: int
) -> List[Dict]:
    """
    Group snapshots into timeframe bars (OHLC).
    
    Args:
        data_points: List of data points with timestamp, ltp, volume
        timeframe_minutes: Timeframe in minutes (e.g., 1, 5, 15)
    
    Returns:
        List of OHLC bars with open, high, low, close, volume, timestamp
    """
    if not data_points:
        return []
    
    # Sort by timestamp
    sorted_points = sorted(data_points, key=lambda x: x.get('timestamp', 0))
    
    bars = []
    current_bar = None
    bar_start_time = None
    bar_points = []  # Track points in current bar for volume calculation
    
    for point in sorted_points:
        timestamp = point.get('timestamp', 0)
        ltp = point.get('ltp', 0) or 0
        bid = point.get('bid', 0) or 0
        ask = point.get('ask', 0) or 0
        volume = point.get('volume', 0) or 0
        
        if timestamp == 0 or ltp == 0:
            continue
        
        point_time = datetime.fromtimestamp(timestamp)
        
        # Use bid/ask to create a price range if available
        # High = max(LTP, Ask), Low = min(LTP, Bid)
        # This gives us a realistic range even when LTP doesn't move
        high_price = max(ltp, ask) if ask > 0 else ltp
        low_price = min(ltp, bid) if bid > 0 else ltp
        
        # Determine which bar this point belongs to
        if timeframe_minutes == 1:
            bar_time = point_time.replace(second=0, microsecond=0)
        else:
            # Round down to nearest timeframe
            minutes = (point_time.minute // timeframe_minutes) * timeframe_minutes
            bar_time = point_time.replace(minute=minutes, second=0, microsecond=0)
        
        # Start new bar if needed
        if current_bar is None or bar_start_time != bar_time:
            # Save previous bar if exists
            if current_bar is not None:
                # Calculate incremental volume for the bar
                # Volume is cumulative, so sum up all volume changes within the bar
                if len(bar_points) > 1:
                    incremental_vol = 0
                    prev_vol = bar_points[0].get('volume', 0) or 0
                    for point in bar_points[1:]:
                        curr_vol = point.get('volume', 0) or 0
                        vol_diff = curr_vol - prev_vol
                        if vol_diff > 0:  # Only count positive changes
                            incremental_vol += vol_diff
                        prev_vol = curr_vol
                    # Also include the first point's volume if it's the only one
                    if incremental_vol == 0 and len(bar_points) == 1:
                        incremental_vol = bar_points[0].get('volume', 0) or 0
                    current_bar['incremental_volume'] = incremental_vol
                else:
                    current_bar['incremental_volume'] = bar_points[0].get('volume', 0) or 0 if bar_points else 0
                bars.append(current_bar)
            
            # Start new bar
            current_bar = {
                'timestamp': int(bar_time.timestamp()),
                'time': bar_time,
                'open': ltp,
                'high': high_price,
                'low': low_price,
                'close': ltp,
                'volume': volume,  # Store last volume (cumulative)
                'points_count': 1
            }
            bar_start_time = bar_time
            bar_points = [point]  # Start tracking points for this bar
        else:
            # Update current bar
            current_bar['high'] = max(current_bar['high'], high_price)
            current_bar['low'] = min(current_bar['low'], low_price)
            current_bar['close'] = ltp  # Close is last LTP in the bar
            current_bar['volume'] = volume  # Update to last volume (cumulative)
            current_bar['points_count'] += 1
            bar_points.append(point)  # Track this point
    
    # Add last bar
    if current_bar is not None:
        # Calculate incremental volume for the last bar
        # Sum up all volume changes within the bar
        if len(bar_points) > 1:
            incremental_vol = 0
            prev_vol = bar_points[0].get('volume', 0) or 0
            for point in bar_points[1:]:
                curr_vol = point.get('volume', 0) or 0
                vol_diff = curr_vol - prev_vol
                if vol_diff > 0:  # Only count positive changes
                    incremental_vol += vol_diff
                prev_vol = curr_vol
            # Also include the first point's volume if it's the only one
            if incremental_vol == 0 and len(bar_points) == 1:
                incremental_vol = bar_points[0].get('volume', 0) or 0
            current_bar['incremental_volume'] = incremental_vol
        else:
            current_bar['incremental_volume'] = bar_points[0].get('volume', 0) or 0 if bar_points else 0
        bars.append(current_bar)
    
    return bars


def calculate_vwap(
    bars: List[Dict],
    price_source: str = "high"
) -> Tuple[List[float], List[int]]:
    """
    Calculate VWAP (Volume Weighted Average Price) from anchor point using OHLC bars.
    
    Args:
        bars: List of OHLC bars with open, high, low, close, volume
        price_source: Source for price calculation ('high' or 'hlc3')
    
    Returns:
        Tuple of (vwap_values, cumulative_volumes)
    """
    cumulative_price_volume = 0.0
    cumulative_volume = 0
    vwap_values = []
    cumulative_volumes = []
    
    for bar in bars:
        # Use incremental volume if available, otherwise use volume
        volume = bar.get('incremental_volume', bar.get('volume', 0) or 0) or 0
        high = bar.get('high', 0) or 0
        low = bar.get('low', 0) or 0
        close = bar.get('close', 0) or 0
        
        if price_source == "high":
            # For primary anchor, use high price of the bar
            price = high
        elif price_source == "hlc3":
            # For secondary anchor, calculate HLC3 from the bar
            price = calculate_hlc3(high, low, close)
        else:
            price = close  # Default to close
        
        if volume > 0:
            # Normal case: volume-weighted calculation
            cumulative_price_volume += price * volume
            cumulative_volume += volume
            vwap = cumulative_price_volume / cumulative_volume if cumulative_volume > 0 else 0
        else:
            # When volume is 0 or unchanged, we still need to account for price changes
            # Use a minimal weight (1) to ensure VWAP reflects price movement
            # This ensures VWAP updates even when volume doesn't change
            cumulative_price_volume += price * 1
            cumulative_volume += 1
            vwap = cumulative_price_volume / cumulative_volume if cumulative_volume > 0 else price
        
        vwap_values.append(vwap)
        cumulative_volumes.append(cumulative_volume)
    
    return vwap_values, cumulative_volumes


def get_day_high_and_data(
    storage: OptionChainStorage,
    strike: int,
    expiry_date: str,
    option_type: str,
    target_date: str
) -> Tuple[float, List[Dict]]:
    """
    Get day's high and all data points for the strike.
    
    Returns:
        Tuple of (day_high, data_points)
    """
    # Get all data points for the strike on the target date
    history = storage.get_strike_volume_history(
        strike=strike,
        expiry_date=expiry_date,
        option_type=option_type,
        start_date=target_date,
        end_date=target_date
    )
    
    if not history:
        raise ValueError(f"No data found for strike {strike}, expiry {expiry_date}, type {option_type} on {target_date}")
    
    # Sort by timestamp
    history.sort(key=lambda x: x.get('timestamp', 0))
    
    # Find day's high (maximum LTP/price)
    # Since we're storing snapshots, LTP represents the price at that moment
    # Day's high is the maximum LTP value
    day_high = max(
        (point.get('ltp', 0) or 0 for point in history if point.get('ltp')),
        default=0.0
    )
    
    if day_high == 0:
        raise ValueError(f"Could not determine day's high for strike {strike}")
    
    return day_high, history


def calculate_anchor_vwap(
    storage: OptionChainStorage,
    strike: int,
    expiry_date: str,
    option_type: str,
    anchor_date: str,
    timeframe_minutes: int = 5,
    current_date: Optional[str] = None
) -> Dict:
    """
    Calculate anchor VWAP from day's high.
    
    Args:
        storage: OptionChainStorage instance
        strike: Strike price
        expiry_date: Expiry date of the option (YYYY-MM-DD)
        option_type: Option type ('CE' or 'PE')
        anchor_date: Date for which we find the high to use as anchor (YYYY-MM-DD)
        timeframe_minutes: Timeframe for bars (default: 5)
        current_date: Date to get current VWAP value (default: same as anchor_date)
    
    Returns:
        Dictionary with anchor VWAP values and current values
    """
    if current_date is None:
        current_date = anchor_date
    
    # Get day's high and data points from anchor date
    day_high, anchor_data_points = get_day_high_and_data(
        storage, strike, expiry_date, option_type, anchor_date
    )
    
    # Get current date data points if different from anchor date
    if current_date != anchor_date:
        _, current_data_points = get_day_high_and_data(
            storage, strike, expiry_date, option_type, current_date
        )
        # Combine anchor date data (from high onwards) with current date data
        data_points = anchor_data_points + current_data_points
    else:
        data_points = anchor_data_points
    
    # Filter data points from the high point onwards
    # Find the index where high was first reached (or closest to it)
    high_index = 0
    min_diff = float('inf')
    for i, point in enumerate(data_points):
        price = point.get('ltp', 0) or 0
        if price > 0:
            diff = abs(price - day_high)
            if diff < min_diff:
                min_diff = diff
                high_index = i
    
    # Use all points from high onwards
    # This includes the high point itself and all subsequent points
    anchor_data_points = data_points[high_index:]
    
    if not anchor_data_points:
        raise ValueError("No data points found from high point")
    
    # Group snapshots into timeframe bars (OHLC)
    bars = group_into_timeframe_bars(anchor_data_points, timeframe_minutes)
    
    if not bars:
        raise ValueError("No bars created from data points")
    
    # Calculate Primary Anchor VWAP (source = High from bars)
    primary_vwap_values, primary_volumes = calculate_vwap(
        bars, price_source="high"
    )
    
    # Calculate Secondary Anchor VWAP (source = HLC3 from bars)
    secondary_vwap_values, secondary_volumes = calculate_vwap(
        bars, price_source="hlc3"
    )
    
    # Get current (latest) values
    current_primary_vwap = primary_vwap_values[-1] if primary_vwap_values else 0.0
    current_secondary_vwap = secondary_vwap_values[-1] if secondary_vwap_values else 0.0
    
    # Get latest price and timestamp from last bar
    latest_bar = bars[-1] if bars else None
    latest_price = latest_bar.get('close', 0) or 0 if latest_bar else 0
    latest_timestamp = latest_bar.get('timestamp', 0) if latest_bar else 0
    latest_time = latest_bar.get('time') if latest_bar else None
    
    # Get high bar info
    high_bar = bars[0] if bars else None
    high_timestamp = high_bar.get('timestamp', 0) if high_bar else anchor_data_points[0].get('timestamp', 0)
    high_time = high_bar.get('time') if high_bar else (datetime.fromtimestamp(anchor_data_points[0].get('timestamp', 0)) if anchor_data_points[0].get('timestamp') else None)
    
    # Calculate total volume (sum of incremental volumes)
    total_volume = sum(bar.get('incremental_volume', 0) or 0 for bar in bars)
    
    return {
        "strike": strike,
        "expiry_date": expiry_date,
        "option_type": option_type,
        "anchor_date": anchor_date,
        "current_date": current_date,
        "timeframe_minutes": timeframe_minutes,
        "day_high": day_high,
        "high_timestamp": high_timestamp,
        "high_time": high_time,
        "primary_anchor_vwap": current_primary_vwap,
        "secondary_anchor_vwap": current_secondary_vwap,
        "primary_vwap_values": primary_vwap_values,
        "secondary_vwap_values": secondary_vwap_values,
        "bars": bars,
        "latest_price": latest_price,
        "latest_timestamp": latest_timestamp,
        "latest_time": latest_time,
        "data_points_count": len(data_points),
        "bars_count": len(bars),
        "total_volume": sum(p.get('volume', 0) or 0 for p in data_points)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Calculate Anchor VWAP from Day's High",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Calculate anchor VWAP using 2025-11-19 high as anchor for expiry 2025-11-25
  python anchor_vwap.py --strike 26000 --anchor-date 2025-11-19 --expiry 2025-11-25 --type CE
  
  # Calculate with 1-minute timeframe
  python anchor_vwap.py --strike 26000 --anchor-date 2025-11-19 --expiry 2025-11-25 --type CE --timeframe 1
  
  # Calculate anchor from one date, get current value from another date
  python anchor_vwap.py --strike 26000 --anchor-date 2025-11-19 --expiry 2025-11-25 --type CE --current-date 2025-11-20
  
  # Calculate with 15-minute timeframe
  python anchor_vwap.py --strike 26000 --anchor-date 2025-11-19 --expiry 2025-11-25 --type CE --timeframe 15
  
  # Calculate for PE option
  python anchor_vwap.py --strike 26000 --anchor-date 2025-11-19 --expiry 2025-11-25 --type PE --timeframe 5
        """
    )
    
    parser.add_argument("--strike", type=int, required=True, help="Strike price")
    parser.add_argument("--anchor-date", type=str, required=True, metavar="YYYY-MM-DD", help="Date for anchor (day's high to use as anchor point)")
    parser.add_argument("--expiry", type=str, required=True, metavar="YYYY-MM-DD", help="Expiry date of the option")
    parser.add_argument("--type", type=str, required=True, choices=["CE", "PE"], help="Option type (CE or PE)")
    parser.add_argument("--current-date", type=str, metavar="YYYY-MM-DD", help="Date to get current VWAP value (default: same as anchor-date)")
    parser.add_argument("--timeframe", type=int, default=5, choices=[1, 3, 5, 15, 30, 60], help="Timeframe in minutes (default: 5)")
    parser.add_argument("--db", type=str, default="data/option_chain.db", help="Database path")
    
    args = parser.parse_args()
    
    # Initialize storage
    try:
        storage = OptionChainStorage(db_path=args.db)
    except Exception as e:
        print(f"Error initializing storage: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Calculate anchor VWAP
    try:
        result = calculate_anchor_vwap(
            storage=storage,
            strike=args.strike,
            expiry_date=args.expiry,
            option_type=args.type,
            anchor_date=args.anchor_date,
            timeframe_minutes=args.timeframe,
            current_date=args.current_date
        )
        
        # Print results
        print("\n" + "=" * 80)
        print("ANCHOR VWAP CALCULATION")
        print("=" * 80)
        print(f"\nStrike: {result['strike']}")
        print(f"Expiry: {result['expiry_date']}")
        print(f"Option Type: {result['option_type']}")
        print(f"Anchor Date: {result['anchor_date']} (day's high used as anchor)")
        if result['current_date'] != result['anchor_date']:
            print(f"Current Date: {result['current_date']} (date for current VWAP value)")
        print(f"Timeframe: {result['timeframe_minutes']} minutes")
        print(f"\nDay's High (from {result['anchor_date']}): {result['day_high']:.2f}")
        if result['high_time']:
            print(f"High Time: {result['high_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nData Points from High: {result['data_points_count']}")
        print(f"Timeframe Bars: {result['bars_count']}")
        print(f"Total Volume: {result['total_volume']:,}")
        
        # Show VWAP progression by bar
        print("\n" + "-" * 100)
        print("VWAP PROGRESSION BY BAR")
        print("-" * 100)
        print(f"{'Bar':<6} {'Time':<20} {'High':<10} {'HLC3':<10} {'Vol':<12} {'Primary VWAP':<15} {'Secondary VWAP':<15}")
        print("-" * 100)
        bars = result.get('bars', [])
        primary_vwap_values = result.get('primary_vwap_values', [])
        secondary_vwap_values = result.get('secondary_vwap_values', [])
        for i, bar in enumerate(bars):
            bar_time = bar.get('time', datetime.fromtimestamp(bar.get('timestamp', 0)))
            bar_high = bar.get('high', 0) or 0
            bar_low = bar.get('low', 0) or 0
            bar_close = bar.get('close', 0) or 0
            bar_hlc3 = calculate_hlc3(bar_high, bar_low, bar_close)
            bar_vol = bar.get('incremental_volume', 0) or 0
            prim_vwap = primary_vwap_values[i] if i < len(primary_vwap_values) else 0.0
            sec_vwap = secondary_vwap_values[i] if i < len(secondary_vwap_values) else 0.0
            print(f"{i:<6} {str(bar_time):<20} {bar_high:<10.2f} {bar_hlc3:<10.2f} {bar_vol:<12,} {prim_vwap:<15.2f} {sec_vwap:<15.2f}")
        
        print("\n" + "-" * 80)
        print("CURRENT ANCHOR VWAP VALUES")
        print("-" * 80)
        print(f"\n1. Primary Anchor VWAP (Source: High from {result['timeframe_minutes']}min bars):")
        print(f"   Current Value: {result['primary_anchor_vwap']:.2f}")
        
        print(f"\n2. Secondary Anchor VWAP (Source: HLC3 from {result['timeframe_minutes']}min bars):")
        print(f"   Current Value: {result['secondary_anchor_vwap']:.2f}")
        
        print(f"\nLatest Price: {result['latest_price']:.2f}")
        if result['latest_time']:
            print(f"Latest Time: {result['latest_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n" + "=" * 80)
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

