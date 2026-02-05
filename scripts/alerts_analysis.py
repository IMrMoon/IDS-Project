#!/usr/bin/env python3
"""
Alert analysis utility for the Simple IDS demonstration.

This script reads a JSONL file containing IDS alerts (as emitted by
`src/alerts/alerts.py`) and produces summary statistics and charts for
experimental evaluation.  It was designed to accompany the traffic
profile script (`scripts/traffic_profile.py`) and the report for the
project.

Features:
  * Groups alerts into phases (quiet, medium, heavy) based on start
    time and predefined durations.  By default, the durations match
    those used in the `test` mode of the traffic profile (35s quiet,
    60s medium, 45s heavy).  Stage boundaries are inferred from the
    earliest alert timestamp and the durations supplied.
  * Aggregates the number of alerts for each phase by severity
    (LOW/MEDIUM/HIGH) and detection type (Rule vs. ML).  Critical
    severities are ignored by default because the demo profile does not
    generate them.
  * Generates a CSV file of the aggregated table for inclusion in
    reports, and produces simple charts (pie and bar) using
    matplotlib.

Usage::

    python3 alerts_analysis.py alerts.jsonl --output-dir outdir

The script writes the following files into ``--output-dir`` (default: current
directory):

  * ``alerts_summary.csv`` – summary table of counts by phase, severity and detection type.
  * ``severity_pie.png`` – pie chart showing the distribution of severities across all phases.
  * ``detection_bar.png`` – bar chart showing the distribution of detection types (Rule vs. ML).

You can override the phase durations and the base timestamp if needed.

Note: pandas and matplotlib must be installed (both are included in
  the project requirements).
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
import re
from typing import Iterable, Tuple, Dict, List
import pandas as pd
import matplotlib.pyplot as plt


def load_alerts(filepath: str) -> List[Dict[str, object]]:
    """Load alerts from a JSONL file.

    Parameters
    ----------
    filepath : str
        Path to the alerts JSONL file.

    Returns
    -------
    list of dict
        Parsed alert dictionaries.
    """
    alerts: List[Dict[str, object]] = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                # skip malformed lines
                continue
    return alerts


def parse_timestamp(ts: str) -> datetime:
    """Parse an ISO formatted timestamp into a naive datetime in UTC."""
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        # Fallback: strip timezone suffix if present
        dt = datetime.fromisoformat(ts.split('Z')[0])
    # Make naive by ignoring tzinfo (they will all be in UTC)
    if dt.tzinfo is not None:
        dt = dt.astimezone(tz=None).replace(tzinfo=None)
    return dt


def parse_profile_log(path: str) -> Tuple[datetime, Tuple[int, int, int]]:
    """Parse a traffic profile log file to extract start timestamp and stage durations.

    The log file is expected to contain lines printed by the
    `traffic_profile.py` script.  The parser looks for a line with
    ``START <timestamp>`` to determine the test start time, and a
    ``stages: quiet=<Xs> -> medium=<Ys> -> heavy=<Zs>`` line to
    determine durations.  Durations are integers in seconds.  If the
    stages line is not present, the parser falls back to default
    durations (35, 60, 45).

    Parameters
    ----------
    path : str
        Path to the log file.

    Returns
    -------
    (datetime, (int, int, int))
        Parsed start timestamp and a tuple of durations (quiet,
        medium, heavy) in seconds.

    Raises
    ------
    ValueError
        If the log does not contain a valid START timestamp.
    """
    start_time: datetime | None = None
    durations: Tuple[int, int, int] = (35, 60, 45)  # default
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if 'START' in line:
                # Example: "[traffic_profile] START 2026-02-05T14:00:00+02:00"
                parts = line.split()
                # The timestamp is expected to be the last token
                ts = parts[-1]
                try:
                    start_time = parse_timestamp(ts)
                except Exception:
                    continue
            elif 'stages:' in line and 'quiet' in line and 'medium' in line and 'heavy' in line:
                # Extract numbers like quiet=35s, medium=60s, heavy=45s
                pattern = r"quiet=(\d+)s.*medium=(\d+)s.*heavy=(\d+)s"
                match = re.search(pattern, line)
                if match:
                    try:
                        q, m, h = match.groups()
                        durations = (int(q), int(m), int(h))
                    except ValueError:
                        pass
    if start_time is None:
        raise ValueError(f"Could not find START timestamp in {path}")
    return start_time, durations


def infer_phase_offsets(durations: Tuple[int, int, int]) -> Tuple[int, int]:
    """Compute cumulative offsets for phase boundaries.

    Given durations for quiet, medium and heavy phases, return the
    offsets (in seconds) delimiting phase transitions.

    Returns
    -------
    (int, int)
        Offset to transition from quiet to medium, and offset to
        transition from medium to heavy.
    """
    quiet_end = durations[0]
    medium_end = durations[0] + durations[1]
    return quiet_end, medium_end


def determine_phase(start_ts: datetime, ts: datetime, durations: Tuple[int, int, int]) -> str:
    """Determine which phase a timestamp falls into.

    Parameters
    ----------
    start_ts : datetime
        The starting timestamp of the experiment (earliest alert).
    ts : datetime
        The timestamp of the alert to categorise.
    durations : tuple
        Durations (in seconds) of quiet, medium, heavy phases.

    Returns
    -------
    str
        One of 'quiet', 'medium' or 'heavy'.  Alerts occurring after
        the heavy phase are assigned to 'heavy'.  Alerts occurring
        before start_ts are assigned to 'quiet'.
    """
    dt = (ts - start_ts).total_seconds()
    quiet_end, medium_end = infer_phase_offsets(durations)
    if dt < quiet_end:
        return 'quiet'
    elif dt < medium_end:
        return 'medium'
    else:
        return 'heavy'


def aggregate_alerts(alerts: Iterable[Dict[str, object]], durations: Tuple[int, int, int], start_ts: datetime | None = None) -> pd.DataFrame:
    """Aggregate alerts by phase, severity and detection type.

    Parameters
    ----------
    alerts : iterable of dict
        Parsed alert records from JSONL.
    durations : tuple of int
        Durations of the quiet, medium and heavy phases in seconds.
    start_ts : datetime, optional
        Explicit start timestamp of the experiment.  If not provided,
        the earliest alert timestamp is used.

    Returns
    -------
    pandas.DataFrame
        A DataFrame with columns: stage, severity, detection, count.
    """
    if not alerts:
        # Return empty DataFrame with expected columns
        return pd.DataFrame(columns=['stage', 'severity', 'detection', 'count'])

    # Determine start timestamp if not supplied
    if start_ts is None:
        timestamps = [parse_timestamp(a['timestamp_utc']) for a in alerts]
        start_ts = min(timestamps)

    # Define helper to map detection type to 'Rule' or 'ML'
    def map_detection(dt: str) -> str:
        return 'ML' if isinstance(dt, str) and dt.upper() == 'ANOMALY' else 'Rule'

    # Count occurrences
    counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for alert in alerts:
        severity = alert.get('severity', 'UNKNOWN')
        # Ignore CRITICAL severity for this summary (demo doesn't produce it)
        if not isinstance(severity, str) or severity.upper() not in {'LOW', 'MEDIUM', 'HIGH'}:
            continue
        detection_type = map_detection(alert.get('detection_type'))
        ts = parse_timestamp(alert['timestamp_utc'])
        stage = determine_phase(start_ts, ts, durations)
        key = (stage, severity.upper(), detection_type)
        counts[key] += 1

    # Convert to DataFrame
    rows = []
    for (stage, severity, detection), count in counts.items():
        rows.append({'stage': stage, 'severity': severity, 'detection': detection, 'count': count})
    df = pd.DataFrame(rows)
    return df


def create_summary_table(df: pd.DataFrame) -> pd.DataFrame:
    """Pivot the aggregated data into a wide summary table.

    The resulting DataFrame has a row per stage and columns for each
    combination of severity and detection type (e.g., LOW-Rule,
    MEDIUM-ML).  Missing combinations are filled with zero.
    """
    if df.empty:
        return df
    pivot = df.pivot_table(index='stage', columns=['severity', 'detection'], values='count', aggfunc='sum', fill_value=0)
    # Sort stages in logical order
    stage_order = ['quiet', 'medium', 'heavy']
    pivot = pivot.reindex(stage_order)
    return pivot


def save_table_as_csv(table: pd.DataFrame, path: str) -> None:
    """Save the summary table as a CSV file."""
    table.to_csv(path)


def generate_charts(df: pd.DataFrame, output_dir: str) -> Tuple[str, str]:
    """Generate severity pie and detection bar charts.

    Parameters
    ----------
    df : pandas.DataFrame
        Aggregated alerts with 'severity' and 'detection' columns.
    output_dir : str
        Directory to save chart images.

    Returns
    -------
    (str, str)
        Paths to the generated pie and bar chart images.
    """
    if df.empty:
        raise ValueError("No data available to generate charts.")

    # Summarise severity distribution
    sev_counts = df.groupby('severity')['count'].sum().reindex(['LOW', 'MEDIUM', 'HIGH']).fillna(0)
    # Summarise detection type distribution
    det_counts = df.groupby('detection')['count'].sum().reindex(['Rule', 'ML']).fillna(0)

    # Pie chart for severity
    pie_path = os.path.join(output_dir, 'severity_pie.png')
    fig1, ax1 = plt.subplots()
    # explode smallest slice slightly for visibility
    explode = [0.05 if c == sev_counts.min() else 0 for c in sev_counts]
    ax1.pie(sev_counts, labels=sev_counts.index, autopct='%1.1f%%', startangle=90, explode=explode, colors=['#4e73df','#f6c23e','#e74a3b'])
    ax1.axis('equal')  # equal aspect ratio ensures pie is drawn as a circle.
    ax1.set_title('Distribution of Alert Severities')
    fig1.tight_layout()
    fig1.savefig(pie_path)
    plt.close(fig1)

    # Bar chart for detection types
    bar_path = os.path.join(output_dir, 'detection_bar.png')
    fig2, ax2 = plt.subplots()
    bars = ax2.bar(det_counts.index, det_counts.values, color=['#2e59d9', '#1cc88a'])
    ax2.set_title('Distribution of Detection Types')
    ax2.set_xlabel('Detection Type')
    ax2.set_ylabel('Number of Alerts')
    for bar in bars:
        height = bar.get_height()
        ax2.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width() / 2, height), xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
    fig2.tight_layout()
    fig2.savefig(bar_path)
    plt.close(fig2)

    return pie_path, bar_path


def main() -> None:
    parser = argparse.ArgumentParser(description='Analyse IDS alerts and produce summary and charts.')
    parser.add_argument('alerts_file', help='Path to alerts JSONL file generated by the IDS.')
    parser.add_argument('--output-dir', default='.', help='Directory to save summary CSV and chart images.')
    parser.add_argument('--durations', nargs=3, type=int, metavar=('QUIET', 'MEDIUM', 'HEAVY'), default=(35, 60, 45),
                        help='Durations of quiet, medium and heavy phases in seconds (default: 35 60 45).')
    parser.add_argument('--start-time', type=str, default=None,
                        help='Explicit ISO timestamp marking the start of the test. Overrides earliest alert time.')
    parser.add_argument('--profile-log', type=str, default=None,
                        help='Path to traffic profile log file containing stage boundaries (overrides --start-time and --durations).')
    args = parser.parse_args()

    alerts = load_alerts(args.alerts_file)
    if not alerts:
        print(f"No alerts loaded from {args.alerts_file}")
        return

    # Determine start_ts and durations
    start_ts: datetime | None = None
    durations = tuple(args.durations)
    if args.profile_log:
        try:
            start_ts, durations = parse_profile_log(args.profile_log)
        except Exception as e:
            print(f"Warning: failed to parse profile log {args.profile_log}: {e}. Falling back to default durations.")
            start_ts = None
    elif args.start_time:
        try:
            start_ts = parse_timestamp(args.start_time)
        except Exception as e:
            print(f"Warning: failed to parse start time '{args.start_time}': {e}. Using earliest alert timestamp instead.")
            start_ts = None

    # Aggregate
    agg_df = aggregate_alerts(alerts, durations, start_ts=start_ts)
    table = create_summary_table(agg_df)

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    table_path = os.path.join(args.output_dir, 'alerts_summary.csv')
    save_table_as_csv(table, table_path)
    # Generate charts
    pie_path, bar_path = generate_charts(agg_df, args.output_dir)

    print("Summary table saved to:", table_path)
    print("Severity pie chart saved to:", pie_path)
    print("Detection bar chart saved to:", bar_path)


if __name__ == '__main__':
    main()