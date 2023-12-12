import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
import datetime
import json
from typing import List

def plot_event_distrib(attacker_ASN: str, time_distrib_df: pd.DataFrame, start_dt: datetime.datetime, end_dt: datetime.datetime, min_suspicion_score: int):
    fig, (ax1) = plt.subplots(ncols=1, sharex=True, figsize=(30, 10), sharey=True)
    sns.lineplot(data=time_distrib_df, x="key_as_string", y = "doc_count", ax=ax1)

    ax1.set_title(f"Count of events per day between {start_dt} and {end_dt} for {attacker_ASN}")
    ax1.tick_params(axis='x', rotation = 90)
    ax1.set_xlabel('Time')
    ax1.set_ylabel('Count')
    locator = mdates.DayLocator(interval=30)
    ax1.xaxis.set_major_locator(locator)

    sns.despine(fig)
    plt.tight_layout()
    plt.savefig(f'../images/score_{min_suspicion_score}/time_distrib/{attacker_ASN}.png')
    plt.close()

def plot_event_count_per_AS(potential_serial_hijacker_ASN: List[str], count_of_events: List[int]):
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_ylabel('Count of events')
    ax.set_xlabel('ASN')
    ax.set_title('Potential Serial Hijackers and suspicious events (MOAS & SubMOAS) count')
    x = potential_serial_hijacker_ASN
    y = count_of_events
    ax.bar(x, y, color='b', width=0.9)
    ax.bar_label(ax.containers[0], label_type='edge')
    ax.tick_params(axis='x', rotation=90)
    plt.savefig('../images/count_of_events_per_potential_hijackers.png')

def plot_routing_info(ASN: str):
    with open(f'../data/AS{ASN}/routing_info.json') as json_file:
        data = json.load(json_file)

    x = list(data.keys())
    y = [data[date]['count_pfx_orig'] for date in data]

    # rpki
    fig, ax = plt.subplots(figsize=(12, 12))
    ax.set_ylabel('Prefixes count')
    ax.set_xlabel('Time')
    ax.set_title(f'RPKI Statuses for prefix originated by AS{ASN}')
    ax.tick_params(axis='x', rotation = 90)
    locator = mdates.DayLocator(interval=30)
    ax.xaxis.set_major_locator(locator)

    rpki_notfound = [data[date]['rpki']['NotFound'] for date in data]
    rpki_invalid = [(data[date]['rpki']['Invalid'] + data[date]['rpki']['Invalid,more-specific']) for date in data]
    rpki_valid = [data[date]['rpki']['Valid'] for date in data]

    plt.plot(x, y, label = "Originated") 
    plt.plot(x, rpki_valid, label = "RPKI Valid") 
    plt.plot(x, rpki_invalid, label = "RPKI Invalid") 
    plt.plot(x, rpki_notfound, label = "RPKI Not Found") 
    plt.legend() 
    plt.savefig(f'../images/AS{ASN}/RPKI_status.png')
    plt.close()

    # irr
    fig, ax = plt.subplots(figsize=(12, 12))
    ax.set_ylabel('Prefixes count')
    ax.set_xlabel('Time')
    ax.set_title(f'IRR Statuses for prefix originated by AS{ASN}')
    ax.tick_params(axis='x', rotation = 90)
    locator = mdates.DayLocator(interval=30)
    ax.xaxis.set_major_locator(locator)

    irr_notfound = [data[date]['irr']['NotFound'] for date in data]
    irr_invalid = [(data[date]['irr']['Invalid'] + data[date]['irr']['Invalid,more-specific']) for date in data]
    irr_valid = [data[date]['irr']['Valid'] for date in data]

    plt.plot(x, y, label = "Originated") 
    plt.plot(x, irr_valid, label = "IRR Valid") 
    plt.plot(x, irr_invalid, label = "IRR Invalid") 
    plt.plot(x, irr_notfound, label = "IRR Not Found") 
    plt.legend() 
    plt.savefig(f'../images/AS{ASN}/IRR_status.png')
    plt.close()

    # prefix status
    fig, ax = plt.subplots(figsize=(12, 12))
    ax.set_ylabel('Prefixes count')
    ax.set_xlabel('Time')
    ax.set_title(f'Statuses for prefix originated by AS{ASN}')
    ax.tick_params(axis='x', rotation = 90)
    locator = mdates.DayLocator(interval=30)
    ax.xaxis.set_major_locator(locator)

    notfound = [data[date]['prefix_status']['NotFound'] for date in data]
    ianapool = [data[date]['prefix_status']['ianapool'] for date in data]
    allocated = [data[date]['prefix_status']['allocated'] for date in data]
    reserved = [data[date]['prefix_status']['reserved'] for date in data]
    available = [data[date]['prefix_status']['available'] for date in data]
    assigned = [data[date]['prefix_status']['assigned'] for date in data]

    plt.plot(x, y, label = "Originated") 
    plt.plot(x, notfound, label = "Not found") 
    plt.plot(x, ianapool, label = "Iana pool") 
    plt.plot(x, allocated, label = "Allocated")
    plt.plot(x, reserved, label = "Reserved")
    plt.plot(x, available, label = "Available")
    plt.plot(x, assigned, label = "Assigned")   
    plt.legend() 
    plt.savefig(f'../images/AS{ASN}/prefix_status.png')
    plt.close()