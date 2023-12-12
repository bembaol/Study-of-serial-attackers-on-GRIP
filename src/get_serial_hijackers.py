#!/usr/bin/env python

###########################################################
## Get AS tagged as a potential attacker:                ##
## - In a suspicious event                               ##
## - On at least 100 different days                      ##
## - Between 2020-01-01 00:00:00 and 2023-10-31 23:59:59 ##
###########################################################

#############
## Imports ##
#############
import os
from elasticsearch import Elasticsearch
import pandas as pd
import datetime
from query_functions import *
from utils import *
from plot_functions import *

import warnings
warnings.filterwarnings("ignore")

#############################
## Definition of constants ##
#############################
timeout = "10m" # increase if it gives you errors about "No context found ..." 

# timestamp and datetime for Jan 01 2020 00:00:00 GMT-0500 (Standard Eastern time)
start_ts = 1577854800 
start_dt = datetime.datetime.fromtimestamp(start_ts) 

# timestamp and datetime for Oct 31 2023 23:59:59 GMT-0400 (Summer Eastern time)
end_ts = 1698811199
end_dt = datetime.datetime.fromtimestamp(end_ts)

# Possible indexes
index_moas = 'observatory-v4-events-moas-*'
index_retagged_moas = 'retagged-v4-events-moas-*'
index_submoas = 'observatory-v4-events-submoas-*'
index_submoas_moas = (index_moas, index_submoas)

index_edges = 'observatory-v4-events-edges-*'
index_all_events = 'observatory-v4-query-events-*'

# Serial behavior hyperparameters
min_nb_events_serial = 100
min_nb_days_serial = 100
min_suspicion_score = 80

if __name__ == '__main__':
    # ElasticSearch Clients
    es = Elasticsearch("https://procida.cc.gatech.edu:9200"
        , verify_certs=False,
        timeout=100, max_retries=1, retry_on_timeout=True, api_key='ak1kZmVJY0JDbFlIYzItdEhmUUg6VEQ4bHB3TGJTZUtxVm54Q0R1bWxjUQ==')

    es_retagged = Elasticsearch("https://procida.cc.gatech.edu:9200"
        , verify_certs=False,
        timeout=100, max_retries=1, retry_on_timeout=True, api_key='QWNkeUVJb0JDbFlIYzItdDdQWDU6Smh6T093OGRTam1RRm1XSU40bnZkUQ==')

    print(f"[{datetime.datetime.now()}] Start potential serial BGP hijackers collection.")

    # Get all ASes involved in at least 100 events between 2020-01-01 00:00:00 and 2023-10-31 23:59:59
    print(f"[{datetime.datetime.now()}] Collecting attackers involved in more than {min_nb_events_serial} events between {start_dt} and {end_dt}.")
    query_multi_attackers = query_attackers_count(start_ts, end_ts, min_doc_count=min_nb_events_serial)
    multi_attackers = point_in_time(es_retagged, index_submoas_moas, timeout, query_multi_attackers)['aggregations']['2']['buckets']
    print(f"    [{datetime.datetime.now()}] Count: {len(multi_attackers)}")

    # Keep only ASes involved in events spread over more than 100 days
    print(f"[{datetime.datetime.now()}] Keep those involved in more than {min_nb_events_serial} events in at least {min_nb_days_serial} different days between {start_dt} and {end_dt}.")

    potential_serial_hijacker_ASN = []
    count_of_events = []
    for attacker in multi_attackers:
        attacker_ASN = attacker['key']
        query_days_with_events = query_time_distrib(start_ts, end_ts, attacker_ASN)
        days_with_events = point_in_time(es_retagged, index_submoas_moas, timeout, query_days_with_events)['aggregations']['2']['buckets']

        if len(days_with_events) > min_nb_days_serial: # Only considering attackers which triggered events in more than 100 different days

            potential_serial_hijacker_ASN.append(attacker_ASN)
            count_of_events.append(attacker['doc_count'])

            if not os.path.isfile(f'../images/AS{attacker_ASN}/time_distrib_susp_events.png'):
                query_whole_time_distrib = query_time_distrib(start_ts, end_ts, attacker_ASN, min_doc_count=0)
                time_distrib = point_in_time(es_retagged, index_submoas_moas, timeout, query_whole_time_distrib)['aggregations']['2']['buckets']
                time_distrib_df = pd.DataFrame(time_distrib)
                plot_event_distrib(attacker_ASN, time_distrib_df, start_dt, end_dt, min_suspicion_score)
                print(f"    [{datetime.datetime.now()}] Plot event time distribution for AS{attacker_ASN}.")

            if os.path.isfile(f'../data/AS{attacker_ASN}/routing_info.json') and not os.path.isfile(f'../images/AS{attacker_ASN}/RPKI_status.png'):
                plot_routing_info(attacker_ASN)
                

            # Rename columns
            # for day in time_distrib:8
            #     day['datetime'] = day.pop('key_as_string')
            #     day['timestamp'] = day.pop('key')
            #     day['nb_events'] = day.pop('doc_count')
            
            # potential_serial_hijacker[attacker_ASN]['days_with_events'] = days_with_events   # we keep only days where an event occured

    print(f"    [{datetime.datetime.now()}] Count: {len(potential_serial_hijacker_ASN)}")


    if not os.path.isfile('../data/potential_serial_hijackers_ASN.txt'):
        with open('../data/potential_serial_hijackers_ASN.txt', 'w') as f:
            for ASN in potential_serial_hijacker_ASN:
                f.write(f"{attacker_ASN}\n")

    # Plot the count of events for each potential hijackers
    if not os.path.isfile(f'../images/count_of_events_per_potential_hijackers.png'):
        plot_event_count_per_AS(potential_serial_hijacker_ASN, count_of_events)
        print(f"    [{datetime.datetime.now()}] Plot event count per AS.")

