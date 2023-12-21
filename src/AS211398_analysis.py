#!/usr/bin/env python

from elasticsearch import Elasticsearch
from query_functions import *
import datetime
import os
import json

import logging
import warnings
warnings.filterwarnings("ignore")

min_suspicion = 80
max_suspicion = 100

may_27_2022 = [1653609600, 1653696000]
may_28_2022 = [1653696000, 1653782400]
may_29_2022 = [1653782400, 1653868800]
may_30_2022 = [1653868800, 1653955200]
may_31_2022 = [1653955200, 1654041600]
june_1_2022 = [1654041600, 1654128000]
june_2_2022 = [1654128000, 1654214400]

august_22_2022 = [1661126400, 1661212800]
august_23_2022 = [1661212800, 1661299200]
august_29_2022 = [1661731200, 1661817600]
august_30_2022 = [1661817600, 1661904000]


days = [may_28_2022, may_29_2022, may_30_2022, june_1_2022, june_2_2022, august_23_2022, august_30_2022]

timeout = "10m" # increase if it gives you errors about "No context found ..." s

# Possible indexes
index_moas = 'observatory-v4-events-moas-*'
index_submoas = 'observatory-v4-events-submoas-*'
index_submoas_moas = (index_moas, index_submoas)

if __name__ == '__main__':
    with open('data/potential_serial_hijackers_ASN.txt') as file:
        ASNs = [line.strip('\n') for line in file]

    es_retagged = Elasticsearch("https://procida.cc.gatech.edu:9200"
        , verify_certs=False,
        timeout=100, max_retries=1, retry_on_timeout=True, api_key='xxxxxx')
    
    event_count = {}
    event_count_per_AS = {}

    for day in days:
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "view_ts": {
                                    "gte": day[0],
                                    "lte": day[1]
                                    }
                                }
                        },
                        {
                            "query_string": {
                                "analyze_wildcard": "true",
                                "query":f"summary.inference_result.primary_inference.suspicion_level: [{min_suspicion} TO {max_suspicion}]"
                                }
                        }
                    ]
                }
            },
            "sort": {
                "view_ts": {
                    "order": "asc"
                }
            },
            "size": 1000
        }
        # suspicious_events = point_in_time(es_retagged, index_submoas_moas, timeout, query)["hits"]["hits"]


        pit = es_retagged.open_point_in_time(index=index_submoas_moas, keep_alive=timeout)
        pit['keep_alive'] = timeout
        query['pit'] = pit

        events = []
    
        res = es_retagged.search(body=query)

        while len(res['hits']['hits']):
            temp_events = res["hits"]["hits"]
            pit['id'] = res["pit_id"]
            for e in temp_events:
                try:
                    info_imp = e["sort"]

                    event = e["_source"]
                    # you can keep specific parts of the event
                    # you can get the tags by event['summary']['tags']
                    # it's a list of dicts [{'name': 'tag_name}, ...]

                    events.append(event)
                except TypeError as err:
                    logging.error("%s", err)
                    logging.error("%s", e)

            query["track_total_hits"] = False # speed up pagination
            query["search_after"] = info_imp

            res = es_retagged.search(body=query)

        # done with searching
        es_retagged.close_point_in_time({'id': pit['id']})


        date = str(datetime.datetime.fromtimestamp(day[0]))
        event_count[date] = {'total': 0, 'moas': 0, 'submoas': 0}
        event_count_per_AS[date] = {}

        print(f"[{datetime.datetime.now()}] Start day {date}")

        for event in events:
            event_count[date]['total'] += 1
            
            event_type = event['event_type']
            attackers = event['summary']['attackers']

            only_211398 = True

            for pfx_event in event['pfx_events']:
                if event_type == 'moas':
                    paths_list = pfx_event['details']['aspaths']
                if event_type == 'submoas':
                    paths_list = pfx_event['details']['sub_aspaths']
                
                for path in paths_list:
                    if path[-1] not in attackers:
                        continue
                    if path[0] != '211398':
                        only_211398 = False
                        break
                
            if only_211398:
                event_count[date][event_type] += 1

                for attacker in pfx_event['attackers']:
                    if attacker in ASNs:
                        if attacker in event_count_per_AS[date].keys():
                            event_count_per_AS[date][attacker] += 1
                        else:
                            event_count_per_AS[date][attacker] = 1

    
    if not os.path.isdir(f'../data/AS211398_collector/'):
        os.mkdir(f'../data/AS211398_collector/')
    with open(f'../data/AS211398_collector/event_count.json', 'w') as fp:
        json.dump(event_count, fp, indent = 2)

    with open(f'../data/AS211398_collector/event_count_per_AS.json', 'w') as fp:
        json.dump(event_count_per_AS, fp, indent = 2)
