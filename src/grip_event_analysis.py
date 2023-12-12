#!/usr/bin/env python

###############################################################################################################################
## Perform an analysis of GRIP events:                                                                                       ##
## - Fraction of suspicious events                                                                                           ##
## - Average duration of events                                                                                              ##
## - Statistics on prefixes:                                                                                                 ##
##      - Number of /24                                                                                                      ##
##      - Fraction covered by ROA                                                                                            ##
## - Number of hidden suspicious (benign event because of previously-announced tag but that were suspicious in a past event) ##
## - Number of prefixes recovered (prefixes that caused a past MOAS/SubMOAS with reversed roles attacker-victim)             ##
## - Statistics on Route Collectors AS Paths:                                                                                ##
##      - Fraction of paths leading to attacker                                                                              ##
##      - Fraction of paths leading to attacker containing victim                                                            ##
##      - Fraction of paths leading to victim containing attacker                                                            ##
##      - Fraction of fooled ASes                                                                                            ##
## - Statistics on Prefix Events:                                                                                            ##
##      - Fraction of default-tr-worthy prefix events                                                                        ##
##      - Average number of prefix events                                                                                    ##
###############################################################################################################################

#############
## Imports ##
#############
import os
from elasticsearch import Elasticsearch
import datetime
from utils import *
from statistics import mean, median

import warnings
warnings.filterwarnings("ignore")

#############################
## Definition of constants ##
#############################
timeout = "10m" # increase if it gives you errors about "No context found ..." 

# timestamp for Jan 01 2020 00:00:00 GMT-0500 (Standard Eastern time)
start_ts = 1577854800 

# timestamp for Oct 31 2023 23:59:59 GMT-0400 (Summer Eastern time)
end_ts = 1698811199

# Possible indexes
index_moas = 'observatory-v4-events-moas-*'
index_submoas = 'observatory-v4-events-submoas-*'
index_submoas_moas = (index_moas, index_submoas)

# Serial behavior hyperparameters
min_nb_events_serial = 100
min_suspicion_score = 80
max_response_size = 5000

benign_as = ['3', '2', '5', '1', '4', '10', '6', '8', '65535']



# Some Functions

if __name__ == '__main__':

    # ElasticSearch client
    es_retagged = Elasticsearch("https://procida.cc.gatech.edu:9200"
        , verify_certs=False,
        timeout=100, max_retries=1, retry_on_timeout=True, api_key='QWNkeUVJb0JDbFlIYzItdDdQWDU6Smh6T093OGRTam1RRm1XSU40bnZkUQ==')

    # Get AS numbers
    ASNs = []
    with open('../data/potential_serial_hijackers_ASN.txt') as file:
        ASNs = [line.strip('\n') for line in file if line.strip('\n') not in benign_as]
    
    print(ASNs)

    for ASN in ASNs:
        print(f"[{datetime.datetime.now()}] Dealing with AS{ASN} events")
        if not os.path.isdir(f'../data/AS{ASN}/'):
            os.mkdir(f'../data/AS{ASN}/')

        query_susp_events = query_attacker_2(start_ts, end_ts, ASN, max_response_size, min_susp = 60, max_susp = 100)
        suspicious_events = point_in_time(es_retagged, index_submoas_moas, timeout, query_susp_events)["hits"]["hits"]

        # Get AS info
        try:
            as_name =  suspicious_events[-1]['_source']['asinfo'][ASN]['asrank']['asnName']
            as_country = suspicious_events[-1]['_source']['asinfo'][ASN]['asrank']['organization']['country']['name']
            as_org = suspicious_events[-1]['_source']['asinfo'][ASN]['asrank']['organization']['orgName']
            as_rank = suspicious_events[-1]['_source']['asinfo'][ASN]['asrank']['rank']
        # For AS65535
        except:
            as_name =  'unknown'
            as_country = 'unknown'
            as_org = 'unknown'
            as_rank = 'unknown'

        prefixes_already_announced = get_tr_not_worthy_events(ASN, start_ts, end_ts, es_retagged, index_submoas_moas, timeout, max_response_size)
        hidden_suspicious_events_count = 0 

        all_tags = []
        tags_per_event = {}

        durations = []

        total_moas = 0
        total_submoas = 0

        total_prefixes = 0
        total_24_prefixes = 0
        total_rpki_prefixes = 0
        recovered_prefixes = 0

        victims = {}
        total_number_of_events_with_victims = 0
        total_number_of_benign_event_with_victims = 0
        total_number_of_suspicious_event_with_victims = 0
        prefixes = {}

        total_fraction_attackers_paths = 0
        total_fraction_attacker_paths_containing_victim = 0
        total_fraction_victims_paths_containing_attacker = 0
        total_fraction_fooled_ASes = 0
        total_fraction_tr_worthy_events = 0

        event_ids = []

        nb_of_events = len(suspicious_events)

        for i, event in enumerate(suspicious_events):
            # Had a case with AS9009, where it was attacker and victim at the same time '--
            if ASN in event['_source']['summary']['victims']:
                continue
            
            # Display time every 100 events to track progress
            if ((i+1)%100 == 0) or (i+1 == 1):
                print(f"    [{datetime.datetime.now()}] event {i+1}/{nb_of_events}")
            event_ids.append(event['_id'])

            # Statistics about event type
            if event['_source']['event_type'] == 'moas':
                total_moas += 1
            elif event['_source']['event_type'] == 'submoas':
                total_submoas += 1
            
            # Start with prefixes analysis
            # Check if the attacker has already had a ROA for any of the prefix involved
            total_rpki_prefixes += rpki_history_filter(event['_source']['summary']['prefixes'], ASN)

            for prefix in event['_source']['summary']['prefixes']:
                total_prefixes += 1

                # Count of /24
                if prefix.endswith("/24"):
                    total_24_prefixes += 1

                # Count for each /8 involved in an event
                first_digit = prefix.split('.')[0]
                if f"{first_digit}.x.x.x" in prefixes.keys():
                    prefixes[f"{first_digit}.x.x.x"].append(prefix)
                else:
                    prefixes[f"{first_digit}.x.x.x"] = [prefix]

                # Check if the prefix is involved in a more recent benign event
                # This benign events are actually hidden suspicious event
                for item in prefixes_already_announced:
                    for pfx in item:
                        if pfx == prefix:
                            hidden_suspicious_events_count += 1
                            prefixes_already_announced.remove(item)
                            break
            
            # Get duration of event.
            # If still ongoing, take the interval between start of the event and 31 October 2023
            if (isinstance(event['_source']['duration'], int)):
                durations.append(event['_source']['duration'])
            else:
                durations.append(end_ts - event['_source']['view_ts'])

            # Victims analysis
            for victim in event['_source']['summary']['victims']:
                if victim not in victims.keys():
                    # Check if there is a suspicious event with reversed roles but same prefix
                    # i.e. if a suspicious former MOAS or subMOAS with the current attackant as victim and the current victim as attacker
                    # That would probably mean that the AS is just trying to recover its prefix
                    query_vict_att = query_attacker_victim(start_ts, end_ts, ASN, victim, max_response_size, min_susp = 0, max_susp = 100)
                    vict_att_events = point_in_time(es_retagged, index_submoas_moas, timeout, query_vict_att)["hits"]["hits"]
                    query_reversed_vict_att = query_attacker_victim(start_ts, end_ts, victim, ASN, max_response_size, min_susp = 0, max_susp = 100)
                    reversed_vict_att_events = point_in_time(es_retagged, index_submoas_moas, timeout, query_reversed_vict_att)["hits"]["hits"]
                    total_number_of_events_with_victims += (len(vict_att_events) + len(reversed_vict_att_events))

                    for reversed_event in (reversed_vict_att_events + vict_att_events):
                        if (reversed_event in reversed_vict_att_events) and (reversed_event not in vict_att_events):
                            if reversed_event['_source']['view_ts'] < event['_source']['view_ts']:
                                same_pfx = [pfx for pfx in reversed_event['_source']['summary']['prefixes'] if pfx in event['_source']['summary']['prefixes']]
                                # print(len(same_pfx), event['_id'])
                                recovered_prefixes += len(same_pfx)

                        if reversed_event['_source']['summary']['inference_result']['primary_inference']['suspicion_level'] <= 20:
                            total_number_of_benign_event_with_victims += 1
                        else:
                            total_number_of_suspicious_event_with_victims += 1

                    victims[victim] = 1

                else:
                    victims[victim] += 1
                    
            # Get tags of the event and add them to the list of the tags of the AS
            # This is useful to compute tags frequencies for each AS
            tags = [tag['name'] for tag in event['_source']['summary']['tags']]
            all_tags.extend(tag for tag in tags if tag not in all_tags)
            tags_per_event[event['_id']] = tags

            # Get some statistics concerning Route Collectors AS path
            analysis = pfx_events_analysis(event['_source']['pfx_events'], 
                                        ASN, 
                                        event['_source']['summary']['victims'],
                                        event['_source']['event_type'])
            
            if analysis is None:
                print(f"    [{datetime.datetime.now()}] {event['_id']} has no victim/attacker paths")
                continue
            
            total_fraction_attackers_paths += analysis['attacker_paths']['fraction']
            total_fraction_attacker_paths_containing_victim += analysis['attacker_paths_containing_victim']['fraction']
            total_fraction_victims_paths_containing_attacker += analysis['victims_paths_containing_attacker']['fraction']
            total_fraction_fooled_ASes += analysis['fooled_ASes']['fraction']
            total_fraction_tr_worthy_events += analysis['tr_worthy_events']['fraction']


        print(f"    [{datetime.datetime.now()}] Information gathered, write summary.")
        if not os.path.isfile(f'../data/AS{ASN}/summary.txt'):
            with open(f'../data/AS{ASN}/summary.txt', 'w') as f:
                f.write('####################\n## Events Summary ##\n####################\n\n')

                f.write(f'ASN: {ASN}\n')
                f.write(f'AS name: {as_name}\n')
                f.write(f'AS rank: {as_rank}\n')
                f.write(f'Organization name: {as_org}\n')
                f.write(f'Country: {as_country}\n')
                f.write('------------------------------\n')

                query_benign_moas = query_attacker_2(start_ts, end_ts, ASN, 10000, min_susp = 0, max_susp = 20)
                benign_moas = point_in_time(es_retagged, index_submoas_moas[0], timeout, query_benign_moas)['hits']['hits']

                query_benign_submoas = query_attacker_2(start_ts, end_ts, ASN, 10000, min_susp = 0, max_susp = 20)
                benign_submoas = point_in_time(es_retagged, index_submoas_moas[1], timeout, query_benign_submoas)['hits']['hits']
                
                f.write(f'Total number of suspicious events (% of suspicious out of all events): {nb_of_events} ({nb_of_events/(nb_of_events+len(benign_moas) + len(benign_submoas))*100} %)\n')
                f.write(f'  MOAS (% of suspicious out of all events): {total_moas} ({total_moas/(total_moas + len(benign_moas))*100} %)\n')
                f.write(f'  SubMOAS (% of suspicious out of all events): {total_submoas} ({total_submoas/(total_submoas + len(benign_submoas))*100} %)\n\n')

                f.write(f'Total number of benign events (% of benign out of all events): {len(benign_moas) + len(benign_submoas)} ({(len(benign_moas) + len(benign_submoas))/(nb_of_events+len(benign_moas) + len(benign_submoas))*100} %)\n')
                f.write(f'  MOAS (% of suspicious out of all events): {len(benign_moas)} ({len(benign_moas)/(total_moas + len(benign_moas))*100} %)\n')
                f.write(f'  SubMOAS (% of suspicious out of all events): {len(benign_submoas)} ({len(benign_submoas)/(total_submoas + len(benign_submoas))*100} %)\n')
                f.write(f'  Event that only has "previously-announced-by-all-newcomers" green tag but prefix caused a suspicious event previously (= hidden suspicious events): {hidden_suspicious_events_count}\n')
                f.write('------------------------------\n')
                
                f.write(f'Average Duration: {str(datetime.timedelta(seconds = mean(durations)))}\n')
                f.write(f'Median duration: {str(datetime.timedelta(seconds = median(durations)))}\n')
                f.write('------------------------------\n')

                f.write(f'Average number of events with each victim: {total_number_of_events_with_victims/len(victims.keys())}\n')
                f.write(f'  Average number of suspicious events with each victim: {total_number_of_suspicious_event_with_victims/len(victims.keys())}\n')
                f.write(f'  Average number of benign events with each victim: {total_number_of_benign_event_with_victims/len(victims.keys())}\n')
                victims = dict(sorted(victims.items(), key=lambda x:x[1], reverse=True))
                f.write(f'Victims targeted more than 5 times:\n')
                for victim in victims.keys():
                    if victims[victim] > 5:
                        f.write(f'  AS{victim}: {victims[victim]} ({victims[victim]/nb_of_events*100} %)\n')
                f.write('------------------------------\n')

                f.write(f'Fraction of /24 prefix: {total_24_prefixes/total_prefixes}\n')
                f.write(f'Fraction of prefixes covered by a ROA: {total_rpki_prefixes/total_prefixes}\n')
                f.write(f'Fraction of prefix already involved in an event but with reversed roles, i.e. attacker as victim and vice versa (= recovered prefixes): {recovered_prefixes/total_prefixes}\n')
                prefixes = dict(sorted(prefixes.items(), key=lambda k: len(k[1]), reverse=True))
                f.write(f'/8 prefixes targeted more than 5 times:\n')
                for prefix in prefixes.keys():
                    if len(prefixes[prefix]) > 5:
                        f.write(f'  {prefix}: {len(prefixes[prefix])} ({len(prefixes[prefix])/total_prefixes*100} %)\n')
                f.write('------------------------------\n')

                f.write(f'Average fraction of attackers paths: {total_fraction_attackers_paths/nb_of_events}\n')
                f.write(f'Average fraction of attackers paths containing at least one victim: {total_fraction_attacker_paths_containing_victim/nb_of_events}\n')
                f.write(f'Average fraction of victims paths containing attacker: {total_fraction_victims_paths_containing_attacker/nb_of_events}\n')
                f.write(f'Average fraction of fooled ASes: {total_fraction_fooled_ASes/nb_of_events}\n')
                f.write(f'Average fraction of suspicious pfx events: {total_fraction_tr_worthy_events/nb_of_events}\n\n')



        print(f"    [{datetime.datetime.now()}] Summary written, compute tags frequencies.")
        if not os.path.isfile(f'../data/AS{ASN}/tags.csv'):
            with open(f'../data/AS{ASN}/tags.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                fields = ['event_id']
                fields.extend(all_tags)
                writer.writerow(fields)
                for event_id in event_ids:
                    row = [event_id]
                    for tag in all_tags:
                        if tag in tags_per_event[event_id]:
                            row.append(1)
                        else:
                            row.append(0)

                    writer.writerow(row)


        if not os.path.isfile(f"../data/AS{ASN}/tags_freq.json"):
            tags = pandas.read_csv(f'../data/AS{ASN}/tags.csv')
            with open(f"../data/AS{ASN}/tags_freq.json", "w") as outfile: 
                json.dump(count_tags(tags), outfile, indent = 2)

        print(f"    [{datetime.datetime.now()}] Tags frequencies computed.")