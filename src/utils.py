from typing import List, Dict, Optional
from typing import Union, Tuple
import requests
import pandas
import yaml
from query_functions import *
from elasticsearch import Elasticsearch

def rpki_history_filter(prefixes: List[str], origin: str) -> int:
    """
    If ``origin` had already had one ROA for at least one prefix in `prefixes`, return 1; else return 0. 
    """
    rpki_filter = False
    for prefix in prefixes:
        rpki_filter = rpki_filter or check_rpki_history(prefix, origin)
    if rpki_filter:
         return 1
    else:
        return 0

def check_rpki_history(prefix: str, origin: str) -> bool:
    """
    If `origin` had already had one ROA for `prefix`, return True; else return False.
    """
    try:
        rpki_history = requests.get(f'https://stat.ripe.net//data/rpki-history/data.json?resource={prefix}&include=ranges', timeout=5)

        rpki_history_json = rpki_history.json()
        data = rpki_history_json['data']['by_prefix'][0]

        origins_rpki_history = [origin['origin'] for origin in data['origins']]
        
        return (origin in origins_rpki_history)
    except:
        return False

def pfx_events_analysis(pfx_events: list, attacker: str, victims: list, event_type: str) -> Dict[str, Dict[str, int]]:
    """
    For all `pfx_events` combined, return count and fraction of:
        Paths originated by `attacker`
        Paths originated by `attacker` and containing at least one of `victims`
        Paths originated by `victims` and containing `attacker`
        ASes having a path originated by `attacker` (fooled ASes)
        Default traceroute worthy events
    """
    res = {'attacker_paths': {}, 
           'attacker_paths_containing_victim': {}, 
           'victims_paths_containing_attacker': {}, 
           'fooled_ASes': {},
           'tr_worthy_events': {}
           }

    attacker_paths = []
    victims_paths = []
    AS_with_path_to_victim = []
    AS_with_path_to_attacker = []
    count_path_originated_by_attacker_containing_victim = 0
    count_path_originated_by_victims_containing_attacker = 0
    count_tr_worthy_pfx_events = 0

    for pfx_event in pfx_events:
        if pfx_event['inferences'][0]['inference_id'] == 'default-tr-worthy':
            count_tr_worthy_pfx_events += 1
        if event_type == 'moas':
            attacker_paths, victims_paths, AS_with_path_to_victim, AS_with_path_to_attacker, count_path_originated_by_attacker_containing_victim, count_path_originated_by_victims_containing_attacker = moas_path_analysis(pfx_event['details']['aspaths'],
                                                                                                                                                                                                                            attacker, 
                                                                                                                                                                                                                            victims,
                                                                                                                                                                                                                            attacker_paths,
                                                                                                                                                                                                                            victims_paths,
                                                                                                                                                                                                                            AS_with_path_to_victim,
                                                                                                                                                                                                                            AS_with_path_to_attacker,
                                                                                                                                                                                                                            count_path_originated_by_attacker_containing_victim,
                                                                                                                                                                                                                            count_path_originated_by_victims_containing_attacker)
        if event_type == 'submoas':
            attacker_paths, victims_paths, AS_with_path_to_victim, AS_with_path_to_attacker, count_path_originated_by_attacker_containing_victim, count_path_originated_by_victims_containing_attacker = submoas_path_analysis(pfx_event['details']['sub_aspaths'],
                                                                                                                                                                                                                            pfx_event['details']['super_aspaths'],
                                                                                                                                                                                                                            attacker, 
                                                                                                                                                                                                                            victims,
                                                                                                                                                                                                                            attacker_paths,
                                                                                                                                                                                                                            victims_paths,
                                                                                                                                                                                                                            AS_with_path_to_victim,
                                                                                                                                                                                                                            AS_with_path_to_attacker,
                                                                                                                                                                                                                            count_path_originated_by_attacker_containing_victim,
                                                                                                                                                                                                                            count_path_originated_by_victims_containing_attacker)
    
    if len(victims_paths) == 0 or len(attacker_paths) == 0:
        return None
    # Attacker paths
    fraction_attacker_paths = len(attacker_paths) / (len(attacker_paths)+len(victims_paths))
    # print("Attacker paths:", len(attacker_paths), fraction_attacker_paths)
    res['attacker_paths']['count'] = len(attacker_paths) 
    res['attacker_paths']['fraction'] = fraction_attacker_paths

    # Path originated by attacker containing victim
    fraction_attacker_paths_containing_victim = count_path_originated_by_attacker_containing_victim / len(attacker_paths)
    # print("Paths originated by attacker containing victim:", count_path_originated_by_attacker_containing_victim, fraction_attacker_paths_containing_victim)
    res['attacker_paths_containing_victim']['count'] = count_path_originated_by_attacker_containing_victim 
    res['attacker_paths_containing_victim']['fraction'] = fraction_attacker_paths_containing_victim

    # Paths originated by victims containing attacker
    fraction_victims_paths_containing_attacker = count_path_originated_by_victims_containing_attacker / len(victims_paths)
    # print("Paths originated by victims containing attacker:", count_path_originated_by_victims_containing_attacker, fraction_victims_paths_containing_attacker)
    res['victims_paths_containing_attacker']['count'] = count_path_originated_by_victims_containing_attacker 
    res['victims_paths_containing_attacker']['fraction'] = fraction_victims_paths_containing_attacker

    # Fooled ASes
    all_AS = [ASN for ASN in AS_with_path_to_attacker]
    all_AS.extend(ASN for ASN in AS_with_path_to_victim if ASN not in AS_with_path_to_attacker)

    fraction_fooled_AS = len(AS_with_path_to_attacker)/len(all_AS)
    # print("Fooled ASes:", len(AS_with_path_to_attacker), fraction_fooled_AS)
    res['fooled_ASes']['count'] = len(AS_with_path_to_attacker) 
    res['fooled_ASes']['fraction'] = fraction_fooled_AS

    # Default Traceroute Worthy
    res['tr_worthy_events']['count'] = count_tr_worthy_pfx_events
    res['tr_worthy_events']['fraction'] = count_tr_worthy_pfx_events / len(pfx_events)
    
    return res 

def moas_path_analysis(paths: str, 
                       attacker: str, 
                       victims: List[str],
                       attacker_paths: List[str],
                       victims_paths: List[str],
                       AS_with_path_to_victim: List[str],
                       AS_with_path_to_attacker: List[str],
                       count_path_originated_by_attacker_containing_victim: int,
                       count_path_originated_by_victims_containing_attacker: int):
    
    paths_list = paths.split(':')

    for path in paths_list:
        if (path in attacker_paths) or (path in victims_paths):
            continue
        temp = path.split(' ')
        if temp[-1] in victims:
            if attacker in temp:
                count_path_originated_by_victims_containing_attacker += 1
            victims_paths.append(path)
            AS_with_path_to_victim.extend(ASN for ASN in temp if (ASN not in AS_with_path_to_victim and ASN not in victims))
        elif temp[-1] == attacker:
            for victim in victims:
                if victim in temp:
                    count_path_originated_by_attacker_containing_victim += 1
            attacker_paths.append(path)
            AS_with_path_to_attacker.extend(ASN for ASN in temp if (ASN not in AS_with_path_to_attacker and ASN != attacker))
        # else:
        #     print(temp[-1])

    return attacker_paths, victims_paths, AS_with_path_to_victim, AS_with_path_to_attacker, count_path_originated_by_attacker_containing_victim, count_path_originated_by_victims_containing_attacker


def submoas_path_analysis(sub_paths: str, 
                          super_paths: str, 
                          attacker: str, 
                          victims: List[str],
                          attacker_paths: List[str],
                          victims_paths: List[str],
                          AS_with_path_to_victim: List[str],
                          AS_with_path_to_attacker: List[str],
                          count_path_originated_by_attacker_containing_victim: int,
                          count_path_originated_by_victims_containing_attacker: int):
    
    sub_paths = sub_paths.split(':')
    super_paths = super_paths.split(':')
    
    for path in sub_paths:
        if path in attacker_paths:
            continue
        temp = path.split(' ')
        for victim in victims:
            if victim in temp:
                count_path_originated_by_attacker_containing_victim += 1
        attacker_paths.append(path)
        AS_with_path_to_attacker.extend(ASN for ASN in temp if (ASN not in AS_with_path_to_attacker and ASN != attacker))

    for path in super_paths:
        if path in victims_paths:
            continue
        temp = path.split(' ')
        if attacker in temp:
            count_path_originated_by_victims_containing_attacker += 1
        victims_paths.append(path)
        AS_with_path_to_victim.extend(ASN for ASN in temp if (ASN not in AS_with_path_to_victim and ASN not in victims))

    return attacker_paths, victims_paths, AS_with_path_to_victim, AS_with_path_to_attacker, count_path_originated_by_attacker_containing_victim, count_path_originated_by_victims_containing_attacker


def get_tags_used_for_clustering(data: pandas.DataFrame) -> List[str]:
    """
    Extract tags from `data`.
    """
    data_columns = data.columns
    not_tags_columns = ['Unnamed: 0', 'event_id', 'timestamp', 'inference_id', 'confidence_level', 'suspicion_level', 'x', 'y', 'km_labels']
    tags_used_for_clustering = []
    for column in data_columns:
        if column not in not_tags_columns:
            tags_used_for_clustering.append(column)
     
    return tags_used_for_clustering

def get_tags_classification(data: pandas.DataFrame, tags_tr_file: Optional[str] = "../data/tags_tr.yaml") -> Dict[str, str]:
    """"
    Map tags present in `data` with a suspiciousness level thanks to `tags_tr_file`.
    """
    with open(tags_tr_file, "r") as stream:
        try:
            tags_tr = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    data_tags = get_tags_used_for_clustering(data)
    
    tags_classification = {}
    for item in (tags_tr['tr_no']):
        for tag in item['tags']:
            if tag in data_tags:
                tags_classification[tag] = 'tr_no'
    for item in (tags_tr['tr_na']):
        for tag in item['tags']:
            if tag in data_tags:
                tags_classification[tag] = 'tr_na'
    for item in (tags_tr['tr_yes']):
        for tag in item['tags']:
            if tag in data_tags:
                tags_classification[tag] = 'tr_yes'

    return tags_classification

def count_tags(data: pandas.DataFrame) -> Dict[str, Dict[str, float]]:
    """
    Compute the percentage of each tag in `data_to_count`. 
    Group the result by tag suspiciousness and sort it in a descending order.
    """
    data_tags = get_tags_used_for_clustering(data)
    tag_class = get_tags_classification(data)

    res = {'tr_no': {}, 'tr_yes': {}, 'tr_na': {}}
    for tag in data_tags:
        try:
            tag_pct = data[tag].value_counts(normalize=True)[1]
            res[tag_class[tag]][tag] = tag_pct
        except:
            continue
    res['tr_no'] = dict(sorted(res['tr_no'].items(), key=lambda x: x[1], reverse=True))
    res['tr_yes'] = dict(sorted(res['tr_yes'].items(), key=lambda x: x[1], reverse=True))
    res['tr_na'] = dict(sorted(res['tr_na'].items(), key=lambda x: x[1], reverse=True))

    return res

def get_tr_not_worthy_tags(tags_tr_file: Optional[str] = "../data/tags_tr.yaml") -> List[str]:
    with open(tags_tr_file, "r") as stream:
        try:
            tags_tr = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    tr_no_tags = []
    for item in (tags_tr['tr_no']):
        for tag in item['tags']:
            tr_no_tags.append(tag)
    
    return tr_no_tags

def get_tr_not_worthy_events(ASN: str,
                start_ts: int, 
                end_ts: int, 
                es_retagged: Elasticsearch, 
                index: Union[str, List[str], Tuple[str]], 
                timeout: str,
                total_nb_of_events: Optional[int] = 5000):

    query_benign_events = query_attacker_2(start_ts, end_ts, ASN, total_nb_of_events, min_susp = 0, max_susp = 20)
    benign_events = point_in_time(es_retagged, index, timeout, query_benign_events)['hits']['hits']

    tr_no_tags = get_tr_not_worthy_tags()
    prefixes_already_announced = []

    for event in benign_events:
        if event['_source']['summary']['inference_result']['primary_inference']['inference_id'] != 'default-not-tr-worthy':
            continue

        tags = [tag['name'] for tag in event['_source']['summary']['tags']]

        if "previously-announced-by-all-newcomers" in tags:
            only_prev_ann_by_all_newcom = True
            for tag in tags:
                if tag == "previously-announced-by-all-newcomers":
                    continue
                if tag in tr_no_tags:
                    only_prev_ann_by_all_newcom = False
        
        else:
            only_prev_ann_by_all_newcom = False
        
        pfx_event = []
        for prefix in event['_source']['summary']['prefixes']:
            if only_prev_ann_by_all_newcom:
                pfx_event.append(prefix)
        
        prefixes_already_announced.append(pfx_event)

    return prefixes_already_announced

def check_caida_as(prefix: str):
    prefix = prefix.split('/')
    ip = prefix[0]
    mask = prefix[1]    
    with open(f"../data/routeviews-rv2-20231129-1200.pfx2as", 'r') as f:
        for line in f:
            if ip in line:
                mapping = [item for item in line.split(' ') if item != '']
                asn = mapping[2]

                print('string found in a file')            
                # don't look for next lines
                break
            
        print('string does not exist in a file')
    