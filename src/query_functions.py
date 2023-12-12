#!/usr/bin/env python

from typing import Union, List, Tuple, Optional
from elasticsearch import Elasticsearch

def point_in_time(es: Elasticsearch, index: Union[str, List[str], Tuple[str]], timeout: str, query: str):
    """
    Open a point in time (https://www.elastic.co/guide/en/elasticsearch/reference/7.12/point-in-time-api.html) for `index` with a a time to live 
    of `timeout`. Then return results matching `query`.
    -----
    Param:
        es: ElasticSearch
            ElastricSearch client object.
        index: String or List[String] or Tuple(String)
            Index names to open point in time
        timeout: String
            Time to live for the point in time
        query: String
            Query 
    """

    pit = es.open_point_in_time(index=index, keep_alive=timeout)
    pit['keep_alive'] = timeout

    query['pit'] = pit

    res = es.search(body=query)
    es.close_point_in_time({'id': pit['id']})

    return res

def query_attackers(start_ts: int, 
                    end_ts: int, 
                    attackers: Union[str, List[str]],
                    min_susp_score: Optional[int] = 60,
                    max_susp_score: Optional[int] = 100) -> dict:
    """
    Query for events between `start_ts` and `end_ts` and that contains these attackers `attackers`.
    -----

    Param:
        start_ts: int
            Interval start timestamp
        end_ts: int
            Interval end timestamp
        attackers: str or List(str)
            Attacker ASN or list of attackers ASN whose events we want 
    """
    query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "view_ts": {
                                    "lte": end_ts,
                                    "gte": start_ts
                                }
                            }, 
                            "range": {
                                "summary.inference_result.primary_inference.suspicion_level": {
                                    "gte": min_susp_score, 
                                    "lte": max_susp_score 
                                }
                            }
                        }
                    ],
                    "should": [],
                    "minimum_should_match": 1
                }
            },
            "sort": {
                "view_ts": {
                    "order": "asc"
                }
            }
        }

    should_part = query['query']['bool']['should']
    for attacker in attackers:
        if isinstance(attacker, str):
            should_part.append({
                                "term": {
                                        "summary.attackers": attacker
                                        }
                                })
        else:
            should_part.append({
                         "bool": {
                            "must": [{
                                        "term": {
                                            "summary.attackers": more_attacker
                                        }
                                    }
                                    for more_attacker in attacker]
                         }
                        })
            
    return query

def query_attacker_2(start_ts: int, end_ts: int, attacker: str, size: int, min_susp: Optional[int] = 60, max_susp: Optional[int] = 100) -> dict:
    """
    Query for events between `start_ts` and `end_ts` whose potential attacker is `attacker`.
    Retrieve at most `size` events. 
    -----

    Param:
        start_ts: int
            Interval start timestamp
        end_ts: int
            Interval end timestamp
        attacker: str
            ASN of the attacker
        size: int
            Number of events to retrieve
    """
    query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "view_ts": {
                                "gte": start_ts,
                                "lte": end_ts
                                }
                            }
                    },
                    {
                        "query_string": {
                            "analyze_wildcard": "true",
                            "query":f"summary.inference_result.primary_inference.suspicion_level: [{min_susp} TO {max_susp}] AND summary.attackers: {attacker}"
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
        "size": 2000
    }

    return query

def query_attacker_victim(start_ts: int, end_ts: int, attacker: str, victim: str, size: int, min_susp: Optional[int] = 60, max_susp: Optional[int] = 100) -> dict:
    """
    Query for events between `start_ts` and `end_ts` whose potential attacker is `attacker`and potential victim is `victim`.
    Retrieve at most `size` events. 
    -----

    Param:
        start_ts: int
            Interval start timestamp
        end_ts: int
            Interval end timestamp
        attacker: str
            ASN of the attacker
        size: int
            Number of events to retrieve
    """
    query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "view_ts": {
                                "gte": start_ts,
                                "lte": end_ts
                                }
                            }
                    },
                    {
                        "query_string": {
                            "analyze_wildcard": "true",
                            "query":f"summary.inference_result.primary_inference.suspicion_level: [{min_susp} TO {max_susp}] AND summary.attackers: {attacker} AND summary.victims: {victim}"
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
        "size": 2000
    }

    return query

def query_attackers_count(start_ts: int, 
                          end_ts: int, 
                          size: Optional[int] = 500, 
                          min_doc_count: Optional[int] = 100,
                          min_susp_score: Optional[int] = 60,
                          max_susp_score: Optional[int] = 100) -> dict:
    """
    Query the count of suspicious events between `start_ts` and `end_ts`, grouped by potential attackers ASN in descendant order.
    Considering only attackers that have at least `min_doc_count` events.
    Retrieve at most `size` attackers. 
    -----

    Param:
        start_ts: int
            Interval start timestamp
        end_ts: int
            Interval end timestamp
        size: int
            Maximum number of retrieved ASes. Default 500.
        min_doc_count: int 
            Minimum number of events for the AS to be considered. Default: 100, must be > 1.
    """
    query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "view_ts": {
                                "gte": start_ts,
                                "lte": end_ts
                                }
                            }
                    },
                    {
                        "query_string": {
                            "analyze_wildcard": "true",
                            "query":f"summary.inference_result.primary_inference.suspicion_level: [{min_susp_score} TO {max_susp_score}]"
                            }
                    }
                ]
            }
        },
        "aggs": {
            "2": {
                "terms": {
                    "field": "summary.attackers",
                    "size": size,
                    "order": {
                        "_count":"desc"
                    },
                    "min_doc_count": min_doc_count
                },
                "aggs":{}
            }
        }
    }

    return query

def query_time_distrib(start_ts: int, 
                       end_ts: int,
                       attacker_ASN: str, 
                       min_doc_count: Optional[int] = 1, 
                       min_susp_score: Optional[int] = 60,
                       max_susp_score: Optional[int] = 100) -> dict:
    """
    Query the count of suspicious events perpetrated by `attacker_ASN` between `start_ts` and `end_ts`, grouped by date (1 day interval) in descendant order.
    Considering only days with at least `min_doc_count` events.
    -----

    Param:
        start_ts: int
            Interval start timestamp
        end_ts: int 
            Interval end timestamp
        attacker_ASN: str
            ASN of the attacker.
        min_doc_count: int
            Minimum number of events for the date to be considered. Default: 1.
    """
    query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "view_ts": {
                                "gte": start_ts, 
                                "lte": end_ts
                            }
                        }
                    },
                    {
                        "query_string": {
                            "analyze_wildcard": "true",
                            "query": f"summary.inference_result.primary_inference.suspicion_level: [{min_susp_score} TO {max_susp_score}] AND summary.attackers: {attacker_ASN}"
                        }
                    }
                ]
            }
        },
        "aggs": {
            "2": {
                "date_histogram": { 
                    "field": "view_ts",
                    "min_doc_count": min_doc_count,
                    "extended_bounds": {
                        "min": start_ts*1000, # For some reasons, when the timestamp is in seconds, it starts in 1970...
                        "max": end_ts*1000
                    },
                    "fixed_interval": "1d"
                },
                "aggs": {}
            }
        }
    }

    return query