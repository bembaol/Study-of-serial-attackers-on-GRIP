# Study-of-serial-attackers-on-GRIP
This project was carried out as part of the CS8803 - Special Topic - Securing the Internet Infrastructure course, taught by Dr. Cecilia Testart.

## Abstract
The Global Routing Intelligence Platform (GRIP) monitors and categorizes BGP incidents globally. In particular, GRIP detects two types of origin errors: MOAS and subMOAS. The oldest Autonomous System (AS) origin is considered as the potential victim while the newest as the potential attacker. Since January $1^{st}$, 2020, several Autonomous Systems (ASes) have been involved as potential attacker in a significant number of conflicts in the global routing system. In this work, we investigate on the causes of these recurring conflicts, trying to figure out if these are legitimate, configuration errors or malicious hijacks. After isolating 28 ASes regularly involved in origin error conflicts, we gathered AS information and potential report of recurring abnormal behavior for each of these ASes in order to make initial assumptions about the origin of their behavior. Based on this initial information, we estimated that there was a non-malicious reason for this recurring behavior for 21 of them. To verify these hypotheses, we then retrieved data supplied by GRIP for each event. For the remaining ASes, we also gathered data collected by GRIP for each event and also from the Internet Health Report in order to have more insights on what could have happened. These data will be useful for further investigations.

## Files
src/ contains 8 files:
- get_serial_hijackers.py: retrieve ASNs of all recurring attackers on GRIP and write them in data/potential_serial_hijackers_ASN.txt. Also plot event count for each ASN in images/ count_of_events_per_potential_hijackers.png and time distribution of events for each AS in images/AS{ASN}/time_distrib_susp_event.png. For some AS it also plot IRR, RPKI and prefix statuses taken from IHR.
- get_ihr_routing_info.py: from IHR, retrieve announced prefixes information (IRR, RPKI and prefix statuses) for each AS between 07/01/2021 and 10/31/2023 and save it in data/AS{ASN}/routing-info.json.
- grip_event_analysis.py: retrieve all type of information concerning each GRIP event and save it in data/AS{ASN}/summary.txt, data/AS{ASN}/tags.csv and data/AS{ASN}/tags_freq.json
- plot_functions.py, query_functions.py and utils.py are helpers
- AS211398_analysis.py: count the number of event only saw by AS211398 vantage point between May 28 and June 2 2022 and August 23 and 30 2022. Save the results in data/AS211398/
- victims_41698_43754.py: count the numbers of common victims between 41689 and 43754 (not used in the summary)
