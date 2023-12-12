#!/usr/bin/env python

import requests
import datetime
import time
import os
import json

ASNs = [198949, 65535, 61317, 28598, 20473, 18013, 12715, 9009, 7018, 4847, 834, 203]

years = [2021, 2022, 2023]
months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
months_30 = ['04', '06', '09', '11']
days = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16',
        '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31']

# rpki_status = ['NotFound', 'Invalid', 'Invalid,more-specific', 'Valid']
# delegated_prefix_status = ['assigned', 'available', 'reserved', 'allocated', 'ianapool', 'NotFound']

routing_info = {}

if __name__ == '__main__':
    time_start = time.time()

    for ASN in ASNs:
        print(f"[{datetime.datetime.now()}] Start {ASN}")
        for year in years:
            if year == 2021:
                temp_months = months[6:]
            elif year == 2023:
                temp_months = months[:10]
            else:
                temp_months = months
            for month in temp_months:
                print(f"    [{datetime.datetime.now()}] Start {year}-{month}")
                if year == 2020 and month == '02':
                    temp_days = days[:29]
                elif year != 2020 and month == '02':
                    temp_days = days[:28]
                elif month in months_30:
                    temp_days = days[:30]
                else:
                    temp_days = days
                for day in days:
                    date = f'{year}-{month}-{day}'
                    routing_info[date] = {'rpki': {'NotFound': 0, 'Invalid': 0, 'Invalid,more-specific': 0, 'Valid': 0},
                                            'irr': {'NotFound': 0, 'Invalid': 0, 'Invalid,more-specific': 0, 'Valid': 0},
                                            'prefix_status': {'assigned': 0, 'available': 0, 'reserved': 0, 'allocated': 0, 'ianapool': 0, 'NotFound': 0}
                                            }

                    url = f'https://ihr.iijlab.net/ihr/api/hegemony/prefixes/?format=json&timebin__gte={date}T00%3A00%3A00.000Z&timebin__lte={date}T23%3A59%3A59.000Z&originasn={ASN}'
                    try:
                        data = requests.get(url).json()
                        routing_info[date]['count_pfx_orig'] = data['count']
                        for pfx in data['results']:
                            routing_info[date]['rpki'][pfx['rpki_status']] += 1
                            routing_info[date]['irr'][pfx['irr_status']] += 1
                            routing_info[date]['prefix_status'][pfx['delegated_prefix_status']] += 1
                    except:
                        routing_info[date]['count_pfx_orig'] = 0

        collecting_time = str(datetime.timedelta(seconds = time.time() - time_start))
        print(f'    Time to collect data for {ASN}: {collecting_time}')

        time_start = time.time()
        if not os.path.isdir(f'../data/AS{ASN}/'):
            os.mkdir(f'../data/AS{ASN}/')
        with open(f'../data/AS{ASN}/routing_info.json', 'w') as fp:
            json.dump(routing_info, fp, indent = 2)

        writing_time = str(datetime.timedelta(seconds = time.time() - time_start))
        print(f'    Time to write data in json file for {ASN}: {writing_time}')



