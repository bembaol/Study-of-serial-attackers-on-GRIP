#!/usr/bin/env python

if __name__ == '__main__':
    victims_AS41689 = []
    with open('../data/AS41689/summary.txt') as fp:
        victim_next_line = False
        for line in fp:
            if line != 'Victims targeted more than 5 times:\n' and not victim_next_line:
                continue
            if line == 'Victims targeted more than 5 times:\n' and not victim_next_line:
                victim_next_line = True
                continue
            if victim_next_line and line == '------------------------------\n':
                break
            
            ASN = line.split(':')[0]

            victims_AS41689.append(ASN)

    print(f"Number of victims with more than 5 events for 41689: {len(victims_AS41689)}")

    victims_AS43754 = []
    with open('../data/AS43754/summary.txt') as fp:
        victim_next_line = False
        for line in fp:
            if line != 'Victims targeted more than 5 times:\n' and not victim_next_line:
                continue
            if line == 'Victims targeted more than 5 times:\n' and not victim_next_line:
                victim_next_line = True
                continue
            if victim_next_line and line == '------------------------------\n':
                break
            
            ASN = line.split(':')[0]

            victims_AS43754.append(ASN)

    print(f"Number of victims with more than 5 events for 43754: {len(victims_AS43754)}")

    overlap = [ASN for ASN in victims_AS41689 if ASN in victims_AS43754]
    print(f"More than 5 events with both: {len(overlap)} ({overlap})")