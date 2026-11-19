#!/usr/bin/env python3

from pathlib import Path, PurePath
from collections import defaultdict
import csv
import ipaddress
import socket
import struct
import bisect


class GeoLocator:
    def __init__(self, csv_country_block: str, csv_country_locations: str):
        self.network_geoid = {}
        self.geoid_country = {}
        
        with open(csv_country_block, mode="r") as file:
            reader = csv.reader(file)

            next(reader)

            for row in reader:
                self.network_geoid[row[0].strip()] = row[1].strip()

        with open(csv_country_locations, mode="r") as file:
            reader = csv.reader(file)

            next(reader)

            for row in reader:
                self.geoid_country[row[0].strip()] = row[5].strip()

        self.network_ranges = [self._network_to_range(net) + (net,) for net in self.network_geoid]
        self.network_ranges.sort(key=lambda x: x[0])
        self.start_ips = [r[0] for r in self.network_ranges]

    def _ip_to_int(self, ip: str):
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def _network_to_range(self, cidr_str: str):
        ip_part, prefix_part = cidr_str.split("/")
        prefix_len = int(prefix_part)

        net_int = self._ip_to_int(ip_part)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

        start_ip = net_int & mask
        end_ip = start_ip | (~mask & 0xFFFFFFFF)

        return start_ip, end_ip

    def get_country(self, ip: str) -> str:
        target = self._ip_to_int(ip)
        
        idx = bisect.bisect_right(self.start_ips, target) - 1

        if idx >= 0:
            start, end, cidr = self.network_ranges[idx]
            if start <= target <= end:
                geoid = self.network_geoid.get(cidr)
                return self.geoid_country.get(geoid) or "Unknown"

        return "Unknown"

        
def get_ips_by_day(path: str) -> dict[str, set]:
    """Gets the list of ip addresses that were observed in a day.

    Args:
        path (str): The path where all the files are (ip-[date].txt)

    Returns:
        The list of unique ip addresses observed.
    """
    ips = defaultdict(set)
    directory = Path(path)
    filenames = [f.name for f in directory.glob("ips-*.txt") if f.is_file()]

    for filename in filenames:
        key = filename.split("T")[0].replace("ips-", "")
        file = PurePath.joinpath(directory, filename)

        with open(file, "r") as content:
            for ip in content:
                ips[key].add(ip.strip())

            #old_file = Path(Path(file).absolute())
            #new_file = PurePath.joinpath(old_file.parent, old_file.name.replace("ips", "read-ips"))
            #old_file.rename(new_file)

    return ips

def get_network_geoid(csv_file: str) -> list[tuple[ipaddress.IPv4Network, str]]:
    """Gets the list of networks and geo identifiers from CVS database.

    Args:
        csv_file (str): The CSV databasae with the geo location data.

    Returns:
        The list of networks and identifiers.
    """
    networks = list()
    
    with open(csv_file, mode="r") as file:
        reader = csv.reader(file)

        next(reader)

        for row in reader:
            networks.append((ipaddress.ip_network(row[0].strip(), strict=False), row[1]))

    return networks
    
def get_country_by_geoid(csv_file: str) -> dict[str, str]:
    """Gets the dictionary of geoid values and their countries.

    Args:
        csv_file (str): The CSV database with the geo location data.

    Returns:
        The dictionary of geoid and countries.
    """
    countries = {}
    
    with open(csv_file, mode="r") as file:
        reader = csv.reader(file)

        next(reader)

        for row in reader:
            countries[row[0].strip()] = row[5]

    return countries

def get_country_attacks(ips: dict[str, set]) -> dict[str, dict[str, int]]:
    """Gets the countries with the amount of IP addresses in them.

    Args:
        ips (dict[str, set]): The set of IP addresses by date.

    Returns:
        The list of countries and amounts of IPs by date.
    """
    countries = {}
    print("Loading geolocation data")
    geo_locator = GeoLocator("GeoLite2-Country-Blocks-IPv4.csv", "GeoLite2-Country-Locations-en.csv")
    
    for date_key, values in ips.items():
        country_attacks = {} 
        print(f"Evaluating data for {date_key}")
        for ip in values:
            country = geo_locator.get_country(ip)
            attacks = country_attacks.get(country) or 0
            country_attacks[country] = attacks + 1
                    
        countries[date_key] = country_attacks

    return countries

    
ips = get_ips_by_day("input/")

final = get_country_attacks(ips)

for key, value in final.items():
    print(f"{key}:")
    for ip, times in value.items():
        print(f"   {ip} \t {times}")
