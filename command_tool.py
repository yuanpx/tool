#! /usr/bin/env python

import subprocess
import os
import stat
import re

DIRECT = 1




def gen_pick_func(keys):
    def pick_func(input):
        pick_keys = set(keys)
        res = {k:v for k,v in input.iteritems() if k in pick_keys}
        return res
    return pick_func

def single_command_go(cmd):
    try:
        res_out = subprocess.check_output(cmd, shell=True)
        return res_out, None
    except subprocess.CalledProcessError, e:
        return None, e

def jude_hardware():
    cmd_out, err = single_command_go('dmidecode -t1')
    if err != None:
        return None, err

    words = set(cmd_out.split())
    if "HP" in words:
        return "HP"

    if "Dell" in words:
        return "Dell"

    return None

def collect_setuptime():
    file_path = '/root/anaconda-ks.cfg'
    if os.path.exists(file_path):
        file_stats = os.stat(file_path)
        return file_stats[stat.ST_CTIME], None

    return "", None



def parse_setuptime(input, err):
    res = {"setuptime": input}
    return res

def collect_facter():
    cmd_out, err = single_command_go('facter')
    if err != None:
        return None, err

    res_lines = cmd_out.splitlines()
    def collect_kv(res, line):
        kv = line.split('=>', 1)
        if kv[0] == line:
            return res
        kv = map(lambda x: x.strip(), kv)
        res[kv[0]]  = kv[1]
        return res


    res = reduce(collect_kv, res_lines, {})

    return res, None

def gen_match_res(input, match_keys):
    def pick_match(res, key):
        res[key] = input[match_keys[key]]
        return res

    res = reduce(pick_match, match_keys.keys(), {})
    return res


def parse_facter(input, err):
    if err != None:
        return {"error", err}

    match_keys = {
        "stname":"fqdn",
        "manufactory":"manufacturer",
        "model":"productname",
        "sn":"serialnumber",
        "os_type":"kernel",
        "os_distribution":"operatingsystem",
        "os_release":"operatingsystemrelease",
        "cpu_model":"processor0",
        "cpu_count":"physicalprocessorcount",
        "cpu_core_count":"processorcount",
        "host_type":"virtual",
        "ram_size":"memorysize",
    }

    res = gen_match_res(input, match_keys)

    return res

def collect_ram():
    cmd_out, err = single_command_go('dmidecode -q -t 17 2>/dev/null')
    if err != None:
        return None, err

    cmd_out = cmd_out.splitlines()
    cmd_out = ",".join(cmd_out)
    ram_group = cmd_out.split(",,")
    def parse_ram(res, ram_line):
        ram_items = ram_line.split(",")[1:]
        def collect_kv(res, item):
            items = item.split(":", 1)
            if items[0] == item:
                return res
            res[items[0].strip()] = items[1].strip()
            return res

        ram = reduce(collect_kv, ram_items, {})
        res.append(ram)
        return res

    res = reduce(parse_ram, ram_group, [])

    return res, None

def parse_ram(input, err):
    if err != None:
        return {"error": err}

    match_keys = {
        "slot":"Locator",
        "capacity":"Size",
        "model":"Type",
        "sn":"Serial Number",
        "manufactory":"Manufacturer"
    }

    res = gen_match_res(input, match_keys)

    return res

def collect_nic():
    cmd_out, err = single_command_go('ip address show')
    if err != None:
        return None, err

    cmd_lines = cmd_out.splitlines()
    line_groups = []
    line_group = []
    for line in cmd_lines:
        splits = line.split(":", 1)
        if len(splits) > 0:
            match = re.match(r'\d+$', splits[0])
            if match:
                if len(line_group) > 0:
                    line_groups.append(line_group)
                    line_group = []

        line_group.append(line)

    if len(line_group) > 0:
        line_groups.append(line_group)

    res = []

    for group in line_groups:
        start_line = group[0]
        items = start_line.split()
        if items[2] == 'lo:':
            continue

        state_index = items.index('state')
        state = items[state_index + 1]
        ether_lines = filter(lambda x: x.strip().startswith(r'link/ether'), group)
        if not any(ether_lines):
            continue

        ether_line = ether_lines[0]
        ether = ether_line.strip().split()[1]

        inet_lines = filter(lambda x: x.strip().startswith(r'inet') and not x.strip().startswith(r'inet6'), group)
        if not any(inet_lines):
            continue

        inet_line = inet_lines[0]
        inet = inet_line.strip().split()[1]

        res.append({
            "inet": inet,
            "ether": ether,
            "state": state,
        })


    return res

def collect_dell_raid_adaptor():
    cmd_out, err = single_command_go(r"megacli -adpCount -Nolog|grep Controller |awk '{print $3}'|awk -F '.' '{print $1}'")
    if err != None:
        return None, err

    cmd_out = cmd_out.strip()
    if cmd_out == "0":
        return None, None

    cmd_lines = cmd_out.splitlines()
    line_groups = []
    line_group = []
    for line in cmd_lines:
        if line.startswith("Adapter #"):
            if len(line_group) > 0:
                line_groups.append(line_group)
                line_group = []

        line_group.append(line)

    if any(line_group):
        line_groups.append(line_group)

    adapter_res = []
    for group in line_groups:
        adapter_name = group[0].strip()
        adapter_dict = {"Adapter": adapter_name}
        for line in group:
            splits = line.split(":")
            if splits[0] == line:
                continue

            adapter_dict[splits[0].strip()] = splits[1].strip()


        adapter_res.append(adapter_dict)


    return adapter_res, None

def collect_dell_raid_type():
    cmd_out, err = single_command_go(r"megacli -LDInfo -Lall -aALL -Nolog | grep 'RAID Level'")
    if err != None:
        return None, err

    cmd_lines = cmd_out.splitlines()
    cmd_lines = [line.strip() for line in cmd_lines]
    raid_types = []
    for line in cmd_lines:
        items = line.split(":")
        raid_types.append(iems[1].strip())

    return {"raid_type": raid_types}, None



def collect_hp_raid_adaptor():
    cmd_out, err = single_command_go(r"hpssacli ctrl all show config | grep 'Smart .*Slot.*'")
    if err != None:
        return None, err

    cmd_out = cmd_out.strip()
    if cmd_out == "0":
        return None, None

    cmd_lines = cmd_out.splitlines()
    index = 0
    adapter_res = []
    for line in cmd_lines:
        line = line.strip()
        items = line.split()
        Adapter = "Adapter_%d" % index
        model = " ".join(items[1:3])
        sn = items[-1].strip()[:-1]
        adapter_res.append({
            "Adapter": Adapter,
            "model": model,
            "sn" : sn,
            "memory_size" : 0,
        }
        )



    return adapter_res, None

def collect_hp_raid_type():
    cmd_out, err = single_command_go(r"hpssacli ctrl all show config | grep 'logicaldrive.*RAID.*'")
    if err != None:
        return None, err

    cmd_lines = cmd_out.splitlines()
    cmd_lines = [line.strip() for line in cmd_lines]

    return {"raid_type": cmd_lines}, None

def collect_raid_adaptor():
    get_methods = {
        "HP": collect_hp_raid_adaptor,
        "Dell": collect_dell_raid_adaptor,
    }

    method = jude_hardware()
    if method == None:
        return None, "Error Machine"

    return get_methods[method]()

def collect_raid_type():
    get_methods = {
        "HP": collect_hp_raid_type,
        "Dell": collect_dell_raid_type,
    }

    method = jude_hardware()
    if method == None:
        return None, "Error Machine"

    return get_methods[method]()

def collect_disk_noraid():
    cmd_out, err = single_command_go(r"lsscsi -g")
    if err != None:
        return None, err

    adapt_infos, err = collect_raid_adaptor()
    if err != None:
        return None, err

    disk_res = []

    cmd_lines = cmd_out.splitlines()
    for line in cmd_lines:
        items = line.split()
        if items[1] <> "disk":
            continue

        cmd_out, err = single_command_go("smartctl -i -A %s" % items[-2])
        if err != None:
            return None, err

        disk_lines = cmd_out.splitlines()
        disk_dict = {"slot": items[0]}
        for disk_line in disk_lines:
            split_items = disk_line.split(":", 1)
            if split_items[0] == disk_line:
                continue

            disk_key = split_items[0].strip()
            disk_value = split_items[1].strip()
            disk_dict[disk_key] = disk_value

        for info in adapt_infos:
            if info["sn"] == disk_dict["Serial number"]:
                disk_dict["adaptor"] = info["Adapter"]

        disk_res.append(disk_dict)

    return disk_res, None

def collect_disk_dell():
    cmd_out, err = single_command_go(r"/opt/dell/srvadmin/bin/omreport storage pdisk controller=0")
    if err != None:
        return None, err

    adapt_infos, err = collect_raid_adaptor()
    if err != None:
        return None, err

    line_groups = cmd_out.split("\n\n")
    disk_res = []
    for state_group in line_groups:
        state_lines = state_group.splitlines()
        state_dict = {}
        for line in state_lines:
            split_items = line.split(":")
            if line == split_items[0]:
                continue

            state_dict[split_items[0].strip()] = split_items[1].strip()

        for info in adapt_infos:
            if info["sn"] == state_dict['Serial No.']:
                state_dict["adaptor"] = info["Adapter"]

        disk_res.append(state_dict)

    return disk_res, None

def collect_disk_hp():
    cmd_out, err = single_command_go(r"hpssacli ctrl slot=0 pd all show detail")
    if err != None:
        return None, err

    adapt_infos, err = collect_raid_adaptor()
    if err != None:
        return None, err

    line_groups = cmd_out.split('\n\n')
    disk_res = []
    for group in line_groups:
        lines = group.splitlines()
        if not lines[0].strip().startswith('physicaldrive'):
            continue

        state_dict = {}
        split_items = lines[0].strip().split()
        state_dict[split_items[0]] = split_items[1]

        for line in lines[1:]:
            split_items = line.split(":")
            if line == split_items[0]:
                continue

            state_dict[split_items[0].strip()] = split_items[1].strip()

        for info in adapt_infos:
            if info["sn"] == state_dict['Serial Number']:
                state_dict["adaptor"] = info["Adapter"]

        disk_res.append(state_dict)

    return disk_res, None

def collect_disk():
    get_methods = {
        "HP": collect_disk_hp,
        "Dell": collect_disk_dell,
    }

    method = jude_hardware()
    if method == None:
        return None, "Error Machine"

    return get_methods[method]()


class CollectItem:
    def __init__(self, collect_func, parse_func, handle_func):
        self._collect_func = collect_func
        self._parse_func = parse_func
        self._handle_func = parse_func

    def go(self):
        res_out, err = self._collect_func()
        res_out = self._parse_func(res_out, err)
        res_out, err = self._handle_func(res_out)
        return res_out, err
