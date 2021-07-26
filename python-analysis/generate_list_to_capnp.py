#python3

import os, logging, codecs, glob
from tqdm import tqdm
from pprint import pprint

root_path = "/home/zfk/Documents/sanchecker/src/"
# query_file = "vul_to_url_websites_pattern1_0to200k.txt"
log_path = "check_pp_pattern1_600kto1m_logs"
# db_relative_path = "../check_pp_pattern1_0to200k_crawl/"
db_relative_path = "../check_pp_pattern1_600kto1m_crawl/"#"../recursive_pp_pattern1_0to200k_crawl/" # many log_files are missing; will also use this path later

write_file = "list_to_capnp_check_pp_pattern1_600kto1m.txt" #"./list_to_capnp_original_recursive_vul_url_0to200k.txt"

if __name__ == "__main__":
    sites_to_capnp = []
    # with codecs.open(os.path.join(root_path, query_file), 'r', encoding='utf-8', errors='replace') as f0:
    #     contents = f0.read()
    #     for idx, line in enumerate(contents.split('\n')):
    #         site = line.split(',')[-1]
    #         site_taint_log_name_starter = site.replace('.', '_', 1) + '_'
    #         sites_to_capnp.append(site_taint_log_name_starter)
    for file in tqdm(os.listdir(os.path.join(root_path, log_path))):
        if "log_file" in file:
            site_taint_log_name_starter = file.replace('log_file','')
            sites_to_capnp.append(site_taint_log_name_starter)
            
    # Dict structure: {<starter_str>:[(<log_name>, <log_size>), ... )], ... }
    # The first element in [] should be the largest taint_log (among logs with the same starter name)
    taint_log_to_capnp_dict = {starter:[('', 10)] for starter in sites_to_capnp}
    for taint_log in tqdm(os.listdir(os.path.join(root_path, db_relative_path))):
        if not '_' in taint_log or os.path.getsize(os.path.join(root_path, db_relative_path, taint_log)) in [0, 336]:
            continue
        for starter in taint_log_to_capnp_dict.keys():
            if taint_log.startswith(starter):
                log_size = os.path.getctime(os.path.join(root_path, db_relative_path, taint_log))
                largest_log_name, largest_log_size = taint_log_to_capnp_dict[starter].pop(0)
                if largest_log_size < log_size:
                    taint_log_to_capnp_dict[starter].insert(0, (taint_log, log_size))
                    if float(largest_log_size/log_size) > 0.5:
                        taint_log_to_capnp_dict[starter].append((largest_log_name, largest_log_size))
                else:
                    taint_log_to_capnp_dict[starter].insert(0, (largest_log_name, largest_log_size))
        else:
            continue

    # pprint(taint_log_to_capnp_dict)
    str_to_write = '\n'.join(each[0] for value_list in taint_log_to_capnp_dict.values() for each in value_list if each[0])
    with open(os.path.join(root_path, write_file), 'w') as ff:
        ff.write(str_to_write)