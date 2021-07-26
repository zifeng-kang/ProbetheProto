#python3

import os, logging
from tqdm import tqdm
from pprint import pprint

write_root_path = "/home/zfk/Documents/sanchecker/src/"

# root_path = "/media/data1/zfk/Documents/sanchecker/src/recursive_pp_logs"
# root_path = "/media/data1/zfk/Documents/sanchecker/src/recursive_pp_pattern1_rankmorethan10k_logs"
root_path = "/home/zfk/Documents/sanchecker/src/recursive_pp_pattern1_0to200k_logs"
ppfound_str = 'ppFOUND!'

# root_path = "/media/data1/zfk/Documents/sanchecker/src/check_pp_logs"
# root_path = "/media/data1/zfk/Documents/sanchecker/src/check_pp_pattern1_rankmorethan10k_logs"
# ppfound_str = 'ppExploitFOUND'

key2_str = '"KEY2"'
value_str = '"VALUE0"'
target_str = key2_str + value_str
# Now only support URL-search checking

#logging.basicConfig(filename=os.path.join(root_path, "possible_pp.log"), #"warning_mismatch_key_value_type.log"),
#                            filemode='a',
#                            level=logging.INFO)
## warning_logger = logging.getLogger('warning_logger')
#possible_pp_logger = logging.getLogger('possible_pp_logger')

# possible_pp_website_record_name = "websites_total_to_pp_pattern1_0to200k.txt"
possible_pp_website_record_name = "new_websites_url_src_to_pp_pattern1_0to200k.txt"
target_type = 'UnknownTaintError:12'

def parse_ppfound(line:str, idx:int, file:str, websites_set:set):
    # line format: 
    # ppfound_str KeyTaintType <key_type> ValueTaintType <value_type> MessageId <id> <str_contents>
    assert ppfound_str in line
    items = line.split(' ')
    if len(items) != 8:
        return None
    flag = (ppfound_str in line) +\
      (ppfound_str == items[0]) +\
      ('KeyTaintType' == items[1]) +\
      ('ValueTaintType' == items[3])
    if flag != 4:
        return None
    key_type = items[2]
    value_type = items[4]
    str_contents = items[-1] # TODO: string processing

    if str_contents[:len(target_str)].upper() == target_str:
        # site = file.replace('_log_file','').replace('_', '.')
        # websites_set.add(site)

        if key_type == target_type and value_type == target_type: 
            # TODO: should add key1_type checking
            site = file.replace('_log_file','').replace('_', '.')
            websites_set.add(site)
        # possible_pp_logger.info(f'{file}:{idx} {line}')
        # with open(os.path.join(root_path, possible_pp_website_record_name), 'a') as f0:
        #     site = file.replace('_log_file','').replace('_', '.')
        #     f0.write(f'{site}\n')

    # if key_type != value_type:
    #     warning_logger.info(f'{file}:{idx} warning {line}')

    return [key_type, value_type]


if __name__ == "__main__":

    import codecs
    count_domain = 0
    count_flow = 0
    total = 0
    source_type_dict = {}
    key_value_type_different_wrt_source_type_dict = {}
    website_count_wrt_source_type_dict = {}
    website_set = set()
    vul_file_list = []
    for file in tqdm(os.listdir(root_path)):
        if "log_file" in file:
            # print(f"Checking {file} ...")
            total += 1
            with codecs.open(os.path.join(root_path, file), 'r', encoding='utf-8', errors='replace') as f0:
                contents = f0.read()
                if not ppfound_str in contents:
                    continue

                count_domain += 1
                vul_file_list.append(file.replace("log_file", ""))
                for idx, line in enumerate(contents.split('\n')):
                    if not ppfound_str in line:
                        continue
                    # print(line)
                    # print(file.replace('_log_file','').replace('_', '.'))
                    # count_domain += 1
                    # website_set.add(line.split(' ')[-1])
                    
                    results = parse_ppfound(line, idx, file, website_set)
                    if not results:
                        continue
                    key_type, value_type = results[0], results[1]
                    if not value_type in source_type_dict.keys(): # count according to value_type
                        source_type_dict[value_type] = 0
                    source_type_dict[value_type] += 1

                    if key_type != value_type:
                        if not value_type in key_value_type_different_wrt_source_type_dict.keys(): # count according to value_type
                            key_value_type_different_wrt_source_type_dict[value_type] = 0
                        key_value_type_different_wrt_source_type_dict[value_type] += 1

                    if not value_type in website_count_wrt_source_type_dict.keys(): # count according to value_type
                        website_count_wrt_source_type_dict[value_type] = set()
                    website_count_wrt_source_type_dict[value_type].add(file.replace('_log_file','').replace('_', '.'))
                    count_flow += 1


    
    pprint(website_set)
    pprint(source_type_dict)
    pprint(key_value_type_different_wrt_source_type_dict)

    website_count_wrt_source_type_dict = {k:len(v) for k,v in website_count_wrt_source_type_dict.items()}
    pprint(website_count_wrt_source_type_dict)

    print("URL-search vul sites: ", len(website_set), " total vul sites: ", count_domain, " total domains: ", total, "total vul fraction: ", float(count_domain)/float(total), " flow counts: ", count_flow)
    with open(os.path.join(write_root_path, possible_pp_website_record_name), 'w') as ff:
        websites_to_pp = '\n'.join([str(idx)+','+each for idx,each in zip(range(len(vul_file_list)),vul_file_list)])
        ff.write(websites_to_pp)
