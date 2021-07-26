#python3

import os, logging
from tqdm import tqdm
from pprint import pprint

write_root_path = "/home/zfk/Documents/sanchecker/src/"

# root_path = "/media/data1/zfk/Documents/sanchecker/src/recursive_pp_logs"
# root_path = "/media/data1/zfk/Documents/sanchecker/src/recursive_pp_pattern1_rankmorethan10k_logs"
root_path = "/home/zfk/Documents/sanchecker/src/check_pp_pattern1_0to200k_logs"
objTainted_str = "ObjTaintedDueToTaintKey!"
ppfound_str = 'ppFOUND!'

# root_path = "/media/data1/zfk/Documents/sanchecker/src/check_pp_logs"
# root_path = "/media/data1/zfk/Documents/sanchecker/src/check_pp_pattern1_rankmorethan10k_logs"
# ppfound_str = 'ppExploitFOUND'

TaintType = ['Cookie',
 'Message',
 'MultipleTaints',
 'Referrer',
 'Storage',
 'UnknownTaintError:11', # URL pathname
 'UnknownTaintError:12', # URL search
 'UnknownTaintError:5', # URL hash
 'UnknownTaintError:7', # URL host
 'UnknownTaintError:8', # URL hostname
 'UnknownTaintError:9', # URL origin
 'UnknownTaintError:6', # URL protocol
 'UnknownTaintError:10', # URL port
 'Url',
 'UnknownTaintError:13', # DOM
 'UnknownTaintError:17', # Network
 'UnknownTaintError:19', # Message origin
 'WindowName']

refactor_dict = {
 'UnknownTaintError:11': 'URL', # URL pathname
 'UnknownTaintError:12': 'URL search', # URL search
 'UnknownTaintError:5': 'URL', # URL hash
 'UnknownTaintError:7': 'URL', # URL host
 'UnknownTaintError:8': 'URL', # URL hostname
 'UnknownTaintError:9': 'URL', # URL origin
 'UnknownTaintError:6': 'URL', # URL protocol
 'UnknownTaintError:10': 'URL', # URL port
 'UnknownTaintError:13': 'DOM', 
 'UnknownTaintError:17': 'Network',
 'UnknownTaintError:19': 'Message origin', 
 'Cookie': 'Cookie',
 'Message': 'Message',
 'MultipleTaints': 'Multiple',
 'Referrer': 'Referrer',
 'Storage': 'Storage',
 'Url': 'URL',
 'WindowName': 'window.name', 
 'ObjTaintedDueToTaintKey!': 'Message' # Unexpected case
}

query_string_type_list = ['Url', 'UnknownTaintError:12', 'Referrer']
target_key_type = 'UnknownTaintError:12'

# For URL-search checking
key2_str = '"testk"'
value_str = '"testv"'
target_str = key2_str + value_str
target_key1_content = '"__proto__"'

#logging.basicConfig(filename=os.path.join(root_path, "possible_pp.log"), #"warning_mismatch_key_value_type.log"),
#                            filemode='a',
#                            level=logging.INFO)
## warning_logger = logging.getLogger('warning_logger')
#possible_pp_logger = logging.getLogger('possible_pp_logger')

# possible_pp_website_record_name = "websites_to_pp_pattern1_0to200k.txt"
possible_pp_website_record_name = "websites_to_pp_cookie_storage_0to200k.txt"

def parse_ppfound(line:str, idx:int, file:str, websites_set:set):
    # line format: 
    # ppfound_str KeyTaintType <key_type> ValueTaintType <value_type> MessageId <id> <str_contents>
    assert line.startswith(ppfound_str)
    items = line.split(' ')
    # len(items) could be greater than 8 because <str_contents> may contain ' '
    if len(items) < 8:
        return None
    flag = (ppfound_str in line) +\
      (ppfound_str == items[0]) +\
      ('KeyTaintType' == items[1]) +\
      ('ValueTaintType' == items[3])
    if flag != 4:
        return None
    key_type = items[2]
    value_type = items[4]
    if_relevant = False
    if key_type == target_key_type and value_type == target_key_type:
        if_relevant = True
        # str_contents = items[-1] 
        str_contents = ''.join(items[7:]) # TODO: string processing
        if str_contents == target_str:
            return key_type, value_type, True, if_relevant

    return key_type, value_type, False, if_relevant

def parse_objTainted(line:str, idx:int, file:str, websites_set:set):
    # Line format: 
    # objTainted_str KeyTaintType <key_type><str_contents>
    # Should take extra efforts to split <key_type> and <str_contents>
    assert line.startswith(objTainted_str)
    items = line.split(' ')
    assert items[1] == 'KeyTaintType'
    contents = ''.join(items[2:]).replace(objTainted_str, '').replace('KeyTaintType', '')
    for each_type in TaintType:
        if contents.startswith(each_type):
            key1_type = each_type
            break
    else:
        # For strange cases
        for each_type in TaintType:
            if each_type in contents:
                key1_type = each_type
                break
        else:
            print("The key1_type of " + contents + " unidentified! ")
            key1_type = None

    # String processing
    if_is_target = False
    if key1_type == target_key_type:
        str_contents = contents.replace(key1_type, '', 1)
        if str_contents == target_key1_content:
            if_is_target = True
    return key1_type, if_is_target

def dict_element_refactor(source_type_dict):
    new_dict = {}
    # count_all_entries = 0
    for value_type, value_each in source_type_dict.items():
        value_type = refactor_dict[value_type]
        for key1_type, key1_each in value_each.items():
            key1_type = refactor_dict[key1_type]
            for key2_type, counts in key1_each.items():
                key2_type = refactor_dict[key2_type]
                new_key = str(set((key1_type, key2_type, value_type)))
                if not new_key in new_dict.keys():
                    new_dict[new_key] = 0
                new_dict[new_key] += counts
                # count_all_entries += counts
    # print('count_all_entries: ', count_all_entries)
    return new_dict


if __name__ == "__main__":

    import codecs
    count_domain = 0
    count_flow = 0
    count_irrelevant_flow, count_data_flow_san, count_tp, count_url_search_flow = 0,0,0,0
    total = 0
    strange_case_count = 0
    source_type_dict = {}
    website_set = set()
    for file in tqdm(os.listdir(root_path)):
        if "log_file" in file:
            # print("Checking " + file)
            total += 1
            with codecs.open(os.path.join(root_path, file), 'r', encoding='utf-8', errors='replace') as f0:
                contents = f0.read()
                if not ppfound_str in contents:
                    continue

                count_domain += 1

                # Initialization
                state = None # use state to store the key1_type
                state_change_count = 0
                state_keep_count = 0
                key1_content = None

                for idx, line in enumerate(contents.split('\n')):
                    if line.startswith(ppfound_str):
                        
                        # continue
                        # print(line)
                        # print(file.replace('_log_file','').replace('_', '.'))
                        # count_domain += 1
                        # website_set.add(line.split(' ')[-1])
                        
                        results = parse_ppfound(line, idx, file, website_set)
                        if not results:
                            continue
                        key2_type, value_type, if_target_value, if_relevant = (each for each in results)
                        # # TODO: Count key1_type, key2_type, value_type
                        # if not value_type in source_type_dict.keys(): # count according to value_type
                        #     source_type_dict[value_type] = {}
                        # if not state in source_type_dict[value_type].keys():
                        #     source_type_dict[value_type][state] = {}
                        # if not key2_type in source_type_dict[value_type][state].keys():
                        #     source_type_dict[value_type][state][key2_type] = 0
                        # source_type_dict[value_type][state][key2_type] += 1
                        # count_flow += 1

                        # if (state is None) or (state_change_count >= 4 and state_keep_count <= 5):
                        #     query_flag = False
                        #     for each_type in query_string_type_list:
                        #         if state == each_type and key2_type == each_type and value_type == each_type:
                        #             query_flag = True
                        #             break
                        #     if not query_flag: # Query string cases are not strange cases
                        #         print("{} {} strange key1_type: {} state_change_count {}; Detected at {}".format(file, idx, state, state_change_count, line))
                        #         strange_case_count += 1


                        if state == target_key_type and key2_type == target_key_type and value_type == target_key_type:
                            count_url_search_flow += 1 
                            if not if_target_value:
                                count_irrelevant_flow += 1
                            else:
                                if key1_content != target_key1_content:
                                    count_data_flow_san += 1
                                else:
                                    count_tp += 1
                        
                        # state = None
                        state_change_count = 0
                        state_keep_count = 0
                        key1_content = None

                    elif line.startswith(objTainted_str):
                        key1_type, if_is_target = parse_objTainted(line, idx, file, website_set)
                        if not key1_type:
                            continue
                        if if_is_target:
                            key1_content = target_key1_content
                            state = key1_type
                        if state != key1_type:
                            state_change_count += 1
                            state = key1_type
                        else:
                            state_keep_count += 1
                    else:
                        continue
                    
                    

    count_ctrl_flow_san = count_url_search_flow - count_tp - count_irrelevant_flow - count_data_flow_san
    print("count_tp", count_tp)
    print("count_irrelevant_flow", count_irrelevant_flow)
    print("count_data_flow_san", count_data_flow_san)
    print("count_ctrl_flow_san", count_ctrl_flow_san)
    print("count_url_search_flow", count_url_search_flow)
    # pprint(source_type_dict)
    # # pprint(website_set)
    # print("Cookie or storage vul sites: ", len(website_set), " total vul sites: ", count_domain, " total domains: ", total, "total vul fraction: ", float(count_domain)/float(total), " flow counts: ", count_flow, " strange_case_count: ", strange_case_count)
    # # with open(os.path.join(write_root_path, possible_pp_website_record_name), 'w') as ff:
    # #     websites_to_pp = '\n'.join([str(idx)+','+each for idx,each in zip(range(len(website_set)),website_set)])
    # #     ff.write(websites_to_pp)

    # # Refactor source_type_dict
    # pprint(dict_element_refactor(source_type_dict))
