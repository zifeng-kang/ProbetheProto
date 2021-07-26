import os, codecs, json
from urllib.parse import quote, quote_plus, unquote, unquote_plus
from try_match import read_and_match, get_replacement
from storage_match_utils import is_json, try_parse_json, traverse_object, log
from match_configs import CONFIG

STORAGE_LOGGING_STR = CONFIG.STORAGE_LOGGING_STR
MESSAGE_LOGGING_STR = CONFIG.MESSAGE_LOGGING_STR
MESSAGE_ORIGIN_START_STR = CONFIG.MESSAGE_ORIGIN_START_STR
MESSAGE_RECEIVER_STR = CONFIG.MESSAGE_RECEIVER_STR
# MESSAGE_ISOBJECT_STR = CONFIG.MESSAGE_ISOBJECT_STR

ALL_LOG_ITEMS = {'Storage': {}, 'Message': {}}

def preprocess_storage(site_log_items, this_site):
    if (not site_log_items) or (not site_log_items[0]) or (not site_log_items[0][0]):
        return False
    new_items = []
    for entry in site_log_items:
        assert len(entry) >= 3
        if len(entry) > 3:
            assert entry[-1] == -1
            if entry[-1] != -1:
                log('Storage Assertion Failed in {}: {}'.format(this_site, entry))
            value = '='.join(entry[1:-1])
            new_items.append([entry[0], value, entry[-1]])
        else:
            new_items.append(entry)
    return new_items

def match_storage(taint_part, taint_source_type, taint_str_to_find, storage_log_file):
    stem = CONFIG.stem
    relative_path = CONFIG.storage_log_relative_path
    all_matches = []
    if storage_log_file in ALL_LOG_ITEMS['Storage'].keys():
        storage_items_list = ALL_LOG_ITEMS['Storage'][storage_log_file]
        if not storage_items_list:
            return all_matches
    else:
        if not os.path.exists(os.path.join(stem, relative_path, storage_log_file)):
            ALL_LOG_ITEMS['Storage'][storage_log_file] = {}
            log("Not exists: {} for {} type".format(storage_log_file, taint_source_type))
            return all_matches
        
        with codecs.open(os.path.join(stem, relative_path, storage_log_file), 'r', encoding='utf-8', errors='replace') as f0:
            contents = f0.read()
            
            ALL_LOG_ITEMS['Storage'][storage_log_file] = {}
            for idx, line in enumerate(contents.split('\n')):
                if not STORAGE_LOGGING_STR in line:
                    continue
                this_site = storage_log_file.replace('_log_file','').replace('_', '.', 1)
                storage_content_to_parse = line[ line.find(STORAGE_LOGGING_STR) + len(STORAGE_LOGGING_STR) : \
                    line.rfind('"') ]
                # No need to unescape quotes when using json.loads
                storage_dict = try_parse_json(storage_content_to_parse)
                if (not storage_dict) or ("storage" not in storage_dict.keys()):
                    log('Fail to parse storage! In: {} Line# {} Content: {}'.format(storage_log_file, idx, line))
                    continue
                this_url = storage_dict['url']
                this_domain = storage_dict['domain']
                if this_site not in this_domain:
                    log('Logged storage has a different domain! Ignoring {} vs {}'.format(this_domain, this_site))
                    continue # this_site = this_domain

                storage_lookup_type = "cookies" if taint_source_type == "Cookie" else "storage"
                site_log_items = storage_dict["storage"][storage_lookup_type]
                storage_items = preprocess_storage(site_log_items, this_site)
                if not storage_items:
                    # Empty storage
                    continue
                ALL_LOG_ITEMS['Storage'][storage_log_file][this_url] = storage_items
    
    for this_url, storage_items_list in ALL_LOG_ITEMS['Storage'][storage_log_file].items():
        this_site = storage_log_file.replace('_log_file','').replace('_', '.', 1)
        matches = read_and_match(which_part=taint_part, taint_value=taint_str_to_find, taint_type=taint_source_type, site_log_items=storage_items_list, site=this_site, url=this_url.split('?')[0])
        if matches and matches not in all_matches:
            # TODO: delete more repeated matches (fuzzily)
            all_matches += matches
        # for match in matches:
        #     matched_key, matched_value, matched_storage_value, fuzzy, addinfo, site, url = match
        #     is_key = ('key' in addinfo)
        #     # store to data.js
        #     continue
    return all_matches

def match_message(taint_part, taint_source_type, taint_str_to_find, message_log_file):
    stem = CONFIG.stem
    relative_path = CONFIG.message_log_relative_path
    all_matches = []
    this_site = message_log_file.replace('_log_file','').replace('_', '.', 1)
    if message_log_file in ALL_LOG_ITEMS['Message'].keys():
        message_items_list = ALL_LOG_ITEMS['Message'][message_log_file]
        if not message_items_list:
            return all_matches
    else:
        if not os.path.exists(os.path.join(stem, relative_path, message_log_file)):
            ALL_LOG_ITEMS['Message'][message_log_file] = []
            log("Not exists: {} for {} type".format(message_log_file, taint_source_type))
            return all_matches
        with codecs.open(os.path.join(stem, relative_path, message_log_file), 'r', encoding='utf-8', errors='replace') as f0:
            # contents = f0.read()
            
            message_items_list = []
            for idx, line in enumerate(f0.readlines()):
                if not MESSAGE_LOGGING_STR in line:
                    continue

                message_content_to_parse = line[ line.find(MESSAGE_LOGGING_STR) + len(MESSAGE_LOGGING_STR) : \
                    line.rfind(MESSAGE_ORIGIN_START_STR) ]
                message_origin = line[ line.find(MESSAGE_ORIGIN_START_STR) + len(MESSAGE_ORIGIN_START_STR) : \
                    line.rfind(MESSAGE_RECEIVER_STR)]
                message_receiver = line[ line.find(MESSAGE_RECEIVER_STR) + len(MESSAGE_RECEIVER_STR) : \
                    line.rfind('", source:')]
                # No need to unescape quotes when using json.loads
                message_dict = try_parse_json(message_content_to_parse)
                # message_dict for fuzzy matching
                
                message_items_list.append([message_content_to_parse, message_origin, message_receiver, message_dict])
            
            ALL_LOG_ITEMS['Message'][message_log_file] = message_items_list
    
    matches = read_and_match(which_part=taint_part, taint_value=taint_str_to_find, taint_type=taint_source_type, site_log_items=message_items_list, site=this_site, url='') #this_url.split('?')[0])
    if matches and matches not in all_matches:
        # TODO: delete more repeated matches (fuzzily)
        all_matches += matches
    # for match in matches:
    #     matched_key, matched_value, matched_storage_value, fuzzy, addinfo, site, url = match
    #     is_key = ('key' in addinfo)
    #     # store to data.js
    #     continue
    return all_matches

def match_url(taint_part, taint_source_type, taint_str_to_find, url_log_file):
    original_str_list = [CONFIG.key1['origin'], CONFIG.key2['origin'], CONFIG.value['origin']]
    original_query = CONFIG.key1['origin'] + '[' + CONFIG.key2['origin'] + ']=' + CONFIG.value['origin']
    new_str_list = [CONFIG.key1['check'][0], CONFIG.key2['check'][0], CONFIG.value['check'][0]]
    new_query = CONFIG.key1['check'][0] + '[' + CONFIG.key2['check'][0] + ']=' + CONFIG.value['check'][0]
    if taint_str_to_find.upper() not in new_query.upper():
        if not any([each.upper() in taint_str_to_find.upper() for each in new_str_list]):
            return []
        else:
            return [[taint_source_type, '', taint_str_to_find, new_query, True, "plain", url_log_file.replace('_log_file','').replace('_', '.', 1), '']]
    return [[taint_source_type, '', taint_str_to_find, new_query, False, "plain", url_log_file.replace('_log_file','').replace('_', '.', 1), '']]

def indicate_if_exploit_generated(exploit_generated_indicator:dict, true_ind_list:list):
    for each in true_ind_list:
        assert each in exploit_generated_indicator.keys()
        exploit_generated_indicator[each] = True

def find_joint_matches(k1k2v:list, log_file:str):
    assert len(k1k2v) == 3
    matches = {'key1':[], 'key2':[], 'value':[]}
    for taint_part, taint_source_type, taint_str_to_find in k1k2v:
        if taint_part == 'key1':
            for each in taint_str_to_find:
                if taint_source_type in CONFIG.types_with_sanitizer and each in CONFIG.sanitizer_dict[taint_part][taint_source_type]:
                    # cannot generate exploit due to a posteriori sanitizers
                    continue
                if k1k2v[1][-1] in each or k1k2v[2][-1] in each or each in k1k2v[1][-1] or each in k1k2v[2][-1]:
                    # cannot generate exploit due to repetition
                    continue
                if taint_source_type == "Message":
                    matches[taint_part] += match_message(taint_part, taint_source_type, each, log_file)
                elif taint_source_type == "Cookie" or taint_source_type == "Storage":
                    matches[taint_part] += match_storage(taint_part, taint_source_type, each, log_file)
                elif taint_source_type in CONFIG.query_string_type_list:
                    # url-based sources
                    matches[taint_part] += match_url(taint_part, taint_source_type, each, log_file)
                # else: # not supported yet TODO: support window.name and URL hash
        else:
            if taint_source_type in CONFIG.types_with_sanitizer and taint_str_to_find in CONFIG.sanitizer_dict[taint_part][taint_source_type]:
                # cannot generate exploit due to a posteriori sanitizers
                continue
            if taint_source_type == "Message":
                matches[taint_part] += match_message(taint_part, taint_source_type, taint_str_to_find, log_file)
            elif taint_source_type == "Cookie" or taint_source_type == "Storage":
                matches[taint_part] += match_storage(taint_part, taint_source_type, taint_str_to_find, log_file)
            elif taint_source_type in CONFIG.query_string_type_list:
                # url-based sources
                matches[taint_part] += match_url(taint_part, taint_source_type, taint_str_to_find, log_file)
            # else: # not supported yet. Should support window.name

    if any([not each for each in matches.values()]):
        log('Cannot generate exploit for: ' + log_file + ' ' + str(matches))
        return None # cannot generate exploit
    # generate exploit and store to corresponding data.js
    # fuzzily match and replace key1, key2, value if it's not found
    taint_types = [each[0][0] for each in matches.values()]
    assert len(taint_types) == 3
    # each element in exploits is a list: 
    # [<taint_type>, <replaced_content>, <site>, <url>, <additional_info>]
    exploits = []
    exploit_generated_indicator = {'key1':False, 'key2':False, 'value':False}
    if len(set(taint_types)) < len(taint_types): # duplicated type
        types_count = {each:0 for each in taint_types}
        for each in taint_types:
            types_count[each] += 1
        for types, counts in types_count.items():
            if counts > 1:
                common_type = types
                break
        # possible fuzzy match of common_type, on key-value pairs
        if common_type in ['Cookie', 'localStorage', 'sessionStorage', 'Message']:
            if taint_types[1] == taint_types[2]:
                # possible: taint_types[0] == taint_types[1] == taint_types[2]
                key, another_key = 'key2', 'key1'

            elif taint_types[0] == taint_types[2]:
                # impossible: taint_types[0] == taint_types[1] == taint_types[2]
                key, another_key = 'key1', 'key2'
            else:
                key = None

            match_list_to_find = matches['key1'] # + matches['key2'] + matches['value']
            key2_content, value_content = k1k2v[1][-1], k1k2v[2][-1]
            for each in match_list_to_find:
                if taint_types[0] == taint_types[1] and taint_types[0] in ['Cookie', 'localStorage', 'sessionStorage', 'Message']:
                # find the storage/message content to parse: it should contain all 3 taint values
                    if_three_taint_types = True if taint_types[0] == taint_types[1] == taint_types[2] else False
                    true_indicate_list = ['key1', 'key2', 'value'] if if_three_taint_types else ['key1', 'key2']
                    if taint_types[0] == 'Message':
                        each_msg_origin, each_tainted_value, each_msg_content, each_if_quoted = each[1], each[2], each[3], each[5]
                        if not each_msg_content:
                            continue
                        each_if_quoted = 'quote' in each_if_quoted

                        if all([ee in each_msg_content for ee in [each_tainted_value, key2_content]]):
                            # should parse the message content to a dict/object (using is_json and try_parse_json in storage_match_utils)
                            if is_json(each_msg_content):
                                msg_obj = try_parse_json(each_msg_content) 
                                if not msg_obj:
                                    continue
                                # find where the key1_string is
                                found_object, is_found = traverse_object(msg_obj, each_tainted_value)
                                if is_found:
                                    
                                    assert each_tainted_value in found_object.keys()
                                    # and then, add two key-value pairs:
                                    #       "__proto__": {get_replacement('key2', 'Message'): get_replacement('value', 'Message')}
                                    #       "constructor": {"prototype": {get_replacement('key2', 'Message'): get_replacement('value', 'Message')}}
                                    # to where the key1_string was found
                                    # the msg_obj is modified at the same time
                                    target = found_object[each_tainted_value]
                                    if isinstance(target, dict):
                                        found_object[get_replacement('key1', 'Message', key1_content=each_tainted_value)] = dict(target)
                                        found_object[get_replacement('key1', 'Message', key1_content=each_tainted_value)].update({get_replacement('key2', 'Message'): get_replacement('value', 'Message')})
                                        found_object["constructor"] = dict(target)
                                        found_object["constructor"].update({"prototype": {get_replacement('key2', 'Message'): get_replacement('value', 'Message')}})
                                    elif isinstance(target, str):
                                        found_object[get_replacement('key1', 'Message', key1_content=each_tainted_value)] = target.replace(key2_content, get_replacement('key2', 'Message'))\
                                            .replace(value_content, get_replacement('value', 'Message'))
                                    else:
                                        log('Unexpected target type! ' + json.dumps(found_object))
                                    # store to exploits
                                    # should consider quoted/unquoted in json.dumps(msg_obj)
                                    dump_str = quote(json.dumps(msg_obj)) if each_if_quoted else json.dumps(msg_obj)
                                else:
                                    # replace the taint value with exploits
                                    for str_to_replace, replacement in zip([each_tainted_value, key2_content, value_content], \
                                        [get_replacement('key1', 'Message', key1_content=each_tainted_value), get_replacement('key2', 'Message'), get_replacement('value', 'Message')]):
                                        each_msg_content = each_msg_content.replace(str_to_replace, replacement)
                                    dump_str = each_msg_content

                                exploits.append(['Message', dump_str, each[-2], each[-1], each_msg_origin])
                                indicate_if_exploit_generated(exploit_generated_indicator, true_indicate_list)
                                continue
                                
                                
                            else:
                                for str_to_replace, replacement in zip([each_tainted_value, key2_content, value_content], \
                                    [get_replacement('key1', 'Message', key1_content=each_tainted_value), get_replacement('key2', 'Message'), get_replacement('value', 'Message')]):
                                    each_msg_content = each_msg_content.replace(str_to_replace, replacement)
                                # dump_str = quote(each_msg_content) if each_if_quoted else each_msg_content
                                dump_str = each_msg_content
                                exploits.append(['Message', dump_str, each[-2], each[-1], each_msg_origin])
                                indicate_if_exploit_generated(exploit_generated_indicator, true_indicate_list)
                        else:
                            continue
                            # raise ValueError('Unexpected behavior of type {} in {}'.format(taint_types[2], log_file))
                    elif taint_types[0] in ['Cookie', 'localStorage', 'sessionStorage']:
                        each_key, each_tainted_value, each_storage_value, each_if_quoted = each[1], each[2], each[3], each[5]
                        if not each_storage_value:
                            continue
                        each_if_quoted = 'quote' in each_if_quoted
                        if all([ee in each_storage_value for ee in (each_tainted_value, key2_content)]):
                            # replace the storage_value with the desired values
                            # both non-key
                            new_storage_value = each_storage_value.replace(each_tainted_value, get_replacement('key1', taint_types[0]))\
                                .replace(key2_content, get_replacement('key2', taint_types[0]))
                            new_key = each_key
                            if value_content in each_storage_value:
                                new_storage_value = new_storage_value.replace(value_content, get_replacement('value', taint_types[0]))
                        elif each_tainted_value in each_key and key2_content in each_storage_value:
                            # one key, one value
                            new_key = each_key.replace(each_tainted_value, get_replacement('key1', taint_types[0]))
                            new_storage_value = each_storage_value\
                                .replace(key2_content, get_replacement('key2', taint_types[0]))
                            if value_content in each_storage_value:
                                new_storage_value = new_storage_value.replace(value_content, get_replacement('value', taint_types[0]))
                        elif each_tainted_value in each_key and key2_content in each_key:
                            # both key
                            new_key = each_key.replace(each_tainted_value, get_replacement('key1', taint_types[0]))\
                                .replace(key2_content, get_replacement('key2', taint_types[0]))
                            new_storage_value = each_storage_value
                            if value_content in each_storage_value:
                                new_storage_value = new_storage_value.replace(value_content, get_replacement('value', taint_types[0]))
                            elif value_content in each_key:
                                new_key = new_key.replace(value_content, get_replacement('value', taint_types[0]))
                        # elif all([each_tainted_value in each_key, key2_content in each_key]):
                        #     new_key = each_key.replace(each_tainted_value, get_replacement('key1', taint_types[0]))\
                        #         .replace(key2_content, get_replacement('key2', taint_types[0]))
                                    
                        #     new_storage_value = each_storage_value
                            
                            # raise ValueError('Unexpected behavior of type {} in {}'.format(taint_types[0], log_file))
                        else:
                            # raise ValueError('Unexpected behavior of type {} in {}'.format(taint_types[0], log_file))
                            continue

                        
                        # if each_if_quoted:
                        #     new_key = quote(new_key)
                        #     new_storage_value = quote(new_storage_value)
                        # else:
                        #     new_key = quote(new_key) if each_key != each_key else new_key
                        #     new_storage_value = quote(new_storage_value) if new_storage_value != unquote_plus(unquote_plus(new_storage_value)) else new_storage_value
                        if taint_types[0] == 'Cookie':
                            exploits.append(['Cookie', new_key+'='+new_storage_value, each[-2], each[-1], '0'])
                            indicate_if_exploit_generated(exploit_generated_indicator, true_indicate_list)
                            
                        else: 
                            assert taint_types[0] in ['localStorage', 'sessionStorage'] 
                            if_local = '1' if taint_types[0] == 'localStorage' else '-1'
                            exploits.append(['Storage', {new_key:new_storage_value}, each[-2], each[-1], if_local]) # 1 for localStorage
                            indicate_if_exploit_generated(exploit_generated_indicator, true_indicate_list)
                            
                    else:
                        continue
            # if exploits: # not empty
            #     return exploits

            if key and not exploits:
                for each_key_match in matches[key]:
                    for each_value_match in matches['value']:
                        if each_key_match[1] == each_value_match[1]:
                            # same storage key, or the same msg origin
                            taint_type = each_key_match[0]
                            key_to_replace = quote_plus(each_key_match[2]) if 'quote' in each_key_match[5] else each_key_match[2]
                            value_to_replace = quote_plus(each_value_match[2]) if 'quote' in each_value_match[5] else each_value_match[2]
                            # if both non-key
                            if key_to_replace in each_value_match[3]:
                                new_key = each_value_match[1]
                                new_storage_value = each_value_match[3].replace(key_to_replace, get_replacement(key, taint_type))\
                                    .replace(value_to_replace, get_replacement('value', taint_type))
                            elif value_to_replace in each_key_match[3]:
                                new_key = each_value_match[1]
                                new_storage_value = each_key_match[3].replace(key_to_replace, get_replacement(key, taint_type))\
                                    .replace(value_to_replace, get_replacement('value', taint_type))
                            else:
                                if taint_type != 'Message':
                                    
                                    # if one key one value
                                    # e.g., cookie: key is 'sbjs_udata', value is 'vst' => key is 'someKey', value is 'someValue'
                                    if key_to_replace and key_to_replace in each_value_match[1] and value_to_replace not in each_value_match[1]:
                                        new_key = each_value_match[1].replace(key_to_replace, get_replacement('key2', taint_type))
                                        new_storage_value = each_value_match[3].replace(value_to_replace, get_replacement('value', taint_type))
                                    # if both key (rare cases)
                                    elif key_to_replace and key_to_replace in each_value_match[1] and value_to_replace in each_value_match[1]:
                                        new_key = each_value_match[1].replace(key_to_replace, get_replacement('key2', taint_type))\
                                            .replace(value_to_replace, get_replacement('value', taint_type))
                                        new_storage_value = each_value_match[3]
                                    else:
                                        continue
                                else:
                                    continue

                            # each_if_quoted = any(['quote' in each_key_match[5], 'quote' in each_value_match[5]])
                            # if each_if_quoted:
                            #     new_key = quote(new_key)
                            #     new_storage_value = quote(new_storage_value)
                            if taint_type == 'Message':
                                exploits.append(['Message', new_storage_value, each_value_match[-2], each_value_match[-1], each_value_match[1]])
                            elif taint_type == 'Cookie':
                                exploits.append(['Cookie', new_key+'='+new_storage_value, each_value_match[-2], each_value_match[-1], '0'])
                            elif taint_type == 'localStorage':
                                exploits.append(['Storage', {new_key:new_storage_value}, each_value_match[-2], each_value_match[-1], '1'])
                            elif taint_type == 'sessionStorage':
                                exploits.append(['Storage', {new_key:new_storage_value}, each_value_match[-2], each_value_match[-1], '-1'])
                            else:
                                raise ValueError('Unexpected taint type for two same types {}'.format(taint_type))
                            indicate_if_exploit_generated(exploit_generated_indicator, ['key2', 'value'])
                            # if exploits:
                            #     return exploits


    #else:
    for kk, generated in exploit_generated_indicator.items():
        # for each taint types that have no exploit generated
        # Generate one exploit per match, and add them to the large exploits list
        if not generated:
            match_to_find = matches[kk]
            for each_match in match_to_find:
                taint_type = each_match[0]
                if taint_type == 'Message':
                    each_msg_origin, each_tainted_value, each_msg_content, each_if_quoted = each[1], each[2], each[3], each[5]
                    new_msg = unquote_plus(unquote_plus(each_msg_content)).replace(each_tainted_value, get_replacement(kk, taint_type))
                    if unquote_plus(unquote_plus(each_msg_content)) != unquote_plus(each_msg_content):
                        new_msg = quote_plus(quote_plus(new_msg)) # double-quoted
                    elif unquote_plus(each_msg_content) != each_msg_content:
                        new_msg = quote_plus(new_msg)
                    exploits.append(['Message', new_msg, each_match[-2], each_match[-1], each_msg_origin])
                elif taint_type in ['Cookie', 'localStorage', 'sessionStorage']:
                    each_key, each_tainted_value, each_storage_value, each_if_quoted = each[1], each[2], each[3], each[5]
                    new_key = each_key.replace(each_tainted_value, get_replacement(kk, taint_type))
                    new_storage_value = each_storage_value.replace(each_tainted_value, get_replacement(kk, taint_type))
                    # if each_key != unquote_plus(each_key):
                    #     new_key = quote_plus(quote_plus(new_key)) # double-quoted
                    # elif unquote_plus(each_key) != each_key:
                    #     new_key = quote_plus(new_key)
                    # if each_storage_value != unquote_plus(each_storage_value):
                    #     new_storage_value = quote_plus(quote_plus(new_storage_value)) # double-quoted
                    # elif unquote_plus(each_storage_value) != each_storage_value:
                    #     new_storage_value = quote_plus(new_storage_value)

                    if taint_type == 'Cookie':
                        exploits.append(['Cookie', new_key+'='+new_storage_value, each_match[-2], each_match[-1], '0'])
                    elif taint_type == 'localStorage':
                        exploits.append(['Storage', {new_key:new_storage_value}, each_match[-2], each_match[-1], '1'])
                    elif taint_type == 'sessionStorage':
                        exploits.append(['Storage', {new_key:new_storage_value}, each_match[-2], each_match[-1], '-1'])
                    else:
                        continue
                else:
                    continue
            

    # each element in exploits is a list: 
    # [<taint_type>, <replaced_content>, <site>, <url>, <additional_info>]
    return exploits


if __name__ == "__main__":
    taint_source_type = "Cookie"
    taint_part = 'key2'
    taint_str_to_find = 'v_id'
    storage_log_file = "pge_com_log_file"
    matches = match_storage(taint_part, taint_source_type, taint_str_to_find, storage_log_file)

