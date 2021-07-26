import os, tqdm
from storage_match_utils import find_storage_match,find_message_match
from match_configs import CONFIG

def get_replacement(which_part, taint_type, key1_content='', mode='check'):
    key1_content_ignore_list = ['__proto__', 'prototype']
    replacement = {
        "key1": key1_content if key1_content in key1_content_ignore_list else CONFIG.key1[mode][0], 
        "key2": taint_type + '_' + CONFIG.key2[mode][0], 
        "value": taint_type + '_' + CONFIG.value[mode][0]
    }
    return replacement[which_part]

def read_and_match(which_part, taint_value, taint_type, site_log_items, site, url):
    if taint_type == "Message":
        matches = find_message_match(site_log_items, taint_value, site, url)
        # generate JS extension according to the matches
    elif taint_type == "Cookie" or taint_type == "Storage": 
        matches = find_storage_match(site_log_items, taint_value, site, url)

    if not matches:
        # not found; should match fuzzily
        if taint_type == "Storage": 
            matches = [['localStorage', '', taint_value, '', True, "plain", site, url], \
                ['sessionStorage', '', taint_value, '', True, "plain", site, url]]
        else:
            matches = [[taint_type, '', taint_value, '', True, "plain", site, url]]
    return matches