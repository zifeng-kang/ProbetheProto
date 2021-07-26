# Copyright (C) 2019 Ben Stock & Marius Steffens
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import print_function

import json
import demjson
import datetime

from copy import deepcopy
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from match_configs import CONFIG


def manual_quote(str_in):
    """
    Custom function to perform quoting
    :param str_in: str to quote
    :return: quotes string
    """
    always_safe = set(list('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                           'abcdefghijklmnopqrstuvwxyz'
                           '0123456789' '_.-'))
    str_out = ""
    for char in str_in:
        if char not in always_safe:
            str_out += "%%%02x" % ord(char)
        else:
            str_out += char

    return str_out


def traverse_object(obj, target):
    if target in obj.keys():
        return obj, True
    is_found = False
    for kk, vv in obj.items():
        if isinstance(vv, dict):
            return_obj, is_found = traverse_object(vv, target)
            if is_found:
                return return_obj, True
    else:
        return None, False


def find_storage_match(items, tainted_value, site, url):
    """
    Fuzzily find the tainted value in the respective storage entry.
    :param items: the storage containing all the observed kvps
    :param tainted_value: the value to find
    :return: list of matched kvps annotated with context(e.g. whether or not the value was only found quoted)
    """
    # tainted_value = tainted_value.decode("ascii", "ignore")
    matches = []
    log("Looking for %s" % tainted_value)
    if is_json(tainted_value):
        tainted_value_dic = try_parse_json(tainted_value)
    else:
        tainted_value_dic = None
    for key, storage_value, storage_type in items:
        # TODO: should put localStorage at the front
        
        if not storage_value or storage_type == 0: # ignoring sessionStorage for now
            continue
        try:
            if tainted_value in storage_value:
                if storage_value.lower()[:3] in ("%7b", "%5b"):
                    matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "quoted", site, url])
                    # each_key, each_tainted_value, each_storage_value, each_if_quoted = each[1], each[2], each[3], each[5]
                else:
                    matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "plain", site, url])
                continue
        except UnicodeDecodeError:
            continue

        try:
            if tainted_value in key:
                matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "key_plain", site, url])
                continue
        except UnicodeDecodeError:
            continue
            
        try:
            if unquote_plus(tainted_value) in unquote_plus(storage_value):
                matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "quoted", site, url])
                continue
        except UnicodeDecodeError:
            continue

        try:
            if unquote_plus(tainted_value) in unquote_plus(key):
                matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "key_quoted", site, url])
                continue
        except UnicodeDecodeError:
            continue
            
        if not tainted_value_dic:
            continue
        
        try:
            if is_json(storage_value):
                storage_value_dic = try_parse_json(storage_value)
            else:
                storage_value_dic = None
            if isinstance(storage_value_dic, dict) and isinstance(tainted_value_dic, dict):
                keys_matching = set(storage_value_dic.keys()) & set(tainted_value_dic.keys())
                if len(keys_matching) and len(keys_matching) == len(tainted_value_dic.keys()):
                    if storage_value.lower()[:3] in ("%7b", "%5b"):
                        matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "dic_keys_quoted", site, url])
                    else:
                        matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "dic_keys", site, url])
                    continue
                elif len(keys_matching):
                    if storage_value.lower()[:3] in ("%7b", "%5b"):
                        matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "somewhat_dic_keys_quoted", site, url])
                    else:
                        matches.append([CONFIG.storage_number_dict[storage_type], key, tainted_value, storage_value, False, "somewhat_dic_keys", site, url])
                    continue
                else:
                    pass
        except Exception as e:
            log('Unable to find match due to Exception {}'.format(e))
    return matches


def find_message_match(items, tainted_value, site, url):
    """
    Fuzzily find the tainted value in the respective storage entry.
    :param items: the storage containing all the observed kvps
    :param tainted_value: the value to find
    :return: list of matched kvps annotated with context(e.g. whether or not the value was only found quoted)
    """
    # tainted_value = tainted_value.decode("ascii", "ignore")
    matches = []
    log("Looking for %s" % tainted_value)
    if is_json(tainted_value):
        tainted_value_dic = try_parse_json(tainted_value)
    else:
        tainted_value_dic = None
    for message_content_to_parse, message_origin, message_receiver, message_dict in items:
        # TODO: why having a message_dict here?? 
        
        if not message_content_to_parse:
            continue
        try:
            if tainted_value in message_content_to_parse:
                if message_content_to_parse.lower()[:3] in ("%7b", "%5b"):
                    matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "quoted", site, message_receiver])
                    # each_msg_origin, each_tainted_value, each_msg_content, each_if_quoted = each[1], each[2], each[3], each[5]
                else:
                    matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "plain", site, message_receiver])
                continue
        except UnicodeDecodeError:
            continue
            
        try:
            if unquote_plus(tainted_value) in unquote_plus(message_content_to_parse):
                matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "quoted", site, message_receiver])
                continue
        except UnicodeDecodeError:
            continue
            
        if not message_dict:
            continue
        
        try:
            # if is_json(storage_value):
            #     storage_value_dic = try_parse_json(storage_value)
            # else:
            #     storage_value_dic = None
            if isinstance(message_dict, dict) and isinstance(tainted_value_dic, dict):
                keys_matching = set(message_dict.keys()) & set(tainted_value_dic.keys())
                if len(keys_matching) and len(keys_matching) == len(tainted_value_dic.keys()):
                    if storage_value.lower()[:3] in ("%7b", "%5b"):
                        matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "dic_keys_quoted", site, message_receiver])
                    else:
                        matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "dic_keys", site, message_receiver])
                    continue
                elif len(keys_matching):
                    if storage_value.lower()[:3] in ("%7b", "%5b"):
                        matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "somewhat_dic_keys_quoted", site, message_receiver])
                    else:
                        matches.append(['Message', message_origin, tainted_value, message_content_to_parse, False, "somewhat_dic_keys", site, message_receiver])
                    continue
                else:
                    pass
        except Exception as e:
            log('Unable to find match due to Exception {}'.format(e))
    return matches


def recursive_replace(data_in, replace_value, replace_with):
    """
    Replace the specified value recursively in the provided object by the payload.
    :param data_in: the object which should be replaced
    :param replace_value: the value which should be replaced
    :param replace_with: the value it should be replaced with
    :return: the object in which the value is replaced
    """
    if isinstance(data_in, int):
        return recursive_replace(str(data_in), replace_value, replace_with)
    if isinstance(data_in, dict):
        data_out = dict()
        for key, value in data_in.items():
            if isinstance(key, int):
                key = str(key)
            if isinstance(value, str) or isinstance(value, unicode):
                data_out[key.replace(replace_value, replace_with)] = value.replace(replace_value, replace_with)
            elif isinstance(value, dict):
                data_out[key.replace(replace_value, replace_with)] = recursive_replace(value, replace_value,
                                                                                       replace_with)
            elif isinstance(value, list):
                data_out[key.replace(replace_value, replace_with)] = recursive_replace(value, replace_value,
                                                                                       replace_with)
            elif isinstance(value, int):
                data_out[key.replace(replace_value, replace_with)] = recursive_replace(value, replace_value,
                                                                                       replace_with)
            else:
                data_out[key.replace(replace_value, replace_with)] = value

    elif isinstance(data_in, list):
        data_out = []
        for element in data_in:
            if isinstance(element, str) or isinstance(element, unicode):
                element = element.replace(replace_value, replace_with)
                data_out.append(element)
            else:
                data_out.append(recursive_replace(element, replace_value, replace_with))
    elif isinstance(data_in, str):
        return data_in.replace(replace_value, replace_with)
    elif data_in is None:
        return data_in
    else:
        raise Exception("No such thing %s" % (type(data_in)))
    return data_out


def is_json(value):
    """
    Heuristic to check whether a given string is in JSON format to prevent costly parse attempts.
    :param value: the value to check
    :return: bool indicating judgement
    """
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return True
    if value.startswith("[") and value.endswith("]"):
        return True
    value = unquote_plus(value)
    if value.startswith("{") and value.endswith("}"):
        return True
    if value.startswith("[") and value.endswith("]"):
        return True
    return False


def try_parse_json(storage_value):
    """
    Try to parse the provided value as JSON/JS objects.
    :param storage_value: the value to parse
    :return: the parsed value or None if not parseable
    """
    try:
        loaded = json.loads(storage_value)
        if type(loaded) in (dict, list):
            return loaded
    except ValueError:
        try:
            loaded = json.loads(unquote_plus(storage_value))
            if type(loaded) in (dict, list):
                return loaded
        except ValueError:
            pass
    try:
        loaded = demjson.decode(storage_value)
        if type(loaded) in (dict, list):
            return loaded
    except Exception as e:
        try:
            loaded = demjson.decode(unquote_plus(storage_value))
            if type(loaded) in (dict, list):
                return loaded
        except Exception as e:
            pass

    return None


def log(st):
    """
    Log functionality. Controllable via the config option --debug.
    :param st: string to log
    :return: None
    """
    if CONFIG.debug:
        ts = datetime.datetime.now()
        print(str(ts), ":", st)
