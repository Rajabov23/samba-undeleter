#!/usr/bin/env python3
# -*- coding: utf8 -*-
### undeleter program for file management ###


# Copyright (C) 2025 Rajabov
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.

import re
import sys
import json
import pathlib
import copy
import shutil
import subprocess
import argparse
import random
import string
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import unquote


HOST = '0.0.0.0'
PORT = 999
AUDIT_LOG = "/var/log/samba/audit.log"
RECOVERY_LOG = "/var/log/samba/undeleter_recovered.log"
#RECOVER_GROUPS = ["teachers"]
SHARE_DIR = "/storage/public"
RECYCLE_DIR = ".recycle"
LANGUAGE = "English" #fallback language
RENAMEAT = "renameat"
UNLINKAT = "unlinkat"
FORBIDDEN_DIRS = ["/srv/public/forbidden1", "/srv/public/forbidden2"]


def read_log(query, file_name):
    '''Read Samba vfs audit log to search for deleted/moved files/folders'''
    max_index = 7 # 7 is targetname
    parced_lines = []
    already_recovered = recall_recovered(RECOVERY_LOG)
    with open(file_name, "r", encoding="utf-8") as file:
        for line in file:
            try:
                single_line = {}
                parts = line.split("|")
                prefix = parts.pop(0)
                domain_and_user = re.sub(".+smbd_audit: (.+)", r"\1", prefix).partition("\\")
                time = prefix.split(" ")[0]
                #time = datetime.fromisoformat(time)
                single_line["time"] = time
                #print(single_line.get("time"))
                single_line["domain"] = domain_and_user[0]
                single_line["user"] = domain_and_user[2]
                single_line["client"] = parts[0]
                single_line["ip"] = parts[1]
                single_line["share"] = parts[2]
                single_line["operation"] = parts[3]
                single_line["status"] = parts[4]
                single_line["sourcename"] = parts[5].strip()
                if len(parts) >= max_index+1:
                    print("MALFORMED LINE:", line)
                elif len(parts) == max_index:
                    single_line["targetname"] = parts[max_index-1].strip()
                is_forbidden = is_forbidden_path(single_line.get("sourcename"))
                single_line["is_forbidden"] = is_forbidden
                if single_line.get("time") in already_recovered:
                    single_line["is_recovered"] = True
                    print("TIME IN ALREADY RECOVERED")
                else:
                    single_line["is_recovered"] = False
                    
                parced_lines.append(single_line)
            except IndexError:
                continue

    found_lines = []
    look_for = "/" + query
    for i in parced_lines:
        if i["sourcename"].strip().endswith(look_for):
            found_lines.append(i)

    return found_lines


def find_by_timestamp(query, file_name):
    '''Read Samba vfs audit log to search line by provided timestamp'''
    max_index = 7 # 7 is targetname
    recovery_line = {}
    already_recovered = recall_recovered(RECOVERY_LOG)
    with open(file_name, "r", encoding="utf-8") as file:
        for line in file:
            try:
                single_line = {}
                parts = line.split("|")
                prefix = parts.pop(0)
                domain_and_user = re.sub(".+smbd_audit: (.+)", r"\1", prefix).partition("\\")
                time = prefix.split(" ")[0]
                #time = datetime.fromisoformat(time)
                single_line["time"] = time
                single_line["domain"] = domain_and_user[0]
                single_line["user"] = domain_and_user[2]
                single_line["client"] = parts[0]
                single_line["ip"] = parts[1]
                single_line["share"] = parts[2]
                single_line["operation"] = parts[3]
                single_line["status"] = parts[4]
                single_line["sourcename"] = parts[5].strip()
                if len(parts) >= max_index+1:
                    print("MALFORMED LINE:", line)
                elif len(parts) == max_index:
                    single_line["targetname"] = parts[max_index-1].strip()
                is_forbidden = is_forbidden_path(single_line.get("sourcename"))
                single_line["is_forbidden"] = is_forbidden
                if single_line.get("time") in already_recovered:
                    single_line["is_recovered"] = True
                else:
                    single_line["is_recovered"] = False

                if time == query:
                    recovery_line = single_line
                    break # found
            except IndexError:
                continue

    return recovery_line


def recover(original_path_str, share_dir_):  # TODO: supply config
    '''Try to recover(move) file from recycle directory'''
    message = {"rec_status": _("Not recovered"), "info": _("Unknown reason")}
    original_path = pathlib.Path(original_path_str)
    recycle_path = pathlib.Path(share_dir_, RECYCLE_DIR)
    relative_path = original_path_str.removeprefix(str(share_dir_)).removeprefix('/')
    real_path = pathlib.Path(recycle_path, relative_path)

    if real_path.exists():
        is_success = move(original_path, real_path)
        if is_success:
            message = {"rec_status": _("Recovered"),
                       "info": _("Recovered"),
                       "found_path": str(real_path)}
    else:
            message = {"rec_status": _("Not recovered"), "info": f"'{str(real_path)}' {_('does not exist')}"}

#    print('recycle_path     ', recycle_path)
#    print('relative_path    ', relative_path)
#    print('moving from', real_path)
#    print('moving to  ', original_path_str)
    return message


def rename(original_path_str, found_path_str):
    '''Try to rename(move) accidentally missplaced file from another directory'''
    message = {"rec_status": _("Not renamed"), "info": _("Unknown reason")}
    original_path = pathlib.Path(original_path_str)
    found_path = pathlib.Path(found_path_str)

    if not found_path.exists():
        message = {"rec_status": _("Not renamed"),
                   "info": f"'{found_path_str}' {_('does not exist')}"}
    else:
        is_success = move(original_path, found_path)
        if is_success:
            message = {"rec_status": _("Renamed"),
                       "info": _("Renamed"),
                       "found_path": str(found_path),}

    return message


def move(original_path, found_path):
    '''Agnostic file/dir mover''' 
    is_success = False

#    print('moving from', found_path)
#    print('moving to  ', original_path)
    recycle_absolute = pathlib.Path(SHARE_DIR, RECYCLE_DIR)
    #print("RECYCLE ABSOLUTE", recycle_absolute)

    is_deleted = False
    if str(found_path).startswith(str(recycle_absolute)):        
        is_deleted = True

    if found_path.exists():
        if original_path.parent:
            original_path.parent.mkdir(parents=True, exist_ok=True) #create nested directory tree 
        if not original_path.exists():
            found_path.rename(original_path)
            if is_deleted:
                Copy_perms(original_path)
            is_success = True
        else:
            random_tail = ''.join(random.choice(string.ascii_letters) for i in range(8))
            new_original_path = pathlib.Path(str(original_path) + "." + random_tail)
            found_path.rename(new_original_path)
            if is_deleted:
                Copy_perms(new_original_path)
            is_success = True
    else:
        print(f'{found_path} does not exists')

    return is_success


def Copy_perms(recovered_path):
    '''Read permissions from share root(SHARE_DIR) and apply to recovered directory'''
    reference_path = pathlib.Path(SHARE_DIR)
    shutil.copystat(reference_path, recovered_path)

    for path in recovered_path.rglob("*"):
        try:
            shutil.copystat(reference_path, path)
        except FileNotFoundError:
            print("Error: The source or destination directory does not exist.")
        except Exception as e:
            print(f"An error occurred: {e}")


def save_recovered(file_path, timestamp):
    '''Write recovered entries to a file'''
    try:
        path = pathlib.Path(file_path)
        print(f'Opening {path}')
        with path.open("a", newline="\n", encoding="UTF-8") as f:
            f.write(timestamp + "\n") #instead of string, for in keys and items, confirm string, key = value f'{key}={value}'
            
            result = True

    except PermissionError:
        result = False
        
    return result
    

def recall_recovered(file_path):
    '''Read previously recovered entries from a file'''
    path = pathlib.Path(file_path)
    result = []
    if path.is_file():
        try:
            with open(file_path, "r", encoding="UTF-8") as file_object:
                for line in file_object:
                    try:
                        dt_object = datetime.fromisoformat(line.strip())
                    except ValueError as e:
                        dt_object = None
                        #print("Not ISO format:", e)
                    if dt_object:
                        result.append(line.strip())
                    
        except SyntaxError as e:
            print(e)
        except PermissionError:
            print("PermissionError: Unable to open", file_path)
        except ValueError as e:
            print("UNABLE TO LOAD FILE (Recall):", e)
    else:
        print(f'{type(path)} is not a file')
        
    #print("ALREADY RECOVERED LIST", result)
    return result


def get_user_groups_by_name(user):
    """find user groups as list by full user name"""
    regex = r"^.+\\"
    out = subprocess.run(["id", user], capture_output=True)
    unparced_id = out.stdout.decode('utf-8')
    groups_regex = re.search(r" groups=(.+[)])(:?\s|$)", unparced_id)
    groups = []
    if groups_regex:
        groups_id = groups_regex.group(1).split(",")
        for j in groups_id:
            g = re.search(r".+\((.+)\)", j)
            if g:
                group = g.group(1).strip()
                group = re.sub(regex, "", group)
                groups.append(group)           
    return groups


def _(s):
    """Translate incoming string"""
#    print("_ LANGUAGE", LANGUAGE)
    russian_strings = {'Got connection from': 'Получено сообщение от',
                      'Server is listening on': 'Сервер слушает на',
                      'Not recovered': 'Не восстановлено',
                      'Recovered': 'Восстановлено',
                      'Not renamed': 'Не переименовано',
                      'Renamed': 'Переименовано',
                      'does not exist': 'не существует',
                      'Unknown reason': 'Неизвестная причина',
                     }
    deutsch_strings = {'Got connection from': 'Verbindung hergestellt von',
                      'Server is listening on': 'der Server hört auf',
                      'Not recovered': 'Nicht wiederhergestellt',
                      'Recovered': 'Wiederhergestellt',
                      'Not renamed': 'Nicht umbenannt',
                      'Renamed': 'Umbenannt',
                      'does not exist': '...',  # TODO
                      'Unknown reason': '...',  # TODO
                     }

    try:
        if LANGUAGE == 'English' or not LANGUAGE:
            return s
        if LANGUAGE == 'Deutsch':
            return deutsch_strings[s]
        if LANGUAGE == 'Russian':
            return russian_strings[s]
    except KeyError:
        print('NO TRANSLATION:', s)
        return f"NT: {s}"


class HttpGetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        '''Request for search'''
        decoded_url = unquote(self.path)
        print(decoded_url)
        client_message = decoded_url.removeprefix('/search/')
        found_lines = read_log(client_message, AUDIT_LOG)  
        print("FOUND LINES", found_lines)
        print('GET MSG:', client_message)
        #print(self.client_address)
        #print(self.path)

        answer = {"found_lines": found_lines,  
                    }
        json_data = json.dumps(answer)
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json_data, 'utf8'))
        # else:
            # self.send_response(204)
            # self.end_headers()

    def do_POST(self):
        '''Request for recovery'''
        global LANGUAGE
        content_length = int(self.headers['Content-Length'])
        
        post_data = json.loads(self.rfile.read(content_length).decode())
        try:
            LANGUAGE = post_data["language"]
        except KeyError:
            LANGUAGE = "English"
            
        print('POST DATA:', post_data)
        recover_line = find_by_timestamp(post_data.get('time'), AUDIT_LOG)
        if not recover_line.get("is_forbidden"):
            recovery_result = do_recovery(recover_line)
        else:
            recovery_result = {"rec_status": _("This path can not be recovered. Check back with your administrator"),
                     "info": _("This path can not be recovered. Check back with your administrator"),}
        
        print('RECOVER_LINE:', recover_line)
        print('recovery_result', recovery_result)
        try:
            json_data = json.dumps(recovery_result)
        except Exception:
            print('UNABLE TO LOAD JSON (POST)')
            json_data = {}
            
        print("JSON DATA", json_data)
        if recovery_result.get("rec_status"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json_data, "utf8"))
        else:
            self.send_response(204)
            self.end_headers()


def is_forbidden_path(path):
    path = pathlib.Path(path)
    for i in FORBIDDEN_DIRS:
        forbidden_dir = pathlib.Path(i)
        if forbidden_dir in path.parents or forbidden_dir == path:
            return True
    
    return False    


def do_recovery(line):
    '''Move deleted or renamed files and folders to original destinations'''
    if line.get("operation") == RENAMEAT and not line.get("targetname"):
        print("NO TARGETNAME:", line)
    if line.get("operation") == RENAMEAT and line.get("status") == "ok":
        if not line.get("targetname"):
            rec_status = {"rec_status": _("targetname is not provided BY THE CLIENT"),
                     "info": _("targetname is not provided BY THE CLIENT"),} #TODO move to child function
        else:
            rec_status = rename(line.get("sourcename"), line.get("targetname"))

    elif line.get("operation") == UNLINKAT and line.get("status") == "ok":
        rec_status = recover(line.get("sourcename"), SHARE_DIR)
    else:
        print("NO DICTIONARY MATCH")

    save_recovered(RECOVERY_LOG, line["time"])

    return rec_status


def handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--unsecure', action='store_true',
                        default=False,
                        help='Skip MAC confinement check. Strongly discouraged')

    return parser.parse_args()


def fail_if_not_confined(profile_basename):
    '''Attempt to create unpredictably named file to determine if process is confined by any MAC.
       Only covers confinement, not necessarily enforcement'''
    random_tail = ''.join(random.choice(string.ascii_letters) for i in range(8))
    path = f'/dev/shm/{profile_basename}.am_i_confined.{random_tail}'

    try:
        with open(path, 'w', encoding="UTF-8") as f:
            f.write("DELETEME\n")
    except Exception:  # expected behavior
        pass

    f = pathlib.Path(path)
    if f.is_file():
        f.unlink()
        raise EnvironmentError(f'''The process is not confined by AppArmor. Refusing to function. Expected action:\n
$ sudo install -m 600 -o root -g root apparmor.d/{profile_basename} /etc/apparmor.d/
$ sudo apparmor_parser --add /etc/apparmor.d/{profile_basename}''')

    return None
                

def Listen(server_class=HTTPServer, handler_class=HttpGetHandler):
    '''Start listening as HTTP server'''
    server_address = ('', PORT)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == '__main__':

    args = handle_args()
    if not args.unsecure:
        fail_if_not_confined(pathlib.Path(sys.argv[0]).stem)
    
    if not pathlib.Path(SHARE_DIR).exists():
        raise EnvironmentError("No such share:", SHARE_DIR)
    
    Listen()
    
