#!/usr/bin/env python3
# -*- coding: utf8 -*-

import unittest
from undeleter import *
from unittest.mock import patch, mock_open
import pathlib
import string
import random

RECYCLE_MODE = 0o333
TEST_PATH = "/tmp/undeleter_tests"

if 'unittest.util' in __import__('sys').modules:
    # Show full diff in self.assertEqual.
    __import__('sys').modules['unittest.util']._MAX_LENGTH = 999999999


class RmTestCase(unittest.TestCase):

    #print("temp dir", temp_dir)
    random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
    #print("random", random_name)
    test_dir = pathlib.Path(TEST_PATH)
    test_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = pathlib.Path(pathlib.PurePath(test_dir, random_name))
    temp_dir.mkdir(parents=True, exist_ok=True)
    samba_dir = pathlib.Path(f'{temp_dir}/samba/')
    samba_dir.mkdir(parents=True, exist_ok=True)


    def setUp(self):
        self.maxDiff = None
        self.file_share = pathlib.Path(f"{self.temp_dir}")
        self.audit_log_contents = r'''2025-04-28T19:30:44.799995+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/Новая папка|/srv/public/dir
2025-04-28T19:30:49.417506+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/dir/Лист Microsoft Excel.xlsx|/srv/public/dir/2.xlsx
2025-04-28T19:30:58.102980+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/dir/2.xlsx|/srv/public/.recycle/2/2.xlsx
2025-04-28T19:30:58.117605+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/dir
2025-11-12T19:58:30.332536+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/489
2025-11-12T20:00:03.443620+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/489/Лист Microsoft Excel.xlsx|/srv/public/.recycle/489/Лист Microsoft Excel.xlsx
2025-11-12T20:00:03.446986+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/489
2025-11-26T18:30:47.414635+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/880/880.xlsx|/srv/public/.recycle/880/880.xlsx
2025-11-26T18:30:48.223051+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/880
2025-11-26T18:31:36.383462+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/Новая папка|/srv/public/245
2025-11-26T18:31:48.498429+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/245/Лист Microsoft Excel.xlsx|/srv/public/.recycle/245/Лист Microsoft Excel.xlsx
2025-11-26T18:31:48.502830+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/245
2025-11-26T18:40:44.996232+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/333/Лист Microsoft Excel.xlsx|/srv/public/.recycle/333/Лист Microsoft Excel.xlsx
2025-11-26T18:40:44.999242+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/333
2025-11-26T18:46:32.405638+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/333/Лист Microsoft Excel.xlsx|/srv/public/.recycle/333/Лист Microsoft Excel.xlsx
2025-11-26T18:46:32.409712+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/333
2025-11-26T18:50:22.783517+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/forbidden1/new2/Лист Microsoft Excel.xlsx|/srv/public/.recycle/forbidden1/new2/Лист Microsoft Excel.xlsx
2025-11-26T18:50:22.788829+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/forbidden1/new2
2025-11-26T18:59:31.514764+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/Новая папка|/srv/public/forbidden2
2025-11-26T18:59:37.974039+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/forbidden2/Новая папка|/srv/public/forbidden2/erw
2025-11-26T18:59:43.981047+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/forbidden2/Лист Microsoft Excel.xlsx|/srv/public/.recycle/forbidden2/Лист Microsoft Excel.xlsx
2025-11-26T18:59:43.984600+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/forbidden2/erw
2025-11-26T18:59:43.988065+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/forbidden2
2025-12-03T16:14:03.361895+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/Новая папка|/srv/public/257
2025-12-03T16:14:10.523120+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/257/Лист Microsoft Excel.xlsx|/srv/public/.recycle/257/Лист Microsoft Excel.xlsx
2025-12-03T16:14:10.528988+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|unlinkat|ok|/srv/public/257
2025-12-03T16:34:04.786198+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.129|192.168.76.129|/srv/public|renameat|ok|/srv/public/333|/srv/public/489/333
2025-12-03T16:35:37.938944+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.129|192.168.76.129|/srv/public|renameat|ok|/srv/public/899/Новая папка|/srv/public/257/Новая папка
2025-12-03T16:35:52.196805+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.129|192.168.76.129|/srv/public|renameat|ok|/srv/public/257/Новая папка (2)|/srv/public/257/sub
2025-12-03T16:35:58.031300+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.129|192.168.76.129|/srv/public|renameat|ok|/srv/public/257/Новая папка|/srv/public/257/sub/Новая папка
'''
# 2025-11-26T18:40:38.021501+03:00 ud smbd_audit: UNDELETER\user1|192.168.76.1|192.168.76.1|/srv/public|renameat|ok|/srv/public/Новая папка|/srv/public/333 


        self.audit_log = f'{self.file_share}/samba/audit.log'
        self.recovered_path = f"{self.file_share}/samba/undeleter_recovered.log"
        self.recycle = pathlib.Path(f"{self.file_share}/{RECYCLE_DIR}")
        self.file_share.mkdir(parents=True, exist_ok=True)
        self.recycle.mkdir(parents=True, exist_ok=True)
        self.recycle.chmod(RECYCLE_MODE)  # mimic actual recycle dir
        
        with open(self.audit_log, "w", encoding ="utf-8") as f:
            f.write(self.audit_log_contents)


    def test_save_and_recall(self):
        self.assertTrue(save_recovered(self.recovered_path, "2025-11-12T20:00:03.446986+03:00"))
        self.assertTrue(save_recovered(self.recovered_path, "2025-13-32T25:58:30.332536+03:00"))  # not ISO format
        self.assertTrue(save_recovered(self.recovered_path, "XXXX-XX-XXXXX:XX:XX.XXXXXXXXX:XX"))
        self.assertTrue(save_recovered(self.recovered_path, "2025-11-12T19:58:30.332536+03:00"))
        self.assertTrue(save_recovered(self.recovered_path, "2025-11-26T18:46:32.409712+03:00"))
        self.assertTrue(save_recovered(self.recovered_path, "JUNK_AuJScCvJv2roqsNZCF2rMehqiMw"))
        self.assertTrue(save_recovered(self.recovered_path, "JUNK_AuJScCv"))

        expected_contents = ["2025-11-12T20:00:03.446986+03:00", "2025-11-12T19:58:30.332536+03:00", "2025-11-26T18:46:32.409712+03:00"]
        self.assertEqual(recall_recovered(self.recovered_path), expected_contents)  # will read only ISO date format
        

    def test_read_log(self):
        result_mixed = [
{'time': '2025-11-26T18:40:44.999242+03:00', 'domain': 'UNDELETER', 'user': 'user1', 'client': '192.168.76.1',  'ip': '192.168.76.1',   'share': '/srv/public', 'operation': 'unlinkat', 'status': 'ok', 'sourcename': '/srv/public/333', 'is_forbidden': False, 'is_recovered': False}, 
{'time': '2025-11-26T18:46:32.409712+03:00', 'domain': 'UNDELETER', 'user': 'user1', 'client': '192.168.76.1',  'ip': '192.168.76.1',   'share': '/srv/public', 'operation': 'unlinkat', 'status': 'ok', 'sourcename': '/srv/public/333', 'is_forbidden': False, 'is_recovered': True},
{'time': '2025-12-03T16:34:04.786198+03:00', 'domain': 'UNDELETER', 'user': 'user1', 'client': '192.168.76.129','ip': '192.168.76.129', 'share': '/srv/public', 'operation': 'renameat', 'status': 'ok', 'sourcename': '/srv/public/333', 'targetname': '/srv/public/489/333', 'is_forbidden': False, 'is_recovered': False}
        ]
        recovery_contents = "2025-11-26T18:46:32.409712+03:00\n"
        recovery_path_readlog = f'{self.samba_dir}recovery_path_read.log' 
        with open(recovery_path_readlog, "w", encoding ="utf-8") as f:
            f.write(recovery_contents)
        self.assertEqual(read_log("333", self.audit_log, recovery_path_readlog), result_mixed)
        #self.assertEqual(read_log("forbidden1", self.audit_log), "")
        
        result_deleted = [
{'client': '192.168.76.1', 'domain': "UNDELETER",'ip': "192.168.76.1", 'is_forbidden': False, 'is_recovered': False, 'operation': 'unlinkat', 'share': '/srv/public', 'sourcename': '/srv/public/dir', 'status': 'ok', 'time': '2025-04-28T19:30:58.117605+03:00', 'user': 'user1'}
        ]
        self.assertEqual(read_log("dir", self.audit_log, self.recovered_path), result_deleted)       


    def test_is_forbidden_path(self):
        self.assertTrue(is_forbidden_path("/srv/public/forbidden1"))
        self.assertTrue(is_forbidden_path("/srv/public/forbidden2"))
        
        self.assertTrue(is_forbidden_path("/srv/public/forbidden1/"))
        self.assertTrue(is_forbidden_path("/srv/public/forbidden2/"))
        
        self.assertTrue(is_forbidden_path("/srv/public/forbidden1/sub_dir1"))
        self.assertTrue(is_forbidden_path("/srv/public/forbidden2/sub_dir2"))
        
        self.assertFalse(is_forbidden_path("/srv/public/dir1"))
        self.assertFalse(is_forbidden_path("/srv/public/dir2"))


    def test_rename(self):
        renamed_dir = pathlib.Path(f"{self.file_share}/moved_to/ren_dir")
        renamed_dir.mkdir(parents=True, exist_ok=True)
        renamed_subdir = pathlib.Path(f"{self.file_share}/moved_to2/ren_dir2")
        renamed_subdir.mkdir(parents=True, exist_ok=True)
        renamed_sub_subdir = pathlib.Path(f"{self.file_share}/moved_to3/subdir3/ren_dir3")
        renamed_sub_subdir.mkdir(parents=True, exist_ok=True)

        # Test (failed) renaming of non-existant dir
        self.assertEqual(rename(f"{self.file_share}/nonexistant", f"{self.file_share}/moved_to/nonexistant"), {'info': f"'{self.file_share}/moved_to/nonexistant' does not exist", 'rec_status': 'Not renamed'})
        # Test renaming after moving from share's root directory
        self.assertEqual(rename(f"{self.file_share}/ren_dir", str(renamed_dir)), {'found_path': f'{self.file_share}/moved_to/ren_dir', 'info': 'Renamed', 'rec_status': 'Renamed'})
        # Test renaming after moving to a nested directory
        self.assertEqual(rename(f"{self.file_share}/subdir/ren_dir2", str(renamed_subdir)), {'found_path': f'{self.file_share}/moved_to2/ren_dir2', 'info': 'Renamed', 'rec_status': 'Renamed'})
        # Test renaming after moving nested directory to a nested directory
        self.assertEqual(rename(f"{self.file_share}/subdir3/ren_dir3", str(renamed_sub_subdir)), {'found_path': f'{self.file_share}/moved_to3/subdir3/ren_dir3', 'info': 'Renamed', 'rec_status': 'Renamed'})
        # Test renaiming ... to already present dir (autogenerated suffix)
        # TODO
        # Test actual renaming in place without moving
        # TODO


    def test_recover(self):
        deleted_path = pathlib.Path(f"{self.file_share}/deleted")  # before deletion
        deleted_dir_recycle = pathlib.Path(f"{self.recycle}/deleted")  # after deletion
        deleted_path_subdir = pathlib.Path(f"{self.file_share}/deleted2/subdir")
        deleted_subdir_recycle = pathlib.Path(f"{self.recycle}/deleted2/subdir")
        deleted_dir_recycle.mkdir(parents=True, exist_ok=True)
        deleted_subdir_recycle.mkdir(parents=True, exist_ok=True)
        deleted_dir_recycle.chmod(RECYCLE_MODE)
        deleted_subdir_recycle.chmod(RECYCLE_MODE)

        # Test recovery of deletion from share's root directory
        self.assertEqual(recover(str(deleted_path), self.file_share),        {'found_path': f'{deleted_dir_recycle}',         'info': 'Recovered', 'rec_status': 'Recovered'})
        assert not deleted_dir_recycle.exists()
        # Test recovery of deletion from nested directory
        self.assertEqual(recover(str(deleted_path_subdir), self.file_share), {'found_path': f'{deleted_subdir_recycle}', 'info': 'Recovered', 'rec_status': 'Recovered'})
        assert not deleted_subdir_recycle.exists()
        # Test (failed) recovery because the dir does not exist
        self.assertEqual(recover(f"{self.file_share}/not_in_recycle", self.file_share), {'info': f"'{self.recycle}/not_in_recycle' does not exist", 'rec_status': 'Not recovered'})
        # Test recovery ... to already present dir (autogenerated suffix)
        # TODO


    # def test_get_user_groups_by_name(self):
        # '''works on my machine ¯\_(ツ)_/¯'''
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\user1'), ['users', 'user1', 'teachers', 'users'])
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\user2'), ['users', 'user2', 'users'])
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\Administrator'), ['root', 'users','enterprise admins', 'domain admins', 'schema admins', 'group policy creator owners', 'denied rodc password replication group', 'users', 'administrators'])
        # self.assertNotEqual(get_user_groups_by_name('UNDELETER\\user2'), [])
        # self.assertNotEqual(get_user_groups_by_name('UNDELETER\\user1'), [])
        # self.assertNotEqual(get_user_groups_by_name('UNDELETER\\Administrator'), [])
        
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\пользователь1'), ['users', 'пользователь1', 'teachers', 'users'])
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\пользователь2'), ['users', 'пользователь2', 'users'])

        # self.assertEqual(get_user_groups_by_name('user1'), ['users', 'user1', 'teachers', 'users'])
        # self.assertEqual(get_user_groups_by_name('user2'), ['users', 'user2', 'users'])
        # self.assertEqual(get_user_groups_by_name('Administrator'), ['root', 'users','enterprise admins', 'domain admins', 'schema admins', 'group policy creator owners', 'denied rodc password replication group', 'users', 'administrators'])
        # self.assertNotEqual(get_user_groups_by_name('user2'), [])
        # self.assertNotEqual(get_user_groups_by_name('user1'), [])
        # self.assertNotEqual(get_user_groups_by_name('Administrator'), [])
        
        # self.assertEqual(get_user_groups_by_name('пользователь1'), ['users', 'пользователь1', 'teachers', 'users'])
        # self.assertEqual(get_user_groups_by_name('пользователь2'), ['users', 'пользователь2', 'users'])
        
        # self.assertEqual(get_user_groups_by_name('NOTEXIST'), [])
        # self.assertEqual(get_user_groups_by_name('UNDELETER\\NOTEXIST'), [])
        
        
    # def test_get_sid_by_name(self):
        # self.assertEqual(get_sid_by_name('UNDELETER\\user1'), "S-1-5-21-933126593-2266183401-1585322145-1104")
        # self.assertEqual(get_sid_by_name('UNDELETER\\user2'), "S-1-5-21-933126593-2266183401-1585322145-1106")
        # self.assertEqual(get_sid_by_name('UNDELETER\\пользователь1'), "S-1-5-21-933126593-2266183401-1585322145-1107")
        # self.assertEqual(get_sid_by_name('UNDELETER\\Administrator'), "S-1-5-21-933126593-2266183401-1585322145-500")
        
        # self.assertEqual(get_sid_by_name('user1'), "S-1-5-21-933126593-2266183401-1585322145-1104")
        # self.assertEqual(get_sid_by_name('user2'), "S-1-5-21-933126593-2266183401-1585322145-1106")
        # self.assertEqual(get_sid_by_name('пользователь1'), "S-1-5-21-933126593-2266183401-1585322145-1107")
        # self.assertEqual(get_sid_by_name('Administrator'), "S-1-5-21-933126593-2266183401-1585322145-500")
        
        # self.assertIsNone(get_sid_by_name('NOTEXIST'))
        # self.assertIsNone(get_sid_by_name('UNDELETER\\NOTEXIST'))
        

    # def test_get_name_by_uid(self):
        # self.assertEqual(get_name_by_uid('3000019'), "UNDELETER\\user1")
        # self.assertEqual(get_name_by_uid('0'), "UNDELETER\\Administrator")
        # self.assertEqual(get_name_by_uid('3000023'), "UNDELETER\\пользователь1")   
        # self.assertIsNone(get_name_by_uid('8888888')) # Non existant user 
    
    
    # def test_is_valid_user(self):
        # self.assertTrue(is_valid_user('UNDELETER\\user1', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('UNDELETER\\user2', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('UNDELETER\\Administrator', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('UNDELETER\\NOTEXIST', RECOVER_GROUPS))
        
        # self.assertTrue(is_valid_user('user1', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('user2', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('Administrator', RECOVER_GROUPS))
        # self.assertFalse(is_valid_user('NOTEXIST', RECOVER_GROUPS))


if __name__ == '__main__':
    unittest.main(exit=False)
    def rm_tree(path):
        path = pathlib.Path(path)
        for child in path.glob('*'):
            if child.is_file():
                child.unlink()
            else:
                rm_tree(child)
        path.rmdir()
    
    #rm_tree(str(TEST_PATH))

