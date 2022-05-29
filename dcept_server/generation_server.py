import os
import sqlite3
from datetime import datetime
import logging
import random


class GenerationServer:
    def __init__(self, config):
        self.config = config
        self.sqlite_path = config.sqlite_path
        self.init_database()
        logging.info(f'Database contains {self.get_record_count()} generated passwords')
        # self.con = None

    def get_record_count(self):
        cur = self.con.cursor()
        cur.execute('SELECT count(password) FROM dcept')
        return cur.fetchone()

    # Initialize the sqlite database. Create the db and tables if it doesn't exist.
    def init_database(self):
        if not os.path.exists(self.sqlite_path):
            self.con = sqlite3.connect(self.sqlite_path, check_same_thread=False)
            cur = self.con.cursor()
            cur.execute('CREATE TABLE dcept (date text, domain text, username text, machine text, password text)')
            # Add a test honeytoken to the database
            cur.execute('INSERT INTO dcept VALUES (?,?,?,?,?)',
                        (datetime.now(), self.config.domain, self.config.honey_username, 'TEST-PC', 'testpassword'))
            self.con.commit()
        else:
            self.con = sqlite3.connect(self.sqlite_path, check_same_thread=False)

    def gen_pass(self, machine):

        password = self.find_machine(machine)
        if password: # the machine actually exists in db
            logging.info(f"Password for {machine} already exists: {password[0]}")
            return password[0]

        alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        while True:
            # Create a random password using the above alphabet
            password = ''.join(random.choice(alpha) for i in range(10))
            logging.info(f"Generated - {password}")
            # Does this password already exist?
            if self.find_pass(password) is None:
                break
            else:
                logging.info('Password collision, regenerating...')

        self.insert_record(machine, password)
        return password

    def find_machine(self, machine):
        cur = self.con.cursor()
        cur.execute('SELECT password FROM dcept WHERE machine=? ORDER BY date DESC', (machine,))
        return cur.fetchone()  # si es None es que no existe

    def find_pass(self, password):
        cur = self.con.cursor()
        cur.execute('SELECT * FROM dcept WHERE password=?', (password,))
        return cur.fetchone()  # si es None es que no existe

    def insert_record(self, machine, password):
        cur = self.con.cursor()
        cur.execute('INSERT INTO dcept VALUES (?,?,?,?,?)',
                    (datetime.now(), self.config.domain, self.config.honey_username, machine, password))
        self.con.commit()
        logging.info(f'Inserted into dcept DB: m:{machine} p:{password}')

    def add_machine(self, machine):  # metodo que genera una nueva contraseña y la añade a la DB
        password = self.gen_pass()
        self.insert_record(machine, password)
        return password

    def get_all_passwords(self):
        cur = self.con.cursor()
        cur.execute('SELECT password FROM dcept ORDER BY date DESC')
        passwords = [row[0] for row in cur.fetchall()]
        return passwords
