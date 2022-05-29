from queue import Queue
import logging
import tempfile
import subprocess
import alert


class Cracker:
    def __init__(self, config, gen_server):
        self.gen_server = gen_server
        self.config = config
        # self.password_queue = Queue(maxsize=100)
        self.password_queue = Queue()

    # def enqueue_job(self, username, domain, enc_timestamp, callback):
    def enqueue_job(self, username, domain, etype, enc_timestamp):
        # self.password_queue.put((username, domain, enc_timestamp, callback))
        self.password_queue.put((username, domain, etype, enc_timestamp))
        logging.debug(f"Cracker enqueued 1 encrypted timestamp. Queue size: {self.password_queue.qsize()}")

    # Take the encrypted timestamp and recover the generated password using a
    # password cracker. This should not take take very long since we are only
    # interested in the short word list of passwords made by the generation server.
    # It should crack the most recent passwords working backward. In practice the
    # only time this subroutine is called is when someone uses the honeytoken
    # domain\username.
    # def recover_password(self, username, domain, enc_timestamp, callback):
    def recover_password(self, username, domain, etype, enc_timestamp):
        logging.debug('Recovering password from encrypted timestamp...')

        if etype in ['17', '18']:
            salt = f'{self.config.domain.upper()}{username.upper()}'
            kerb_hash = [f'$krb5pa${etype}${username}${domain.upper()}${salt}${enc_timestamp}',
                         f'$krb5pa${etype}${username}${domain.upper()}$${enc_timestamp}']
        elif etype == '23':
            kerb_hash = [f'$krb5pa${etype}${username}${domain.upper()}$${enc_timestamp[32:]}{enc_timestamp[:32]}']
        else:
            logging.info('Invalid etype to crack')
            return
        logging.debug(f'Hashes to crack: {kerb_hash}')

        with tempfile.TemporaryDirectory(suffix='-dcept') as tmp_dir:
            word_path = tmp_dir + "/wordlist.tmp"
            pass_path = tmp_dir + "/encpass.tmp"
            pot_path = tmp_dir + "/john.pot"
            john_path = self.config.john_path

            with open(pass_path, 'w') as f:
                for hash in kerb_hash:
                    f.write(hash + '\n')

            with open(word_path, 'w') as f:
                wordlist = self.gen_server.get_all_passwords()
                if len(wordlist) == 0:
                    logging.info("Generation server hasn't issued any passwords. There is nothing to crack")
                    return
                logging.info(f"Testing {len(wordlist)} password(s)")
                f.write('\n'.join(wordlist))

            redirect_str = ''
            if logging.getLogger().getEffectiveLevel() != logging.DEBUG:
                redirect_str = "2>/dev/null"

            #result = subprocess.check_output(
                #f"{john_path} --wordlist={word_path} --pot={pot_path} --format=krb5pa-sha1 {pass_path} {redirect_str}",
                #shell=True)
            result = subprocess.check_output(
                f"{john_path} --wordlist={word_path} --pot={pot_path} {pass_path} {redirect_str}", shell=True)

        logging.debug('Cracking job completed')
        logging.debug(f'Cracking tool output: {result}')

        for line in result.decode("utf-8").split("\n"):
            if line.strip().endswith("(?)"):
                password = line.strip().split(" ")[0]
                logging.info(f"Cracked! Password: {password}")
                self.password_hit(password)

    def run(self):
        while True:
            if not self.password_queue.empty():
                item = self.password_queue.get()
                self.recover_password(item[0], item[1], item[2], item[3])

    def password_hit(self, password):
        record = self.gen_server.find_pass(password)
        message = f"[ALERT] Honeytoken for {record[1]}\\{record[2]} '{record[4]}' was stolen from {record[3]} "
        logging.critical(message)
        alert.send_alert(message, self.config)
