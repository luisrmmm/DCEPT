import pyshark
import logging
import requests


def kerbsniff(config, cracker):
    print(f"kerbsniff: Looking for {config.domain}\\{config.honey_username} on {config.interface}")
    # solo capturasmos los apquetes asp req qeu contengan el usuario honye y el realm estipulado
    # filtered_cap = pyshark.LiveCapture(interface, bpf_filter='tcp port 88',
    #                                   display_filter=f'kerberos.msg_type == 10 and lower(kerberos.CNameString) ==
    #                                   {username.lower()} and upper(kerberos.realm) contains {realm.upper()}')
    filtered_cap = pyshark.LiveCapture(interface=config.interface, bpf_filter='tcp port 88',
                                       display_filter='kerberos.msg_type == 10')

    for packet in filtered_cap.sniff_continuously():
        kp = packet['kerberos']

        kerb_name = str(kp.cnamestring)
        kerb_realm = str(kp.realm)
        logging.debug(f'kerb-as-req for domain user {kerb_realm}\\{kerb_name}')

        if kerb_name.lower() == config.honey_username.lower() and config.realm.lower() in kerb_realm.lower():
            # coinciden el usuario y el realm
            if kp.padata_type == '2': # enctimestamp
                kerb_etype = str(kp.etype)
                if kerb_etype in ['18', '17', '23']:
                    enc_timestamp = kp.padata_value.replace(":", "")[22:]

                    logging.info(f"Ready to crack (user:{kerb_name} domain:{kerb_realm} etype:{kerb_etype} timestamp:{enc_timestamp})")
                    if not config.master_node:
                        logging.debug("Enqueing local cracking task")
                        cracker.enqueue_job(kerb_name, kerb_realm, kerb_etype, enc_timestamp)
                    else:
                        logging.debug("Sending cracking task to master node")
                        try:
                            payload = {'kerb_name': kerb_name, 'kerb_realm': kerb_realm, 'kerb_etype': kerb_etype, 'enc_timestamp': enc_timestamp}
                            requests.post(f"http://{config.master_node}:{config.honeytoken_port}/notify", payload)
                        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                            logging.error('Error connecting to master node for sending cracking task')
                            logging.error(e)
                else:
                    logging.debug(f"Not supported etype {kerb_etype} in kerb-as-req for '{kerb_realm}\\{kerb_name}'")
                    continue
            else:
                logging.debug(f"No PA-DATA PA-ENC-TIMESTAMP in kerb-as-req for '{kerb_realm}\\{kerb_name}'")
                continue
        else:
            logging.debug(f"Ignoring kerb-as-req for '{kerb_realm}\\{kerb_name}'")
            continue

# def notifyMaster(username, domain, encTimestamp):
#    url = 'http://%s/notify' % (config.master_node)
#    values = {'u': username,
#              'd': domain,
#              't': encTimestamp
#              }
#    data = urllib.urlencode(values)

#    try:
#        req = urllib2.Request(url, data)
#        response = urllib2.urlopen(req, timeout=30)
#    except (urllib2.URLError, socket.timeout) as e:
#        message = "DCEPT slave Failed to communicate with master node '%s'" % (config.master_node)
#        logging.error(message)
#        alert.sendAlert(message)
#        return False
#    return True
