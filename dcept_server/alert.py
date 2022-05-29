from smtplib import SMTP, SMTPException
from email.message import EmailMessage
from datetime import datetime


def send_alert(message, config):
    message = f'{datetime.now()} {message}'

    if config.smtp_host:
        send_email(config.smtp_host, config.email_address, config.subject, message, config.smtp_port)

    # if config.syslog_host:
    #    send_syslog(config.syslog_host, message, 1, 4, config.syslog_port)

    if config.file_path:
        log_file(config.file_path, message)


def log_file(file_path, message):
    with open(file_path, 'a') as f:
        f.write(f'{message} \n')


# Sends a single syslog message UDP packet. See RFC3164
# def send_syslog(host, message, severity=1, facility=4, port=514):
    # severity = 1 - Alert: Action must be taken immediately
    # facility = 4 - security/authorization messages

    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # data = '<%d>%s' % (severity + facilit y *8, message)
    # sock.sendto(data, (host, int(port)))
    # sock.close()


# rsyslog = logging.handlers.SysLogHandler(address=(host, port), facility=logging.handlers.SysLogHandler.LOG_USER, socktype=socket.SOCK_DGRAM)
# rsyslog.critical(message)


# Send an email notification to authenticated SMTP server
def send_email(smtp_host, email_address, subject, message, port):
    msg = EmailMessage()
    msg.set_content(message)
    msg['Subject'] = subject
    msg['From'] = 'dcept'
    msg['To'] = email_address

    # Send the message via our own SMTP server.
    try:
        with SMTP(smtp_host, port) as s:
            s.send_message(msg)
        print("Successfully sent email")
    except SMTPException:
        print("Error: unable to send email")
