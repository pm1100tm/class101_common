import time

from datetime import datetime


class TimeUtils:
    """ 시간 관련 값 편집
        *author
            - SWD
        *history
            - 2022.02.04 파일 생성
    """
    
    @staticmethod
    def get_today() -> datetime:
        """ 현재 시간 취득
            현재 시간을 datetime 포멧으로 리턴한다.
            *param
             - None
             
            *return
             - ex) 2022-03-04 10:01:10.762220
        """
        return datetime.today()
    
    @staticmethod
    def get_time_seconds() -> str:
        """ 현재 시간의 초 값 취득
            time.time (the current time in seconds since the Epoch) 으로 얻은 현재 시간의 초 값을, 소숫점 아래를 버린 후 str 값으로 리턴한다.
            *param
             - None
            
            * return
             - ex) 1646356123.624165 -> 1646356123
        """
        return str(int(time.time()))
    
    @staticmethod
    def get_today_ymdhms() -> str:
        """ 현재 시간 취득 (YmdHMS 포멧)
            *param
             - None
            
            *return
             - ex) 20220304102952
        """
        return datetime.today().strftime('%Y%m%d%H%M%S')
    
    @staticmethod
    def get_today_ymdhmsf() -> str:
        """ 현재 시간 밀리세컨크까지 취득 (YmdHMSf 포멧)
            *param
             - None
            
            *return
             - ex) 20220304102952876725
        """
        return datetime.today().strftime('%Y%m%d%H%M%S%f')
