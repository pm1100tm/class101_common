class CommonUtil:
    """ 공통 유틸 클래스
    """
    
    @staticmethod
    def print_log(
        app_name     : str,
        method_name  : str,
        request_data : dict   = None,
        request_param: dict   = None,
        class_       : object = None
    ) -> None:
        """ print request body or query params with class name of method name
            param
             -app_name     : 앱 이름
             -method_name  : 메서드 명
             -request_data : 리퀘스트 바디
             -request_param: 쿼리스트링
             -class_       : 클래스 인스턴스
            
            return
             - None
        """
        class_name    = class_.__class__.__name__ if class_ else '[not-class]'
        data          = request_data if request_data else request_param
        data_to_print = dict()
        
        if data:
            
            for key, value in data.items():
                if 'password' == key:
                    pass
                
                else:
                    data_to_print[key] = value
        
        print('*' * 50)
        print(f"[{app_name}-{class_name}-{method_name}])")
        print(data_to_print)
    
    @staticmethod
    def return_data(msg: str=None, err_msg: str=None, data: dict=None) -> dict:
        return {
            'msg'    : msg,
            'err_msg': err_msg,
            'data'   : data
        }
