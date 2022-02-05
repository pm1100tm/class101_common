class CommonUtil:
    
    @staticmethod
    def print_log(app_name: str, method_name: str, request_data: dict=None, class_: object=None) -> None:
        """ print request body with class name
        """
        data_to_print = dict()
        for key, value in request_data.items():
            if 'password' == key:
                pass
            
            else:
                data_to_print[key] = value
        
        class_name = class_.__class__.__name__ if class_ else '[class-name]'
        print('*' * 50)
        print(f"[{app_name}-{class_name}-{method_name}]::{data_to_print}")
    
    @staticmethod
    def return_data(msg: str=None, err_msg: str=None, data: dict=None) -> dict:
        return {
            'msg'    : msg,
            'err_msg': err_msg,
            'data'   : data
        }
