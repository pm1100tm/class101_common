class CommonConst:
    BLANK_STR = ''


class AppNameConst:
    MENU    = 'menu'
    ACCOUNT = 'account'
    PRODUCT = 'product'


class MethodNameConst:
    CREATE   = 'create'
    UPDATE   = 'create'
    LIST     = 'create'
    RETRIEVE = 'retrieve'
    GET      = 'get'
    POST     = 'post'
    DELETE   = 'delete'

    SIGN_UP_KAKAO             = 'signup_kakao'
    SIGN_UP_KAKAO_CALLBACK    = 'signup_kakao_callback'
    SIGN_UP_KAKAO_GET_PROFILE = 'signup_kakao_get_profile'

    SIGN_IN = 'sign_in'


class ResponseMsgConst:
    SUCCESS    = 'SUCCESS'
    FAIL       = 'FAIL'
    NO_CONTENT = 'NO_CONTENT'

    KEY_ERROR             = 'KEY_ERROR'
    ATTRIBUTE_ERROR       = 'ATTRIBUTE_ERROR'
    VALUE_ERROR           = 'VALUE_ERROR'
    ATTRIBUTE_VALUE_ERROR = 'ATTRIBUTE/VALUE_ERROR'
    NOT_NULL_ERROR        = 'REQUIRED_FIELD_ERROR'
