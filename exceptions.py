class NotNullException(Exception):
    def __init__(self, *args):
        super().__init__(f'필수 입력 값이 없습니다. {args}')


class UserExistsException(Exception):
    def __init__(self, *args):
        super().__init__(f'존재하는 아이디입니다.')


class UserNotExistsException(Exception):
    def __init__(self, *args):
        super().__init__(f'입력하진 정보가 존재하지 않습니다.')


class UserDeletedException(Exception):
    def __init__(self, *args):
        super().__init__(f'탈퇴 또는 휴면 계정입니다.')


class PasswordNotCorrectException(Exception):
    def __init__(self, *args):
        super().__init__(f'로그인 정보가 일치하지 않습니다.')


class RequestsError(Exception):
    def __init__(self, msg=None):
        super().__init__(msg if msg else 'KAKAO 요청 에러')


class SelfAuthException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class DataEncryptoException(Exception):
    def __init__(self, msg):
        super().__init__(msg)
