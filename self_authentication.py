import traceback
import json
import base64
import hashlib
import requests

from urllib                                 import parse
from cryptography.hazmat.primitives         import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Cipher                          import AES
from hmac                                   import HMAC

from django.conf                            import settings

from common.const                           import CommonConst
from common.util_date                       import TimeUtils
from common.exceptions                      import SelfAuthException, DataEncryptoException


class N_API:
    N_API_HOST               = settings.N_API_HOST
    N_URI_ISSUE_TOKEN        = settings.N_URI_ISSUE_TOKEN
    N_URI_ISSUE_CRYPTO_TOKEN = settings.N_URI_ISSUE_CRYPTO_TOKEN
    N_URI_REVOKE_TOKEN       = settings.N_URI_REVOKE_TOKEN
    N_CLIENT_ID              = settings.N_CLIENT_ID
    N_CLIENT_SECRET          = settings.N_CLIENT_SECRET
    N_PRODUCT_ID             = settings.N_PRODUCT_ID
    CONTENT_TYPE_X_WWW       = CommonConst.CONTENT_TYPE_X_WWW
    CONTENT_TYPE_AP_JSON     = CommonConst.CONTENT_TYPE_APP_JSON
    
    def issue_institution_token(self) -> dict:
        """ N*** API - 기관용 토큰 발급
            *param
                - None
            
            *return
                - access_token_data (dict: 발급받은 기관용 토큰, 만료 시간)
        """
        url = self.N_API_HOST + self.N_URI_ISSUE_TOKEN
        token_auth_key = base64.b64encode(f'{self.N_CLIENT_ID}:{self.N_CLIENT_SECRET}'.encode()).decode()
        
        headers = {
            'Content-Type' : self.CONTENT_TYPE_X_WWW,
            'Authorization': f'Basic {token_auth_key}',
        }
        
        req_data = {
            'scope'     : 'default',
            'grant_type': 'client_credentials'
        }
        
        response = requests.post(url=url,
                                 data=req_data,
                                 headers=headers).json()
        
        data_header = response['dataHeader']
        data_body = response['dataBody']
        
        if data_header['GW_RSLT_CD'] != '1200':
            raise SelfAuthException(data_header['GW_RSLT_MSG'])
        
        access_token_data = {
            'access_token': data_body['access_token'],
            'expires_in'  : data_body['expires_in'],
        }
        
        return access_token_data
    
    def discard_institution_token(self, access_token: str) -> None:
        """ N API 기관용 토큰 폐기
            param
            - access_token (만료할 기관용 토큰)

            return
            - tuple(bool, str) (요청 성공시 True, N_API 요청 실패 시 False)
        """
        url = self.N_API_HOST + self.N_URI_REVOKE_TOKEN
        
        current_timestamp = TimeUtils.get_time_seconds()
        token_auth_key    = base64.b64encode(f'{access_token}:{current_timestamp}:{self.N_CLIENT_ID}'.encode()).decode()
        
        headers = {
            'Content-Type' : self.CONTENT_TYPE_X_WWW,
            'Authorization': f'Basic {token_auth_key}',
        }
        
        response = requests.post(url=url, headers=headers).json()
        data_header = response['dataHeader']
        
        if data_header['GW_RSLT_CD'] != '1200':
            raise SelfAuthException(data_header['GW_RSLT_MSG'])

    def issue_crypto_token(self, access_token):
        """ N API 암호화 토큰 발행
            *param
            - access_token (만료할 기관용 토큰)

            *return
            - crypto_token_data (N 표준창 서비스 요청에 필요한 data set)
        """
        url = self.N_API_HOST + self.N_URI_ISSUE_CRYPTO_TOKEN
        
        current_timestamp     = TimeUtils.get_time_seconds()
        crypto_token_auth_key = base64.b64encode(f'{access_token}:{current_timestamp}:{self.N_CLIENT_ID}'.encode()).decode()
        
        req_dtim = TimeUtils.get_today_ymdhms()
        req_no   = f"{'Req'}{TimeUtils.get_today_ymdhmsf()}"
        
        headers = {
            'Content-Type' : self.CONTENT_TYPE_AP_JSON,
            'Authorization': f'bearer {crypto_token_auth_key}',
            'productID'    : self.N_PRODUCT_ID,
        }
        
        req_data = {
            'dataHeader': {
                "CNTY_CD": 'ko'  # 고정
            },
            'dataBody'  : {
                'req_dtim': req_dtim,
                'req_no'  : req_no,
                'enc_mode': '1'  # 고정(사용할 암복호화 구분. 1 : AES128/CBC/PKCS7)
            }
        }
        
        response = requests.post(url=url,
                                 data=json.dumps(req_data),
                                 headers=headers).json()
        
        data_header = response['dataHeader']
        data_body   = response['dataBody']
        
        if data_header['GW_RSLT_CD'] != '1200':
            
            if data_body['rsp_cd'] != 'P000':
                msg = data_header['GW_RSLT_MSG']
                test = str(data_body['rsp_cd'])
                
                msg += data_body['res_msg'] if test.startswith('EAPI') else ''
                raise SelfAuthException(msg)
        
        crypto_token_data = {
            # request_data
            'req_dtim'        : req_dtim,
            'req_no'          : req_no,
            
            # response
            'msg'             : data_header['GW_RSLT_MSG'],
            'site_code'       : data_body['site_code'],
            'token_version_id': data_body['token_version_id'],
            'token_val'       : data_body['token_val'],
            'period'          : data_body['period'],
        }
        
        return crypto_token_data
    
    def generate_sha_signature(self, crypto_token_data) -> bytes:
        """ 데이터 암호화 대칭키(key, iv), 무결성키 생성을 위한 Sha256 해싱 값
            req_dtim.trim() + req_no.trim() + token_val.trim() 후 Sha256 및 base64 encoding
        """
        material_to_encrypt = crypto_token_data['req_dtim'] + crypto_token_data['req_no'] + crypto_token_data['token_val']
        sha_signature: bytes = hashlib.sha256(material_to_encrypt.encode()).digest()
        base64_code: bytes = base64.b64encode(sha_signature)
        return base64_code
    
    def generate_key(self, base64_code: bytes) -> bytes:
        """ 데이터 암호화 대칭키 (key)
        """
        key: bytes = base64_code[:16]
        return key
    
    def generate_iv(self, base64_code: bytes) -> bytes:
        """ 데이터 암호화 Initial Vector (iv)
        """
        iv: bytes = base64_code[-16:]
        return iv
    
    def generate_hmac_key(self, base64_code: bytes) -> bytes:
        """ 무결성키 생성에 필요한 키 (암호화값 위변조 체크용)
        """
        hmac_key: bytes = base64_code[:32]
        return hmac_key
    
    def generate_integrity_value(self, encrypto_data, hmac_key) -> str:
        """ 무결성키 생성
        """
        enc_data = encrypto_data.encode()
        hm = HMAC(hmac_key, enc_data, hashlib.sha256)
        hmac_auth = base64.b64encode(hm.digest()).decode()
        return hmac_auth
    
    def generate_kihmac_data(self, crypto_token_data):
        """ 위의 key, iv, hmac 키 데이터 세트 리턴
        """
        base64_code = self.generate_sha_signature(crypto_token_data=crypto_token_data)
        kihmac_data = {
            'key_value': self.generate_key(base64_code=base64_code),
            'iv_value' : self.generate_iv(base64_code=base64_code),
            'hmac_key' : self.generate_hmac_key(base64_code=base64_code),
        }
        
        return kihmac_data


class AESCipherCBC:
    """ AES-128-CBC(PKCS7 padding) 방식 암/복호화 모듈
    """
    BS         = algorithms.AES.block_size
    AES_MODE   = AES.MODE_CBC
    RETURN_URL = settings.N_RETURN_URL
    
    def pkcs7_padding(self, data) -> bytes:
        """ PKCS7 패딩
        """
        if not isinstance(data, bytes):
            data = data.encode()
        
        try:
            padder = padding.PKCS7(self.BS).padder()
            padded_data = padder.update(data) + padder.finalize()
        
        except ValueError:
            traceback.print_exc()
            raise DataEncryptoException('pkcs7_padding error!')
        
        else:
            return padded_data
    
    def pkcs7_unpadding(self, data) -> bytes:
        """ PKCS7 언패딩 (현재 사용되지 않으나, 다른 방식으로 암/복호화 할 시 필요하여 남겨둠)
        """
        un_padder = padding.PKCS7(self.BS).unpadder()
        data = un_padder.update(data)
        
        try:
            un_padded_data = data + un_padder.finalize()
        
        except ValueError:
            traceback.print_exc()
            raise DataEncryptoException('pkcs7_unpadding error!')
        
        else:
            return un_padded_data
    
    def encrypt_data(self, crypto_token_data, key, iv) -> str:
        """ 요청데이터 암호화
        """
        request_data = {
            'requestno'  : crypto_token_data['req_no'],
            'returnurl'  : self.RETURN_URL,
            'sitecode'   : crypto_token_data['site_code'],
            'authtype'   : 'M', # 인증수단 고정 값 (M: 휴대폰 인증)
            'methodtype' : 'get',
            'popupyn'    : 'Y',
        }
        
        raw: bytes = json.dumps(request_data).encode()
        padded_data: bytes = self.pkcs7_padding(raw)
        
        cipher = AES.new(key, self.AES_MODE, iv)
        
        cipher_data: bytes = cipher.encrypt(padded_data)
        encrypt: str = base64.b64encode(cipher_data).decode()
        
        return encrypt
    
    def decrypt_data(self, enc_data: str, key: bytes, iv: bytes):
        """ 본인인증 결과 데이터 복호화
        """
        cipher = AES.new(key, self.AES_MODE, iv)
        
        try:
            url_decoded_data: str = parse.unquote(enc_data) # URL decode
            decode_data: bytes = base64.b64decode(url_decoded_data)
            
            decrypted_data: str = cipher.decrypt(decode_data).decode('euc-kr') # euc-kr 고정
            result_data: str = decrypted_data[:decrypted_data.index('}') + 1] # } 이후의 문자열 값 소거하여, json 형식으로 변환
            dict_data = json.loads(result_data)
            
        except Exception:
            traceback.print_exc()
            raise DataEncryptoException('decrypt_data error!')
            
        else:
            return dict_data
