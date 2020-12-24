/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2018 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_phpcrypto.h"
//#include "cryptAPIc.h"
#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

/* If you declare any globals in php_phpcrypto.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(phpcrypto)
*/

/* True global resources - no need for thread safety here */
static int le_phpcrypto;

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("phpcrypto.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_phpcrypto_globals, phpcrypto_globals)
    STD_PHP_INI_ENTRY("phpcrypto.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_phpcrypto_globals, phpcrypto_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_phpcrypto_compiled(string arg)
   Return a string to confirm that the module is compiled in */
   
#ifdef WIN32
	typedef int __stdcall (*fSM4Crypt1)(int flag, char *data, int len, char *redata, int *relen, char *yin,int yinlen);
	typedef int __stdcall (*fSM4Crypt2)(int flag, char *data, int len, char *redata, int *relen, char *key,int keylen);
	typedef int __stdcall (*fCryptFile)(int flag, char *key, int keylen, char * infilename,char *outfilename, int format);
	typedef int __stdcall (*fCryptKey)(int flag, char * inkey, int inlen, char *outkey, int *outlen);
	typedef int __stdcall (*fSM3Crypt)(char *data, int len, char *redata, int *relen);
	typedef int __stdcall (*fCryptLmkMac)(char *data, int *len,char *verson, int *verlen,char *pubkey,int *pubkeylen);
	typedef int __stdcall (*fMACCrypt)(int flag, char *data, int len, char *key, int keylen, char *redata, int *relen);
	typedef int __stdcall (*fSM2Sign)(char *data, int len, char *redata, int *relen, char *pkey1,int pkey1len,char *pkey2,int pkey2len);
	typedef int __stdcall (*fSM2Verify)(char *data, int len, char *verifydata, int verifydatalen, char *pkey,int pkeylen);
	typedef int __stdcall (*fSM2SignHash)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);
	typedef int __stdcall (*fSM2VerifyHash)(char *data, int len, char *verifydata, int verifydatalen, char *pkey,int pkeylen);
	typedef int __stdcall (*fSM2Encrypt)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);
	typedef int __stdcall (*fSM2Decrypt)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);
	typedef int __stdcall (*fSM2Genkey)(char *privkey, int *privkeylen, char *pubkey, int *pubkeylen);      
	typedef int __stdcall (*fHextoAsc)(char *hex, int hexlen,char *asc, int *asclen); 
	typedef int __stdcall (*fAsctoHex)(char *asc, int asclen,char *hex, int *hexlen);  
	typedef int __stdcall (*fbase64_decode)(const char *bdata, int bdlen, char *ret, int *retlen);
	typedef int __stdcall (*fbase64_encode)(const char *data,int dlen, char *ret,int *retlen);
	typedef int __stdcall (*fSM2FormatConvert)(int mode,char *cipher, int len,char *out, int *outLen);
    typedef int __stdcall (*fSM4CBCCrypt)(int flag, char *data, int len, char *redata, int *relen, char *yin,int yinlen,char *iv,int ivlen);
#else
  typedef int (*fSM4Crypt1)(int flag, char *data, int len, char *redata, int *relen, char *yin,int yinlen);    
	typedef int (*fSM4Crypt2)(int flag, char *data, int len, char *redata, int *relen, char *key,int keylen);    
	typedef int (*fCryptFile)(int flag, char *key, int keylen, char * infilename,char *outfilename, int format); 
	typedef int (*fCryptKey)(int flag, char * inkey, int inlen, char *outkey, int *outlen);                      
	typedef int (*fSM3Crypt)(char *data, int len, char *redata, int *relen);                                     
	typedef int (*fCryptLmkMac)(char *data, int *len,char *verson, int *verlen,char *pubkey,int *pubkeylen);                                 
	typedef int (*fMACCrypt)(int flag, char *data, int len, char *key, int keylen, char *redata, int *relen);    
	typedef int (*fSM2Sign)(char *data, int len, char *redata, int *relen, char *pkey1,int pkey1len,char *pkey2,int pkey2len);              
	typedef int (*fSM2Verify)(char *data, int len, char *verifydata, int verifydatalen, char *pkey,int pkeylen); 
	typedef int (*fSM2SignHash)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);              
	typedef int (*fSM2VerifyHash)(char *data, int len, char *verifydata, int verifydatalen, char *pkey,int pkeylen); 
	typedef int (*fSM2Encrypt)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);           
	typedef int (*fSM2Decrypt)(char *data, int len, char *redata, int *relen, char *pkey,int pkeylen);           
	typedef int (*fSM2Genkey)(char *privkey, int *privkeylen, char *pubkey, int *pubkeylen);                     
	typedef int (*fHextoAsc)(char *hex, int hexlen,char *asc, int *asclen);                                      
	typedef int (*fAsctoHex)(char *asc, int asclen,char *hex, int *hexlen);                                      
	typedef int (*fbase64_decode)(const char *bdata, int bdlen, char *ret, int *retlen);                         
	typedef int (*fbase64_encode)(const char *data,int dlen, char *ret,int *retlen);                    	typedef int (*fSM2FormatConvert)(int mode,char *cipher, int len,char *out, int *outLen);
    typedef int (*fSM4CBCCrypt)(int flag, char *data, int len, char *redata, int *relen, char *yin,int yinlen,char *iv,int ivlen);     
#endif
fSM4Crypt1      SM4Crypt1 = NULL;
fSM4Crypt2      SM4Crypt2 = NULL;
fCryptFile      CryptFile = NULL;
fCryptKey       CryptKey = NULL;
fSM3Crypt       SM3Crypt = NULL;
fCryptLmkMac    CryptLmkMac = NULL;
fMACCrypt       MACCrypt = NULL;
fSM2Sign        SM2Sign = NULL;
fSM2Verify      SM2Verify = NULL;
fSM2SignHash    SM2SignHash = NULL;
fSM2VerifyHash  SM2VerifyHash = NULL;
fSM2Encrypt     SM2Encrypt = NULL;
fSM2Decrypt     SM2Decrypt = NULL;
fSM2Genkey      SM2Genkey = NULL;
fHextoAsc       HextoAsc = NULL;
fAsctoHex       AsctoHex = NULL;
fbase64_decode  base64_decode = NULL;
fbase64_encode  base64_encode = NULL;
fSM2FormatConvert	SM2FormatConvert = NULL;
fSM4CBCCrypt    SM4CBCCrypt = NULL;

PHP_FUNCTION(confirm_phpcrypto_compiled)
{
	char *arg = NULL;
	size_t arg_len, len;
	//char *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &arg, &arg_len) == FAILURE) {
		return;
	}
	/*
	strg = strpprintf(0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "phpcrypto", arg);

	RETURN_STR(strg);*/
	return;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_crypto_init, 0, 0, 1)
    ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()
//以下是函数实现
PHP_FUNCTION(php_crypto_init){
	char *path = NULL;
	size_t len = 0;
	
	int recode = 0;
	
	//传入的字符串后面会自动补充结束符\0
	//传入的参数是引用传递，修改值则php中的值也会变
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &path,&len) == FAILURE) {
        RETURN_LONG(-1001);
    }
		
#ifdef WIN32
	HINSTANCE hDll=NULL;
	hDll = LoadLibrary(path);

	if(hDll==NULL)
	{
		//printf("找不到libcryptAPIsm.dll\n");
		RETURN_LONG(-1002);
	}
	SM4Crypt1      =     (fSM4Crypt1    )GetProcAddress(hDll, "SM4Crypt1"); 
	SM4Crypt2      =     (fSM4Crypt2    )GetProcAddress(hDll, "SM4Crypt2"); 
	CryptFile      =     (fCryptFile    )GetProcAddress(hDll, "CryptFile"); 
	CryptKey       =     (fCryptKey     )GetProcAddress(hDll, "CryptKey"); 
	SM3Crypt       =     (fSM3Crypt     )GetProcAddress(hDll, "SM3Crypt"); 
	CryptLmkMac    =     (fCryptLmkMac  )GetProcAddress(hDll, "CryptLmkMac"); 
	MACCrypt       =     (fMACCrypt     )GetProcAddress(hDll, "MACCrypt");
	SM2Sign        =     (fSM2Sign      )GetProcAddress(hDll, "SM2Sign"); 
	SM2Verify      =     (fSM2Verify    )GetProcAddress(hDll, "SM2Verify"); 
	SM2SignHash    =     (fSM2SignHash  )GetProcAddress(hDll, "SM2SignHash"); 
	SM2VerifyHash  =     (fSM2VerifyHash)GetProcAddress(hDll, "SM2VerifyHash"); 
	SM2Encrypt     =     (fSM2Encrypt   )GetProcAddress(hDll, "SM2Encrypt"); 
	SM2Decrypt     =     (fSM2Decrypt   )GetProcAddress(hDll, "SM2Decrypt"); 
	SM2Genkey      =     (fSM2Genkey    )GetProcAddress(hDll, "SM2Genkey"); 
	HextoAsc       =     (fHextoAsc     )GetProcAddress(hDll, "HextoAsc"); 
	AsctoHex       =     (fAsctoHex     )GetProcAddress(hDll, "AsctoHex"); 
	base64_decode  =     (fbase64_decode)GetProcAddress(hDll, "base64_decode"); 
	base64_encode  =     (fbase64_encode)GetProcAddress(hDll, "base64_encode"); 
	SM2FormatConvert  =     (fSM2FormatConvert  )GetProcAddress(hDll, "SM2FormatConvert");
    SM4CBCCrypt    =     (fSM4CBCCrypt  )GetProcAddress(hDll, "SM4CBCCrypt");
#else
	void *hDll;

	hDll = dlopen(path, RTLD_LAZY);//RTLD_NOW 
    	if(hDll==NULL)
	{
		//printf("找不到libcryptAPIsm_lnx32.so \n");
		RETURN_LONG(-1002);
	}
	SM4Crypt1      =     (fSM4Crypt1    )dlsym(hDll, "SM4Crypt1"); 
	SM4Crypt2      =     (fSM4Crypt2    )dlsym(hDll, "SM4Crypt2"); 
	CryptFile      =     (fCryptFile    )dlsym(hDll, "CryptFile"); 
	CryptKey       =     (fCryptKey     )dlsym(hDll, "CryptKey"); 
	SM3Crypt       =     (fSM3Crypt     )dlsym(hDll, "SM3Crypt"); 
	CryptLmkMac    =     (fCryptLmkMac  )dlsym(hDll, "CryptLmkMac"); 
	MACCrypt       =     (fMACCrypt     )dlsym(hDll, "MACCrypt"); 
	SM2Sign        =     (fSM2Sign      )dlsym(hDll, "SM2Sign"); 
	SM2Verify      =     (fSM2Verify    )dlsym(hDll, "SM2Verify"); 
	SM2SignHash    =     (fSM2SignHash  )dlsym(hDll, "SM2SignHash"); 
	SM2VerifyHash  =     (fSM2VerifyHash)dlsym(hDll, "SM2VerifyHash"); 
	SM2Encrypt     =     (fSM2Encrypt   )dlsym(hDll, "SM2Encrypt"); 
	SM2Decrypt     =     (fSM2Decrypt   )dlsym(hDll, "SM2Decrypt"); 
	SM2Genkey      =     (fSM2Genkey    )dlsym(hDll, "SM2Genkey"); 
	HextoAsc       =     (fHextoAsc     )dlsym(hDll, "HextoAsc"); 
	AsctoHex       =     (fAsctoHex     )dlsym(hDll, "AsctoHex"); 
	base64_decode  =     (fbase64_decode)dlsym(hDll, "base64_decode"); 
	base64_encode  =     (fbase64_encode)dlsym(hDll, "base64_encode"); 
	SM2FormatConvert    =     (fSM2FormatConvert  )dlsym(hDll, "SM2FormatConvert");
    SM4CBCCrypt    =     (fSM4CBCCrypt  )dlsym(hDll, "SM4CBCCrypt");
#endif
	
	
	
	RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM4Crypt1, 0, 0, 4)
    ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, yin)
ZEND_END_ARG_INFO()
//以下是函数实现
PHP_FUNCTION(php_SM4Crypt1){
	long flag = 0;
	char *data = NULL;
	size_t len = 0;
	zval *redata;
	int relen = 0;
	char *yin = NULL;
	size_t yinlen = 0;
	int recode = 0;
	
	char *predata = NULL;
	//传入的字符串后面会自动补充结束符\0
	//传入的参数是引用传递，修改值则php中的值也会变
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "lsz/s!", &flag, &data,&len,&redata,&yin,&yinlen) == FAILURE) {
        RETURN_LONG(-1001);
    }
		
	predata = (char *)emalloc(sizeof(char)*(len+64));
	if(predata == NULL){
		RETURN_LONG(-7);
	}
	recode = SM4Crypt1(flag, data, len, predata, &relen, yin,yinlen);
	if( recode == 0 ){
		zval_dtor(redata);
    	ZVAL_STRINGL(redata, predata,relen);
		
	}

	if(predata != NULL){
		efree(predata);
		predata = NULL;
	}
	RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM4Crypt2, 0, 0, 4)
    ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, key) 
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM4Crypt2){

	long flag = 0;
    char *data = NULL;
    size_t len = 0;                                                      
    zval *redata;
    int relen = 0;
    char *key = NULL;
    size_t keylen = 0;
    int recode = 0;
    
    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lsz/s!", &flag, &data,&len,&redata,&key,&keylen) == FAILURE) {
        RETURN_LONG(-1001);
    }
        
    predata = (char *)emalloc(sizeof(char)*(len+64));
    if(predata == NULL){
        RETURN_LONG(-7);
    }   
    
    recode = SM4Crypt1(flag, data, len, predata, &relen, key,keylen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);
        
    }   

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    } 
    RETURN_LONG(recode);

}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_CryptFile, 0, 0, 5)
    ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, infilename)
    ZEND_ARG_INFO(0, outfilename)
	ZEND_ARG_INFO(0, format)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_CryptFile){
	
	long flag = 0;
    char *key = NULL;
    size_t keylen = 0;
    char *infilename =  NULL;
    size_t infilenamelen = 0;
    char *outfilename = NULL;
    size_t outfilenamelen = 0;
	long format = 0;
    int recode = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "lsssl", &flag, &key,&keylen,&infilename,&infilenamelen,&outfilename,&outfilenamelen,&format) == FAILURE) {
        RETURN_LONG(-1001);
    }

	recode = CryptFile(flag, key, keylen, infilename,outfilename, format);

	RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_CryptKey, 0, 0, 3)
    ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, inkey)
    ZEND_ARG_INFO(1, outkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_CryptKey){
	long flag = 0;
    char *inkey = NULL;
    size_t inlen = 0;
    zval *outkey =  NULL;
    int outlen = 16;
    int recode = 0;

	char *poutkey = NULL;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls!z/", &flag, &inkey,&inlen,&outkey) == FAILURE) {
        RETURN_LONG(-1001);
    }

	poutkey = (char *)emalloc(sizeof(char)*(inlen+64));
    if(poutkey == NULL){
        RETURN_LONG(-7);
    }

    recode = CryptKey(flag, inkey, inlen, poutkey, &outlen);
    if( recode == 0 ){
        zval_dtor(outkey);
        ZVAL_STRINGL(outkey, poutkey,outlen);

    }

    if(poutkey != NULL){
        efree(poutkey);
        poutkey = NULL;
    } 
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM3Crypt, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM3Crypt){
    char *data = NULL;
    size_t len = 0;
    zval *redata =  NULL;
    int relen = 0;
    int recode = 0;

    char *predata = NULL;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/", &data,&len,&redata) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*128);
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM3Crypt(data, len, predata, &relen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_MACCrypt, 0, 0, 4)
	ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(1, redata)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_MACCrypt){
	long flag = 0;
    char *data = NULL;
    size_t len = 0;
	char *key = NULL;
    size_t keylen = 0;
    zval *redata;
    int relen = 0;
    int recode = 0;

    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lssz/", &flag, &data,&len,&key,&keylen,&redata) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*128);
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = MACCrypt(flag, data, len, key, keylen, predata, &relen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);

}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_CryptLmkMac, 0, 0, 3)
    ZEND_ARG_INFO(1, data)
    ZEND_ARG_INFO(1, verson)
    ZEND_ARG_INFO(1, pubkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_CryptLmkMac){

    zval *data = NULL;
    int len = 0;
    zval *verson = NULL;
    int verlen = 0;
    zval *pubkey;
    int pubkeylen = 0;
    int recode = 0;
	
	char *pdata = NULL;
	char *pverson = NULL;
	char *ppubkey = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "z/z/z/", &data, &verson,&pubkey) == FAILURE) {
        RETURN_LONG(-1001);
    }

	pdata = (char *)emalloc(sizeof(char)*1024);
    if(pdata == NULL){
        recode = -7;
		goto endclean;
    }
	pverson = (char *)emalloc(sizeof(char)*1024);
    if(pverson == NULL){
        recode = -7;
        goto endclean;
    }
	ppubkey = (char *)emalloc(sizeof(char)*1024);
    if(ppubkey == NULL){
        recode = -7;
        goto endclean;
    }	
	
	recode = CryptLmkMac(pdata, &len,pverson, &verlen,ppubkey,&pubkeylen);
	if( recode == 0 ){
        zval_dtor(data);
        ZVAL_STRINGL(data, pdata,len);
		zval_dtor(verson);
        ZVAL_STRINGL(verson, pverson,verlen);
		zval_dtor(pubkey);
        ZVAL_STRINGL(pubkey, ppubkey,pubkeylen);
    }

endclean:
	if(pdata != NULL){
        efree(pdata);
        pdata = NULL;
    }
	if(pverson != NULL){
        efree(pverson);
        pverson = NULL;
    }
	if(ppubkey != NULL){
        efree(ppubkey);
        ppubkey = NULL;
    }
    RETURN_LONG(recode);	
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2Sign, 0, 0, 4)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, pkey1)
	ZEND_ARG_INFO(0, pkey2)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2Sign){
	
	char *data = NULL;
    size_t len = 0;
    zval *redata = NULL;
    int relen = 0;
    char *pkey1 = NULL;
    size_t pkey1len = 0;
	char *pkey2 = NULL;
    size_t pkey2len = 0;
    int recode = 0;

	char *predata = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/ss", &data,&len,&redata,&pkey1,&pkey1len,&pkey2,&pkey2len) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*pkey2len*2);
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM2Sign(data, len, predata, &relen, pkey1,pkey1len,pkey2,pkey2len);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2Verify, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, verifydata)
    ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2Verify){
	
	char *data = NULL;
    size_t len = 0;
    char *verifydata = NULL;
    size_t verifydatalen = 0;
    char *pkey = NULL;
    size_t pkeylen = 0;
    int recode = 0;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &data,&len,&verifydata,&verifydatalen,&pkey,&pkeylen) == FAILURE) {
        RETURN_LONG(-1001);
    } 
   
    recode = SM2Verify(data, len, verifydata, verifydatalen, pkey,pkeylen);

    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2SignHash, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2SignHash){
	char *data = NULL;
    size_t len = 0;
    zval *redata = NULL;
    int relen = 0;
    char *pkey = NULL;
    size_t pkeylen = 0;

    int recode = 0;

    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/s", &data,&len,&redata,&pkey,&pkeylen) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*pkeylen*4);
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM2SignHash(data, len, predata, &relen, pkey,pkeylen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2VerifyHash, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, verifydata)
    ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2VerifyHash){
	char *data = NULL;
    size_t len = 0;
    char *verifydata = NULL;
    size_t verifydatalen = 0;
    char *pkey = NULL;
    size_t pkeylen = 0;
    int recode = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &data,&len,&verifydata,&verifydatalen,&pkey,&pkeylen) == FAILURE) {
        RETURN_LONG(-1001);
    }

    recode = SM2VerifyHash(data, len, verifydata, verifydatalen, pkey,pkeylen);

    RETURN_LONG(recode);	
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2Encrypt, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2Encrypt){
	char *data = NULL;
    size_t len = 0;
    zval *redata = NULL;
    int relen = 0;
    char *pkey = NULL;
    size_t pkeylen = 0;

    int recode = 0;

    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/s", &data,&len,&redata,&pkey,&pkeylen) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*(len+128));
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM2Encrypt(data, len, predata, &relen, pkey,pkeylen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);	
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2Decrypt, 0, 0, 3)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2Decrypt){
	
	char *data = NULL;
    size_t len = 0;
    zval *redata = NULL;
    int relen = 0;
    char *pkey = NULL;
    size_t pkeylen = 0;

    int recode = 0;

    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/s", &data,&len,&redata,&pkey,&pkeylen) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*len);
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM2Decrypt(data, len, predata, &relen, pkey,pkeylen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2Genkey, 0, 0, 2)
    ZEND_ARG_INFO(1, privkey)
    ZEND_ARG_INFO(1, pubkey)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2Genkey){
	zval *privkey = NULL;
    int privkeylen = 0;
    zval *pubkey = NULL;
    int pubkeylen = 0;
    
    int recode = 0;
    
    char *pprivkey = NULL;
	char *ppubkey = NULL;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z/z/", &privkey,&pubkey) == FAILURE) {
        RETURN_LONG(-1001);
    }
    
   	pprivkey = (char *)emalloc(sizeof(char)*128);
    if(pprivkey == NULL){
        recode = -7;
		goto endclean;
    }
	ppubkey = (char *)emalloc(sizeof(char)*256);
    if(ppubkey == NULL){
        recode = -7;
        goto endclean;
    }
    
    recode = SM2Genkey(pprivkey, &privkeylen, ppubkey, &pubkeylen);
    if( recode == 0 ){
        zval_dtor(privkey);
        ZVAL_STRINGL(privkey, pprivkey,privkeylen);
		zval_dtor(pubkey);
        ZVAL_STRINGL(pubkey, ppubkey,pubkeylen);
    }

endclean:
    if(pprivkey != NULL){
        efree(pprivkey);
        pprivkey = NULL;
    }
	if(ppubkey != NULL){
        efree(ppubkey);
        ppubkey = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_HextoAsc, 0, 0, 2)
    ZEND_ARG_INFO(0, hex)
    ZEND_ARG_INFO(1, asc)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_HextoAsc){
	
	char *hex = NULL;
    size_t hexlen = 0;
    zval *asc = NULL;
    int asclen = 0;

    int recode = 0;

    char *pasc = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/", &hex,&hexlen,&asc) == FAILURE) {
        RETURN_LONG(-1001);
    }

    pasc = (char *)emalloc(sizeof(char)*(hexlen/2));
    if(pasc == NULL){
        recode = -7;
        goto endclean;
    }

    recode = HextoAsc(hex, hexlen,pasc, &asclen);
    if( recode == 0 ){
        zval_dtor(asc);
        ZVAL_STRINGL(asc, pasc,asclen);
    }

endclean:
    if(pasc != NULL){
        efree(pasc);
        pasc = NULL;
    }
    RETURN_LONG(recode);	
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_AsctoHex, 0, 0, 2)
    ZEND_ARG_INFO(0, asc)
    ZEND_ARG_INFO(1, hex)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_AsctoHex){
	
	char *asc = NULL;
    size_t asclen = 0;
    zval *hex = NULL;
    int hexlen = 0;

    int recode = 0;

    char *phex = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/", &asc,&asclen,&hex) == FAILURE) {
        RETURN_LONG(-1001);
    }

    phex = (char *)emalloc(sizeof(char)*(asclen*2));
    if(phex == NULL){
        recode = -7;
        goto endclean;
    }

    recode = AsctoHex(asc, asclen,phex, &hexlen);
    if( recode == 0 ){
        zval_dtor(hex);
        ZVAL_STRINGL(hex, phex,hexlen);
    }

endclean:
    if(phex != NULL){
        efree(phex);
        phex = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_base64_decode, 0, 0, 2)
    ZEND_ARG_INFO(0, bdata)
    ZEND_ARG_INFO(1, ret)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_base64_decode){
	
	char *bdata = NULL;
    size_t bdlen = 0;
    zval *ret = NULL;
    int retlen = 0;
    
    int recode = 0;
    
    char *pret = NULL;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/", &bdata,&bdlen,&ret) == FAILURE) {
        RETURN_LONG(-1001);
    }
    
    pret = (char *)emalloc(sizeof(char)*(bdlen));
    if(pret == NULL){
        recode = -7;
        goto endclean;
    }
    
    recode = base64_decode(bdata, bdlen, pret, &retlen);
    if( recode == 0 ){
        zval_dtor(ret);
        ZVAL_STRINGL(ret, pret,retlen);
    }

endclean:
    if(pret != NULL){
        efree(pret);
        pret = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_base64_encode, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, ret)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_base64_encode){
	
	char *data = NULL;
    size_t dlen = 0;
    zval *ret = NULL;
    int retlen = 0;
    
    int recode = 0;
    
    char *pret = NULL;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/", &data,&dlen,&ret) == FAILURE) {
        RETURN_LONG(-1001);
    }
    
    pret = (char *)emalloc(sizeof(char)*(dlen*2));
    if(pret == NULL){
        recode = -7;
        goto endclean;
    }
    
    recode = base64_encode(data, dlen, pret, &retlen);
    if( recode == 0 ){
        zval_dtor(ret);
        ZVAL_STRINGL(ret, pret,retlen);
    }

endclean:
    if(pret != NULL){
        efree(pret);
        pret = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM2FormatConvert, 0, 0, 3)
	ZEND_ARG_INFO(0, mode)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, ret)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM2FormatConvert){

	long mode = 0;
    char *data = NULL;
    size_t dlen = 0;
    zval *ret = NULL;
    int retlen = 0;

    int recode = 0;

    char *pret = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lsz/",&mode,&data,&dlen,&ret) == FAILURE) {
        RETURN_LONG(-1001);
    }

    pret = (char *)emalloc(sizeof(char)*(dlen+32));
	retlen = dlen + 32;
    if(pret == NULL){
        recode = -7;
        goto endclean;
    }
	
    recode = SM2FormatConvert(mode,data, dlen, pret, &retlen);
    if( recode == 0 ){
        zval_dtor(ret);
        ZVAL_STRINGL(ret, pret,retlen);
    }

endclean:
    if(pret != NULL){
        efree(pret);
        pret = NULL;
    }
    RETURN_LONG(recode);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_php_SM4CBCCrypt, 0, 0, 5)
    ZEND_ARG_INFO(0, flag)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, redata)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()
PHP_FUNCTION(php_SM4CBCCrypt){

    long flag = 0;
    char *data = NULL;
    size_t len = 0;
    zval *redata;
    int relen = 0;
    char *key = NULL;
    size_t keylen = 0;
    char *iv = NULL;
    size_t ivlen = 0;
    int recode = 0;

    char *predata = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "lsz/ss", &flag, &data,&len,&redata,&key,&keylen,&iv,&ivlen) == FAILURE) {
        RETURN_LONG(-1001);
    }

    predata = (char *)emalloc(sizeof(char)*(len+64));
    if(predata == NULL){
        RETURN_LONG(-7);
    }

    recode = SM4CBCCrypt(flag, data, len, predata, &relen, key,keylen,iv,ivlen);
    if( recode == 0 ){
        zval_dtor(redata);
        ZVAL_STRINGL(redata, predata,relen);

    }

    if(predata != NULL){
        efree(predata);
        predata = NULL;
    }
    RETURN_LONG(recode);

}

/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_phpcrypto_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_phpcrypto_init_globals(zend_phpcrypto_globals *phpcrypto_globals)
{
	phpcrypto_globals->global_value = 0;
	phpcrypto_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(phpcrypto)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(phpcrypto)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(phpcrypto)
{
#if defined(COMPILE_DL_PHPCRYPTO) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(phpcrypto)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(phpcrypto)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "phpcrypto support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ phpcrypto_functions[]
 *
 * Every user visible function must have an entry in phpcrypto_functions[].
 */
const zend_function_entry phpcrypto_functions[] = {
	PHP_FE(confirm_phpcrypto_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE(php_crypto_init,   arginfo_php_crypto_init)
	PHP_FE(php_SM4Crypt1,     arginfo_php_SM4Crypt1)
	PHP_FE(php_SM4Crypt2,     arginfo_php_SM4Crypt2)
	PHP_FE(php_CryptFile,     arginfo_php_CryptFile)
	PHP_FE(php_CryptKey,      arginfo_php_CryptKey)
	PHP_FE(php_SM3Crypt,      arginfo_php_SM3Crypt)
	PHP_FE(php_MACCrypt,      arginfo_php_MACCrypt)
	PHP_FE(php_CryptLmkMac,   arginfo_php_CryptLmkMac)
	PHP_FE(php_SM2Sign,       arginfo_php_SM2Sign)
	PHP_FE(php_SM2Verify,     arginfo_php_SM2Verify)
	PHP_FE(php_SM2SignHash,   arginfo_php_SM2SignHash)
	PHP_FE(php_SM2VerifyHash, arginfo_php_SM2VerifyHash)
	PHP_FE(php_SM2Encrypt,    arginfo_php_SM2Encrypt)
	PHP_FE(php_SM2Decrypt,    arginfo_php_SM2Decrypt)
	PHP_FE(php_SM2Genkey,     arginfo_php_SM2Genkey)
	PHP_FE(php_HextoAsc,      arginfo_php_HextoAsc)
	PHP_FE(php_AsctoHex,      arginfo_php_AsctoHex)
	PHP_FE(php_base64_decode, arginfo_php_base64_decode)
	PHP_FE(php_base64_encode, arginfo_php_base64_encode)
	PHP_FE(php_SM2FormatConvert,     arginfo_php_SM2FormatConvert)
    PHP_FE(php_SM4CBCCrypt,      arginfo_php_SM4CBCCrypt)
	PHP_FE_END	/* Must be the last line in phpcrypto_functions[] */
};
/* }}} */

/* {{{ phpcrypto_module_entry
 */
zend_module_entry phpcrypto_module_entry = {
	STANDARD_MODULE_HEADER,
	"phpcrypto",
	phpcrypto_functions,
	PHP_MINIT(phpcrypto),
	PHP_MSHUTDOWN(phpcrypto),
	PHP_RINIT(phpcrypto),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(phpcrypto),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(phpcrypto),
	PHP_PHPCRYPTO_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PHPCRYPTO
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(phpcrypto)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
