<?php
function string2hex($string){
	$hex = '';
	for($i = 0;$i < strlen($string); $i++){
		$ch = dechex(ord($string[$i]));
		if(strlen($ch)==1){
			$ch = "0".$ch;
		}
		$hex .=$ch;
	}
	return $hex;
}
/*
function hex2string($hex){
	//echo "$hex \n";
	$string = '';
	for($i = 0;$i < strlen($hex);$i++){
		$string .= chr(hexdec($hex[$i].$hex[$i++]));
	}
	return $string;
}
*/
if(!extension_loaded('phpcrypto')) {
	dl('phpcrypto.so');
}

$module = 'phpcrypto';
$functions = get_extension_funcs($module);
echo "Functions available in the test extension:\n";
foreach($functions as $func) {
    echo $func."\n";
}
echo "\n";

//先加载动态库，否则无法调用接口
function test_php_crypto_init(){
    $php_func = 'php_crypto_init';
    echo "--------$php_func--------\n";
	$path = "/home/essc50mysql/mf/src_crypt/libcryptAPIsm_lnx64.so";//国密动态库路径
    $recode = $php_func($path);
    echo "recode：$recode \n";//如果非零，则加载失败
}

//test php_SM4Crypt1
function test_php_SM4Crypt1(){
	$php_func = 'php_SM4Crypt1';
	echo "--------$php_func--------\n";
	$data = "this is a test! 这是个测试！";
	$key = "1234567890123456";//如果是hex编码，务必解码
	$recode = $php_func(0,$data,$redata,$key);
	echo "recode：$recode \n";
	echo "redata: ".string2hex($redata)." len:".strlen($redata)." \n";
	$recode = $php_func(1,$redata,$dedata,$key);
	echo "recode：$recode \n";
    echo "plain: ".$dedata." \n";
}

//test SM4Crypt2
function test_php_SM4Crypt2(){
    $php_func = 'php_SM4Crypt2';
	echo "--------$php_func--------\n";
    $data = "this is a test! 这是个测试！";
    $key = "1234567890123456";//如果是hex编码，务必解码
    $recode = $php_func(0,$data,$redata,$key);
    echo "recode：$recode \n";
    echo "redata: ".string2hex($redata)." len:".strlen($redata)." \n";
    $recode = $php_func(1,$redata,$dedata,$key);
    echo "recode：$recode \n";
    echo "plain: ".$dedata." \n";
}

//test php_CryptFile
function test_php_CryptFile(){
    $php_func = 'php_CryptFile';
	echo "--------$php_func--------\n";
    $flag = 2;
    $infilename = "/home/essc50mysql/mf/src_crypt/test_cryptfile";
    $encodefilename = "/home/essc50mysql/mf/src_crypt/test_encode_cryptfile";
    $format = 1;
    $key = "1234567890123456";//如果是hex编码，务必解码
    $recode = $php_func($flag, $key, $infilename,$encodefilename,$format);
    echo "recode：$recode \n";
    $flag = 3;
    $decodefilename = "/home/essc50mysql/mf/src_crypt/test_decode_cryptfile";
    $recode = $php_func($flag, $key, $encodefilename,$decodefilename,$format);
    echo "recode：$recode \n";
}

//test php_CryptKey
function test_php_CryptKey(){
    $php_func = 'php_CryptKey';
	echo "--------$php_func--------\n";
    $flag = 0;
    $plainkey = "1234567890123456";
    $recode = $php_func($flag, $plainkey,$cipherkey);
    echo "recode：$recode \n";
	echo "cipherkey: ".string2hex($cipherkey)." len:".strlen($cipherkey)." \n";
    $flag = 2;
    $recode = $php_func($flag, NULL,$genkey);
    echo "recode：$recode \n";
	echo "genkey: ".string2hex($genkey)." len:".strlen($genkey)." \n";
}

//test php_SM3Crypt
function test_php_SM3Crypt(){
    $php_func = 'php_SM3Crypt';
	echo "--------$php_func--------\n";
	$data = "this is test 这是测试！";
    $recode = $php_func($data,$sm3hash);
    echo "recode：$recode \n";
    echo "sm3hash: ".string2hex($sm3hash)." len:".strlen($sm3hash)." \n";
}

//test php_MACCrypt
function test_php_MACCrypt(){
    $php_func = 'php_MACCrypt';
    echo "--------$php_func--------\n";
    $flag = 0;
    $data = "this is test 这是测试！this is test 这是测试！";
	$key = "1234567890123456";
    $recode = $php_func($flag,$data, $key,$redata);
    echo "recode：$recode \n";
    echo "flag:".$flag." redata: ".string2hex($redata)." len:".strlen($redata)." \n";
    $flag = 1;
    $recode = $php_func($flag,$data, $key,$redata);
    echo "recode：$recode \n";
    echo "flag:".$flag." redata: ".string2hex($redata)." len:".strlen($redata)." \n";
}

//test php_CryptLmkMac
function test_php_CryptLmkMac(){
    $php_func = 'php_CryptLmkMac';
    echo "--------$php_func--------\n";
    $recode = $php_func($data,$version, $pubkey);
    echo "recode：$recode \n";
    echo "keymac: ".string2hex($data)." version:".$version." pubkey".string2hex($pubkey)." len:".strlen($pubkey)." \n";
}

//test php_SM2Genkey
function test_php_SM2Genkey(){
    $php_func = 'php_SM2Genkey';
    //echo "--------$php_func--------\n";
    $recode = $php_func($privkey, $pubkey);
    //echo "recode：$recode \n";
    echo "privkey: ".string2hex($privkey)." len:".strlen($privkey)." pubkey: ".string2hex($pubkey)." len:".strlen($pubkey)." \n";
	return array($privkey, $pubkey);
}


//test php_SM2Sign
function test_php_SM2SignAndSM2Verify(){
    $php_func = 'php_SM2Sign';
    echo "--------$php_func--------\n";
    $data = "this is test 这是测试！this is test 这是测试！";//数据有中文则需要注意字符编码的问题
    $sm2keys = test_php_SM2Genkey();//0 privkey 1 pubkey
    //签名
	$recode = $php_func($data, $redata,$sm2keys[0],$sm2keys[1]);
    echo "recode：$recode \n";
    echo "signValue: ".string2hex($redata)." len:".strlen($redata)." \n";
	//php_SM2Sign接口返回的签名值是RS格式，以下示例转DER编码
	$php_func = 'php_SM2FormatConvert';
	$recode = $php_func(202,$redata, $der);
	echo "recode：$recode \n";
    echo "signValue DER: ".string2hex($der)." len:".strlen($der)." \n";

	//验签
	$php_func = 'php_SM2Verify';
    $recode = $php_func($data, $redata,$sm2keys[1]);
    echo "recode：$recode \n";

	//php_SM2Verify 接收的签名值是RS格式，若对方给的签名值是DER格式
	//则通过如下方式转换,然后再验签
	$php_func = 'php_SM2FormatConvert';
    $recode = $php_func(201,$der, $rs);
    echo "recode：$recode \n";
    echo "signValue RS: ".string2hex($rs)." len:".strlen($rs)." \n";
}

//test php_SM2SignHash php_SM2VerifyHash
function test_php_SM2SignHashAndSM2VerifyHash(){
    $php_func = 'php_SM2SignHash';
    echo "--------$php_func--------\n";
    $data = "this is test 这是测试！this is test 这是测试！";
    $sm2keys = test_php_SM2Genkey();//0 privkey 1 pubkey
	
	$php_func = 'php_SM3Crypt';
    $recode = $php_func($data,$sm3hash);
    echo "recode：$recode \n";
    echo "sm3hash: ".string2hex($sm3hash)." len:".strlen($sm3hash)." \n";
	
	$php_func = 'php_SM2SignHash';
    $recode = $php_func($sm3hash, $redata,$sm2keys[0]);
    echo "recode：$recode \n";
    echo "signValue: ".string2hex($redata)." len:".strlen($redata)." \n";
    $php_func = 'php_SM2VerifyHash';
    $recode = $php_func($sm3hash, $redata,$sm2keys[1]);
    echo "recode：$recode \n";
}

//test php_SM2Encrypt php_SM2Decrypt
function test_php_SM2EncryptAndSM2Decrypt(){
    $php_func = 'php_SM2Encrypt';
    echo "--------$php_func--------\n";
    $data = "this is test 这是测试！this is test 这是测试！";
    $sm2keys = test_php_SM2Genkey();//0 privkey 1 pubkey
	
	//加密	
	$recode = $php_func($data, $cipher,$sm2keys[1]);
    echo "recode：$recode \n";
    echo "cipher: ".string2hex($cipher)." len:".strlen($cipher)." \n";
	//php_SM2Encrypt接口返回的密文值是c1c3c2格式，以下示例转DER编码
    $php_func = 'php_SM2FormatConvert';
    $recode = $php_func(102,$cipher, $der);
    echo "recode：$recode \n";
    echo "cipher DER: ".string2hex($der)." len:".strlen($der)." \n";    

	//解密
	$php_func = 'php_SM2Decrypt';
    $recode = $php_func($cipher, $plain,$sm2keys[0]);
    echo "recode：$recode \n";
	echo "plain: $plain\n";
	
	//php_SM2Decrypt 接收密文值是c1c3c2格式，若对方给的密文值是DER格式
    //则通过如下方式转换，然后再传入接口解密
    $php_func = 'php_SM2FormatConvert';
    $recode = $php_func(101,$der, $c1c3c2);
    echo "recode：$recode \n";
    echo "cipher c1c3c2: ".string2hex($c1c3c2)." len:".strlen($c1c3c2)." \n";	
}

//test php_HextoAsc php_AsctoHex
function test_php_HextoAscAndAsctoHex(){
    $php_func = 'php_AsctoHex';
    echo "--------$php_func--------\n";
    $data = "this is test 这是测试！this is test 这是测试！";

    $recode = $php_func($data, $hex);
    echo "recode：$recode \n";
    echo "hex: $hex len:".strlen($hex)." \n";
    $php_func = 'php_HextoAsc';
    $recode = $php_func($hex, $asc);
    echo "recode：$recode \n";
    echo "plain: $asc\n";
}

//test php_base64_decode php_base64_encode
function test_php_base64_decodeAndbase64_encode(){
    $php_func = 'php_base64_encode';
    echo "--------$php_func--------\n";
    $data = "this is test 这是测试！this is test 这是测试！";

    $recode = $php_func($data, $base64);
    echo "recode：$recode \n";
    echo "base64char: $base64 len:".strlen($base64)." \n";
    $php_func = 'php_base64_decode';
    $recode = $php_func($base64, $orgin);
    echo "recode：$recode \n";
    echo "plain: $orgin\n";
}

//test 
function test_php_SM2FormatConvert(){
    $php_func = 'php_SM2FormatConvert';
    echo "--------$php_func--------\n";
	//hex编码的DER密文
	$data = 
	"308198021F5A9D5395EE7A52463E07727CAEA3001A3D95ADF105992B3F8430C0B63D5272022011BC87B586EA976FF2A8009393FE3F71FEBD11FD249F59796054DB66B4789C6D04201D3FAEF883C8D839DDF36FC083B125DE65D8E58B3AACEB97CEBCF529A8F0C2A7043119C9E04B8DB90E6CC0898A85665DA1FA990B4DB6197AE55674D68C3AB5328D408D0B7EBAE99ED6C8243FED2A18C024545A";
	//先解码再转der格式（如果是base64编码，则用base64解码）
	$php_HextoAsc = 'php_HextoAsc';
    $recode = $php_HextoAsc($data, $dataAsc);
	$recode = $php_func(101,$dataAsc, $c1c3c2);
    echo "recode：$recode \n";
    echo "c1c3c2: ".string2hex($c1c3c2)." len:".strlen($c1c3c2)." \n";
}

//test SM4CBCCrypt
function test_php_SM4CBCCrypt(){
    $php_func = 'php_SM4CBCCrypt';
    echo "--------$php_func--------\n";
    $data = "this is a test! 这是个测试！";
    $plainkey = "1234567890123456";//如果是hex编码，务必解码

	//接口是密文key，将明文key加密后再传入php_SM4CBCCrypt进行数据加密	
	//不必要每次都加密key,建议手工加密一次，将key密文保存使用，key明文保存至安全的地方
	//若是会话级别的key则自行定策略
	$php_CryptKey = 'php_CryptKey';
    $recode = $php_CryptKey(0, $plainkey,$key);
    echo "recode：$recode \n";

	//打印key密文
	$php_hex = 'php_AsctoHex';
    $recode = $php_hex($key, $hex);
    echo "recode：$recode \n";
    echo "hex: $hex len:".strlen($hex)." \n";
	
	$iv = "1234567812345678";
	//加密
    $recode = $php_func(0,$data,$redata,$key,$iv);
    echo "recode：$recode \n";
    echo "redata: ".string2hex($redata)." len:".strlen($redata)." \n";
    //解密
	$recode = $php_func(1,$redata,$dedata,$key,$iv);
    echo "recode：$recode \n";
    echo "plain: ".$dedata." \n";
}

function run_test(){
	//先初始化接口，初始化成功后，可重复调用加解密接口
	test_php_crypto_init();

    test_php_SM4Crypt1();
    echo "\n";
    test_php_SM4Crypt2();
    echo "\n";
    test_php_CryptFile();
	echo "\n";
	test_php_CryptKey();
   	echo "\n";
    test_php_SM3Crypt();
	echo "\n";
    test_php_MACCrypt();
	echo "\n";
    test_php_CryptLmkMac();
	echo "\n";
    test_php_SM2SignAndSM2Verify();
	echo "\n";
    test_php_SM2SignHashAndSM2VerifyHash();
	echo "\n";
    test_php_SM2EncryptAndSM2Decrypt(); 
	echo "\n";
	test_php_HextoAscAndAsctoHex();
	echo "\n";
    test_php_base64_decodeAndbase64_encode();
	echo "\n";
    test_php_SM2FormatConvert();
    echo "\n";
    test_php_SM4CBCCrypt();
}
run_test();
?>
