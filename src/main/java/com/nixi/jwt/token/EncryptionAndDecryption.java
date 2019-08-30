package com.nixi.jwt.token;


import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import com.alibaba.fastjson.JSONObject;

public class EncryptionAndDecryption {
	/**
	 * 
	* @author NIXI
	* @Title: getBase64UrlPlaintext
	* @Description: 解密base64Url
	* @param ciphertext
	* @return    参数
	* @return String    返回类型
	 */
	public static String getBase64UrlPlaintext(String ciphertext) {
		byte[] bs = Base64.getUrlDecoder().decode(ciphertext);
		String plaintext = "";
		try {
			plaintext = new String(bs,"utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return plaintext;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: getSignature
	* @Description: 获取签名
	* @param data 待签名数据
	* @param key 密钥
	* @return 签名
	* @throws InvalidKeyException    参数
	* @return String    返回类型
	 */
	public static String getSignature(String data, String key) throws InvalidKeyException {
		String signature = "";
		try {
			//执行签名算法设置为HS256
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
			//插入密钥
			sha256_HMAC.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
			
			//执行签名并将所得的byte[]转为16进制字符串
			signature = new HexBinaryAdapter().marshal(sha256_HMAC.doFinal(data.getBytes()));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signature;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: getBase64UrlCiphertext
	* @Description: 获取base64url加密的密文
	* @param jwtHeaderJson
	* @param jwtPayload
	* @return    参数
	* @return String    返回类型
	 */
	public static String getBase64UrlCiphertext(JSONObject jwtHeaderJson, JSONObject jwtPayload) {
		String jwtHeaderBase64UrlStr = "";//base64加密的头部信息
		String jwtPayLoadBase64UrlStr = "";//base64加密的负载信息
		String ciphertext = "";//密文
		try {
			//对头部信息以及负载进行base64url算法
			 jwtHeaderBase64UrlStr = Base64.getUrlEncoder().encodeToString(jwtHeaderJson.toString().getBytes("utf-8"));
			 jwtPayLoadBase64UrlStr = Base64.getUrlEncoder().encodeToString(jwtPayload.toString().getBytes("utf-8"));
			 ciphertext = (jwtHeaderBase64UrlStr+"."+jwtPayLoadBase64UrlStr).replaceAll("=", "");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ciphertext;
	}
}
