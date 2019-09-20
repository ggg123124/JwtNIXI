
package com.nixi.jwt.token;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;





import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.nixi.jwt.enumclass.TokenStateEnum;
import com.nixi.jwt.jwt.T_JwtToken;


public class TokenUtil {
	
	
	/**
	 * 
	* @author NIXI
	* @Title: getToken
	* @Description: 获取token
	* @param jwtToken jwtToken实体
	* @param key 密钥
	* @return token字符串
	* @throws InvalidKeyException
	* @throws IllegalStateException
	* @throws UnsupportedEncodingException    参数
	* @return String    返回类型
	 */
	public static String getToken(T_JwtToken jwtToken,String key) throws InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		JSONObject jwtHeaderJson = (JSONObject) JSON.toJSON(jwtToken.getHeader());//头部信息
	
		JSONObject jwtPayload = new JSONObject(jwtToken.getPayload());//负载信息
		//检查payload是否含有签发时间以及失效时间，如果没有则使用默认值
		jwtPayload = checkPayload(jwtPayload);
		
		String ciphertext = "";//密文
		String signature = "";//签名
		String token = "";//jwttoken
		
		System.out.println(jwtPayload);
		
		//获取头部以及负载的密文
		ciphertext = EncryptionAndDecryption.getBase64UrlCiphertext(jwtHeaderJson, jwtPayload);
		//获取签名
		signature = EncryptionAndDecryption.getSignature(ciphertext, key);
		
		
		//拼接token
		token = ciphertext+"."+signature;
		return token;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: checkPayload
	* @Description: 用于检查payload是否有签发时间以及有效时间，如果没有则默认设置签发时间为当前时间，有效时间为一个小时
	* @param payload
	* @return    参数
	* @return JSONObject    返回类型
	 */
	private static JSONObject checkPayload(JSONObject payload) {
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		if(payload.get("exp")==null) {	
			long time = new Date().getTime();
			time += 3600000;
			Date exp = new Date(time);	
			payload.put("exp", format.format(exp));
		}
		if(payload.get("iat")==null) {
			payload.put("iat", format.format(new Date()));
		}
		return payload;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: readToken
	* @Description: 读取token数据
	* @param token
	* @return    参数
	* @return Map<String,Object>    返回类型
	 */
	public static Map<String, Object> readToken(String token){
		String ciphertext =  "";
		String[] headerAndPayload = {};
		Map<String, Object> map = new HashMap<String, Object>();
		//日期格式化
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		headerAndPayload = token.split("\\.");
		//被base64url加密的头部信息
		String jwtHeaderBase64UrlStr = headerAndPayload[0];
		//被base64url加密的负载信息
		String jwtPayloadBase64UrlStr = headerAndPayload[1];
		ciphertext = jwtHeaderBase64UrlStr+"."+jwtPayloadBase64UrlStr;
		
		
		//取出头部以及负载并将其转为json格式
		String jwtHeaderStr = EncryptionAndDecryption.getBase64UrlPlaintext(jwtHeaderBase64UrlStr);
		String jwtPayloadStr = EncryptionAndDecryption.getBase64UrlPlaintext(jwtPayloadBase64UrlStr);
		JSONObject jwtHeaderJson = JSONObject.parseObject(jwtHeaderStr);
		JSONObject jwtPayloadJson = JSONObject.parseObject(jwtPayloadStr);
		Date expirationTime = null;
		
		
		
		map.put("jwtHeader", jwtHeaderJson);
		map.put("jwtPayload", jwtPayloadJson);
		
		return map;
	}
	
	
	/**
	 * 
	* @author NIXI
	* @Title: tokenCheck
	* @Description: 检查token是否合法和有效,并返回数据
	* @param token
	* @param key
	* @return 
	* @throws InvalidKeyException    参数
	* @return String    返回类型
	 */
	public static Map<String, Object> tokenCheck(String token,String key) throws InvalidKeyException {
		String ciphertext =  "";
		String[] headerAndPayload = {};
		Map<String, Object> map = new HashMap<String, Object>();
		//日期格式化
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		headerAndPayload = token.split("\\.");
		//被base64url加密的头部信息
		String jwtHeaderBase64UrlStr = headerAndPayload[0];
		//被base64url加密的负载信息
		String jwtPayloadBase64UrlStr = headerAndPayload[1];
		ciphertext = jwtHeaderBase64UrlStr+"."+jwtPayloadBase64UrlStr;
		String jwtSecret = headerAndPayload[2];
		String signature = "";
		
		//String reqStr = "";
		
		//如果签名对不上则报错
		signature = EncryptionAndDecryption.getSignature(ciphertext, key);
		if(!jwtSecret.equals(signature)) {
			map.put("tokenState", TokenStateEnum.INVALID);
			map.put("message","签名不正确，负载可能遭到修改");
			return map;
		}
		//取出头部以及负载并将其转为json格式
		String jwtHeaderStr = EncryptionAndDecryption.getBase64UrlPlaintext(jwtHeaderBase64UrlStr);
		String jwtPayloadStr = EncryptionAndDecryption.getBase64UrlPlaintext(jwtPayloadBase64UrlStr);
		JSONObject jwtHeaderJson = JSONObject.parseObject(jwtHeaderStr);
		JSONObject jwtPayloadJson = JSONObject.parseObject(jwtPayloadStr);
		Date expirationTime = null;
		
		if(jwtPayloadJson.get("exp")!=null) {
			try {
				expirationTime = format.parse((String) jwtPayloadJson.get("exp"));
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}else {
			map.put("tokenState", TokenStateEnum.INVALID);
			map.put("message", "该token没有过期时间，非法token");
			return map;
		}
		
		try {
			expirationTime = format.parse((String) jwtPayloadJson.get("exp"));
			
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(new Date().getTime()>expirationTime.getTime()) {
			map.put("tokenState", TokenStateEnum.EXPIRED);
			map.put("message", "token已失效");
			return map;
		}
		
		map.put("jwtHeader", jwtHeaderJson);
		map.put("jwtPayload", jwtPayloadJson);
		map.put("tokenState", TokenStateEnum.VALID);
		return map;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: getToken
	* @Description: 获取token
	* @param payload 负载数据
	* @param key 密钥
	* @return    token
	* @return String    返回类型
	 */
	public static String getToken(Map<String, Object> payload,String key) {
		JSONObject jwtHeaderJson = new JSONObject();
		jwtHeaderJson.put("alg", "HS256");
		jwtHeaderJson.put("typ", "JWT");
		JSONObject jwtPayload = new JSONObject(payload);
		jwtPayload = checkPayload(jwtPayload);
		String ciphertext = "";
		String signatrue = "";
		String token = "";
		ciphertext = EncryptionAndDecryption.getBase64UrlCiphertext(jwtHeaderJson, jwtPayload);
		try {
			signatrue = EncryptionAndDecryption.getSignature(ciphertext, key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		token = ciphertext+"."+signatrue;
		
		return token;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: getToken
	* @Description: 获取token
	* @param payload 负载
	* @param key 密钥
	* @param validTime 有效时间,单位秒
	* @return    参数
	* @return String    返回类型
	 */
	public static String getToken(Map<String, Object> payload,String key,long validTime) {
		JSONObject jwtHeaderJson = new JSONObject();
		jwtHeaderJson.put("alg", "HS256");
		jwtHeaderJson.put("typ", "JWT");
		JSONObject jwtPayload = new JSONObject(payload);
		//日期格式化
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		long time = new Date().getTime();
		validTime *= 1000;
		time += validTime;
		
		String ciphertext = "";
		String signatrue = "";
		String token = "";
		jwtPayload.put("exp", format.format(new Date(time)));
		jwtPayload = checkPayload(jwtPayload);
		ciphertext = EncryptionAndDecryption.getBase64UrlCiphertext(jwtHeaderJson, jwtPayload);
		try {
			signatrue = EncryptionAndDecryption.getSignature(ciphertext, key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		token = ciphertext+"."+signatrue;
		
		return token;
	}
	
	/**
	 * 
	* @author NIXI
	* @Title: getToken
	* @Description: 根据传入的头部以及负载信息获取token
	* @param head
	* @param payload
	* @param key
	* @param validTime
	* @return    token字符串
	* @return String    返回类型
	 */
	public static String getToken(Map<String, Object> head ,Map<String, Object> payload,String key,long validTime) {
		JSONObject jwtHeaderJson = new JSONObject(head);
		jwtHeaderJson.put("alg", "HS256");
		jwtHeaderJson.put("typ", "JWT");
		JSONObject jwtPayload = new JSONObject(payload);
		//日期格式化
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		long time = new Date().getTime();
		validTime *= 1000;
		time += validTime;
		
		String ciphertext = "";
		String signatrue = "";
		String token = "";
		jwtPayload.put("exp", format.format(new Date(time)));
		jwtPayload = checkPayload(jwtPayload);
		ciphertext = EncryptionAndDecryption.getBase64UrlCiphertext(jwtHeaderJson, jwtPayload);
		try {
			signatrue = EncryptionAndDecryption.getSignature(ciphertext, key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		token = ciphertext+"."+signatrue;
		
		return token;
	}
	
	
}
