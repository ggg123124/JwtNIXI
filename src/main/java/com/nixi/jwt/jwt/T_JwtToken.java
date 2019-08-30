package com.nixi.jwt.jwt;

import java.util.Map;

public class T_JwtToken {
	private T_JwtHeader header;
	private Map<String, Object> payload;
	private String secret;
	public T_JwtHeader getHeader() {
		return header;
	}
	public void setHeader(T_JwtHeader header) {
		this.header = header;
	}
	public Map<String, Object> getPayload() {
		return payload;
	}
	public void setPayload(Map<String, Object> payload) {
		this.payload = payload;
	}
	public String getSecret() {
		return secret;
	}
	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	public T_JwtToken() {};
	
	
}
