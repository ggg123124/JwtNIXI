package com.nixi.jwt.enumclass;

public enum TokenStateEnum {
	/**
	  * 过期
	  */
	EXPIRED("EXPIRED"),
	/**
	 * 无效(token不合法)
	 */
	INVALID("INVALID"), 
	/**
	 * 有效的
	 */
	VALID("VALID");  
	private String  state;  
	private TokenStateEnum(String state) {  
        this.state = state;  
    }
	
	/**
	 * 
	* @author NIXI
	* @Title: getTokenStateEnum
	* @Description: 根据名称获取枚举对象
	* @param tokenState
	* @return    参数
	* @return TokenStateEnum    返回类型
	 */
	public static TokenStateEnum getTokenStateEnum(String tokenState){
		TokenStateEnum[] states=TokenStateEnum.values();
		TokenStateEnum ts=null;
    	for (TokenStateEnum state : states) {
			if(state.toString().equals(tokenState)){
				ts=state;
				break;
			}
		}
    	return ts;
    }

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}
	
}
