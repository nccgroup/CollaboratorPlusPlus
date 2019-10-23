package com.nccgroup.collaboratorplusplus.extension;

import java.util.ArrayList;
import java.util.HashMap;

public enum DNSQueryType {
    A(1),
    AAAA(28),
    CNAME(5),
    MX(15),
    NS(2),
    SRV(33),
    SOA(6),
    TXT(16);

    private int code;

    DNSQueryType(int code){
        this.code = code;
    }

    static HashMap<Integer, DNSQueryType> types;
    static {
        types = new HashMap<>();
        for (DNSQueryType type : DNSQueryType.values()) {
            types.put(type.code, type);
        }
    }

    public static String getTypeByCode(int code){
        if(types.containsKey(code)) return types.get(code).toString();
        else return "UNKNOWN";
    }
}
