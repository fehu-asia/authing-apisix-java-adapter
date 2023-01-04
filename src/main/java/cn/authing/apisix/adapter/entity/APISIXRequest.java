package cn.authing.apisix.adapter.entity;

import lombok.Data;
import lombok.ToString;

import java.util.Map;

@Data
@ToString
public class APISIXRequest {
    private String uri;
    private String method;
    private String request_id;
    private String host;
    private String remote_addr;
    private Map<String, Object> args;
    private Map<String, Object> headers;
    private Map<String, Object> configs;
}
