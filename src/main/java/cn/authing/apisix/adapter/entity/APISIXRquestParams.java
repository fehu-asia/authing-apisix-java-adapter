package cn.authing.apisix.adapter.entity;

import lombok.Data;
import lombok.ToString;

import java.util.Map;

/**
 * APISIX 请求实体类
 */
@Data
@ToString
public class APISIXRquestParams {
    /**
     * APISIX 请求上下文
     */
    APISIXRequest request;
    /**
     * 插件配置
     */
    Map<String, Object> pluginConfig;

}
