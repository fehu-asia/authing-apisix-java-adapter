package cn.authing.apisix.adapter.controller;

import cn.authing.apisix.adapter.entity.APISIXRquestParams;
import cn.authing.sdk.java.client.ManagementClient;
import cn.authing.sdk.java.dto.CheckPermissionDto;
import cn.authing.sdk.java.dto.CheckPermissionRespDto;
import cn.authing.sdk.java.dto.CheckPermissionsRespDto;
import cn.authing.sdk.java.model.ManagementClientOptions;
import cn.hutool.http.HttpStatus;
import cn.hutool.http.HttpUtil;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StopWatch;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Gao FeiHu
 * @version 1.0.0
 * @date 2022.12.22
 * @email gaofeihu@authing.cn
 */
@RestController
@Slf4j
public class IsAllowController {

    /**
     * 用户池 ID
     */
    public static String ACCESS_KEY_ID = "";
    /**
     * 用户池密钥
     */
    public static String ACCESS_KEY_SECRET = "";
    /**
     * Authing SDK
     * See
     * https://docs.authing.cn/v3/reference/
     */
    ManagementClient managementClient;

    /**
     * 初始化 ManagementClient
     *
     * @param ak  用户池 ID
     * @param aks 用户池密钥
     */
    public void init(String ak, String aks) {
        log.info("init ManagementClient ......");
        try {
            // 保存用户池 ID 和密钥
            ACCESS_KEY_ID = ak;
            ACCESS_KEY_SECRET = aks;
            // 初始化
            ManagementClientOptions options = new ManagementClientOptions();
            options.setAccessKeyId(ak);
            options.setAccessKeySecret(aks);
            managementClient = new ManagementClient(options);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("初始化 managementClient 失败，可能无法请求！");
        }
    }

    /**
     * 是否放行
     *
     * @param apisixRquestParams 请求 body ，包含了 APISIX 插件的配置以及请求上下文
     * @param response           HttpServletResponse
     * @return 200 OK 放行
     * 403 forbidden 禁止访问
     * 500 internal server error 请求错误 可根据实际需求放行或拒绝
     */
    @PostMapping("/isAllow")
    public Object isAllow(@RequestBody APISIXRquestParams apisixRquestParams, HttpServletResponse response) {

        // 请求计时器
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        // 请求 ID 与 APISIX 一致
        String requestID = apisixRquestParams.getRequest().getRequest_id();

        log.info("{} ==> 请求入参 : {} ", requestID, new Gson().toJson(apisixRquestParams));

        try {
            // 0. 若插件为多实例用于实现不同业务逻辑，此处可对应修改为多实例模式
            if (managementClient == null || !ACCESS_KEY_ID.equals(apisixRquestParams.getPluginConfig().get("user_pool_id"))) {
                init((String) apisixRquestParams.getPluginConfig().get("user_pool_id"), (String) apisixRquestParams.getPluginConfig().get("user_pool_secret"));
            }

            // 1. 拿到 accessToken
            String authorization = (String) apisixRquestParams.getRequest().getHeaders().get("authorization");
            if (!StringUtils.hasLength(authorization)) {
                return result(response, stopWatch, requestID, HttpStatus.HTTP_UNAUTHORIZED, "HTTP_UNAUTHORIZED");
            }

            String accessToken = authorization;
            if (authorization.startsWith("Bearer")) {
                accessToken = authorization.split(" ")[1].trim();
            }


            log.info("{} ==> accessToken : {} ", requestID, accessToken);
            // 2. 解析 accessToken 拿到应用 ID 和用户 ID
            JWSObject parse = JWSObject.parse(accessToken);
            Map<String, Object> payload = parse.getPayload().toJSONObject();
            String aud = (String) payload.get("aud");
            String sub = (String) payload.get("sub");

            // 3. 校验 accessToken
            // 在线校验
            String result = onlineValidatorAccessToken(accessToken, aud);
            log.info("{} ==> accessToken 在线结果 : {} ", requestID, result);
            if (!result.contains("{\"active\":true")) {
                return result(response, stopWatch, requestID, HttpStatus.HTTP_UNAUTHORIZED, "HTTP_UNAUTHORIZED");
            }

//            // 离线校验
//            if (null == offlineValidatorAccessToken(accessToken, aud)) {
//                return result(response, stopWatch, requestID, HttpStatus.HTTP_UNAUTHORIZED, "HTTP_UNAUTHORIZED");
//            }

            // 4. 获取到 APISIX 中的请求方法，对应 Authing 权限中的 action
            String action = apisixRquestParams.getRequest().getMethod();

            // 5. 获取到 APISIX 中的请求路径
            String resource = apisixRquestParams.getRequest().getUri();

            // 6. 去 Authing 请求，判断是否有权限
            // TODO 可在此添加 Redis 对校验结果进行缓存
            CheckPermissionDto reqDto = new CheckPermissionDto();
            reqDto.setUserId(sub);
            reqDto.setNamespaceCode(aud);
            reqDto.setResources(Arrays.asList(resource));
            reqDto.setAction(action);
            CheckPermissionRespDto checkPermissionRespDto = managementClient.checkPermission(reqDto);
            log.info(new Gson().toJson(checkPermissionRespDto));

            // 7. 由于我们是单个 resource 校验，所以只需要判断第一个元素即可
            List<CheckPermissionsRespDto> resultList = checkPermissionRespDto.getData().getCheckResultList();
            if (resultList.isEmpty() || resultList.get(0).getEnabled() == false) {
                return result(response, stopWatch, requestID, HttpStatus.HTTP_FORBIDDEN, "HTTP_FORBIDDEN");
            }

            return result(response, stopWatch, requestID, HttpStatus.HTTP_OK, "ok");

        } catch (Exception e) {
            e.printStackTrace();
            log.error("请求错误！", e);
            return result(response, stopWatch, requestID, HttpStatus.HTTP_INTERNAL_ERROR, e.getMessage());
        }
    }


    public String result(HttpServletResponse response, StopWatch stopWatch, String requestID, int status, String msg) {
        stopWatch.stop();
        log.info("{} ==> 请求耗时：{} , 请求出参 : http_status_code={},msg={} ", requestID, stopWatch.getTotalTimeMillis() + "ms", status, msg);
        response.setStatus(status);
        return msg;
    }


    public String onlineValidatorAccessToken(String accessToken, String aud) {
        HashMap<String, Object> paramMap = new HashMap<>();
        paramMap.put("token", accessToken);
        paramMap.put("token_type_hint", "access_token");
        paramMap.put("client_id", aud);
        return HttpUtil.post("https://api.authing.cn/" + aud + "/oidc/token/introspection", paramMap);

    }

    public JWTClaimsSet offlineValidatorAccessToken(String accessToken, String aud) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                    new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource =
                    null;

            keySource = new RemoteJWKSet<>(new URL("https://api.authing.cn/" + aud + "/oidc/.well-known/jwks.json"));

            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

            jwtProcessor.setJWSKeySelector(keySelector);

            return jwtProcessor.process(accessToken, null);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (BadJOSEException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } finally {
            return null;
        }
    }
}
