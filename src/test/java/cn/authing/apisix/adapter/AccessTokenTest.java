package cn.authing.apisix.adapter;

import cn.hutool.http.HttpUtil;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class AccessTokenTest {

    @SneakyThrows
    public static void main(String[] args) {
        // The access token to validate, typically submitted with a HTTP header like
// Authorization: Bearer eyJraWQiOiJDWHVwIiwidHlwIjoiYXQrand0IiwiYWxnIjoi...
        String accessToken =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAzT0FEb3hjNlVES0V5V1hrS3BrV0dWTGtUMnpfOERvUjIyNnZ1WVhtUFEifQ.eyJzdWIiOiI2M2ExMzFjYTUxOWRlZjM0ZjQ4ZjQ1NmUiLCJhdWQiOiI2M2ExNDhjMDk3ODgxODQ5MjNiNDI4NzYiLCJzY29wZSI6Im9mZmxpbmVfYWNjZXNzIG9wZW5pZCBwcm9maWxlIHBob25lIGVtYWlsIiwiaWF0IjoxNjcxNzY1Nzc5LCJleHAiOjE2NzM0ODU3NzksImp0aSI6IkNMWER5U19SaXNVUmVUcnNZaEVGdXFPUlBUV3BCeElYbHlvdWNpaGRfaFYiLCJpc3MiOiJodHRwczovL3hhc21kYWtuZ2RzLmF1dGhpbmcuY24vb2lkYyJ9.tB6zii96jXs6yZswVS1v_Hu72Tji70ULJa7XmZ8OkZ7UN0sawHAdnq7I_BbO5UqkzMcaHEOOUKC8GCKp-ES64wTqU5SwQDADl-TobOFD1ivb_30YWiWAQDCkgnaW9Gvl0G80Q01Muu34Sh1WfmTLBvCzkjm1lPEqwjFU0p21HO-FDQNu0G8_z1qzg_Oj_itTnyA0aEonzmuCLeR0PXXZTUGjbVPbM3xL53s1yUI_xhvJg3Wv7vrOBKyNfD-UqK-WS_yoXsBLYAdp-kBPdxsq1hkehtn4_yp2FfThBtwt2Ral3IsVIlYPacM4SWbcmI15utzUJFMwQFFypH5wHF4D9g";


        JWSObject parse = JWSObject.parse(accessToken);
        Map<String, Object> payload = parse.getPayload().toJSONObject();
        Object aud = payload.get("aud");
        Object sub = payload.get("sub");
        System.out.println(aud);
        System.out.println(sub);


        // 在线校验
        HashMap<String, Object> paramMap = new HashMap<>();
        paramMap.put("token", accessToken);
        paramMap.put("token_type_hint", "access_token");
//        paramMap.put("client_id", aud);
        String response = HttpUtil.post("https://api.authing.cn/" + aud + "/oidc/token/introspection?access_token", paramMap);
        System.out.println(response);
        System.out.println(response.startsWith("{\"active\":true"));

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
//        jwtProcessor.setJWSTypeVerifier(
//                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also handle key-rollover
        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL("https://api.authing.cn/" + aud + "/oidc/.well-known/jwks.json"));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens issued by the Connect2id
        // server, may differ with other servers
//        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
//                new JWTClaimsSet.Builder().issuer("https://xasmdakngds.authing.cn/oidc").build(),
//                new HashSet<>(Arrays.asList("sub", "iat", "exp", "scp", "cid", "jti"))));

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());


        String s = "z274v8GGK-PS4u8jEpJPrCDzYFaP1GdrnNN1a75w6pxobE0flVI6OIq4qcmj9id6cPDLSZlSIaK4xo_TbaANO_p9P-32GH-ne8CFXNvPjc9Rzyqgqd-pWxYGuLjrMivIsv4K-viBDjwdOgOAPqlx7MBx5dEkNHrpHdNji48Z5PLtQcM7I4BLCo25K7y2MJxdph1nO2KeM5QX411LTnoifIGYAJ2WSu6ddol2oVuvNKmsl6IfpbWtm6n7XzucDEMTDASx2AdBlP8JSJEq9i8bIkn6xBcZj3SZiNKTwaIliUJoEJlgv9oQHyxdIJPdWbOnmXeLeqWJ6s546ZbEEkVSew";
//        JWTValidator.of(accessToken).validateAlgorithm(JWTSignerUtil.rs256(new rspu));


    }
}
