package com.pwl.api;

import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.pwl.config.MessageUtils;
import com.pwl.domain.Login.UserInfo;
import com.pwl.jwt.JWTService;
import com.pwl.mapper.Login.LoginMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/Login/")
public class ApiLogin {

    @Autowired
    private LoginMapper loginMapper;

    @Autowired
    private JWTService jwtService;
    
    @Value("${passwordless.corpId}")
    private String corpId;
    
    @Value("${passwordless.serverId}")
    private String serverId;
    
    @Value("${passwordless.serverKey}")
    private String serverKey;
    
    @Value("${passwordless.simpleAutopasswordUrl}")
    private String simpleAutopasswordUrl;
    
    @Value("${passwordless.restCheckUrl}")
    private String restCheckUrl;
    
    @Value("${passwordless.pushConnectorUrl}")
    private String pushConnectorUrl;
    
    @Value("${passwordless.recommend}")
    private String recommend;
    
    // Passwordless URL 엔드포인트
    private String isApUrl = "/ap/rest/auth/isAp";                                    // 비밀번호리스 등록 상태 체크
    private String joinApUrl = "/ap/rest/auth/joinAp";                                // 비밀번호리스 등록 API
    private String withdrawalApUrl = "/ap/rest/auth/withdrawalAp";                    // 비밀번호리스 해제 API
    private String getTokenForOneTimeUrl = "/ap/rest/auth/getTokenForOneTime";          // One-Time Token 요청 API
    private String getSpUrl = "/ap/rest/auth/getSp";                                  // 인증 요청 API
    private String resultUrl = "/ap/rest/auth/result";                                // 인증 결과 확인 API
    private String cancelUrl = "/ap/rest/auth/cancel";                                // 인증 취소 API

    // 등록 위한 사용자 인증, 임시 토큰 발급
    @PostMapping(value="passwordlessManageCheck", produces="application/json;charset=utf8")
    public Map<String, Object> passwordlessManageCheck(
            @RequestParam(value = "id", required = false) String id,
            @RequestParam(value = "pw", required = false) String pw,
            HttpServletRequest request) {

        if (id == null) id = "";
        if (pw == null) pw = "";

        System.out.println("passwordlessManageCheck : id [" + id + "] pw [" + pw + "]");

        Map<String, Object> mapResult = new HashMap<>();

        if (!id.equals("") && !pw.equals("")) {
            UserInfo userinfo = new UserInfo();
            userinfo.setManagerId(id);
            userinfo.setManagerPwd(pw);
            UserInfo newUserinfo = loginMapper.getUserInfo(userinfo);

            if (newUserinfo != null) {
                String tmpToken = java.util.UUID.randomUUID().toString();
                String tmpTime = Long.toString(System.currentTimeMillis());
                System.out.println("passwordlessManageCheck : token [" + tmpToken + "] time [" + tmpTime + "]");
                HttpSession session = request.getSession(true);
                session.setAttribute("PasswordlessToken", tmpToken);
                session.setAttribute("PasswordlessTime", tmpTime);
                mapResult.put("PasswordlessToken", tmpToken);
                mapResult.put("result", "OK");
            } else {
                mapResult.put("result", "유효하지 않은 id 또는 비밀번호."); // 유효하지 않은 id 또는 비밀번호.
            }
        } else {
            mapResult.put("result", "id 또는 비밀번호가 비어있음."); // id 또는 비밀번호가 비어있음.
        }
        return mapResult;
    }

    // -----------------------------------------------------------------
    // 비밀번호리스 관련 API 호출 - 리팩토링: 각 역할별 메서드로 분리
    @RequestMapping(value="/passwordlessCallApi")
    public ModelMap passwordlessCallApi(
            @RequestParam(required = false) String url,
            @RequestParam(required = false) String params,
            HttpServletRequest request, HttpServletResponse response) {

        ModelMap modelMap = new ModelMap(); // 반환할 Map

        url = (url == null) ? "" : url;
        params = (params == null) ? "" : params;

        // 파라미터 파싱 및 세션 토큰 검증
        Map<String, String> mapParams = getParamsKeyValue(params);
        String userId = mapParams.get("userId");
        String userToken = mapParams.get("token");

        if (!validateSensitiveRequest(url, userToken, request, modelMap)) {
            return modelMap;
        }

        // 사용자 존재 여부 확인
        UserInfo userinfo = new UserInfo();
        userinfo.setManagerId(userId);
        UserInfo existingUser = loginMapper.getUserInfo(userinfo);
        if (existingUser == null) {
            modelMap.put("result", "해당 사용자는 존재하지 않습니다");
            return modelMap;
        }

        // 추가 파라미터 설정
        String random = java.util.UUID.randomUUID().toString();
        String sessionId = System.currentTimeMillis() + "_sessionId";
        String ip = request.getRemoteAddr();
        if (ip.equals("0:0:0:0:0:0:0:1"))
            ip = "127.0.0.1";

        String apiUrl = getApiUrl(url);
        if (apiUrl.isEmpty()) {
            modelMap.put("result", "Invalid URL parameter");
            return modelMap;
        }

        // getSpUrl인 경우 추가 파라미터 병합
        if (url.equals("getSpUrl")) {
            params += "&clientIp=" + ip + "&sessionId=" + sessionId + "&random=" + random + "&password=";
        }

        // API 호출
        String fullUrl = restCheckUrl + apiUrl;
        String result = "";
        try {
            result = callApi("POST", fullUrl, params);
        } catch (Exception e) {
            modelMap.put("result", "Error calling API");
            return modelMap;
        }

        // URL 별 결과 처리
        processApiResponse(url, modelMap, result, mapParams, existingUser, sessionId, request.getSession());
        modelMap.put("data", result);
        return modelMap;
    }

    /**
     * 민감한 요청(joinApUrl, withdrawalApUrl)에 대해 세션 토큰 및 타임아웃 검증을 수행합니다.
     */
    private boolean validateSensitiveRequest(String url, String userToken, HttpServletRequest request, ModelMap modelMap) {
        if (url.equals("joinApUrl") || url.equals("withdrawalApUrl")) {
            HttpSession session = request.getSession();
            String sessionUserToken = (String) session.getAttribute("PasswordlessToken");
            String sessionTime = (String) session.getAttribute("PasswordlessTime");
            if (sessionUserToken == null) sessionUserToken = "";
            if (sessionTime == null) sessionTime = "";

            long nowTime = System.currentTimeMillis();
            long tokenTime = 0L;
            int gapTime = 0;
            try {
                tokenTime = Long.parseLong(sessionTime);
                gapTime = (int) (nowTime - tokenTime);
            } catch (Exception e) {
                gapTime = Integer.MAX_VALUE;
            }

            boolean matchToken = (!sessionUserToken.equals("") && sessionUserToken.equals(userToken));
            System.out.println("passwordlessCallApi : userToken match = " + matchToken + ", gapTime = " + gapTime);

            if (!matchToken) {
                modelMap.put("result", "비정상적인 접근입니다");
                return false;
            } else if (gapTime > 5 * 60 * 1000) {
                modelMap.put("result", "토큰이 만료되었습니다");
                return false;
            }
        }
        return true;
    }

    /**
     * 전달된 url 값에 따라 API의 엔드포인트를 반환합니다.
     */
    private String getApiUrl(String url) {
        if (url.equals("isApUrl"))
            return isApUrl;
        if (url.equals("joinApUrl"))
            return joinApUrl;
        if (url.equals("withdrawalApUrl"))
            return withdrawalApUrl;
        if (url.equals("getTokenForOneTimeUrl"))
            return getTokenForOneTimeUrl;
        if (url.equals("getSpUrl"))
            return getSpUrl;
        if (url.equals("resultUrl"))
            return resultUrl;
        if (url.equals("cancelUrl"))
            return cancelUrl;
        return "";
    }

    /**
     * URL에 따른 API 호출 결과를 처리합니다.
     */
    private void processApiResponse(String url, ModelMap modelMap, String result, Map<String, String> mapParams,
                                    UserInfo userinfo, String sessionId, HttpSession session) {
        JSONParser parser = new JSONParser();
        try {
            switch (url) {
                case "getTokenForOneTimeUrl" -> {
                        JSONObject jsonResponse = (JSONObject) parser.parse(result);
                        JSONObject jsonData = (JSONObject) jsonResponse.get("data");
                        String token = (String) jsonData.get("token");
                        String oneTimeToken = getDecryptAES(token, serverKey.getBytes());
                        System.out.printf("Token [%s] --> oneTimeToken [%s]%n", token, oneTimeToken);
                        modelMap.put("oneTimeToken", oneTimeToken);
                    }

                case "getSpUrl" -> modelMap.put("sessionId", sessionId);

                case "joinApUrl" -> modelMap.put("pushConnectorUrl", pushConnectorUrl);

                case "isApUrl" -> {
                    String isQRReg = mapParams.get("QRReg");
                    if ("T".equals(isQRReg)) {
                        JSONObject jsonResponse = (JSONObject) parser.parse(result);
                        JSONObject jsonData = (JSONObject) jsonResponse.get("data");
                        boolean exist = (boolean) jsonData.get("exist");
                        if (exist) {
                            System.out.println("QR Registration complete. Changing password.");
                            String newPw = System.currentTimeMillis() + ":" + userinfo.getManagerId();
                            userinfo.setManagerPwd(newPw);
                            loginMapper.updatePassword(userinfo);
                        }
                    }
                }

                case "resultUrl" -> {
                        JSONObject jsonResponse = (JSONObject) parser.parse(result);
                        JSONObject jsonData = (JSONObject) jsonResponse.get("data");
                        if (jsonData != null) {
                            String auth = (String) jsonData.get("auth");
                            if ("Y".equals(auth)) {
                                System.out.println("Authentication success. Changing password and setting session.");
                                String token = jwtService.createToken(userinfo);
                                String newPw = System.currentTimeMillis() + ":" + userinfo.getManagerId();
                                userinfo.setManagerPwd(newPw);
                                loginMapper.updatePassword(userinfo);
                                modelMap.put("token", token);
                            }
                        }
                    }

                default -> {
                    throw new RuntimeException("알 수 없는 url입니다");
                }
            }
        } catch (ParseException pe) {

        }
        modelMap.put("result", "OK");
    }

    public String callApi(String type, String requestURL, String params) {
        String retVal = "";
        Map<String, String> mapParams = getParamsKeyValue(params);
        try {
            URIBuilder b = new URIBuilder(requestURL);
            Set<String> set = mapParams.keySet();
            Iterator<String> keyset = set.iterator();
            while (keyset.hasNext()) {
                String key = keyset.next();
                String value = mapParams.get(key);
                b.addParameter(key, value);
            }
            URI uri = b.build();
            CloseableHttpClient httpClient = HttpClientBuilder.create().build();
            org.apache.http.HttpResponse response;
            if (type.toUpperCase().equals("POST")) {
                HttpPost httpPost = new HttpPost(uri);
                httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
                response = httpClient.execute(httpPost);
            } else {
                HttpGet httpGet = new HttpGet(uri);
                httpGet.addHeader("Content-Type", "application/x-www-form-urlencoded");
                response = httpClient.execute(httpGet);
            }
            HttpEntity entity = response.getEntity();
            retVal = EntityUtils.toString(entity);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return retVal;
    }

    public Map<String, String> getParamsKeyValue(String params) {
        String[] arrParams = params.split("&");
        Map<String, String> map = new HashMap<>();
        for (String param : arrParams) {
            String name = "";
            String value = "";
            String[] tmpArr = param.split("=");
            name = tmpArr[0];
            if (tmpArr.length == 2)
                value = tmpArr[1];
            map.put(name, value);
        }
        return map;
    }

    private static String getDecryptAES(String encrypted, byte[] key) {
        String strRet = null;
        byte[] strIV = key;
        if (key == null || strIV == null)
            return null;
        try {
            SecretKey secureKey = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(strIV));
            byte[] byteStr = java.util.Base64.getDecoder().decode(encrypted);
            strRet = new String(c.doFinal(byteStr), "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strRet;
    }
}