package org.likelion.likelion_12th_team05.global.auth.kakaoAuth;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import org.likelion.likelion_12th_team05.user.domain.Role;
import org.likelion.likelion_12th_team05.user.domain.User;
import org.likelion.likelion_12th_team05.user.domain.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class KakaoLoginService {
    @Value("${kakao.client-id}")
    private String KAKAO_CLIENT_ID;

    private final UserRepository userRepository;
    private final KaKaoTokenProvider kaKaoTokenProvider;

    private static final String KAKAO_TOKEN_URL = "https://kauth.kakao.com/oauth/token";
    private static final String KAKAO_REDIRECT_URI = "http://localhost:8080/login/oauth2/code/kakao";

    // 카카오에서 전달해준 인가 코드로 액세스 토큰 리다이렉트
    public String getKakaoAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", KAKAO_CLIENT_ID);
        params.add("redirect_uri", KAKAO_REDIRECT_URI);
        params.add("code", code);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(KAKAO_TOKEN_URL, request, String.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            String json = response.getBody();
            Gson gson = new Gson();
            KakaoToken tokenResponse = gson.fromJson(json, KakaoToken.class);
            return tokenResponse.getAccessToken();
        } else {
            throw new RuntimeException("카카오 액세스 토큰 발급에 실패하였습니다." + response.getStatusCode());
        }
    }

    // 카카오 로그인 후 JWT 토큰을 반환하는 메소드
    public KakaoToken signUpOrSignInWithKakao(String kakaoAccessToken) {
        KakaoUserInfo kakaoUserInfo = getUserInfoFromKakao(kakaoAccessToken);

        if (kakaoUserInfo.getKakao_account() == null || kakaoUserInfo.getKakao_account().getEmail() == null) {
            throw new RuntimeException("카카오 회원가입 정보가 없습니다.");
        }
        // 이메일로 사용자를 찾거나 새로 생성
        User user = userRepository.findByEmail(kakaoUserInfo.getKakao_account().getEmail()).orElseGet(() ->
                userRepository.save(User.builder()
                        .email(kakaoUserInfo.getKakao_account().getEmail())
                        .name(kakaoUserInfo.getProperties().getNickname())
                        .role(Role.ROLE_KAKAO)
                        .build())
        );
        // JWT 토큰 생성
        return kaKaoTokenProvider.generateToken(user);
    }

    // 카카오 사용자 정보를 가져오는 메소드
    public KakaoUserInfo getUserInfoFromKakao(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();
        String url = "https://kapi.kakao.com/v2/user/me";  // 카카오 사용자 정보 요청 URL

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            String json = responseEntity.getBody();
            Gson gson = new Gson();
            return gson.fromJson(json, KakaoUserInfo.class);
        } else {
            throw new RuntimeException("카카오 사용자 정보 조회에 실패하였습니다." + responseEntity.getStatusCode()
                    + ", Response: " + responseEntity.getBody());
        }
    }
}