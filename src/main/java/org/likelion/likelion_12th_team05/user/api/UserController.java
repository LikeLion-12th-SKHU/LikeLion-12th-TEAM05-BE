package org.likelion.likelion_12th_team05.user.api;

import jakarta.validation.Valid;
import org.likelion.likelion_12th_team05.common.error.SuccessCode;
import org.likelion.likelion_12th_team05.config.ApiResponseTemplate;
import org.likelion.likelion_12th_team05.global.auth.googleAuth.AuthLoginService;
import org.likelion.likelion_12th_team05.global.auth.googleAuth.GoogleToken;
import org.likelion.likelion_12th_team05.user.api.dto.request.UserSignInReqDto;
import org.likelion.likelion_12th_team05.user.api.dto.request.UserSignUpReqDto;
import org.likelion.likelion_12th_team05.user.api.dto.response.UserSignInResDto;
import org.likelion.likelion_12th_team05.user.application.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private final UserService userService;
    private final AuthLoginService authLoginService;

    public UserController(UserService userService, AuthLoginService authLoginService) {
        this.userService = userService;
        this.authLoginService = authLoginService;
    }

    // 자체 회원가입
    @PostMapping("/sign-up")
    public ApiResponseTemplate<String> userSignUp(@RequestBody @Valid UserSignUpReqDto userSignUpReqDto) {
        userService.userSignUp(userSignUpReqDto);
        return ApiResponseTemplate.successResponse(userSignUpReqDto.refreshToken(), SuccessCode.USER_SIGNUP_SUCCESS);
    }

    @GetMapping("/code/google")
    public GoogleToken googleCallback(@RequestParam(name = "code") String code) {
        String googleAccessToken = authLoginService.getGoogleAccessToken(code);
        return signUpOrSignIn(googleAccessToken);
    }

    public GoogleToken signUpOrSignIn(String googleAccessToken) {
        return authLoginService.signUpOrSignIn(googleAccessToken);
    }

    // 자체 로그인
    @GetMapping("/sign-in")
    private ApiResponseTemplate<UserSignInResDto> userSignIn(@RequestBody @Valid UserSignInReqDto userSignInReqDto) {
        UserSignInResDto userSignInResDto = userService.userSignIn(userSignInReqDto);
        return ApiResponseTemplate.successResponse(userSignInResDto, SuccessCode.USER_LOGIN_SUCCESS);
    }
}
