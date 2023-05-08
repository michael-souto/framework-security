package com.detrasoft.framework.security.interceptors;

import com.detrasoft.framework.core.context.GenericContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class UserInterceptor implements HandlerInterceptor {
    @Autowired
    private TokenStore tokenStore;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        if (SecurityContextHolder.getContext().getAuthentication().getDetails() != null
                && SecurityContextHolder.getContext().getAuthentication().getDetails()
                .getClass() == OAuth2AuthenticationDetails.class) {
            OAuth2AuthenticationDetails obj = (OAuth2AuthenticationDetails) SecurityContextHolder.getContext()
                    .getAuthentication().getDetails();
            OAuth2AccessToken toke = tokenStore.readAccessToken(obj.getTokenValue());

            GenericContext.setContexts("token", obj.getTokenValue());

            Object id_detrasoft = toke.getAdditionalInformation().get("id_detrasoft");
            GenericContext.setContexts("id_detrasoft", (id_detrasoft != null ? id_detrasoft.toString() : null));

            Object id_user = toke.getAdditionalInformation().get("id_user");
            GenericContext.setContexts("id_user", (id_user != null ? id_user.toString() : null));

            Object firstName = toke.getAdditionalInformation().get("first_name");
            GenericContext.setContexts("first_name", firstName != null ? firstName.toString() : null);

            Object last_name = toke.getAdditionalInformation().get("last_name");
            GenericContext.setContexts("last_name", last_name != null ? last_name.toString() : null);

            Object email = toke.getAdditionalInformation().get("email");
            GenericContext.setContexts("email", (email != null ? email.toString() : null));

            Object phone = toke.getAdditionalInformation().get("phone");
            GenericContext.setContexts("phone", (phone != null ? phone.toString() : null));

            Object type = toke.getAdditionalInformation().get("type");
            GenericContext.setContexts("type", (type != null ? type.toString() : null));

            Object business = toke.getAdditionalInformation().get("business");
            GenericContext.setContexts("business", (business != null ? business.toString() : null));

            Object img = toke.getAdditionalInformation().get("img");
            GenericContext.setContexts("img", (img != null ? img.toString() : null));

            Object urlHome = toke.getAdditionalInformation().get("url_home");
            GenericContext.setContexts("url_home", (urlHome != null ? urlHome.toString() : null));
        }

        return true;
    }
}
