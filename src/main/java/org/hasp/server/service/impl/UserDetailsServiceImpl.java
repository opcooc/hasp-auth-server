package org.hasp.server.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.TransferUser;
import org.hasp.server.mapper.UserMapper;
import org.hasp.server.repository.core.TransferUserRepository;
import org.hasp.server.support.CustomUser;
import org.hasp.server.utils.SecurityConstants;
import org.hasp.server.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class UserDetailsServiceImpl implements UserDetailsService {

    private final TransferUserRepository transferUserRepository;

    @Override
    public CustomUser loadUserByUsername(String username) throws UsernameNotFoundException {
        HttpServletRequest request = SecurityUtils.getHttpServletRequest();
        String source = request.getParameter(SecurityConstants.OAUTH_FORM_LOGIN_TYPE_PARAM);
        source = source == null ? SecurityConstants.OAUTH_FORM_USERNAME_LOGIN_TYPE : source;
        boolean contact = !SecurityConstants.OAUTH_FORM_USERNAME_LOGIN_TYPE.contains(source);
        TransferUser user = transferUserRepository.load(username, source);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return UserMapper.toCustomUser(user, contact);
    }

}
