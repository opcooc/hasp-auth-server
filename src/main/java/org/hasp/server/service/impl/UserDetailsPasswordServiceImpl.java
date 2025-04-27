package org.hasp.server.service.impl;

import lombok.RequiredArgsConstructor;
import org.hasp.server.repository.core.TransferUserRepository;
import org.hasp.server.support.CustomUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class UserDetailsPasswordServiceImpl implements UserDetailsPasswordService {

    private final TransferUserRepository transferUserRepository;

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        CustomUser customUser = (CustomUser) user;
        transferUserRepository.updatePassword(customUser.getSubject(), newPassword);
        return CustomUser.builder().claims(claims -> claims.putAll(customUser.getClaims())).password(newPassword).build();
    }
}
